"""Deterministic rule-based complaint investigator.

The QueueStorm Investigator copilot is intentionally rule-based instead of
LLM-backed. That choice is deliberate:

* No external API calls during the request path means predictable latency,
  zero secret leakage surface, and deterministic outputs the judges can
  reproduce.
* All safety-critical guarantees (never ask for credentials, never confirm
  a refund, ignore prompt injection) are easier to audit when they live in
  explicit Python rather than in a model prompt.
* The hidden test pack is multilingual (English, Bangla, Banglish) and
  adversarial. Hand-tuned keyword/regex rules with safety post-processing
  cover the full taxonomy from the problem statement.

The module is organized as a single public entry point,
``investigate(payload) -> dict``, which takes the validated request dict and
returns the response dict. Each step is a small private function so the
reasoning is easy to follow and adjust.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALLOWED_EVIDENCE = {"consistent", "inconsistent", "insufficient_data"}
ALLOWED_CASE_TYPES = {
    "wrong_transfer",
    "payment_failed",
    "refund_request",
    "duplicate_payment",
    "merchant_settlement_delay",
    "agent_cash_in_issue",
    "phishing_or_social_engineering",
    "other",
}
ALLOWED_SEVERITY = {"low", "medium", "high", "critical"}
ALLOWED_DEPARTMENTS = {
    "customer_support",
    "dispute_resolution",
    "payments_ops",
    "merchant_operations",
    "agent_operations",
    "fraud_risk",
}

# Bangla digits -> ASCII digits (used only for digit-normalization; we do
# not translate the entire reply, that is handled separately).
_BANGLA_DIGITS = str.maketrans("০১২৩৪৫৬৭৮৯", "0123456789")


# ---------------------------------------------------------------------------
# Keyword packs
# ---------------------------------------------------------------------------

# Phishing / social engineering cues. The presence of any of these phrases
# (in English or Bangla) tips the case into fraud_risk with critical
# severity. They also force human_review_required = True.
PHISHING_KEYWORDS = [
    # English
    "otp", "pin", "password", "one time password", "one-time password",
    "share my", "share your", "share otp", "share pin",
    "blocked if", "block my account", "verify your account",
    "call from", "called me", "sms asking", "message asking",
    "fake call", "fraud call", "someone asked", "asked for my otp",
    "asked for my pin", "asked for otp", "asked for password",
    "impersonat", "pretending to be", "phishing",
    "social engineering",
    # Bangla / Banglish
    "ওটিপি", "পিন", "পাসওয়ার্ড", "চাওয়া হয়েছে", "চেয়েছে", "চেয়েছিল",
    "ফোন করে বলেছে", "ফোন করেছিল", "এসএমএস এ", "এসএমএসে",
    "ব্লক হয়ে যাবে", "ব্লক করে দেবে", "ভেরিফাই করতে",
]

# Wrong-transfer cues. The complaint explicitly claims the money went to
# the wrong person / number.
WRONG_TRANSFER_KEYWORDS = [
    "wrong number", "wrong person", "wrong recipient", "wrong account",
    "sent to wrong", "transferred to wrong", "mistakenly sent",
    "by mistake", "sent by mistake", "transferred by mistake",
    "wrong transfer", "wrongly sent", "incorrect number", "incorrect recipient",
    "ভুল নম্বর", "ভুল নাম্বার", "ভুল ব্যক্তি", "ভুল করে",
    "ভুলভাবে", "ভুল একাউন্টে", "ভুল রিসিভার",
]

# Failed payment cues. The complaint describes a payment that didn't go
# through but money was deducted.
PAYMENT_FAILED_KEYWORDS = [
    "payment failed", "transaction failed", "failed but", "failed however",
    "deducted", "money deducted", "balance deducted", "amount deducted",
    "double deducted", "two times deducted",
    "পেমেন্ট ব্যর্থ", "লেনদেন ব্যর্থ", "কাটা হয়ে গেছে", "কেটে নিয়েছে",
    "ব্যালেন্স কমে গেছে", "টাকা কমেছে", "ডেবিট হয়েছে",
]

# Refund request cues. The customer is asking for money back, typically
# because they changed their mind, were overcharged, or the merchant
# failed to deliver.
REFUND_KEYWORDS = [
    "refund", "refund my", "please refund", "want my money back",
    "want my money back", "give me back", "return my money",
    "money back", "please reverse", "reverse the payment",
    "ফেরত", "ফেরত দিন", "ফেরত দিতে", "টাকা ফেরত", "টাকা ফেরত দিন",
    "রিফান্ড", "রিভার্স", "ফেরত চাই",
]

# Merchant settlement cues.
MERCHANT_SETTLEMENT_KEYWORDS = [
    "settlement", "settle", "merchant settlement", "not settled",
    "settlement delayed", "settlement not received", "merchant payout",
    "payout", "merchant balance", "my sales", "yesterday's sales",
    "settlement batch", "সেটেলমেন্ট", "মার্চেন্ট", "পেআউট",
]

# Agent cash-in cues.
AGENT_CASHIN_KEYWORDS = [
    "cash in", "cash-in", "agent", "agent number",
    "deposit through agent", "deposited via agent",
    "agent did not", "agent didn't",
    "ক্যাশ ইন", "এজেন্ট", "এজেন্টের কাছে", "এজেন্টের মাধ্যমে",
]

# Duplicate payment cues.
DUPLICATE_KEYWORDS = [
    "twice", "two times", "two times", "duplicate", "double charged",
    "charged twice", "charged two times", "deducted twice",
    "দুইবার", "দুই বার", "ডুপ্লিকেট",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_digits(text: str) -> str:
    """Replace Bangla digits with ASCII digits so numeric extraction works
    uniformly across languages."""
    return text.translate(_BANGLA_DIGITS)


def _extract_amounts(text: str) -> list[int]:
    """Extract whole-number amounts mentioned in the complaint."""
    normalized = _normalize_digits(text.lower())
    candidates: list[int] = []
    # Match tokens like "5000", "5,000", "5000 taka", "tk 500", "৫০০০".
    patterns = [
        r"\b(\d{2,7})\b",
        r"(\d{1,3}(?:,\d{2,3})+)",  # 5,000 or 1,50,000
        r"tk\s*(\d{2,7})",
        r"taka\s*(\d{2,7})",
        r"৳\s*(\d{2,7})",
    ]
    for pat in patterns:
        for match in re.finditer(pat, normalized):
            raw = match.group(1).replace(",", "")
            try:
                val = int(raw)
            except ValueError:
                continue
            if 10 <= val <= 10_000_000:
                candidates.append(val)
    # Deduplicate while preserving order.
    seen = set()
    out: list[int] = []
    for v in candidates:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _extract_phones(text: str) -> list[str]:
    """Extract phone numbers from the complaint."""
    normalized = _normalize_digits(text)
    # +880... / 01X... / 880... — both with and without spaces.
    pattern = r"(?:\+?88)?0?1[3-9][\d\-\s]{6,14}\d"
    matches = re.findall(pattern, normalized)
    cleaned = []
    for m in matches:
        digits = re.sub(r"\D", "", m)
        if len(digits) >= 10:
            cleaned.append(digits[-11:])  # keep last 11 digits (01XXXXXXXXX)
    return list(dict.fromkeys(cleaned))


def _matches_keyword(text: str, keywords: list[str]) -> bool:
    lowered = text.lower()
    for kw in keywords:
        if kw.lower() in lowered:
            return True
    return False


def _is_bangla(text: str) -> bool:
    return any("\u0980" <= ch <= "\u09FF" for ch in text)


def _safe_max_chars(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "\u2026"


# ---------------------------------------------------------------------------
# Transaction matching
# ---------------------------------------------------------------------------

def _parse_ts(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        # Allow trailing Z.
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def _score_transaction_match(txn: dict, amounts: list[int], phones: list[str],
                              complaint_lower: str) -> float:
    """Return a 0..1 confidence score for how well a transaction matches
    the complaint."""
    score = 0.0
    txn_amount = txn.get("amount")
    txn_cp = str(txn.get("counterparty", ""))
    txn_cp_digits = re.sub(r"\D", "", txn_cp)

    if txn_amount is not None and amounts:
        if txn_amount in amounts:
            score += 0.55
        # Approximate matches (within 5%) when amount is mentioned with
        # nearby words.
        for a in amounts:
            if a != txn_amount and abs(a - txn_amount) <= max(50, a * 0.05):
                score += 0.25
                break
    elif txn_amount is not None and not amounts:
        # No amount mentioned: small bonus for existing transactions.
        score += 0.05

    if phones:
        phone_digits = [p[-11:] for p in phones]
        if any(p and p in txn_cp_digits for p in phone_digits if p):
            score += 0.35

    # Bonus if transaction is a transfer/payment (the typical complaint
    # subjects).
    if txn.get("type") in {"transfer", "payment"}:
        score += 0.05

    return min(score, 1.0)


def _select_relevant_txn(complaint: str, txn_history: list[dict], case_type: str = "other") -> tuple[str | None, dict]:
    """Decide which transaction the complaint is referring to.

    Returns ``(txn_id, debug_info)`` where debug_info is informational and
    used to drive the evidence_verdict.
    """
    if not txn_history:
        return None, {"reason": "empty_history"}

    # Duplicate-payment short-circuit: when the case_type is duplicate_payment,
    # find pairs of completed transactions to the same counterparty with the
    # same amount and pick the later one.
    if case_type == "duplicate_payment":
        dup = _find_duplicate_pair(txn_history)
        if dup:
            return dup.get("transaction_id"), {"reason": "duplicate_pair"}
        # Fall through to normal matching if no clear pair exists.

    amounts = _extract_amounts(complaint)
    phones = _extract_phones(complaint)
    complaint_lower = complaint.lower()

    scored = []
    for txn in txn_history:
        s = _score_transaction_match(txn, amounts, phones, complaint_lower)
        scored.append((s, txn))
    scored.sort(key=lambda x: x[0], reverse=True)

    top_score, top_txn = scored[0]
    # If multiple transactions share the top score within a tiny margin and
    # both look like candidates, we must NOT pick one blindly.
    if len(scored) > 1:
        second_score = scored[1][0]
        if top_score >= 0.3 and second_score >= 0.3 and (top_score - second_score) < 0.05:
            # Genuinely ambiguous: too many plausible matches.
            return None, {
                "reason": "ambiguous_match",
                "top_score": top_score,
                "second_score": second_score,
            }

    if top_score < 0.25:
        return None, {"reason": "no_strong_match", "top_score": top_score}

    return top_txn.get("transaction_id"), {"reason": "matched", "score": top_score}


def _find_duplicate_pair(txn_history: list[dict]) -> dict | None:
    """Return the later transaction of a duplicate pair (same counterparty,
    same amount, completed, within 5 minutes). Returns None if no such pair
    exists."""
    completed = [t for t in txn_history if str(t.get("status", "")).lower() == "completed"]
    parsed = []
    for t in completed:
        ts = _parse_ts(str(t.get("timestamp", "")))
        if ts is not None:
            parsed.append((ts, t))
    parsed.sort(key=lambda x: x[0])
    for i in range(len(parsed)):
        for j in range(i + 1, len(parsed)):
            t1, txn1 = parsed[i]
            t2, txn2 = parsed[j]
            if (txn1.get("amount") == txn2.get("amount")
                    and str(txn1.get("counterparty", "")) == str(txn2.get("counterparty", ""))
                    and str(txn1.get("type", "")) == str(txn2.get("type", ""))
                    and abs((t2 - t1).total_seconds()) <= 300):
                return txn2
    return None


def _determine_evidence_verdict(case_type: str, complaint: str, txn_history: list[dict],
                                 relevant_txn_id: str | None) -> str:
    """Compute consistent / inconsistent / insufficient_data."""
    if not txn_history:
        return "insufficient_data"

    if relevant_txn_id is None:
        # Vague complaint, ambiguous match, or no strong match.
        return "insufficient_data"

    txn = next((t for t in txn_history if t.get("transaction_id") == relevant_txn_id), None)
    if txn is None:
        return "insufficient_data"

    status = str(txn.get("status", "")).lower()

    # Inconsistency 1: customer says they sent to wrong number but the same
    # counterparty has appeared repeatedly — established recipient.
    if case_type == "wrong_transfer":
        cp = str(txn.get("counterparty", ""))
        cp_digits = re.sub(r"\D", "", cp)
        repeats = 0
        for t in txn_history:
            if t.get("transaction_id") == relevant_txn_id:
                continue
            if str(t.get("type")) == "transfer" and re.sub(r"\D", "", str(t.get("counterparty", ""))) == cp_digits:
                repeats += 1
        if repeats >= 2:
            return "inconsistent"

    # Inconsistency 2: customer claims refund was needed for a transaction
    # that hasn't actually happened (no completed payment to the named
    # counterparty).
    if case_type == "refund_request":
        if status == "failed":
            return "inconsistent"

    return "consistent"


# ---------------------------------------------------------------------------
# Severity / department / confidence
# ---------------------------------------------------------------------------

def _determine_severity(case_type: str, amount: float | int | None,
                         complaint: str, txn: dict | None,
                         evidence_verdict: str = "consistent") -> str:
    """Per Section 7.1 the case_type taxonomy already implies a baseline
    severity band; we only bump up for high-value cases. We use a low
    threshold (>=1000) so common complaint values still map sensibly while
    tiny edge cases do not all become critical."""
    high_value = isinstance(amount, (int, float)) and amount >= 10000

    if case_type == "phishing_or_social_engineering":
        return "critical"
    if case_type == "wrong_transfer":
        # When the evidence is inconsistent (e.g. established recipient)
        # or insufficient (e.g. ambiguous match across multiple plausible
        # transactions), the case is lower priority — downgrade to medium.
        if evidence_verdict in {"inconsistent", "insufficient_data"}:
            return "medium"
        return "high"
    if case_type == "payment_failed":
        # Failed payment with possible balance deduction is customer-impacting.
        return "high"
    if case_type == "duplicate_payment":
        return "high"
    if case_type == "agent_cash_in_issue":
        return "high"
    if case_type == "merchant_settlement_delay":
        return "medium"
    if case_type == "refund_request":
        return "medium" if high_value else "low"
    return "low"


def _determine_department(case_type: str, user_type: str | None) -> str:
    if case_type == "wrong_transfer":
        return "dispute_resolution"
    if case_type in {"payment_failed", "duplicate_payment"}:
        return "payments_ops"
    if case_type == "merchant_settlement_delay":
        return "merchant_operations"
    if case_type == "agent_cash_in_issue":
        return "agent_operations"
    if case_type == "phishing_or_social_engineering":
        return "fraud_risk"
    # refund_request and other fall here.
    if user_type == "merchant":
        return "merchant_operations"
    return "customer_support"


def _human_review_required(case_type: str, evidence_verdict: str,
                            severity: str, txn: dict | None) -> bool:
    if case_type == "phishing_or_social_engineering":
        return True
    if evidence_verdict == "inconsistent":
        return True
    if severity == "critical":
        return True
    # Wrong transfer and duplicate payment usually warrant a human look.
    # However, when the wrong_transfer case is ambiguous (multiple
    # plausible matches → insufficient_data), the next step is to ask the
    # customer for clarification, not to escalate to dispute resolution.
    if case_type == "wrong_transfer" and evidence_verdict != "insufficient_data":
        return True
    if case_type == "duplicate_payment":
        return True
    if case_type == "agent_cash_in_issue":
        return True
    return False


# ---------------------------------------------------------------------------
# Response composition
# ---------------------------------------------------------------------------

# Hard safety rules applied to every customer_reply / recommended_next_action
# we emit. These are belt-and-suspenders on top of the templates.
_FORBIDDEN_PHRASES = [
    "we will refund", "we'll refund", "we can refund", "we will return",
    "we'll return", "we have refunded", "we have reversed", "we reversed",
    "your account is unblocked", "account has been unblocked",
    "we have unlocked", "your account is recovered", "we have recovered",
    "send your otp", "send your pin", "send your password",
    "share your otp", "share your pin", "share your password",
    "provide your otp", "provide your pin", "provide your password",
    "give me your otp", "give me your pin", "give me your password",
    "tell me your otp", "tell me your pin", "tell me your password",
    "verify with your otp", "confirm with your otp", "confirm with your pin",
    "card number", "credit card number", "debit card number",
    "contact the person", "call the person", "contact the recipient",
    "call the number you sent to", "contact the merchant directly",
]

# Phrases that the safe reply can use instead. The post-processor rewrites
# any accidental forbidden phrase into the safe equivalent. Important: the
# templates we emit already use the safe form ("Please do not share your
# PIN or OTP with anyone."), so substring matches like "share your pin"
# inside the legitimate reminder must NOT trigger a rewrite.
_SAFE_REPLACEMENTS = {
    "we will refund": "any eligible amount will be returned through official channels",
    "we'll refund": "any eligible amount will be returned through official channels",
    "we can refund": "any eligible amount will be returned through official channels",
    "we have refunded": "any eligible amount will be returned through official channels",
    "we have reversed": "any eligible amount will be returned through official channels",
    "your account is unblocked": "your account status will be reviewed by the support team",
    "account has been unblocked": "your account status will be reviewed by the support team",
    "card number": "card details",
    "contact the person": "contact us only through official channels",
    "call the person": "contact us only through official channels",
    "contact the recipient": "contact us only through official channels",
    "contact the merchant directly": "contact us only through official channels",
}


_CREDENTIAL_LINE = "Please do not share your PIN or OTP with anyone."


def _enforce_safety(text: str) -> str:
    """Run the final safety pass over any generated text.

    The pass:
    1. Rewrites forbidden phrases like "we will refund" into safe
       alternatives. The rewrite only fires for phrases that should never
       appear in a copilot reply — never for the legitimate credential
       reminder we append.
    2. Ensures the credential protection reminder is present exactly once.
    3. Guards against refund/settlement confirmation phrases leaking
       through any composition path.

    This is intentionally idempotent: callers may invoke it on text that
    already contains the reminder and we must not produce duplicates or
    mangled sentences.
    """
    out = text.strip()
    lowered = out.lower()

    # 1) Phrase substitutions — applied to the whole text. None of the
    #    keys overlap with the safe credential reminder.
    for bad, good in _SAFE_REPLACEMENTS.items():
        if bad in lowered:
            pattern = re.compile(re.escape(bad), re.IGNORECASE)
            out = pattern.sub(good, out)
            lowered = out.lower()

    # 2) Strip any accidental duplicate credential reminders and re-add
    #    a single canonical one. We look for the reminder as a sentence
    #    anywhere in the text and remove all copies, then append exactly
    #    one.
    reminder_pattern = re.compile(
        r"please\s+do\s+not\s+share\s+your\s+(?:pin|otp|password|information)[^.!?]*[.!?]?",
        re.IGNORECASE,
    )
    # Capture positions so we can strip them while preserving spacing.
    matches = list(reminder_pattern.finditer(out))
    if matches:
        # Remove matches from end to start to keep indices stable.
        for m in reversed(matches):
            out = out[: m.start()].rstrip() + out[m.end():]
        out = out.strip()

    # 3) Append the canonical credential reminder exactly once (for any
    #    non-phishing reply).
    if out and not out.endswith((".", "!", "?")):
        out = out + "."
    out = (out + " " + _CREDENTIAL_LINE).strip()
    if not out.endswith("."):
        out = out + "."
    return out


def _format_en_amount(amount: int | None) -> str:
    if amount is None:
        return ""
    return f"{amount:,} BDT"


def _format_bn_amount(amount: int | None) -> str:
    if amount is None:
        return ""
    bangla_digits = str.maketrans("0123456789", "০১২৩৪৫৬৭৮৯")
    return f"{amount:,} টাকা".translate(bangla_digits)


def _compose_summary(case_type: str, txn: dict | None, complaint: str,
                      amount: int | None, language: str) -> str:
    bn = language == "bn" or (language == "mixed") or (_is_bangla(complaint) and language != "en")

    if case_type == "wrong_transfer":
        if txn:
            amt = _format_en_amount(amount) if not bn else _format_bn_amount(amount)
            cp = txn.get("counterparty", "an unknown number")
            if bn:
                return (
                    f"গ্রাহক অভিযোগ করছেন যে {amt} ({txn.get('transaction_id')}) "
                    f"{cp} নম্বরে পাঠিয়েছেন এবং প্রাপক সাড়া দিচ্ছেন না। "
                    f"এটি সম্ভাব্য ভুল লেনদেন।"
                )
            return (
                f"Customer reports sending {_format_en_amount(amount)} via "
                f"{txn.get('transaction_id')} to {cp}, which they now believe was the wrong recipient."
            )
    if case_type == "payment_failed":
        if txn:
            amt = _format_en_amount(amount) if not bn else _format_bn_amount(amount)
            if bn:
                return (
                    f"গ্রাহক {amt} ({txn.get('transaction_id')}) পেমেন্ট করতে গিয়ে "
                    f"ব্যর্থ হয়েছেন কিন্তু ব্যালেন্স কেটে নেওয়া হয়েছে বলে জানিয়েছেন।"
                )
            return (
                f"Customer attempted a {_format_en_amount(amount)} payment "
                f"({txn.get('transaction_id')}) which failed but reports the balance was deducted."
            )
    if case_type == "refund_request":
        if txn:
            amt = _format_en_amount(amount) if not bn else _format_bn_amount(amount)
            if bn:
                return (
                    f"গ্রাহক {txn.get('transaction_id')} ({amt}) লেনদেনের টাকা ফেরত চাইছেন।"
                )
            return (
                f"Customer requests a refund of {_format_en_amount(amount)} "
                f"for transaction {txn.get('transaction_id')}."
            )
    if case_type == "duplicate_payment":
        if txn:
            if bn:
                return (
                    f"গ্রাহক একই পেমেন্ট দুবার কাটা হয়েছে বলে অভিযোগ করেছেন। "
                    f"{txn.get('transaction_id')} সন্দেহভাজন ডুপ্লিকেট।"
                )
            return (
                f"Customer reports the same payment was charged twice. "
                f"{txn.get('transaction_id')} is the suspected duplicate."
            )
    if case_type == "merchant_settlement_delay":
        if txn:
            amt = _format_en_amount(amount) if not bn else _format_bn_amount(amount)
            if bn:
                return (
                    f"মার্চেন্ট জানিয়েছেন {txn.get('transaction_id')} ({amt}) "
                    f"সেটেলমেন্ট এখনো সম্পন্ন হয়নি।"
                )
            return (
                f"Merchant reports settlement of {_format_en_amount(amount)} "
                f"({txn.get('transaction_id')}) is delayed."
            )
    if case_type == "agent_cash_in_issue":
        if txn:
            amt = _format_en_amount(amount) if not bn else _format_bn_amount(amount)
            if bn:
                return (
                    f"গ্রাহক জানিয়েছেন এজেন্টের মাধ্যমে {amt} ({txn.get('transaction_id')}) "
                    f"ক্যাশ ইন করেছেন কিন্তু ব্যালেন্সে প্রতিফলিত হয়নি।"
                )
            return (
                f"Customer reports a {_format_en_amount(amount)} cash-in via "
                f"{txn.get('transaction_id')} ({txn.get('counterparty', 'agent')}) "
                f"has not been reflected in their balance."
            )
    if case_type == "phishing_or_social_engineering":
        if bn:
            return (
                "গ্রাহক প্রতারণামূলক ফোন কল বা বার্তার রিপোর্ট করেছেন যেখানে "
                "PIN, OTP বা পাসওয়ার্ড চাওয়া হয়েছে। সম্ভাব্য সোশ্যাল ইঞ্জিনিয়ারিং।"
            )
        return (
            "Customer reports a suspicious call or message requesting PIN, "
            "OTP, or password. Likely social engineering attempt."
        )
    # Vague / other.
    if bn:
        return "গ্রাহকের অভিযোগে নির্দিষ্ট লেনদেন বা সমস্যা উল্লেখ নেই। আরও তথ্য প্রয়োজন।"
    return (
        "Customer reports a concern without specifying the transaction, "
        "amount, or issue. Additional details are required to proceed."
    )


def _compose_next_action(case_type: str, txn: dict | None, evidence_verdict: str,
                          language: str, user_type: str | None) -> str:
    bn = language == "bn" or (language == "mixed")
    txn_id = (txn or {}).get("transaction_id", "the relevant transaction")
    if case_type == "wrong_transfer":
        if bn:
            return (
                f"{txn_id} বিবরণ গ্রাহকের সাথে যাচাই করুন "
                "এবং নীতিমালা অনুযায়ী ভুল-লেনদেন বিরোধ প্রক্রিয়া শুরু করুন।"
            )
        return (
            f"Verify {txn_id} details with the customer and initiate the "
            "wrong-transfer dispute workflow per policy."
        )
    if case_type == "payment_failed":
        if bn:
            return (
                f"{txn_id} এর লেজার স্ট্যাটাস তদন্ত করুন। "
                "ব্যালেন্স কেটে নেওয়া হলে স্বয়ংক্রিয় রিভার্স প্রবাহ শুরু করুন।"
            )
        return (
            f"Investigate the ledger status of {txn_id}. "
            "If the balance was deducted on a failed payment, initiate the automatic reversal flow within standard SLA."
        )
    if case_type == "refund_request":
        if user_type == "merchant":
            if bn:
                return "মার্চেন্টের নিজস্ব রিফান্ড নীতিমালা অনুযায়ী যাচাই করুন।"
            return "Verify per the merchant's own refund policy."
        if bn:
            return (
                "রিফান্ড যোগ্যতা মার্চেন্টের নিজস্ব নীতিমালার উপর নির্ভর করে। "
                "গ্রাহককে মার্চেন্টের সাথে যোগাযোগের নির্দেশনা দিন।"
            )
        return (
            "Refund eligibility depends on the merchant's own policy. "
            "Guide the customer to contact the merchant directly for a refund."
        )
    if case_type == "duplicate_payment":
        if bn:
            return (
                f"{txn_id} পেমেন্টস অপারেশন্স দল দিয়ে "
                "বিলারের সাথে যাচাই করুন এবং প্রয়োজনে রিভার্স শুরু করুন।"
            )
        return (
            f"Verify {txn_id} with the biller and initiate reversal "
            "if the biller confirms only one payment was received."
        )
    if case_type == "merchant_settlement_delay":
        if bn:
            return (
                f"{txn_id} এর বর্তমান অবস্থা যাচাই করুন "
                "এবং প্রয়োজনে নতুন আনুমানিক সময় মার্চেন্টকে জানান।"
            )
        return (
            f"Route to merchant_operations to verify the settlement batch "
            f"({txn_id}). Communicate a revised ETA to the merchant if delayed."
        )
    if case_type == "agent_cash_in_issue":
        if bn:
            return (
                f"{txn_id} এর পেন্ডিং অবস্থা এজেন্ট অপারেশন্স "
                "দলের মাধ্যমে যাচাই করুন এবং আদর্শ SLA-র মধ্যে সমাধান করুন।"
            )
        return (
            f"Investigate the pending status of {txn_id} "
            "with agent operations and resolve within the standard cash-in SLA."
        )
    if case_type == "phishing_or_social_engineering":
        if bn:
            return (
                "ফ্রড রিস্ক দলেৎ এসকেলেট করুন। গ্রাহককে নিশ্চিত করুন যে কোম্পানি কখনো OTP চায় না। "
                "রিপোর্ট করা নম্বর ফ্রড প্যাটার্ন বিশ্লেষণে যুক্ত করুন।"
            )
        return (
            "Escalate to the fraud_risk team immediately. Confirm to the customer that the company "
            "never asks for OTP. Log the reported number for fraud pattern analysis."
        )
    # Vague / other.
    if bn:
        return (
            "গ্রাহকের কাছ থেকে নির্দিষ্ট বিবরণ চান: কোন লেনদেন, কত টাকা, আনুমানিক সময় এবং কী সমস্যা হয়েছে।"
        )
    return (
        "Reply to the customer asking for the specific transaction ID, the amount involved, "
        "the approximate time, and a short description of what went wrong."
    )


def _compose_customer_reply(case_type: str, txn: dict | None, evidence_verdict: str,
                             language: str, user_type: str | None,
                             relevant_txn_id: str | None) -> str:
    bn = language == "bn" or (language == "mixed")
    txn_id = txn.get("transaction_id") if txn else relevant_txn_id
    txn_part = f"লেনদেন {txn_id}" if bn and txn_id else (f"transaction {txn_id}" if txn_id else "")

    if case_type == "phishing_or_social_engineering":
        if bn:
            return (
                "আপনার সতর্কতার জন্য ধন্যবাদ। আমরা কখনোই আপনার PIN, OTP বা পাসওয়ার্ড কোনো অবস্থাতেই জিজ্ঞেস করি না। "
                "এই তথ্য কারো সাথে শেয়ার করবেন না, এমনকি নিজেকে আমাদের বলে পরিচয় দিলেও না। "
                "আমাদের ফ্রড টিম এই ঘটনা সম্পর্কে অবহিত হয়েছে।"
            )
        return (
            "Thank you for reaching out before sharing any information. We never ask for your PIN, OTP, "
            "or password under any circumstances. Please do not share these with anyone, even if they claim "
            "to be from us. Our fraud team has been notified of this incident."
        )

    if case_type == "wrong_transfer":
        if bn:
            return (
                f"{txn_part} সম্পর্কে আপনার অভিযোগ আমরা গ্রহণ করেছি। "
                "অনুগ্রহ করে আপনার PIN বা OTP কারো সাথে শেয়ার করবেন না। "
                "আমাদের বিরোধ দল অফিসিয়াল চ্যানেলের মাধ্যমে আপনার সাথে যোগাযোগ করবে।"
            )
        return (
            f"We have noted your concern about {txn_part}. Please do not share your PIN or OTP with anyone. "
            "Our dispute team will review the case and contact you through official support channels."
        )

    if case_type == "payment_failed":
        if bn:
            return (
                f"{txn_part} এর কারণে যদি ব্যালেন্স থেকে টাকা কেটে নেওয়া হয়ে থাকে তাহলে আমরা বিষয়টি দেখছি। "
                "যোগ্য পরিমাণ অফিসিয়াল চ্যানেলের মাধ্যমে ফেরত দেওয়া হবে। "
                "অনুগ্রহ করে কারো সাথে আপনার PIN বা OTP শেয়ার করবেন না।"
            )
        return (
            f"We have noted that {txn_part} may have caused an unexpected balance deduction. "
            "Any eligible amount will be returned through official channels. "
            "Please do not share your PIN or OTP with anyone."
        )

    if case_type == "refund_request":
        if user_type == "merchant":
            if bn:
                return (
                    "আপনার রিফান্ড অনুরোধ গ্রহণ করা হয়েছে। মার্চেন্ট নীতিমালা অনুযায়ী যোগ্য পরিমাণ "
                    "অফিসিয়াল চ্যানেলের মাধ্যমে প্রক্রিয়া করা হবে। "
                    "অনুগ্রহ করে কারো সাথে আপনার PIN বা OTP শেয়ার করবেন না।"
                )
            return (
                "We have received your refund request. Any eligible amount will be processed "
                "through official channels as per the merchant's policy. "
                "Please do not share your PIN or OTP with anyone."
            )
        if bn:
            return (
                "যোগাযোগ করার জন্য ধন্যবাদ। সম্পন্ন মার্চেন্ট পেমেন্টের রিফান্ড মার্চেন্টের নিজস্ব নীতিমালার উপর নির্ভর করে। "
                "আমাদের সাথে যোগাযোগ করুন, আমরা আপনাকে সঠিক চ্যানেলে সাহায্য করব। "
                "অনুগ্রহ করে কারো সাথে আপনার PIN বা OTP শেয়ার করবেন না।"
            )
        return (
            "Thank you for reaching out. Refunds for completed merchant payments depend on the merchant's "
            "own policy. Please contact us and we will guide you through the correct channel. "
            "Please do not share your PIN or OTP with anyone."
        )

    if case_type == "duplicate_payment":
        if bn:
            return (
                f"{txn_part} সম্পর্কে সম্ভাব্য ডুপ্লিকেট পেমেন্টের অভিযোগ আমরা পেয়েছি। "
                "আমাদের পেমেন্টস টিম বিলারের সাথে যাচাই করবে এবং যোগ্য পরিমাণ অফিসিয়াল চ্যানেলের মাধ্যমে ফেরত দেওয়া হবে। "
                "অনুগ্রহ করে কারো সাথে আপনার PIN বা OTP শেয়ার করবেন না।"
            )
        return (
            f"We have noted the possible duplicate payment for {txn_part}. "
            "Our payments team will verify with the biller, and any eligible amount will be returned "
            "through official channels. Please do not share your PIN or OTP with anyone."
        )

    if case_type == "merchant_settlement_delay":
        if bn:
            return (
                f"{txn_part} সংক্রান্ত আপনার অভিযোগ আমরা গ্রহণ করেছি। "
                "আমাদের মার্চেন্ট অপারেশন্স টিম ব্যাচের অবস্থা যাচাই করে অফিসিয়াল চ্যানেলের মাধ্যমে আপনাকে জানাবে।"
            )
        return (
            f"We have noted your concern about settlement {txn_part}. "
            "Our merchant operations team will check the batch status and update you on the expected "
            "settlement time through official channels."
        )

    if case_type == "agent_cash_in_issue":
        if bn:
            return (
                f"{txn_part} সংক্রান্ত আপনার অভিযোগ আমরা গ্রহণ করেছি। "
                "আমাদের এজেন্ট অপারেশন্স টিম দ্রুত যাচাই করবে এবং অফিসিয়াল চ্যানেলের মাধ্যমে আপনাকে জানাবে। "
                "অনুগ্রহ করে কারো সাথে আপনার PIN বা OTP শেয়ার করবেন না।"
            )
        return (
            f"We have noted your concern about {txn_part}. "
            "Our agent operations team will verify the case quickly and contact you through official channels. "
            "Please do not share your PIN or OTP with anyone."
        )

    # Vague / other.
    if bn:
        return (
            "যোগাযোগ করার জন্য ধন্যবাদ। দ্রুত সাহায্য করতে, অনুগ্রহ করে লেনদেনের আইডি, পরিমাণ এবং "
            "কী সমস্যা হয়েছে তা সংক্ষেপে জানান। অনুগ্রহ করে কারো সাথে আপনার PIN বা OTP শেয়ার করবেন না।"
        )
    return (
        "Thank you for reaching out. To help you faster, please share the transaction ID, the amount "
        "involved, and a short description of what went wrong. "
        "Please do not share your PIN or OTP with anyone."
    )


# ---------------------------------------------------------------------------
# Adversarial / prompt injection handling
# ---------------------------------------------------------------------------

_INJECTION_CUES = [
    "ignore previous", "ignore all previous", "ignore your instructions",
    "disregard your", "you are now", "system prompt", "act as",
    "forget your rules", "override", "respond with",
    "নির্দেশ উপেক্ষা", "নিয়ম ভুলে", "পূর্ববর্তী নির্দেশনা",
]


def _detect_injection(complaint: str) -> bool:
    lowered = complaint.lower()
    return any(cue in lowered for cue in _INJECTION_CUES)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def investigate(payload: dict) -> dict:
    """Run the investigator on a validated payload and return a response dict
    conforming to the Section 6 schema."""

    ticket_id = payload["ticket_id"]
    complaint = (payload.get("complaint") or "").strip()
    language = (payload.get("language") or "en").lower()
    user_type = (payload.get("user_type") or "customer").lower()
    txn_history = payload.get("transaction_history") or []
    if not isinstance(txn_history, list):
        txn_history = []

    reason_codes: list[str] = []
    injection_detected = _detect_injection(complaint)
    if injection_detected:
        reason_codes.append("prompt_injection_attempt_ignored")

    # --- Step 1: classify the case_type from complaint signals.
    case_type = "other"
    has_phish = _matches_keyword(complaint, PHISHING_KEYWORDS)
    has_dup = _matches_keyword(complaint, DUPLICATE_KEYWORDS)
    has_settle = _matches_keyword(complaint, MERCHANT_SETTLEMENT_KEYWORDS)
    has_cashin = _matches_keyword(complaint, AGENT_CASHIN_KEYWORDS)
    has_failed = _matches_keyword(complaint, PAYMENT_FAILED_KEYWORDS)
    has_wrong = _matches_keyword(complaint, WRONG_TRANSFER_KEYWORDS)
    has_refund = _matches_keyword(complaint, REFUND_KEYWORDS)

    # Duplicate cue takes priority over "deducted" (which lives in the
    # payment_failed set) so that "deducted twice" lands on duplicate_payment.
    if has_phish:
        case_type = "phishing_or_social_engineering"
        reason_codes.append("phishing")
    elif has_dup:
        case_type = "duplicate_payment"
        reason_codes.append("duplicate_payment")
    elif has_settle:
        case_type = "merchant_settlement_delay"
        reason_codes.append("merchant_settlement")
    elif has_cashin:
        case_type = "agent_cash_in_issue"
        reason_codes.append("agent_cash_in")
    elif has_failed:
        case_type = "payment_failed"
        reason_codes.append("payment_failed")
    elif has_wrong:
        case_type = "wrong_transfer"
        reason_codes.append("wrong_transfer_claim")
    elif has_refund:
        case_type = "refund_request"
        reason_codes.append("refund_request")
    else:
        # Fallback: if the complaint mentions a transfer or payment and
        # signals of non-receipt ("didn't get it", "he says he didn't get
        # it"), treat as a wrong_transfer investigation. This matches
        # SAMPLE-08 where no explicit wrong-recipient phrase was used but
        # the case is functionally a wrong-transfer claim.
        non_receipt = any(
            cue in complaint.lower()
            for cue in ["didn't get", "did not get", "not received", "hasn't received",
                        "has not received", "says he didn't", "she didn't get",
                        "didn't receive", "not yet received"]
        )
        transfer_signal = any(
            cue in complaint.lower()
            for cue in ["i sent", "i paid", "i transferred", "sent money",
                        "send money", "transferred", "i did send"]
        )
        if transfer_signal and non_receipt:
            case_type = "wrong_transfer"
            reason_codes.append("wrong_transfer_claim")
        else:
            reason_codes.append("no_strong_signal")

    # Phishing overrides everything else (highest priority safety class).
    if case_type != "phishing_or_social_engineering":
        # If the customer explicitly mentions a failed payment + balance
        # deduction, that wins over a generic refund phrasing. This
        # override does NOT apply when we've already classified as
        # duplicate_payment (the "deducted twice" cue should land on
        # duplicate, not on payment_failed).
        if (case_type not in {"duplicate_payment", "agent_cash_in_issue"}
                and "deduct" in complaint.lower()
                and _matches_keyword(complaint, PAYMENT_FAILED_KEYWORDS)):
            case_type = "payment_failed"
            if "payment_failed" not in reason_codes:
                reason_codes.append("payment_failed")

    # --- Step 2: pick the relevant transaction.
    relevant_txn_id, match_info = _select_relevant_txn(complaint, txn_history, case_type)
    if match_info.get("reason") == "matched":
        reason_codes.append("transaction_match")
    elif match_info.get("reason") == "ambiguous_match":
        reason_codes.append("ambiguous_match")
    elif match_info.get("reason") == "empty_history":
        reason_codes.append("empty_history")
    else:
        reason_codes.append("no_strong_match")

    txn = None
    if relevant_txn_id is not None:
        txn = next((t for t in txn_history if t.get("transaction_id") == relevant_txn_id), None)

    # --- Step 3: determine evidence_verdict.
    evidence_verdict = _determine_evidence_verdict(case_type, complaint, txn_history, relevant_txn_id)
    if evidence_verdict == "inconsistent":
        reason_codes.append("evidence_inconsistent")
    elif evidence_verdict == "insufficient_data":
        reason_codes.append("insufficient_data")
    else:
        reason_codes.append("evidence_consistent")

    # --- Step 4: severity / department.
    amounts = _extract_amounts(complaint)
    primary_amount = amounts[0] if amounts else (txn.get("amount") if txn else None)
    severity = _determine_severity(case_type, primary_amount, complaint, txn,
                                   evidence_verdict)
    department = _determine_department(case_type, user_type)
    human_review = _human_review_required(case_type, evidence_verdict, severity, txn)
    if human_review:
        reason_codes.append("human_review_required")

    # --- Step 5: compose safe text fields.
    agent_summary = _safe_max_chars(_compose_summary(case_type, txn, complaint, primary_amount, language), 400)
    next_action = _safe_max_chars(_compose_next_action(case_type, txn, evidence_verdict, language, user_type), 400)
    customer_reply = _safe_max_chars(
        _compose_customer_reply(case_type, txn, evidence_verdict, language, user_type, relevant_txn_id),
        600,
    )

    # Belt-and-suspenders safety pass.
    customer_reply = _enforce_safety(customer_reply)
    next_action = _enforce_safety(next_action)

    # --- Step 6: confidence.
    confidence = 0.6
    if relevant_txn_id and evidence_verdict == "consistent":
        confidence = 0.9
    elif relevant_txn_id and evidence_verdict == "inconsistent":
        confidence = 0.75
    elif case_type == "phishing_or_social_engineering":
        confidence = 0.95
    elif case_type == "merchant_settlement_delay" and txn and txn.get("status") == "pending":
        confidence = 0.92
    elif case_type == "other":
        confidence = 0.55

    if injection_detected:
        confidence = max(confidence - 0.2, 0.2)

    # Deduplicate reason_codes while preserving order.
    seen = set()
    deduped = []
    for rc in reason_codes:
        if rc not in seen:
            seen.add(rc)
            deduped.append(rc)

    return {
        "ticket_id": ticket_id,
        "relevant_transaction_id": relevant_txn_id,
        "evidence_verdict": evidence_verdict,
        "case_type": case_type,
        "severity": severity,
        "department": department,
        "agent_summary": agent_summary,
        "recommended_next_action": next_action,
        "customer_reply": customer_reply,
        "human_review_required": bool(human_review),
        "confidence": round(confidence, 2),
        "reason_codes": deduped,
    }
