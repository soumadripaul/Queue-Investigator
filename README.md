# QueueStorm Investigator

> **SUST Preliminary Challenge Submission** — Rule-based Django API for intelligent support ticket investigation.

A safe internal copilot API for support agents. Submit one complaint and a short transaction history, and get back a fully structured investigator response: evidence verdict, case classification, department routing, and customer-safe messaging — all in under 30 seconds, with zero external model dependency.

---

## Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [API Reference](#api-reference)
- [Local Setup](#local-setup)
- [Testing](#testing)
- [AI Approach & Evidence Logic](#ai-approach--evidence-logic)
- [Safety Guardrails](#safety-guardrails)
- [Model Specification](#model-specification)
- [Environment Variables](#environment-variables)
- [Assumptions & Limitations](#assumptions--limitations)
- [Submission Checklist](#submission-checklist)

---

## Features

- **Two required endpoints** — `GET /health` and `POST /analyze-ticket`
- **Multilingual support** — English, Bangla, and mixed Bangla-English complaint text
- **Deterministic evidence reasoning** — complaint + transaction matching with no LLM dependency
- **Structured output** — returns `relevant_transaction_id`, `evidence_verdict`, `case_type`, `severity`, `department`, and safe messaging
- **Prompt-injection resistant** — adversarial instructions in complaint text are detected and ignored
- **Safety guardrails** — no credential requests, no unauthorized refund promises

---

## Tech Stack

| Component | Details |
|-----------|---------|
| Language | Python 3.12+ |
| Framework | Django 6 |
| Rule Engine | `queinvestigator_app/investigator.py` |
| External APIs | None |
| Runtime cost | **$0.00 per request** |

---

## API Reference

### `GET /health` — Health Check

**Response `200 OK`:**
```json
{"status": "ok"}
```

---

### `POST /analyze-ticket` — Ticket Analysis

**Headers:** `Content-Type: application/json`

Accepts the challenge request schema and returns the full structured response schema.

**Example request:**
```bash
curl -X POST http://127.0.0.1:8000/analyze-ticket \
  -H "Content-Type: application/json" \
  -d '{
    "ticket_id": "TKT-001",
    "complaint": "My payment failed and money was deducted.",
    "transaction_history": [
      {
        "transaction_id": "TXN-1",
        "timestamp": "2026-04-14T14:08:22Z",
        "type": "payment",
        "amount": 1200,
        "counterparty": "MRC-12",
        "status": "failed"
      }
    ]
  }'
```

**Error responses:**
- `400` — Malformed JSON
- `422` — Missing or empty required fields (e.g. blank complaint)

---

## Local Setup

### Linux / macOS

```bash
# 1. Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Copy env template
cp .env.example .env

# 4. Start the server
python manage.py runserver 0.0.0.0:8000

# 5. Confirm readiness
curl http://127.0.0.1:8000/health
```

### Windows

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python manage.py runserver 0.0.0.0:8000
```

---

## Runbook (Judge Reproducibility)

From the repository root, these two commands are all that's needed:

```bash
pip install -r requirements.txt
python manage.py runserver 0.0.0.0:8000
```

Verify with:

```bash
GET  http://127.0.0.1:8000/health
POST http://127.0.0.1:8000/analyze-ticket
```

---

## Testing

### 1. API unit tests

```bash
python manage.py test
```

### 2. Public sample-case evaluator

Validates core fields (`relevant_transaction_id`, `evidence_verdict`, `case_type`, `department`) against all 10 public sample cases:

```bash
python test_investigator.py
```

### 3. Generate sample output artifact

Writes investigator outputs for all sample cases to `sample_output.json`:

```bash
python generate_sample_output.py
```

---

## AI Approach & Evidence Logic

This service uses a **fully deterministic rule-based engine** — no LLM, no external API calls, no secrets in the request path.

**Processing pipeline:**

1. **Case classification** — Complaint text is matched against multilingual keyword and phrase packs to assign the required `case_type` taxonomy label.
2. **Entity extraction** — Amounts and phone numbers are parsed from complaint text.
3. **Transaction scoring** — Each entry in `transaction_history` is scored; the best match becomes `relevant_transaction_id`.
4. **Evidence verdict** — One of three outcomes:
   - `consistent` — complaint aligns with transaction data
   - `inconsistent` — complaint contradicts transaction data
   - `insufficient_data` — no clear correlation can be established
5. **Routing & severity** — Maps findings to `severity`, `department`, and `human_review_required`.
6. **Response generation** — Produces a safe agent summary, recommended next action, and customer-facing reply.

### Why Rule-Based?

| Criterion | Rule-Based (this) | LLM-Based |
|-----------|:-----------------:|:---------:|
| Latency predictability | ✅ | ⚠️ |
| No outbound dependency | ✅ | ❌ |
| Auditability for safety | ✅ | ⚠️ |
| Runtime API cost | ✅ $0 | ❌ Variable |
| Handles 30s budget | ✅ Always | ⚠️ Risk |

---

## Safety Guardrails

Safety is enforced at both generation and post-processing stages:

- **No credential harvesting** — never asks for PIN, OTP, password, or full card number
- **No unauthorized promises** — never confirms refunds, reversals, or account recovery without authority
- **No third-party redirection** — avoids directing users to suspicious or unverified external parties
- **Prompt-injection resistance** — adversarial instructions embedded in complaint text are detected and ignored
- **Credential protection reminder** — added to all customer-facing message outputs

---

## Model Specification

| Metric | Specification |
|--------|--------------|
| Model name | N/A (Deterministic Rule Engine) |
| Where it runs | Local Python process |
| Why chosen | Safety, reproducibility, and latency |
| External API dependency | None |
| Runtime cost | **$0.00 per request** |

---

## Environment Variables

No external API keys or credentials are required. `.env.example` is included for optional Django configuration.

| Variable | Purpose | Default |
|----------|---------|---------|
| `DJANGO_SECRET_KEY` | Django secret key | Set in `.env` |
| `DJANGO_DEBUG` | Enable debug mode | `False` |
| `DJANGO_ALLOW_ALL_HOSTS` | Allow all hosts | `False` |

---

## Assumptions & Limitations

**Assumptions:**
- Input follows the documented JSON schema for `ticket_id`, `complaint`, and `transaction_history`
- Transaction histories are short (typically 2–5 entries)
- Currency values are in BDT
- Empty complaints return `422`

**Known Limitations:**
- Rule-based parsing may miss unusual phrasing not covered by keyword packs
- No external account lookup or live system integration
- Engine relies solely on the provided complaint and transaction payload
- `recommended_next_action` is template-oriented for operational consistency

---

## Submission Checklist

- [x] Required endpoints implemented and validated (`/health`, `/analyze-ticket`)
- [x] Dependency file included: `requirements.txt`
- [x] Sample output artifact included: `sample_output.json`
- [x] Environment template included: `.env.example`
- [x] Reproducible runbook included in this README
- [x] No external LLM or API dependency required to run locally
- [x] Safety guardrails documented and enforced