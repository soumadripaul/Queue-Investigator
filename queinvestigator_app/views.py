"""HTTP views for the QueueStorm Investigator copilot."""

from __future__ import annotations

import json
import logging
import traceback
from typing import Any

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from .investigator import investigate


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Error helpers
# ---------------------------------------------------------------------------

def _err(status: int, message: str) -> JsonResponse:
    return JsonResponse({"error": message}, status=status)


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------

@require_GET
def health(_request):
    """Lightweight readiness probe. Must respond within 60 seconds of start."""
    return JsonResponse({"status": "ok"})


# ---------------------------------------------------------------------------
# /analyze-ticket
# ---------------------------------------------------------------------------

@csrf_exempt
@require_POST
def analyze_ticket(request):
    """Validate the request, run the investigator, and return a structured
    response conforming to the Section 6 schema."""

    # ---- Parse body ------------------------------------------------------
    raw = request.body or b""
    if not raw:
        return _err(400, "Request body is empty.")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _err(400, "Malformed JSON body.")
    if not isinstance(payload, dict):
        return _err(400, "Request body must be a JSON object.")

    # ---- Validate top-level fields --------------------------------------
    ticket_id = payload.get("ticket_id")
    complaint = payload.get("complaint")
    if not isinstance(ticket_id, str) or not ticket_id.strip():
        return _err(400, "Missing or invalid 'ticket_id'.")
    if not isinstance(complaint, str):
        return _err(400, "Missing or invalid 'complaint'.")
    if not complaint.strip():
        return _err(422, "Empty complaint text.")

    # Optional fields are best-effort normalized; we never 400 on them.
    normalized: dict[str, Any] = {
        "ticket_id": ticket_id.strip(),
        "complaint": complaint.strip(),
        "language": payload.get("language") or "en",
        "channel": payload.get("channel") or "in_app_chat",
        "user_type": payload.get("user_type") or "customer",
        "campaign_context": payload.get("campaign_context"),
        "transaction_history": payload.get("transaction_history") or [],
        "metadata": payload.get("metadata") or {},
    }

    if not isinstance(normalized["transaction_history"], list):
        return _err(400, "'transaction_history' must be an array.")

    # Soft-validate each transaction entry shape; drop malformed ones
    # rather than failing the whole request.
    cleaned_history: list[dict] = []
    for entry in normalized["transaction_history"]:
        if isinstance(entry, dict) and isinstance(entry.get("transaction_id"), str):
            cleaned_history.append(entry)
    normalized["transaction_history"] = cleaned_history

    # ---- Run investigator ------------------------------------------------
    try:
        result = investigate(normalized)
    except Exception as exc:  # pragma: no cover - defensive guard
        # Never leak stack traces or internal details per Section 8.
        logger.exception("Investigator failed: %s", exc)
        return _err(500, "Internal error during analysis.")

    return JsonResponse(result, status=200)
