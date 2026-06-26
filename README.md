# QueueStorm Investigator

Rule-based Django API service for the SUST Preliminary challenge.

This service analyzes one complaint plus a short transaction history and returns a structured investigator response with evidence verdict, routing, and safe customer messaging.

## Features

- Exposes required endpoints: `GET /health`, `POST /analyze-ticket`
- Deterministic evidence reasoning using complaint + transaction matching
- Supports English, Bangla, and mixed complaint text patterns
- Safety guardrails to prevent credential requests and unauthorized promises
- Prompt-injection resistant rules (ignores adversarial instructions in complaint text)
- Fast local execution with no external model/API dependency

## Tech Stack

- Python 3.12+
- Django 6
- Rule-based investigator engine in `queinvestigator_app/investigator.py`

## API Contract

### 1) Health

- Method: `GET`
- Path: `/health`
- Response:

```json
{"status": "ok"}
```

### 2) Analyze Ticket

- Method: `POST`
- Path: `/analyze-ticket`
- Content-Type: `application/json`
- Request/response follow the challenge schema.

## Local Setup

1. Create and activate a virtual environment (optional if you already use `queuevenv`):

```bash
python -m venv .venv
.venv\\Scripts\\activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. (Optional) copy env template:

```bash
copy .env.example .env
```

4. Run server:

```bash
python manage.py runserver 0.0.0.0:8000
```

5. Check readiness:

```bash
curl http://127.0.0.1:8000/health
```

## Runbook (Judge Reproducibility)

Use these exact commands from repo root:

```bash
pip install -r requirements.txt
python manage.py runserver 0.0.0.0:8000
```

Then call:

- `GET http://127.0.0.1:8000/health`
- `POST http://127.0.0.1:8000/analyze-ticket`

## Testing

### 1) API tests

```bash
python manage.py test
```

### 2) Public sample-case evaluator

```bash
python test_investigator.py
```

This validates core fields against all 10 public sample cases (`txn`, `verdict`, `case`, `dept`).

### 3) Generate sample output artifact

```bash
python generate_sample_output.py
```

Writes `sample_output.json`.

## AI Approach and Evidence Logic

The solution is intentionally deterministic and rule-based instead of LLM-based:

- Classifies complaint into required `case_type` taxonomy with multilingual keyword packs.
- Extracts likely amounts/phone numbers from complaint text.
- Scores each transaction in `transaction_history` and selects `relevant_transaction_id`.
- Produces `evidence_verdict`:
  - `consistent`
  - `inconsistent`
  - `insufficient_data`
- Maps to severity, department, and human review policy.
- Generates agent summary, action, and customer-safe reply.

### Why rule-based?

- Predictable latency (<30s budget)
- No outbound dependency risk
- Easier to audit for strict safety requirements
- No token/runtime model cost

## Safety Logic

Guardrails are enforced in both generation and post-processing:

- Never asks for PIN/OTP/password/full card number
- Never confirms refund/reversal/account recovery without authority
- Avoids directing users to suspicious or untrusted third parties
- Adds credential-protection reminder in customer communications
- Detects and ignores prompt-injection cues in complaint text

## MODELS

This submission uses **no external ML/LLM model** in runtime.

- Model name: `N/A (deterministic rule engine)`
- Where it runs: local Python process
- Why chosen: strongest reliability/cost/safety tradeoff for this challenge window
- Cost impact: effectively zero API cost per request

## Assumptions

- Input follows documented JSON schema for primary fields.
- Transaction history is short (typically 2 to 5 entries).
- Currency values are in BDT.
- Semantic validity checks are lightweight (e.g., empty complaint -> 422).

## Known Limitations

- Rule-based parsing may miss unusual phrasing not covered by keyword packs.
- No deep NLU context tracking beyond current ticket payload.
- `recommended_next_action` remains template-oriented for operational consistency.

## Submission Checklist

- [x] Required endpoints implemented
- [x] Dependency file included (`requirements.txt`)
- [x] Sample output file included (`sample_output.json`)
- [x] `.env.example` included
- [x] Reproducible runbook included in this README
