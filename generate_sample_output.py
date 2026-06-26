"""Run the offline investigator over each public sample case and dump a
single combined `sample_output.json` file containing our output for every
case. This is the artifact expected by the prelim deliverables list."""
import json
import os
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "queinvestigator_project.settings")

import django  # noqa: E402

django.setup()

from queinvestigator_app.investigator import investigate  # noqa: E402


def main():
    with open("SUST_Preli_Sample_Cases.json", encoding="utf-8") as fh:
        data = json.load(fh)

    outputs = []
    for case in data["cases"]:
        out = investigate(case["input"])
        # Drop fields the spec marks optional when they were not produced.
        if "confidence" not in out:
            out["confidence"] = None
        if "reason_codes" not in out:
            out["reason_codes"] = []
        outputs.append({
            "id": case["id"],
            "label": case["label"],
            "output": out,
        })

    payload = {
        "_meta": {
            "title": "QueueStorm Investigator — Sample Outputs",
            "description": (
                "One output per public sample case, produced by running "
                "`investigate()` over the inputs in "
                "SUST_Preli_Sample_Cases.json. Compare against the "
                "expected_output field of each case to see the diff."
            ),
            "generator": "generate_sample_output.py",
        },
        "outputs": outputs,
    }

    with open("sample_output.json", "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)

    print(f"Wrote sample_output.json with {len(outputs)} cases.")


if __name__ == "__main__":
    main()