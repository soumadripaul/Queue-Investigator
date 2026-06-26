"""Offline smoke test of the investigator against the public sample cases.

Usage:
    queuevenv\\Scripts\\python.exe test_investigator.py
"""
import json
import os
import sys

# Force UTF-8 stdout so Bangla text prints correctly on Windows.
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "queinvestigator_project.settings")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import django  # noqa: E402

django.setup()

from queinvestigator_app.investigator import investigate  # noqa: E402


def main():
    with open("SUST_Preli_Sample_Cases.json", "r", encoding="utf-8") as fh:
        data = json.load(fh)
    ok = 0
    for case in data["cases"]:
        got = investigate(case["input"])
        exp = case["expected_output"]
        matches = {
            "txn": exp["relevant_transaction_id"] == got["relevant_transaction_id"],
            "verdict": exp["evidence_verdict"] == got["evidence_verdict"],
            "case": exp["case_type"] == got["case_type"],
            "dept": exp["department"] == got["department"],
        }
        score = sum(matches.values())
        if score == 4:
            ok += 1
        print(f"== {case['id']} ({case['label']}) score={score}/4 == {matches}")
        # Write expected vs actual to per-case files to keep console output
        # manageable while preserving the full content for inspection.
        with open(f"_case_{case['id']}.expected.json", "w", encoding="utf-8") as ef:
            json.dump(exp, ef, ensure_ascii=False, indent=2)
        with open(f"_case_{case['id']}.actual.json", "w", encoding="utf-8") as af:
            json.dump(got, af, ensure_ascii=False, indent=2)
    print(f"\nTOTAL: {ok}/10 fully matching on txn+verdict+case+dept")


if __name__ == "__main__":
    main()