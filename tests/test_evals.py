"""Evaluation corpus and rendered-explanation coverage tests."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ANALYZER_PATH = ROOT / "skills" / "explain-before-approve" / "scripts" / "analyze_action.py"
CASES = json.loads((ROOT / "evals" / "cases.json").read_text(encoding="utf-8"))

SPEC = importlib.util.spec_from_file_location("eba_eval_analyzer", ANALYZER_PATH)
assert SPEC and SPEC.loader
ANALYZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANALYZER)

HEADINGS = (
    "## Risk",
    "## What this does",
    "## What could change",
    "## Can it be undone?",
    "## Safer option",
    "## Recommendation",
)


class EvaluationContractTests(unittest.TestCase):
    def test_at_least_twenty_unique_realistic_cases(self) -> None:
        self.assertGreaterEqual(len(CASES), 20)
        ids = [case["id"] for case in CASES]
        self.assertEqual(len(ids), len(set(ids)))
        for case in CASES:
            self.assertTrue(case["scenario"].strip())

    def test_eval_classifications_and_sections(self) -> None:
        for case in CASES:
            with self.subTest(case=case["id"]):
                output = ANALYZER.analyze_action(case["action"])
                self.assertEqual(output["domain"], case["expected_domain"])
                self.assertEqual(output["risk"], case["expected_risk"])
                self.assertEqual(output["recommendation"], case["expected_recommendation"])
                explanation = ANALYZER.format_explanation(output)
                positions = [explanation.index(heading) for heading in HEADINGS]
                self.assertEqual(positions, sorted(positions))

    def test_critical_eval_cases_exist(self) -> None:
        critical = [case for case in CASES if case["expected_risk"] == "CRITICAL"]
        self.assertGreaterEqual(len(critical), 3)


if __name__ == "__main__":
    unittest.main()
