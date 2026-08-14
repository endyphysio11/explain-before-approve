#!/usr/bin/env python3
"""Objective acceptance runner for Explain Before Approve v0.1."""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ANALYZER_PATH = ROOT / "skills" / "explain-before-approve" / "scripts" / "analyze_action.py"
FIXTURES_PATH = ROOT / "tests" / "fixtures" / "cases.json"
EVAL_CASES_PATH = ROOT / "evals" / "cases.json"
REVIEW_PATH = ROOT / "evals" / "review-results.json"

REQUIRED_OUTPUT_FIELDS = {
    "domain",
    "risk",
    "recommendation",
    "action_summary",
    "impact",
    "reversibility",
    "safer_alternatives",
    "uncertainties",
    "signals",
}
STRING_FIELDS = {"domain", "risk", "recommendation", "action_summary", "reversibility"}
ARRAY_FIELDS = {"impact", "safer_alternatives", "uncertainties", "signals"}
DOMAINS = {"git", "filesystem", "packages", "database", "secrets", "unknown"}
RISKS = {"LOW", "MODERATE", "HIGH", "CRITICAL"}
RECOMMENDATIONS = {"SAFE_TO_APPROVE", "REVIEW_FIRST", "DO_NOT_APPROVE"}
EXPLANATION_HEADINGS = (
    "## Risk",
    "## What this does",
    "## What could change",
    "## Can it be undone?",
    "## Safer option",
    "## Recommendation",
)
README_HEADINGS = (
    "## problem",
    "## who this is for",
    "## before and after",
    "## installation",
    "## usage",
    "## supported domains",
    "## risk model",
    "## limitations",
    "## safety philosophy",
    "## contributing",
    "## license",
)


def load_analyzer() -> Any:
    spec = importlib.util.spec_from_file_location("eba_acceptance_analyzer", ANALYZER_PATH)
    if not spec or not spec.loader:
        raise RuntimeError("Analyzer could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def valid_schema(output: dict[str, Any]) -> bool:
    return (
        REQUIRED_OUTPUT_FIELDS.issubset(output)
        and all(isinstance(output.get(field), str) and output[field].strip() for field in STRING_FIELDS)
        and all(isinstance(output.get(field), list) for field in ARRAY_FIELDS)
        and output["domain"] in DOMAINS
        and output["risk"] in RISKS
        and output["recommendation"] in RECOMMENDATIONS
    )


def analyzer_static_safety() -> bool:
    tree = ast.parse(ANALYZER_PATH.read_text(encoding="utf-8"))
    forbidden_modules = {"subprocess", "os", "pty"}
    forbidden_names = {"eval", "exec", "compile"}
    forbidden_attributes = {"system", "popen", "Popen", "run", "call", "check_call", "check_output"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if {alias.name.split(".")[0] for alias in node.names} & forbidden_modules:
                return False
        if isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in forbidden_modules:
                return False
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in forbidden_names:
                return False
            if isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_attributes:
                return False
    return True


def run_tests() -> tuple[bool, str]:
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )
    evidence = (completed.stdout + completed.stderr).strip()
    return completed.returncode == 0, evidence


def qualitative_metrics(eval_risks: dict[str, str]) -> tuple[str, float, bool, int]:
    if not REVIEW_PATH.is_file():
        return "missing", 0.0, False, 0
    review = json.loads(REVIEW_PATH.read_text(encoding="utf-8"))
    reviewer_type = review.get("reviewer_type", "missing")
    if reviewer_type not in {"independent", "self-evaluation"}:
        return reviewer_type, 0.0, False, 0
    entries = review.get("cases", [])
    by_id = {entry.get("id"): entry for entry in entries}
    if set(by_id) != set(eval_risks):
        return reviewer_type, 0.0, False, len(entries)
    dimensions = (
        "understandable",
        "technically_faithful",
        "risk_communicated",
        "reversibility",
        "safer_alternative",
        "recommendation_justified",
    )
    awarded = 0
    critical_minimum = True
    for entry in entries:
        scores = entry.get("scores", {})
        if set(scores) != set(dimensions) or any(scores[key] not in (0, 1, 2) for key in dimensions):
            return reviewer_type, 0.0, False, len(entries)
        total = sum(scores.values())
        awarded += total
        if entry.get("expected_risk") != eval_risks[entry["id"]]:
            return reviewer_type, 0.0, False, len(entries)
        if eval_risks[entry["id"]] == "CRITICAL" and total < 10:
            critical_minimum = False
    percentage = awarded / (len(entries) * 12) if entries else 0.0
    return reviewer_type, percentage, critical_minimum, len(entries)


def repository_complete() -> tuple[bool, list[str]]:
    required = (
        "README.md",
        "LICENSE",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "PROJECT_SPEC.md",
        "CHANGELOG.md",
        "FINAL_REPORT.md",
        "skills/explain-before-approve/SKILL.md",
        "skills/explain-before-approve/references/risk-model.md",
        "skills/explain-before-approve/references/git.md",
        "skills/explain-before-approve/references/filesystem.md",
        "skills/explain-before-approve/references/packages.md",
        "skills/explain-before-approve/references/database.md",
        "skills/explain-before-approve/references/secrets.md",
        "skills/explain-before-approve/scripts/analyze_action.py",
        "tests/test_analyzer.py",
        "tests/test_safety.py",
        "tests/fixtures/cases.json",
        "evals/README.md",
        "evals/cases.json",
        "evals/rubric.md",
        "evals/acceptance.py",
    )
    missing = [path for path in required if not (ROOT / path).is_file()]
    return not missing, missing


def main() -> int:
    analyzer = load_analyzer()
    fixtures = json.loads(FIXTURES_PATH.read_text(encoding="utf-8"))
    eval_cases = json.loads(EVAL_CASES_PATH.read_text(encoding="utf-8"))
    outputs = [analyzer.analyze_action(case["action"]) for case in fixtures]

    fixture_count = len(fixtures)
    exact_risk = sum(out["risk"] == case["expected_risk"] for case, out in zip(fixtures, outputs)) / fixture_count
    severe_indices = [i for i, case in enumerate(fixtures) if case["expected_risk"] in {"HIGH", "CRITICAL"}]
    severe_recall = sum(outputs[i]["risk"] in {"HIGH", "CRITICAL"} for i in severe_indices) / len(severe_indices)
    critical_indices = [i for i, case in enumerate(fixtures) if case["expected_risk"] == "CRITICAL"]
    critical_recall = sum(outputs[i]["risk"] == "CRITICAL" for i in critical_indices) / len(critical_indices)
    domain_accuracy = sum(out["domain"] == case["expected_domain"] for case, out in zip(fixtures, outputs)) / fixture_count
    critical_to_low = sum(outputs[i]["risk"] == "LOW" for i in critical_indices)
    critical_to_safe = sum(outputs[i]["recommendation"] == "SAFE_TO_APPROVE" for i in critical_indices)
    schema_complete = all(valid_schema(output) for output in outputs)

    explanations_complete = True
    eval_classifications_match = True
    for case in eval_cases:
        output = analyzer.analyze_action(case["action"])
        explanation = analyzer.format_explanation(output)
        explanations_complete &= all(heading in explanation for heading in EXPLANATION_HEADINGS)
        eval_classifications_match &= (
            output["domain"] == case["expected_domain"]
            and output["risk"] == case["expected_risk"]
            and output["recommendation"] == case["expected_recommendation"]
        )

    forbidden_claims = (
        "this is production",
        "this is development",
        "a backup exists",
        "the backup exists",
        "is fully reversible",
    )
    uncertainty_pass = True
    for case, output in zip(fixtures, outputs):
        if "important_context_unknown" in case["tags"]:
            rendered = json.dumps(output).lower()
            uncertainty_pass &= not any(claim in rendered for claim in forbidden_claims)

    tests_pass, test_evidence = run_tests()
    static_safety = analyzer_static_safety()
    complete_files, missing_files = repository_complete()
    readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
    readme_complete = all(heading in readme for heading in README_HEADINGS)
    reviewer_type, qualitative, critical_qualitative, review_count = qualitative_metrics(
        {case["id"]: case["expected_risk"] for case in eval_cases}
    )

    gate_a = complete_files and tests_pass
    gate_b = static_safety and tests_pass
    gate_c = critical_to_low == 0 and critical_to_safe == 0
    gate_d = exact_risk >= 0.90 and severe_recall >= 0.95 and critical_recall == 1.0 and domain_accuracy >= 0.95
    gate_e = schema_complete and explanations_complete and eval_classifications_match
    gate_f = uncertainty_pass
    gate_g = tests_pass
    gate_h = readme_complete
    hard_gates = {
        "A_repository": gate_a,
        "B_safety": gate_b,
        "C_critical_false_safe": gate_c,
        "D_classification": gate_d,
        "E_output_completeness": gate_e,
        "F_uncertainty": gate_f,
        "G_tests": gate_g,
        "H_documentation": gate_h,
    }

    safety_points = (20 if gate_b else 0) + (10 if gate_c else 0) + (5 if gate_f else 0)
    classification_points = exact_risk * 15 + severe_recall * 5 + critical_recall * 3 + domain_accuracy * 2
    ux_points = qualitative * 20
    test_points = (6 if tests_pass else 0) + (2 if fixture_count >= 80 else 0) + (2 if len(eval_cases) >= 20 else 0)
    oss_files = all((ROOT / path).is_file() for path in ("LICENSE", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md"))
    tree = ast.parse(ANALYZER_PATH.read_text(encoding="utf-8"))
    imports = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        (node.module or "").split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    )
    imports.discard("__future__")
    analyzer_stdlib = {"json", "re", "shlex", "sys", "typing"}
    stdlib_only = imports.issubset(analyzer_stdlib)
    readme_examples_verified = (
        analyzer.analyze_action("git push --force-with-lease origin main")["risk"] == "HIGH"
        and analyzer.analyze_action("rm -rf node_modules")["risk"] == "MODERATE"
        and analyzer.analyze_action("rm -rf /")["risk"] == "CRITICAL"
    )
    readme_claims_verified = eval_classifications_match and static_safety and stdlib_only and readme_examples_verified
    documentation_points = (4 if readme_complete else 0) + (2 if oss_files else 0) + (1 if readme_claims_verified else 0)
    provider_independent = "provider-independent" in (ROOT / "README.md").read_text(encoding="utf-8")
    no_proprietary_runtime = stdlib_only and not bool(imports & {"openai", "anthropic", "google", "boto3"})
    portability_points = (1 if stdlib_only else 0) + (1 if no_proprietary_runtime else 0) + (1 if provider_independent else 0)
    total_score = safety_points + classification_points + ux_points + test_points + documentation_points + portability_points

    qualitative_pass = qualitative >= 0.90 and critical_qualitative and review_count >= 20
    complete = all(hard_gates.values()) and qualitative_pass and total_score >= 95
    result = {
        "status": "PASS" if complete else "FAIL",
        "hard_gates": hard_gates,
        "metrics": {
            "fixture_count": fixture_count,
            "evaluation_case_count": len(eval_cases),
            "reviewed_case_count": review_count,
            "reviewer_type": reviewer_type,
            "exact_risk_accuracy": exact_risk,
            "high_critical_recall": severe_recall,
            "critical_recall": critical_recall,
            "domain_accuracy": domain_accuracy,
            "critical_to_low": critical_to_low,
            "critical_to_safe_to_approve": critical_to_safe,
            "qualitative_score": qualitative,
            "critical_qualitative_minimum": critical_qualitative,
            "schema_complete": schema_complete,
            "explanations_complete": explanations_complete,
            "tests_pass": tests_pass,
            "static_safety_pass": static_safety,
            "readme_claims_verified": readme_claims_verified,
            "stdlib_only": stdlib_only,
            "no_proprietary_runtime": no_proprietary_runtime,
            "provider_independent": provider_independent,
        },
        "score": {
            "core_safety": safety_points,
            "risk_classification": classification_points,
            "human_readable_ux": ux_points,
            "tests_evals": test_points,
            "documentation_oss": documentation_points,
            "portability_architecture": portability_points,
            "total": total_score,
        },
        "missing_files": missing_files,
        "test_evidence": test_evidence.splitlines()[-4:],
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
