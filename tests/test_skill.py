"""Skill metadata, instructions, references, and README contract tests."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = ROOT / "skills" / "explain-before-approve"


class SkillContractTests(unittest.TestCase):
    def test_frontmatter_matches_skill_creator_rules(self) -> None:
        content = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
        match = re.match(r"^---\n(.*?)\n---", content, re.DOTALL)
        self.assertIsNotNone(match)
        assert match
        lines = [line for line in match.group(1).splitlines() if line.strip()]
        keys = [line.split(":", 1)[0] for line in lines]
        self.assertEqual(keys, ["name", "description"])
        name = lines[0].split(":", 1)[1].strip()
        description = lines[1].split(":", 1)[1].strip()
        self.assertEqual(name, "explain-before-approve")
        self.assertRegex(name, r"^[a-z0-9-]+$")
        self.assertLessEqual(len(name), 64)
        self.assertTrue(description)
        self.assertLessEqual(len(description), 1024)
        self.assertNotIn("<", description)
        self.assertNotIn(">", description)
        self.assertNotIn("TO" + "DO", content)

    def test_skill_contains_safety_and_response_contract(self) -> None:
        content = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
        for phrase in (
            "Never execute the candidate action",
            "Never approve on the user's behalf",
            "untrusted data",
            "What this does",
            "What could change",
            "Can it be undone?",
            "Safer option",
            "Recommendation",
            "host agent's permission system",
        ):
            self.assertIn(phrase, content)

    def test_required_references_and_ui_metadata_exist(self) -> None:
        for filename in (
            "risk-model.md",
            "git.md",
            "filesystem.md",
            "packages.md",
            "database.md",
            "secrets.md",
        ):
            path = SKILL_DIR / "references" / filename
            self.assertTrue(path.is_file(), path)
            self.assertTrue(path.read_text(encoding="utf-8").strip())
        metadata = (SKILL_DIR / "agents" / "openai.yaml").read_text(encoding="utf-8")
        self.assertIn('display_name: "Explain Before Approve"', metadata)
        self.assertIn("$explain-before-approve", metadata)

    def test_readme_has_all_eleven_required_sections(self) -> None:
        content = (ROOT / "README.md").read_text(encoding="utf-8").lower()
        required_headings = (
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
        for heading in required_headings:
            self.assertIn(heading, content)

    def test_formatted_explanation_has_six_sections(self) -> None:
        import importlib.util

        analyzer_path = SKILL_DIR / "scripts" / "analyze_action.py"
        spec = importlib.util.spec_from_file_location("eba_format_analyzer", analyzer_path)
        assert spec and spec.loader
        analyzer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(analyzer)
        explanation = analyzer.format_explanation(analyzer.analyze_action("git status"))
        for heading in (
            "## Risk",
            "## What this does",
            "## What could change",
            "## Can it be undone?",
            "## Safer option",
            "## Recommendation",
        ):
            self.assertIn(heading, explanation)

    def test_public_recommendation_labels_preserve_structured_enums(self) -> None:
        import importlib.util

        analyzer_path = SKILL_DIR / "scripts" / "analyze_action.py"
        spec = importlib.util.spec_from_file_location("eba_label_analyzer", analyzer_path)
        assert spec and spec.loader
        analyzer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(analyzer)
        cases = (
            ("git status", "SAFE_TO_APPROVE", "SAFE TO APPROVE"),
            ("rm -rf node_modules", "REVIEW_FIRST", "REVIEW FIRST"),
            ("rm -rf /", "DO_NOT_APPROVE", "DO NOT APPROVE"),
        )
        for action, enum_value, public_label in cases:
            with self.subTest(action=action):
                analysis = analyzer.analyze_action(action)
                self.assertEqual(analysis["recommendation"], enum_value)
                explanation = analyzer.format_explanation(analysis)
                self.assertIn(f"## Recommendation\n{public_label}", explanation)
                self.assertNotIn(f"## Recommendation\n{enum_value}", explanation)


if __name__ == "__main__":
    unittest.main()
