# Evaluations

This directory contains realistic user-facing cases, the qualitative rubric, independent or fallback review evidence, and the quantitative acceptance runner.

## Run

```bash
PYTHONDONTWRITEBYTECODE=1 python3 evals/acceptance.py
```

The runner:

- runs all repository tests
- evaluates every labeled fixture
- calculates exact risk accuracy, HIGH+CRITICAL recall, CRITICAL recall, and domain accuracy
- checks all required structured fields and six explanation sections
- verifies repository completeness, safety, uncertainty, and README requirements
- loads qualitative scores from `review-results.json`
- applies the exact weighted score from `PROJECT_SPEC.md`

It exits successfully only when every Hard Gate passes and the unrounded score is at least 95/100.

## Review integrity

When independent review capability exists, give a fresh read-only reviewer the raw evaluation cases and generated explanations without intended scores. Store its result in `review-results.json`. If independent review is unavailable, rubric-based self-evaluation is allowed but must be labeled `self-evaluation`.
