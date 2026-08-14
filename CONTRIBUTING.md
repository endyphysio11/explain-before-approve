# Contributing

Thank you for helping make approval decisions understandable and safer.

## Development setup

EBA uses Python 3 and the standard library only. Clone the repository and run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
python3 evals/acceptance.py
```

## Change workflow

1. Read `PROJECT_SPEC.md` and preserve its safety boundary.
2. Add or update a labeled fixture before changing a classification rule.
3. Make the smallest deterministic change that handles the evidence.
4. Run the complete test suite and acceptance checks.
5. Update domain references and public documentation when behavior changes.

## Fixture requirements

Every fixture requires an ID, candidate action, expected domain, risk, recommendation, required signals, tags, and notes. Candidate text must remain inert data. Add `important_context_unknown` whenever missing environment or recovery context materially affects the decision.

Do not remove difficult fixtures, weaken expected results, lower thresholds, or suppress safety tests merely to obtain a passing result.

## Writing guidance

Write for a smart adult who is not a software engineer. Explain technical terms immediately. State uncertainty rather than inventing production status, backups, or reversibility.

## Pull requests

Describe the user-visible behavior, safety impact, test evidence, and fixture changes. Keep unrelated refactors separate. Do not include credentials, personal paths, generated caches, or machine-specific configuration.
