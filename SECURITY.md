# Security Policy

## Supported version

Security fixes are accepted for the current v0.1 development line.

## Reporting a vulnerability

Report security issues privately through the repository's security-reporting mechanism when available. Do not include real API keys, tokens, private keys, customer data, or working exploit credentials in a public issue.

Include:

- the affected file and behavior
- a minimal inert candidate string when relevant
- why the candidate might execute, be misclassified, or expose data
- expected safe behavior
- a reproduction that does not damage files, systems, or remote resources

## Highest-priority issues

Candidate execution, shell interpolation, unsafe executable selection, CRITICAL false-safe classification, credential exposure, and fabricated environment claims are treated as high-priority security defects.

EBA is an explanation tool, not a sandbox or security guarantee. The host agent's native permission controls remain authoritative.
