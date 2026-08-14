# Explain Before Approve

**Understand what your coding agent wants to do before you approve it.**

Built for people who build with AI but don't speak terminal.

Before:

```bash
git push --force-with-lease origin main
```

After:

> **🟠 HIGH — REVIEW FIRST**  
> This rewrites the shared `main` branch with your local history. Work that exists remotely but not locally may disappear from the visible branch. Recovery may be possible from old commit IDs, but it is not a simple Undo. Fetch and compare both histories first.

Explain Before Approve (EBA) is an open-source Agent Skill plus a deterministic Python analyzer. It explains the action; the human decides.

## Problem

Coding agents ask permission for shell commands, Git operations, file changes, package installation, SQL, and credential-related actions. A raw command is not enough context for many capable builders to make an informed decision. EBA translates that request into what will happen, what could change, how recovery works, a safer option, and a recommendation.

## Who this is for

EBA is designed for vibe coders, designers, founders, researchers, product managers, students, domain experts, and anyone else building with an AI coding agent without deep terminal experience.

## Before and after

Input:

```bash
rm -rf node_modules
```

Explanation:

> **🟡 MODERATE — REVIEW FIRST**  
> This deletes the project's generated dependency directory. It can normally be recreated from the package manifest and lockfile, although any manual changes inside it would be lost. Confirm the path contains only generated dependencies.

That is intentionally different from `rm -rf /`, which EBA classifies as **🔴 CRITICAL — DO NOT APPROVE** because it can destroy filesystem-root data.

## Installation

EBA's core has no runtime dependencies beyond Python 3.

Clone the repository:

```bash
git clone https://github.com/endyphysio11/explain-before-approve.git
cd explain-before-approve
```

For Codex, copy `skills/explain-before-approve` into your Codex skills directory, or keep it in a workspace that loads repository skills. Other agent-skill hosts may use the same provider-independent folder format, but compatibility is experimental unless that host's current skill mechanism has been verified.

## Usage

Run the deterministic analyzer:

```bash
python3 skills/explain-before-approve/scripts/analyze_action.py "git push --force-with-lease origin main"
```

It returns structured JSON with `domain`, `risk`, `recommendation`, impact, reversibility, safer alternatives, uncertainties, and deterministic signals.

Invoke the Agent Skill with requests such as:

- “Should I approve this?”
- “What does this command do?”
- “Is this safe?”
- “My coding agent wants permission to run `git clean -fd`.”

Candidate input is untrusted data. Integrations must pass it as a direct argv/data value or through the analyzer's fixed `--stdin` mode; never interpolate it into a shell command.

## Supported domains

v0.1 intentionally supports five domains:

- Git: reads, pulls, pushes, history rewrites, resets, cleanup, branches, and tags
- Filesystem: reads, creation, copies, moves, deletion scope, overwrites, permissions, and ownership
- Packages: npm, pnpm, yarn, pip, pipx, brew, and apt
- Database and SQL: reads, writes, destructive statements, schema changes, and migrations
- Secrets and environment: environment files, keys, tokens, credential output, staging, transmission, modification, and deletion

Unsupported or malformed input returns a conservative structured `unknown` result rather than being executed.

## Risk model

| Risk | Typical meaning | Usual recommendation |
|---|---|---|
| 🟢 LOW | Read-only, local, non-sensitive | SAFE TO APPROVE |
| 🟡 MODERATE | Limited local change, usually reversible | REVIEW FIRST |
| 🟠 HIGH | Shared, destructive, credential-related, difficult, or materially uncertain | REVIEW FIRST |
| 🔴 CRITICAL | Catastrophic destruction, known production loss, or credential exfiltration | DO NOT APPROVE |

Recommendations are guidance, never automatic approvals.

## Limitations

- EBA recognizes patterns; it is not malware detection, antivirus, a sandbox, or a security guarantee.
- It cannot infer an environment, backup, hidden script behavior, or remote ownership from missing evidence.
- Package lifecycle scripts and arbitrary embedded code can have effects beyond deterministic pattern analysis.
- It does not intercept every host permission prompt and does not replace the host agent's permission system.
- v0.1 is limited to the five documented domains and does not provide enterprise policy, telemetry, or cloud services.

## Safety philosophy

**AI explains. Human decides.**

EBA never executes candidate input and never approves on the user's behalf. Candidate strings—including SQL, scripts, substitutions, and prompt-injection-like text—remain inert data. Deterministic HIGH and CRITICAL findings cannot be silently downgraded by the explanatory layer. Important unknowns are stated instead of invented.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing risk rules, fixtures, or documentation. Safety thresholds and expected results must not be weakened merely to make tests pass.

Security-sensitive reports should follow [SECURITY.md](SECURITY.md).

## License

Explain Before Approve is available under the [MIT License](LICENSE).
