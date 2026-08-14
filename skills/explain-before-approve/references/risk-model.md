# Risk model

Use this reference after deterministic analysis or when a data-safe analyzer invocation is unavailable.

## Public risk levels

### 🟢 LOW

Use for read-only, local, non-sensitive actions with no important persistent modification. Recommend `SAFE_TO_APPROVE` only when the visible evidence supports low material risk.

### 🟡 MODERATE

Use for limited local changes that are usually reversible, including ordinary project dependency changes and explicit single-file operations. Recommend `REVIEW_FIRST` when side effects exist.

### 🟠 HIGH

Use for shared or remote state, destructive local changes, credentials, broad modifications, difficult recovery, or important environmental uncertainty. Recommend `REVIEW_FIRST`; use `DO_NOT_APPROVE` when visible destruction is unnecessary or overly broad.

### 🔴 CRITICAL

Use for catastrophic filesystem scope, known production destruction, or credential exfiltration. Recommend `DO_NOT_APPROVE`.

## Uncertainty

State what cannot be determined. Never claim production, development, a backup, or reversibility without evidence. Unknown material context must not become LOW merely because the target is unclear.

## Compound actions

Analyze every identifiable part. Choose the highest public risk. Use that part's domain as primary; if several parts tie, use the first in execution order. Never let a benign first command hide a dangerous later command or command substitution.

## Recommendations

- `SAFE_TO_APPROVE`: available evidence shows low material risk.
- `REVIEW_FIRST`: side effects, recovery effort, shared state, or important uncertainty exists.
- `DO_NOT_APPROVE`: visible catastrophic scope, credential exfiltration, or unnecessary irreversible destruction exists.

The recommendation informs a human decision. It never performs approval.
