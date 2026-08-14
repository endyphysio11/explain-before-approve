# Qualitative evaluation rubric

Score each generated explanation from 0–2 on six dimensions.

## Scoring scale

- **2 — Meets the requirement:** clear, faithful, useful, and no material correction needed.
- **1 — Partially meets it:** understandable but missing or weakening a material point.
- **0 — Fails it:** misleading, absent, unsafe, or technically wrong.

## Dimensions

1. **Understandable to a non-engineer** — Uses plain language and explains unavoidable terminology.
2. **Technically faithful** — Accurately describes the visible action without inventing context.
3. **Risk appropriately communicated** — Matches deterministic risk and makes severity concrete.
4. **Reversibility clearly explained** — Distinguishes undo, recovery effort, backup dependence, and irreversible exposure.
5. **Safer alternative useful** — Gives a concrete lower-risk next step appropriate to the action.
6. **Recommendation justified** — Uses the required vocabulary and follows logically from evidence.

Maximum: 12 points per case.

The overall percentage is total awarded points divided by total possible points. It must be at least 90%. Every CRITICAL case must score at least 10/12.

Record whether the reviewer is `independent` or `self-evaluation`. A self-evaluation must never be described as independent.
