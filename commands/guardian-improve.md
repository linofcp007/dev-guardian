---
description: Turn measured tech debt into improvement specs for dev-spec-driven. Transforma a dívida em specs. Convierte la deuda en specs.
argument-hint: "[scope hint, e.g. 'only services/']"
---

Invoke the `guardian-improve` skill: the bridge from findings to specs. It takes the ROI-ranked
hotspots, quality-rule violations, oversized files, duplication and coverage gaps from the quality
gate and drafts each top item as an **improvement spec seed** — problem, affected files, current
metric → target metric, and draft EARS acceptance criteria.

Steps:

1. Gather findings from `.guardian/guardian.db` (don't rescan unless stale).
2. Cluster them into 3–7 improvement units by root cause / file, ranked by ROI.
3. Draft each as a language-agnostic, metric-anchored seed (Current → Target is the acceptance test).
4. Add each to the `dev-spec-driven` backlog (`spec_backlog`), and offer to scaffold the top one into
   a full feature with `/spec`. If dev-spec-driven isn't installed, write seeds to
   `docs/improvement-specs/`.
5. Recommend tackling the top 1–2 this cycle. Remind: grill → spec → fix → re-run the gate to prove
   the delta.

Closes the loop: measure → spec → fix → re-measure. Pairs with `/guardian-grill` (understand before
you refactor) and `/guardian-debt` (the raw ranking).

Scope hint (optional): $ARGUMENTS

Respond in the user's language (EN/PT/ES).
