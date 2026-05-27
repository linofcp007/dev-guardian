---
description: Consolidated tech-debt score + top hotspots ranked by ROI. Dívida técnica. Deuda técnica.
---

Produce a **consolidated tech-debt view** — heavier than `guardian-quality` (which is per-scan), aimed at "what should we actually attack next?"

The skill should:

1. Pull aggregated quality + security + bug findings from `.guardian/guardian.db` across all scans.
2. Compute a `risk_score` per file (defect density × severity × churn from `git log`).
3. Surface the **top 10 hotspots** — files / modules that score worst, with a one-line "why".
4. For each hotspot, propose one of: 🛠️ refactor / 🧪 add tests / 📚 document the gotcha / 🗑️ delete (when usage is near zero).
5. Estimate effort vs. impact for each so the user can sort by ROI rather than gut feel.

Avoid recommending mass rewrites — favour smallest moves with biggest impact. If the project is genuinely clean, say so plainly.

Scope hint (e.g. "only services/", "only frontend"): $ARGUMENTS
