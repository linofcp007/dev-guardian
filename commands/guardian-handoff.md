---
description: Project handoff snapshot — pending work, debt, next actions. Passa o projeto. Pasa el proyecto.
---

Produce a complete **handoff document** for someone else picking up the project — useful before holidays, leaving the team, or onboarding a new maintainer.

The snapshot should contain:
1. **Current state** — last `audit_executive` summary (🔴 / 🟡 / 🟢 counts) + active CVEs from the `cves` table.
2. **Open commitments** — unfinished branches (`git branch --no-merged main`), open PRs, draft commits.
3. **Active suppressions** — items in the `suppressions` table with their expiry dates and stated reasons.
4. **Tech debt hotspots** — `risk_score` top-5 files / modules.
5. **Toolchain map** — output of `detect_stack` + which scanners are installed locally vs. expected.
6. **Top 3 next actions**, ranked by impact (what should the next person actually do first?).

Output is a single markdown document the user can paste into a Notion / Confluence / docs handoff page.

Handoff context (optional, e.g. "going on holiday 2 weeks", "leaving the team"): $ARGUMENTS
