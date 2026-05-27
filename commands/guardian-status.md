---
description: Project health dashboard — latest scans, deltas, baseline, expiring suppressions. Estado do projeto. Estado del proyecto.
---

Show the **current health** of the project in one screen. Read-only — no scanning runs, no mutations. Pulls everything from `.guardian/guardian.db`.

The skill should display:

1. **Latest scan** — when, what tools, how many 🔴 / 🟡 / 🟢 / ℹ️, scan duration.
2. **Delta vs. previous scan** — what got better, what got worse, what's new.
3. **Baseline status** — is there a baseline set? When? How far has the project drifted from it?
4. **Suppressions** — list active items with their reason and expiry. Highlight any expiring within 7 days.
5. **Active CVEs** — top 5 by severity, with the package and the fixed-in version when available.
6. **Last commands run** — recent invocations of Guardian commands to give the user a sense of cadence.

If no scans have been run yet, suggest `guardian-init` or `guardian-scan`. Output should fit in one terminal screen — terse, table-oriented.

Filter hint (optional, e.g. "only security", "only deps"): $ARGUMENTS
