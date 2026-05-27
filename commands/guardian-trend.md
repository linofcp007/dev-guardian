---
description: Findings trend over the last N scans — are we improving? Tendência. Tendencia.
---

Show **how the project is trending** over time. Read-only — pulls from `.guardian/guardian.db`.

The skill should:
1. Pull the last N scans (default N = 10) of each category from the `scans` table.
2. Plot (ASCII / table) the finding counts per scan, grouped by severity. Show direction arrows: ↑ getting worse, ↓ getting better, → flat.
3. Identify recurring rule IDs that keep coming back — the "chronic" findings the team isn't actually fixing.
4. Identify findings that were resolved and stayed resolved — celebrate the wins.
5. Compute a simple **debt half-life** for the project: based on resolution velocity, how long would it take to clear the current backlog?

Output is a snapshot, not a recommendation — for action items, route to `guardian-debt` or `guardian-audit`.

Window override (optional, e.g. "last 30 days", "last 20 scans"): $ARGUMENTS
