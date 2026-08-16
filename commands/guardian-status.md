---
description: Project health dashboard — latest scans, deltas, baseline, expiring suppressions. Estado do projeto. Estado del proyecto.
---

Show the **current health** of the project in one screen. Read-only — no scan runs, no mutation.

Run `node "${CLAUDE_PLUGIN_ROOT}/cli/dev-guardian.mjs" status --project .` and show its output **verbatim** — that one screen is the deterministic source of truth (a single query pass over `.guardian/guardian.db`), not improvised here. It already covers:

1. **Latest scan** — when, what type, how long it took.
2. **Risk score and band**, carrying a coverage caveat whenever the scan behind it was partial.
3. **Open findings and CVEs**, by severity.
4. **Both deltas** — since the previous scan of the same type, and since the active baseline. Either shows as an explicit "none" when there's nothing to compare against, never as a zero.
5. **Hotspots** — up to 3 files, ranked by finding count, not severity.
6. **Missing scanners**, and what that leaves out of the numbers — shown only when coverage is partial.
7. **Suppressions** — active count, and anything expiring within 7 days.

`status` always exits `0` once it renders — including over a project full of criticals, or one that's never been scanned, in which case it names the scan command to run instead of showing empty numbers. It reports; it does not gate. The only non-zero exit is `3`, on a usage error.

Add, on top of that verbatim output:

- **Interpretation** — which hotspot to fix first, whether the deltas are trending the right way, how much less a "looks clean" read is worth when a scanner is missing.
- **Understanding gate** — read `.guardian/last-grill.md` (written by `guardian-grill`) directly; it's a file, not something `status` reports. Show its latest verdict 🟢 / 🟡 / 🔴 with scope and gap count — missing, or older than the current diff, show ⚪ "not run for current changes". A full gate needs both code metrics *and* understanding.

For the full page — filterable and sortable, everything this screen has no room for — point at `dev-guardian dashboard`. Both render the same snapshot, so they never disagree, and both are a picture of the **last scan**, not a live view: a new scan means re-running the command to see it.

Filter hint for the interpretation above (optional, e.g. "only security", "only deps") — `status` itself takes no filter flag: $ARGUMENTS
