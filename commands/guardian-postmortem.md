---
description: Post-incident analysis template with evidence pulled from the project. Análise post-mortem. Análisis post-incidente.
---

Produce a structured **post-mortem** for an incident, pulling supporting evidence from the project's own history and the Guardian's persisted findings.

The skill should produce a markdown document with sections:

1. **Timeline** — assemble from commit timestamps, deploy SHAs, recent merged PRs, and any incident time provided in `$ARGUMENTS`.
2. **Root cause** — best-effort hypothesis based on `git log`, recent changes, and any 🔴 findings in `.guardian/guardian.db` that match the symptom.
3. **Impact** — file/module blast radius derived from the offending commit's diff.
4. **What worked** / **What didn't** — gaps in detection: were there findings that were suppressed, or scanners that were skipped?
5. **Action items** — concrete, owned, dated. Each one should map to a Guardian command the team can run to prevent recurrence (e.g. *"Run `/guardian-prerelease` before every release"*, *"Stop suppressing X category"*).

The output is the **document**, not a one-line summary. The user will paste this into a docs / Notion / incident-tracker page.

Incident description (symptom + time + affected service): $ARGUMENTS
