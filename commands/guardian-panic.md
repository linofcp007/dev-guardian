---
description: Triage mode — something just blew up in production. Pânico. Pánico.
---

**Incident triage mode.** Use when production just broke and the user needs to know *fast* what could have caused it and what the blast radius is.

The skill must move in this order, no preamble:

1. **What changed recently** — last 24 h of commits, last deployment SHA, recent merged PRs.
2. **Active 🔴 findings** in `.guardian/guardian.db` — anything currently flagged that could be related.
3. **Suspicious recent suppressions** — items added to `suppressions` in the last 7 days (sometimes the trigger).
4. **Secrets that might be in play** — `scan_secrets` against the recent diff (in case a key leaked).
5. **Likely culprits ranked by confidence** — short list, each with the evidence.

Be terse and operational. No long explanations. Surface evidence, propose investigation paths, recommend a rollback target if one exists. The user is on fire — every extra word costs.

Symptom or error message (optional but very helpful): $ARGUMENTS
