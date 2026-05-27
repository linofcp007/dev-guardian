---
description: Review code that just landed from someone else (merged PR, pulled main). Código que chegou de fora. Código entrante.
---

Run after pulling someone else's changes — a merged PR landed on `main`, a colleague pushed to a shared branch, or a Dependabot/Renovate PR auto-merged. The goal is to inspect work you did **not** write and might not yet trust.

The skill should:
1. Identify the set of new commits ingested in the most recent fast-forward / merge (default: `git log HEAD@{1}..HEAD`).
2. Per author, list which files were touched and surface anything in security-sensitive paths (auth, payments, crypto, env handling, migrations).
3. Run `scan_sast` + `scan_secrets` focused on those files.
4. Run a quick `bug_hunt` pass on the diff — does the new code look obviously broken?
5. Surface 🔴 / 🟡 findings and offer to open follow-up issues via `create_github_issues`.

Distinguish "trusted internal commits" from "external / bot-generated" if the author looks like a bot.

Scope hint (e.g. "since yesterday", a commit range): $ARGUMENTS
