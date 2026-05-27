---
description: Deep pre-PR / pre-deploy review. Revisão antes de PR ou deploy. Revisión antes de PR o despliegue.
---

Invoke the `guardian-review` skill for a senior-level review of the pending changes before PR, merge, or deploy.

The review should combine:

- Security checks (secrets, injection, auth)
- Bug hunt on the diff (logic, edge cases, error handling)
- Quality (complexity, duplication, naming)
- Test coverage and CI status of the changed files

End with a clear verdict: ✅ ready / ⚠️ ready with notes / 🔴 do not merge.

Branch, PR number, or scope hint (optional): $ARGUMENTS
