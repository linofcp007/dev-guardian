---
description: Quick scan before pushing — diff + secrets in pending commits. Antes do push. Antes del push.
---

Invoke the `guardian-security` skill in **fast mode**, focused on what is about to leave the local machine. This is the lightweight gate to run **before `git push`**.

Steps the skill should perform:
1. Compute the set of commits that exist locally but not on the remote tracking branch (`git log @{u}..HEAD`).
2. Run `scan_secrets` (gitleaks) across those commits only — full history not needed.
3. Run `scan_sast` only on files touched in those commits.
4. Surface 🔴 / 🟡 findings inline and ask whether to abort the push when any 🔴 is found.

Optimised for speed: the whole thing should finish in seconds, not minutes. If the user says they have already pushed, redirect to `guardian-review` instead.

Branch hint or scope (optional): $ARGUMENTS
