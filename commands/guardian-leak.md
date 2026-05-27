---
description: Secret-leak emergency response — scan history + rotation checklist. Vazou secret. Filtración de secretos.
---

**Secret-leak response.** Use when the user thinks credentials, API keys, tokens, `.env`, or any sensitive material may have been committed or pushed.

The skill must:

1. Run `scan_secrets` (gitleaks) against the **entire git history** — not just HEAD. Use `--log-opts="--all"`.
2. For each finding, identify when it was introduced, who introduced it, and whether it was pushed to the remote (`git branch -a --contains`).
3. Classify each leaked secret by type (AWS key, GitHub PAT, Stripe key, JWT, generic) and emit a **rotation checklist** specific to each provider — exact dashboard URLs, what to revoke, what to regenerate.
4. Explain the BFG / `git filter-repo` flow if the user wants to scrub history — but be honest that **rotation is mandatory**, history rewrite is best-effort.
5. Suggest follow-ups: gitleaks pre-commit hook, GitHub push protection, organisation-wide secret scanning.

This is high-stakes — be clear, ordered, urgent without being dramatic.

Suspected leak description or affected file (optional): $ARGUMENTS
