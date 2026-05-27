---
description: Validate a fix after applying it — regression-check the same category. Após corrigir. Tras corregir.
---

Run after fixing a bug or vulnerability that the Guardian previously surfaced. The goal is to confirm the fix actually works **and** that no regression was introduced in the same category.

The skill should:
1. Read the most recent `findings` rows from `.guardian/guardian.db` that match the fix description.
2. Re-run the specific scanner that originally produced those findings (Semgrep rule, Trivy CVE, gitleaks pattern, bug_hunt category).
3. Confirm the original findings are gone and report any **new** findings of the same category that emerged from the fix.
4. Compare via `diff_scans` against the last baseline so the user sees the delta clearly.
5. If everything is clean, offer to `set_baseline` so the new state becomes the reference going forward.

Verdict: ✅ fix verified, no regressions / ⚠️ fix verified but introduced X new findings / 🔴 fix did not resolve the original issue.

Fix description or finding_id (optional): $ARGUMENTS
