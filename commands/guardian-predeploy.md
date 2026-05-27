---
description: Full pre-deploy gate — audit + env vars + prod-secret hygiene. Antes do deploy. Antes del despliegue.
---

Invoke the full deploy-readiness gate. This is the heavyweight counterpart to `guardian-prepush` and should run **before any production deploy**.

The flow:

1. Run `audit_executive` (security + quality + deps combined).
2. Verify no `.env*` files are tracked, no hardcoded production credentials, no `localhost`/`127.0.0.1` references in production config.
3. Check `compliance_check` for missing GDPR / RGPD / LOPD basics (privacy policy, cookie consent, data-retention) when the app handles personal data.
4. Check that the SBOM exists (`generate_sbom` if missing) so the deployed artifact is documented.
5. Verify CI status of the current branch is green.

End with a clear verdict: ✅ deploy / ⚠️ deploy with caveats (listed) / 🔴 do not deploy. Refuse 🔴 silently is never acceptable — always list the blocking findings.

Deploy target hint (e.g. "production", "staging", URL): $ARGUMENTS
