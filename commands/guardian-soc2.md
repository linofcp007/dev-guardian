---
description: SOC 2 / ISO 27001 evidence pack — formatted output for auditors. Pacote SOC 2. Paquete SOC 2.
---

Produce an **evidence pack** suitable for SOC 2 Type II / ISO 27001 audits, pulled from the project's history and Guardian's persisted state.

The skill should emit a structured bundle covering:

1. **CC6.1 Logical Access** — evidence that authentication is enforced (auth code paths, missing-auth findings from SAST, multi-factor support).
2. **CC6.6 Vulnerability Management** — last N CVE scans with dates, time-to-remediation per finding, current open vulnerabilities.
3. **CC7.1 Detection of Security Events** — observability scaffolding in place (logging, metrics, error tracking), GlitchTip / Sentry presence.
4. **CC7.2 Incident Response** — references to any `guardian-postmortem` outputs in the repo.
5. **CC8.1 Change Management** — PR review evidence, branch protection settings, pre-commit hooks, CI gates.
6. **A.5–A.18 (ISO 27001 Annex A)** — map relevant findings to specific Annex A controls.

Output is markdown ready to paste into the auditor's evidence portal. Includes a **caveat footer**: this is supporting evidence, not a complete control list — the audit firm decides what's sufficient.

Audit firm or specific control hint (optional, e.g. "Drata", "CC6 only"): $ARGUMENTS
