---
description: Generate a stakeholder-ready report — markdown / PDF / exec summary. Gera relatório. Genera informe.
---

Generate a **stakeholder-ready** Guardian report. Different from `guardian-status` (terminal-oriented snapshot) and `guardian-audit` (technical findings) — this output is meant to be shared with people who don't read code.

The skill should produce a structured markdown document (the user can then convert to PDF) containing:

1. **Executive summary** — 3 sentences. Where is the project, what's the biggest risk, what's the recommended next move.
2. **Security posture** — counts of 🔴 / 🟡 / 🟢 findings + trend vs. last reporting period.
3. **Compliance** — GDPR / RGPD readiness, license posture, SBOM availability.
4. **Quality** — high-level tech debt score, hotspots **described in business terms** (not file paths).
5. **Dependencies** — outdated / vulnerable count, supply-chain risks.
6. **Recommended next 5 actions** — in plain language, ordered by impact.

Tone is non-technical. No raw rule IDs, no scanner names — translate findings into outcomes. Where helpful, include a glossary footer.

Use `report_export` MCP tool to write to disk if the user wants a file (default: print inline).

Reporting period / audience (e.g. "monthly board", "Q1 stakeholders"): $ARGUMENTS
