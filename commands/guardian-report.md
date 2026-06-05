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

**Output format — Markdown by default.** Print the 6 sections above as Markdown inline — that is the primary deliverable. Optionally persist it to a file with `report_export content_markdown="<the markdown>"` (writes `report.md`, the default format).

- **Secondary — a branded, shareable file:** when the user wants something polished to send or print to PDF, call `report_export format=html content_markdown="<the markdown>" title="…" lang=<en|pt|es>`. Set `lang` to the user's language so the shell chrome (footer, `<html lang>`) matches. It wraps the same prose in the Pro Digital Key shell (dark/light toggle, system default, self-contained, opens offline, print-friendly) so every report looks the same.

Reporting period / audience (e.g. "monthly board", "Q1 stakeholders"): $ARGUMENTS
