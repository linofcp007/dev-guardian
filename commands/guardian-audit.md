---
description: Executive audit (security+quality+deps). Relatório executivo. Informe ejecutivo.
---

Run a combined audit by invoking, in order:

1. `guardian-security` (full security scan)
2. `guardian-quality` (code quality and tech debt)
3. `guardian-deps` (dependency CVEs and supply chain)

Then aggregate everything into a single executive-style report:

- One-paragraph summary
- 🔴 Critical findings (block deploy/merge)
- 🟡 High findings (fix before release)
- 🟢 Medium / Low (backlog)
- ℹ️ Info / observations
- Recommended next 3 actions, ranked by impact

Scope (optional): $ARGUMENTS
