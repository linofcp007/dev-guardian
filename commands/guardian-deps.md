---
description: Dependency updates, CVEs, supply chain. Dependências e CVEs. Dependencias y CVEs.
---

Invoke the `guardian-deps` skill for dependency management, vulnerability scanning, and supply-chain hygiene.

The skill should:
- Scan deps for known CVEs (Trivy / npm audit / pip-audit / bundler-audit / govulncheck etc., based on stack)
- Identify abandoned, typosquatted, or suspicious packages
- Propose safe upgrade paths and offer to configure Renovate or Dependabot
- Report findings as 🔴 / 🟡 / 🟢 with concrete next actions

Scope (optional, e.g. "only direct deps", "production only"): $ARGUMENTS
