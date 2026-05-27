---
description: Security scan (SAST, secrets, CVEs, IaC). Scan completo. Escaneo completo.
---

Invoke the `guardian-security` skill to run a comprehensive security scan on the current project.

Coverage:
- SAST with Semgrep
- Secret scanning with gitleaks
- Dependency CVEs with Trivy
- Container / Dockerfile scan with Trivy
- IaC scan (Terraform, Kubernetes, Ansible) with Trivy

Report findings prioritized as 🔴 Critical / 🟡 High / 🟢 Medium-Low / ℹ️ Info. Offer to auto-fix the safe ones; never push fixes without confirmation.

Scope hint (optional, e.g. "only deps", "only secrets", path): $ARGUMENTS
