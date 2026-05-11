---
description: Full security scan — SAST, secrets, dependency CVEs, containers, IaC. Scan completo de segurança (SAST, secrets, deps, containers, IaC).
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
