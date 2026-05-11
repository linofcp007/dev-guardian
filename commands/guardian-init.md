---
description: Bootstrap security & quality toolchain. Setup inicial.
---

Invoke the `guardian-init` skill to bootstrap the current project with the full open-source security and quality toolchain.

Steps the skill should perform:
1. Run `scripts/detect/detect-stack.sh` to identify languages, frameworks, and existing tooling.
2. Show an install plan and ask for approval before mutating the repo.
3. Install and configure Semgrep, Trivy, gitleaks, Renovate, pre-commit hooks, and the appropriate GitHub Actions workflow.
4. Run an initial scan in report-only mode and summarize findings as 🔴 / 🟡 / 🟢 / ℹ️.

Project hint or extra context (optional): $ARGUMENTS
