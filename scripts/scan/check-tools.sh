#!/usr/bin/env bash
# check-tools.sh — Verifica quais ferramentas estão instaladas e os respetivos versions.
# Output: JSON em stdout.

set -euo pipefail

has() { command -v "$1" >/dev/null 2>&1; }
ver() { "$@" 2>/dev/null | head -1 | tr -d '"' || echo "?"; }

semgrep_v=$(has semgrep && semgrep --version 2>/dev/null || echo "")
trivy_v=$(has trivy && trivy --version 2>/dev/null | head -1 | awk '{print $2}' || echo "")
gitleaks_v=$(has gitleaks && gitleaks version 2>/dev/null || echo "")
ruff_v=$(has ruff && ruff --version 2>/dev/null | awk '{print $2}' || echo "")
precommit_v=$(has pre-commit && pre-commit --version 2>/dev/null | awk '{print $2}' || echo "")
bandit_v=$(has bandit && bandit --version 2>/dev/null | head -1 | awk '{print $2}' || echo "")
syft_v=$(has syft && syft version 2>/dev/null | grep Version | awk '{print $2}' || echo "")
node_v=$(has node && node --version 2>/dev/null || echo "")
python_v=$(has python3 && python3 --version 2>/dev/null | awk '{print $2}' || echo "")
docker_v=$(has docker && docker --version 2>/dev/null | awk '{print $3}' | tr -d ',' || echo "")
k6_v=$(has k6 && k6 version 2>/dev/null | head -1 | awk '{print $2}' || echo "")

cat <<EOF
{
  "semgrep": "${semgrep_v}",
  "trivy": "${trivy_v}",
  "gitleaks": "${gitleaks_v}",
  "ruff": "${ruff_v}",
  "pre-commit": "${precommit_v}",
  "bandit": "${bandit_v}",
  "syft": "${syft_v}",
  "node": "${node_v}",
  "python": "${python_v}",
  "docker": "${docker_v}",
  "k6": "${k6_v}"
}
EOF
