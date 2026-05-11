#!/usr/bin/env bash
# review-scan.sh — Scan focado apenas nos ficheiros do diff (para revisão pré-PR).
# Uso: bash review-scan.sh "<ficheiros separados por espaço>"
#  ou: bash review-scan.sh   (default: diff vs origin/main)

set -euo pipefail

if [ "$#" -ge 1 ] && [ -n "$1" ]; then
  FILES="$1"
else
  FILES=$(git diff --name-only origin/main...HEAD 2>/dev/null || git diff --name-only HEAD~1 2>/dev/null || echo "")
fi

if [ -z "$FILES" ]; then
  echo "Sem ficheiros para rever."
  exit 0
fi

mkdir -p .guardian/reports
TS=$(date +%Y%m%d-%H%M%S)
OUT=".guardian/reports/review-${TS}"
mkdir -p "$OUT"

echo "Ficheiros a rever:"
echo "$FILES" | tr ' ' '\n' | sed 's/^/  /'
echo ""

# Semgrep só nos ficheiros do diff
if command -v semgrep >/dev/null; then
  echo "$FILES" | tr ' ' '\n' | xargs -r semgrep --config=auto --json --output="$OUT/sast.json" --quiet || true
fi

# gitleaks só no diff atual (não histórico)
if command -v gitleaks >/dev/null; then
  gitleaks protect --no-banner --staged --report-format=json --report-path="$OUT/secrets.json" --redact || true
fi

# Trivy se package manifests mudaram
if command -v trivy >/dev/null; then
  if echo "$FILES" | grep -qE "(package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|requirements.*\.txt|poetry\.lock|uv\.lock|composer\.lock|Gemfile\.lock|Cargo\.lock|go\.sum)"; then
    trivy fs --scanners vuln --format json --output "$OUT/deps.json" --quiet . || true
  fi
fi

echo "Reports em: $OUT/"
