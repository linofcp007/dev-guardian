#!/usr/bin/env bash
# initial-scan.sh — Scan inicial em modo "report only" depois do guardian init.
# Não falha em findings, só mostra o estado atual.

set -uo pipefail  # sem -e: não para em findings
PROJECT="${1:-.}"
cd "$PROJECT"

echo "Estado inicial do projeto:"
echo ""

if command -v gitleaks >/dev/null; then
  echo -n "  Secrets: "
  COUNT=$(gitleaks detect --no-banner --report-format=json --report-path=/tmp/_gl.json --redact 2>/dev/null && cat /tmp/_gl.json | grep -c '"RuleID"' 2>/dev/null || echo 0)
  echo "$COUNT findings"
fi

if command -v trivy >/dev/null; then
  echo -n "  Vulnerabilidades de dependências: "
  trivy fs --scanners vuln --severity HIGH,CRITICAL --quiet --format json --output /tmp/_trivy.json . 2>/dev/null
  COUNT=$(grep -c '"VulnerabilityID"' /tmp/_trivy.json 2>/dev/null || echo 0)
  echo "$COUNT HIGH/CRITICAL"
fi

if command -v semgrep >/dev/null; then
  echo -n "  SAST (Semgrep): "
  semgrep --config=auto --quiet --json --output=/tmp/_sg.json . 2>/dev/null || true
  COUNT=$(grep -c '"check_id"' /tmp/_sg.json 2>/dev/null || echo 0)
  echo "$COUNT findings"
fi

echo ""
echo "Para detalhe completo: guardian scan"
