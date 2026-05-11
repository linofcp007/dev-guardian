#!/usr/bin/env bash
# quality-scan.sh — Análise de qualidade de código (complexidade, duplicação, dead code).
# Uso: bash quality-scan.sh [project-path]

set -euo pipefail

PROJECT="${1:-.}"
cd "$PROJECT"

mkdir -p .guardian/reports
TS=$(date +%Y%m%d-%H%M%S)
OUT=".guardian/reports/quality-${TS}"
mkdir -p "$OUT"

b() { printf '\033[34m%s\033[0m\n' "$*"; }

# Duplicação (multi-lang)
if command -v jscpd >/dev/null; then
  b "=== Duplicação (jscpd) ==="
  jscpd --reporters json --output "$OUT/dup" --silent . || true
fi

# Python — ruff + radon
if find . -name "*.py" -not -path '*/\.*' | head -1 | grep -q .; then
  b "=== Python (ruff + radon) ==="
  command -v ruff >/dev/null && ruff check --output-format json . > "$OUT/ruff.json" 2>/dev/null || true
  command -v radon >/dev/null && radon cc -j . > "$OUT/complexity-py.json" 2>/dev/null || true
fi

# JS/TS — eslint
if [ -f package.json ]; then
  b "=== JS/TS (eslint) ==="
  if [ -f .eslintrc.json ] || [ -f .eslintrc ] || [ -f eslint.config.js ]; then
    npx eslint . --format json -o "$OUT/eslint.json" || true
  fi
fi

# Go
if [ -f go.mod ] && command -v staticcheck >/dev/null; then
  b "=== Go (staticcheck) ==="
  staticcheck -f json ./... > "$OUT/staticcheck.json" 2>/dev/null || true
fi

echo "Reports em: $OUT/"
