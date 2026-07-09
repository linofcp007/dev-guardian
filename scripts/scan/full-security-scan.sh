#!/usr/bin/env bash
# full-security-scan.sh — Corre todos os scanners de segurança e produz outputs JSON unificados.
# Uso: bash full-security-scan.sh [project-path]

set -euo pipefail

PROJECT="${1:-.}"
cd "$PROJECT"

mkdir -p .guardian/reports
TS=$(date +%Y%m%d-%H%M%S)
OUT=".guardian/reports/security-${TS}"
mkdir -p "$OUT"

g() { printf '\033[32m%s\033[0m\n' "$*"; }
y() { printf '\033[33m%s\033[0m\n' "$*"; }
b() { printf '\033[34m%s\033[0m\n' "$*"; }

# Adiciona .guardian ao .gitignore se ainda não estiver
if [ -f .gitignore ] && ! grep -q "^.guardian" .gitignore; then
  echo "" >> .gitignore
  echo "# dev-guardian outputs" >> .gitignore
  echo ".guardian/" >> .gitignore
fi

b "=== SAST (Semgrep) ==="
if command -v semgrep >/dev/null; then
  semgrep --config=auto --json --output="$OUT/sast.json" --quiet . || y "Semgrep retornou findings"
  g "✓ Semgrep: $OUT/sast.json"
elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  # Fallback: Semgrep não está no PATH mas há um daemon Docker — corre a imagem
  # oficial. --mount (em vez de -v) evita a ambiguidade da drive no Windows e
  # tolera espaços no caminho. Output vai para dentro do mount → fica no host.
  SEMGREP_IMAGE="${GUARDIAN_SEMGREP_IMAGE:-semgrep/semgrep}"
  y "Semgrep não instalado — a usar Docker ($SEMGREP_IMAGE)"
  docker run --rm --mount "type=bind,source=$(pwd),target=/src" -w /src "$SEMGREP_IMAGE" \
    semgrep --config=auto --json --output="/src/$OUT/sast.json" --quiet /src \
    || y "Semgrep (docker) retornou findings"
  if [ -s "$OUT/sast.json" ]; then
    g "✓ Semgrep (docker): $OUT/sast.json"
  else
    y "⚠️ Semgrep (docker) falhou — SAST NÃO correu (resultado não fiável)"
  fi
else
  y "⚠️ Semgrep não instalado e Docker indisponível — SAST SALTADO. '0 findings' NÃO é um resultado limpo."
fi

b "=== Secrets (gitleaks) ==="
if command -v gitleaks >/dev/null; then
  gitleaks detect --no-banner --report-format=json --report-path="$OUT/secrets.json" --redact || y "gitleaks encontrou secrets"
  g "✓ gitleaks: $OUT/secrets.json"
else
  y "gitleaks não instalado — skip"
fi

b "=== Dependencies (Trivy) ==="
if command -v trivy >/dev/null; then
  trivy fs --scanners vuln,license --format json --output "$OUT/deps.json" --quiet . || y "Trivy encontrou vulnerabilidades"
  g "✓ Trivy fs: $OUT/deps.json"

  if [ -f Dockerfile ]; then
    trivy config --format json --output "$OUT/dockerfile.json" Dockerfile || true
    g "✓ Trivy Dockerfile: $OUT/dockerfile.json"
  fi
else
  y "Trivy não instalado — skip"
fi

b "=== Bandit (Python SAST) ==="
if command -v bandit >/dev/null && find . -name "*.py" -not -path '*/\.*' | head -1 | grep -q .; then
  bandit -r . -f json -o "$OUT/bandit.json" -q 2>/dev/null || y "Bandit encontrou issues"
  g "✓ Bandit: $OUT/bandit.json"
fi

b "=== Sumário ==="
echo "Reports em: $OUT/"
ls -1 "$OUT/"
