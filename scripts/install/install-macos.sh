#!/usr/bin/env bash
# install-macos.sh — Instala ferramentas dev-guardian em macOS via Homebrew.
# Uso: bash install-macos.sh

set -euo pipefail

g() { printf '\033[32m%s\033[0m\n' "$*"; }
y() { printf '\033[33m%s\033[0m\n' "$*"; }
r() { printf '\033[31m%s\033[0m\n' "$*"; }
b() { printf '\033[34m%s\033[0m\n' "$*"; }
has() { command -v "$1" > /dev/null 2>&1; }

# Garante Homebrew
if ! has brew; then
  b "Instalando Homebrew..."
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  # Apple Silicon
  if [ -d /opt/homebrew/bin ]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
  fi
fi
g "✓ Homebrew"

# Tools via brew
b "=== Instalando ferramentas via brew ==="
brew_install() {
  local pkg="$1"
  if brew list "$pkg" >/dev/null 2>&1; then
    g "✓ $pkg (já instalado)"
  else
    brew install "$pkg" && g "✓ $pkg"
  fi
}

brew_install git
brew_install python
brew_install pipx
brew_install semgrep
brew_install trivy
brew_install gitleaks
brew_install pre-commit
brew_install ruff
brew_install syft
brew_install node
brew_install k6

# Bandit via pipx (Python SAST)
if ! has bandit; then pipx install bandit; fi
has bandit && g "✓ bandit"

# jscpd via npm
has jscpd || npm install -g jscpd >/dev/null 2>&1
has jscpd && g "✓ jscpd"

# nuclei (DAST, opcional) — active scanner used by scan_dast, not installed by default
y "=== nuclei (DAST) — não instalado por defeito ==="
echo "  Se precisares: brew install nuclei (ou usa a tool MCP install_toolchain)"

echo ""
g "=== Instalação concluída ==="
