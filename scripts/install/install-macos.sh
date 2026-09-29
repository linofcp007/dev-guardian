#!/usr/bin/env bash
# install-macos.sh — Instala ferramentas dev-guardian em macOS via Homebrew
# (o Trivy a partir da sua release fixada, verificada pelo sha256).
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

# Instala uma ferramenta a partir do arquivo de uma release FIXADA, com o seu
# sha256 verificado ANTES de desempacotar — a mesma função do install-linux.sh,
# com o shasum do macOS. O Trivy vem por aqui e não pelo brew: o tap do
# fornecedor (aquasecurity/trivy) instala os binários do próprio fornecedor, que
# a revisão da 3.0 encontrou na 0.69.3, e foi pela "última release" que chegou o
# Trivy v0.69.4 malicioso a 2026-03-19. As versões, os arquivos e as somas são
# os de PINNED_RELEASES em mcp/src/runners/installCatalog.ts (um teste
# mantém-nos iguais). Cada passo falha por si: quem chama faz
# "instala_fixado … || r …", e dentro de uma função chamada assim o bash ignora
# o set -e.
# Uso: instala_fixado <nome> <url base> <arquivo amd64> <sha256 amd64> <arquivo arm64> <sha256 arm64>
instala_fixado() {
  local nome="$1" base="$2" asset sum tmp
  case "$(uname -m)" in
    x86_64|amd64) asset="$3"; sum="$4" ;;
    aarch64|arm64) asset="$5"; sum="$6" ;;
    *) echo "$nome: sem arquivo fixado para este CPU ($(uname -m))" >&2; return 1 ;;
  esac
  tmp="$(mktemp -d)" || return 1
  if curl -sSfL -o "$tmp/arquivo.tar.gz" "$base/$asset" \
    && echo "$sum  $tmp/arquivo.tar.gz" | shasum -a 256 -c - \
    && tar -xzf "$tmp/arquivo.tar.gz" -C "$tmp" "$nome" \
    && install -m 0755 "$tmp/$nome" "$HOME/.local/bin/$nome"; then
    rm -rf "$tmp"
    return 0
  fi
  rm -rf "$tmp"
  return 1
}

brew_install git
brew_install python
brew_install pipx
brew_install semgrep

# Trivy — a release fixada (ver instala_fixado), em ~/.local/bin.
b "=== Trivy (release fixada) ==="
mkdir -p "$HOME/.local/bin"
if ! has trivy && [ ! -x "$HOME/.local/bin/trivy" ]; then
  instala_fixado trivy "https://github.com/aquasecurity/trivy/releases/download/v0.74.0" \
    trivy_0.74.0_macOS-64bit.tar.gz 472816f6888dda689d075c30254d4210b4d1035acf365aa72332f584c2f60485 \
    trivy_0.74.0_macOS-ARM64.tar.gz 1caada5e0e2091909357c7525d3aa76f4b660b13821bc143b190c7483e31cc11 \
    || r "Falhou Trivy — instala a v0.74.0 à mão (https://github.com/aquasecurity/trivy/releases/tag/v0.74.0)"
fi
if [ -x "$HOME/.local/bin/trivy" ]; then
  g "✓ Trivy em $HOME/.local/bin/trivy"
  case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) y "  ~/.local/bin não está no PATH: o dev-guardian procura lá sozinho, mas o teu terminal não — acrescenta-o ao teu shell." ;;
  esac
elif has trivy; then
  g "✓ Trivy (já instalado)"
fi

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

# nuclei (DAST, opcional) — scanner ativo usado por scan_dast, não instalado por defeito
y "=== nuclei (DAST) — não instalado por defeito ==="
echo "  Se precisares: brew install nuclei (ou usa a tool MCP install_toolchain)"

echo ""
g "=== Instalação concluída ==="
