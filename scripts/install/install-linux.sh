#!/usr/bin/env bash
# install-linux.sh — Instala todas as ferramentas open-source do dev-guardian em Linux.
# Suporta: Debian/Ubuntu, Fedora/RHEL, Arch. Idempotente — não duplica instalações.
# Uso: bash install-linux.sh [--no-sudo]

set -euo pipefail

NO_SUDO=0
[[ "${1:-}" == "--no-sudo" ]] && NO_SUDO=1

# Cor de output
g() { printf '\033[32m%s\033[0m\n' "$*"; }
y() { printf '\033[33m%s\033[0m\n' "$*"; }
r() { printf '\033[31m%s\033[0m\n' "$*"; }
b() { printf '\033[34m%s\033[0m\n' "$*"; }

# Verifica se um comando existe
has() { command -v "$1" > /dev/null 2>&1; }

# Detecta package manager do sistema
if has apt-get; then PKG=apt
elif has dnf; then PKG=dnf
elif has yum; then PKG=yum
elif has pacman; then PKG=pacman
else r "Package manager não reconhecido. Continuando com binários portáteis."; PKG=none
fi

SUDO=""
if [ "$NO_SUDO" -eq 0 ] && [ "$(id -u)" -ne 0 ] && has sudo; then
  SUDO=sudo
fi

# Instala pacote do sistema (com fallback para "sem sudo")
sys_install() {
  local pkg="$1"
  if [ "$PKG" = "none" ] || [ "$NO_SUDO" -eq 1 ]; then
    y "Skip apt install para $pkg (modo no-sudo). Usar fallback."
    return 1
  fi
  case "$PKG" in
    apt) $SUDO apt-get update -qq && $SUDO apt-get install -y "$pkg" ;;
    dnf|yum) $SUDO "$PKG" install -y "$pkg" ;;
    pacman) $SUDO pacman -Sy --noconfirm "$pkg" ;;
  esac
}

# Garante ~/.local/bin no PATH (para binários portáteis sem sudo)
ensure_local_bin() {
  mkdir -p "$HOME/.local/bin"
  case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *)
      y "Adicionando ~/.local/bin ao PATH (em ~/.bashrc)"
      echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
      export PATH="$HOME/.local/bin:$PATH"
      ;;
  esac
}

# Instala uma ferramenta a partir do arquivo de uma release FIXADA, com o seu
# sha256 verificado ANTES de desempacotar — nunca "a mais recente": foi por
# esse caminho (a última release do GitHub, o repositório apt, um install.sh
# do ramo principal) que chegou o Trivy v0.69.4 malicioso a 2026-03-19. As versões,
# os arquivos e as somas são os de PINNED_RELEASES em
# mcp/src/runners/installCatalog.ts (um teste mantém-nos iguais).
# Cada passo falha por si: quem chama faz "instala_fixado … || r …", e dentro
# de uma função chamada assim o bash ignora o set -e.
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
    && echo "$sum  $tmp/arquivo.tar.gz" | sha256sum -c - \
    && tar -xzf "$tmp/arquivo.tar.gz" -C "$tmp" "$nome" \
    && install -m 0755 "$tmp/$nome" "$HOME/.local/bin/$nome"; then
    rm -rf "$tmp"
    return 0
  fi
  rm -rf "$tmp"
  return 1
}

# Dependências básicas
b "=== Verificar dependências básicas ==="
for dep in curl git python3; do
  if ! has "$dep"; then
    y "Instalando $dep..."
    sys_install "$dep" || r "Falhou — instala $dep manualmente"
  else
    g "✓ $dep"
  fi
done

ensure_local_bin

# pipx (gestor de Python apps em isolamento)
b "=== pipx ==="
if ! has pipx; then
  if has python3; then
    python3 -m pip install --user pipx --break-system-packages 2>/dev/null || python3 -m pip install --user pipx
    python3 -m pipx ensurepath || true
    export PATH="$HOME/.local/bin:$PATH"
  fi
fi
has pipx && g "✓ pipx" || y "pipx não disponível — algumas ferramentas Python vão ser instaladas com pip --user"

# Semgrep
b "=== Semgrep ==="
if ! has semgrep; then
  if has pipx; then pipx install semgrep; else python3 -m pip install --user semgrep --break-system-packages 2>/dev/null || python3 -m pip install --user semgrep; fi
fi
has semgrep && g "✓ Semgrep $(SEMGREP_ENABLE_VERSION_CHECK=0 semgrep --version 2>/dev/null)"

# Trivy — a release fixada (TRIVY_INSTALL_TAG), com ou sem sudo: o
# repositório apt da Aqua serve sempre a mais recente.
b "=== Trivy ==="
if ! has trivy; then
  instala_fixado trivy "https://github.com/aquasecurity/trivy/releases/download/v0.74.0" \
    trivy_0.74.0_Linux-64bit.tar.gz 2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a \
    trivy_0.74.0_Linux-ARM64.tar.gz b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5 \
    || r "Falhou Trivy — instala a v0.74.0 à mão (https://github.com/aquasecurity/trivy/releases/tag/v0.74.0)"
fi
has trivy && g "✓ Trivy $(TRIVY_SKIP_VERSION_CHECK=true TRIVY_DISABLE_TELEMETRY=true trivy --version 2>/dev/null | head -1)"

# gitleaks
b "=== gitleaks ==="
if ! has gitleaks; then
  instala_fixado gitleaks "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1" \
    gitleaks_8.30.1_linux_x64.tar.gz 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb \
    gitleaks_8.30.1_linux_arm64.tar.gz e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080 \
    || r "Falhou gitleaks — instala a v8.30.1 à mão (https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1)"
fi
has gitleaks && g "✓ gitleaks $(gitleaks version 2>/dev/null)"

# pre-commit
b "=== pre-commit ==="
if ! has pre-commit; then
  if has pipx; then pipx install pre-commit; else python3 -m pip install --user pre-commit --break-system-packages 2>/dev/null || python3 -m pip install --user pre-commit; fi
fi
has pre-commit && g "✓ pre-commit"

# ruff (Python)
b "=== ruff ==="
if ! has ruff; then
  if has pipx; then pipx install ruff; else python3 -m pip install --user ruff --break-system-packages 2>/dev/null || python3 -m pip install --user ruff; fi
fi
has ruff && g "✓ ruff"

# bandit (Python SAST)
if ! has bandit; then
  if has pipx; then pipx install bandit; else python3 -m pip install --user bandit --break-system-packages 2>/dev/null || python3 -m pip install --user bandit; fi
fi
has bandit && g "✓ bandit"

# Syft (SBOM) — a release fixada, nunca o install.sh do ramo principal.
b "=== Syft (SBOM) ==="
if ! has syft; then
  instala_fixado syft "https://github.com/anchore/syft/releases/download/v1.52.0" \
    syft_1.52.0_linux_amd64.tar.gz caeedb81fb0491615f1ebd1761e4145d41ee86dd2cc7bf80669f9f5ad9d6133d \
    syft_1.52.0_linux_arm64.tar.gz c46d5e4c28e12aa4c5becfaa343ef1c7f89045b6b895f2c21d471c62db09c706 \
    || r "Falhou Syft — instala a v1.52.0 à mão (https://github.com/anchore/syft/releases/tag/v1.52.0)"
fi
has syft && g "✓ Syft"

# Node tools (jscpd, license-checker) — se Node estiver instalado
if has npm; then
  b "=== Node tools (npm global) ==="
  has jscpd || npm install -g jscpd >/dev/null 2>&1 || y "Falhou jscpd — instalar manualmente se precisares"
  has license-checker || npm install -g license-checker >/dev/null 2>&1 || true
  has jscpd && g "✓ jscpd"
fi

# nuclei (opcional, scanner ativo usado por scan_dast)
y "=== nuclei (DAST) — não instalado por defeito ==="
echo "  Sem instalação automática no Linux — ver https://docs.projectdiscovery.io/opensource/nuclei/install (install_toolchain confirma o mesmo)"

# k6 (load testing — opcional)
y "=== k6 (load testing) — não instalado por defeito ==="
echo "  Se precisares: brew install k6 (macOS) ou ver https://k6.io/docs/getting-started/installation/"

echo ""
g "=== Instalação concluída ==="
echo "Ferramentas instaladas em /usr/local/bin (com sudo) ou ~/.local/bin (sem sudo)."
echo "Para validar: corre a ferramenta MCP check_toolchain do dev-guardian."
