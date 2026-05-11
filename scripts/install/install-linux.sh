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
has semgrep && g "✓ Semgrep $(semgrep --version 2>/dev/null)"

# Trivy
b "=== Trivy ==="
if ! has trivy; then
  if [ "$PKG" = "apt" ] && [ "$NO_SUDO" -eq 0 ]; then
    $SUDO apt-get install -y wget apt-transport-https gnupg lsb-release
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | $SUDO gpg --dearmor -o /usr/share/keyrings/trivy.gpg
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | $SUDO tee /etc/apt/sources.list.d/trivy.list
    $SUDO apt-get update -qq && $SUDO apt-get install -y trivy
  else
    # Binário portátil
    TRIVY_VERSION=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d 'v')
    ARCH_TAG=$(uname -m | sed 's/x86_64/64bit/;s/aarch64/ARM64/')
    curl -sL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${ARCH_TAG}.tar.gz" | tar -xz -C "$HOME/.local/bin" trivy
  fi
fi
has trivy && g "✓ Trivy $(trivy --version 2>/dev/null | head -1)"

# gitleaks
b "=== gitleaks ==="
if ! has gitleaks; then
  GL_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d 'v')
  ARCH_TAG=$(uname -m | sed 's/x86_64/x64/;s/aarch64/arm64/')
  curl -sL "https://github.com/gitleaks/gitleaks/releases/download/v${GL_VERSION}/gitleaks_${GL_VERSION}_linux_${ARCH_TAG}.tar.gz" | tar -xz -C "$HOME/.local/bin" gitleaks
  chmod +x "$HOME/.local/bin/gitleaks"
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

# Syft (SBOM)
b "=== Syft (SBOM) ==="
if ! has syft; then
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b "$HOME/.local/bin"
fi
has syft && g "✓ Syft"

# Node tools (jscpd, license-checker) — se Node estiver instalado
if has npm; then
  b "=== Node tools (npm global) ==="
  has jscpd || npm install -g jscpd >/dev/null 2>&1 || y "Falhou jscpd — instalar manualmente se precisares"
  has license-checker || npm install -g license-checker >/dev/null 2>&1 || true
  has jscpd && g "✓ jscpd"
fi

# OWASP ZAP (opcional, grande)
y "=== OWASP ZAP (DAST) — não instalado por defeito ==="
echo "  Se precisares: docker pull zaproxy/zap-stable"

# k6 (load testing — opcional)
y "=== k6 (load testing) — não instalado por defeito ==="
echo "  Se precisares: brew install k6 (macOS) ou ver https://k6.io/docs/getting-started/installation/"

echo ""
g "=== Instalação concluída ==="
echo "Ferramentas instaladas em /usr/local/bin (com sudo) ou ~/.local/bin (sem sudo)."
echo "Para validar: bash $(dirname "$0")/../scan/check-tools.sh"
