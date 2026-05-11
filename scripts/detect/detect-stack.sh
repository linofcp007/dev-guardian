#!/usr/bin/env bash
# detect-stack.sh — Identifica linguagens, package managers, frameworks e ferramentas existentes.
# Output: JSON em stdout.
# Uso: bash detect-stack.sh [project-path]

set -euo pipefail

PROJECT="${1:-.}"
cd "$PROJECT"

has_file() { [ -f "$1" ] && echo true || echo false; }
has_glob() { compgen -G "$1" > /dev/null && echo true || echo false; }
has_dir() { [ -d "$1" ] && echo true || echo false; }

# OS detection
detect_os() {
  case "$(uname -s)" in
    Linux*)
      if grep -qi microsoft /proc/version 2>/dev/null; then echo "wsl"
      elif [ -f /etc/debian_version ]; then echo "debian"
      elif [ -f /etc/redhat-release ]; then echo "rhel"
      elif [ -f /etc/arch-release ]; then echo "arch"
      else echo "linux"; fi
      ;;
    Darwin*) echo "macos" ;;
    CYGWIN*|MINGW*|MSYS*) echo "windows" ;;
    *) echo "unknown" ;;
  esac
}

OS=$(detect_os)
ARCH=$(uname -m)

# Languages and package managers
LANGUAGES=()
PKG_MANAGERS=()
FRAMEWORKS=()

# JS/TS
if [ -f package.json ]; then
  LANGUAGES+=("javascript")
  if [ -f tsconfig.json ] || ls *.ts 2>/dev/null | head -1 > /dev/null; then
    LANGUAGES+=("typescript")
  fi
  if [ -f pnpm-lock.yaml ]; then PKG_MANAGERS+=("pnpm")
  elif [ -f yarn.lock ]; then PKG_MANAGERS+=("yarn")
  elif [ -f bun.lockb ] || [ -f bun.lock ]; then PKG_MANAGERS+=("bun")
  else PKG_MANAGERS+=("npm"); fi

  # Framework detection
  grep -q '"react"' package.json 2>/dev/null && FRAMEWORKS+=("react")
  grep -q '"next"' package.json 2>/dev/null && FRAMEWORKS+=("nextjs")
  grep -q '"vue"' package.json 2>/dev/null && FRAMEWORKS+=("vue")
  grep -q '"@angular' package.json 2>/dev/null && FRAMEWORKS+=("angular")
  grep -q '"svelte"' package.json 2>/dev/null && FRAMEWORKS+=("svelte")
  grep -q '"express"' package.json 2>/dev/null && FRAMEWORKS+=("express")
  grep -q '"fastify"' package.json 2>/dev/null && FRAMEWORKS+=("fastify")
  grep -q '"@nestjs' package.json 2>/dev/null && FRAMEWORKS+=("nestjs")
  grep -q '"astro"' package.json 2>/dev/null && FRAMEWORKS+=("astro")
fi

# Python
if [ -f pyproject.toml ] || [ -f requirements.txt ] || [ -f Pipfile ] || [ -f setup.py ] || [ -f setup.cfg ]; then
  LANGUAGES+=("python")
  if [ -f poetry.lock ]; then PKG_MANAGERS+=("poetry")
  elif [ -f uv.lock ]; then PKG_MANAGERS+=("uv")
  elif [ -f Pipfile.lock ]; then PKG_MANAGERS+=("pipenv")
  else PKG_MANAGERS+=("pip"); fi

  grep -q "django" requirements*.txt pyproject.toml 2>/dev/null && FRAMEWORKS+=("django")
  grep -q "flask" requirements*.txt pyproject.toml 2>/dev/null && FRAMEWORKS+=("flask")
  grep -q "fastapi" requirements*.txt pyproject.toml 2>/dev/null && FRAMEWORKS+=("fastapi")
fi

# PHP
if [ -f composer.json ]; then
  LANGUAGES+=("php")
  PKG_MANAGERS+=("composer")
  [ -f wp-config.php ] || [ -f wp-config-sample.php ] && FRAMEWORKS+=("wordpress")
  grep -q "laravel/framework" composer.json 2>/dev/null && FRAMEWORKS+=("laravel")
  grep -q "symfony/" composer.json 2>/dev/null && FRAMEWORKS+=("symfony")
  # Kadence (WordPress)
  [ -d wp-content/themes/kadence ] || [ -d wp-content/plugins/kadence-blocks ] && FRAMEWORKS+=("kadence")
fi

# Go
[ -f go.mod ] && { LANGUAGES+=("go"); PKG_MANAGERS+=("gomod"); }

# Rust
[ -f Cargo.toml ] && { LANGUAGES+=("rust"); PKG_MANAGERS+=("cargo"); }

# Ruby
[ -f Gemfile ] && { LANGUAGES+=("ruby"); PKG_MANAGERS+=("bundler"); }

# Java/Kotlin
[ -f pom.xml ] && { LANGUAGES+=("java"); PKG_MANAGERS+=("maven"); }
[ -f build.gradle ] || [ -f build.gradle.kts ] && { LANGUAGES+=("java"); PKG_MANAGERS+=("gradle"); }

# Docker
HAS_DOCKER=$(has_file Dockerfile)
HAS_COMPOSE=$([ -f docker-compose.yml ] || [ -f compose.yml ] || [ -f docker-compose.yaml ] && echo true || echo false)

# IaC
HAS_TERRAFORM=$(has_glob "*.tf")
HAS_KUBERNETES=$([ -d k8s ] || [ -d kubernetes ] || has_glob "*.yaml" && grep -lq "apiVersion: " *.yaml 2>/dev/null && echo true || echo false)
HAS_ANSIBLE=$([ -d roles ] || [ -f ansible.cfg ] && echo true || echo false)

# CI
HAS_GHA=$(has_dir .github/workflows)
HAS_GITLAB_CI=$(has_file .gitlab-ci.yml)

# Existing tools
EXISTING=()
[ -f .semgrep.yml ] || [ -f .semgrep/semgrep.yml ] && EXISTING+=("semgrep")
[ -f .gitleaks.toml ] && EXISTING+=("gitleaks")
[ -f .trivyignore ] && EXISTING+=("trivy")
[ -f renovate.json ] || [ -f .renovaterc ] || [ -f .renovaterc.json ] && EXISTING+=("renovate")
[ -f .github/dependabot.yml ] && EXISTING+=("dependabot")
[ -f .pre-commit-config.yaml ] && EXISTING+=("pre-commit")
[ -f .eslintrc ] || [ -f .eslintrc.json ] || [ -f eslint.config.js ] && EXISTING+=("eslint")
[ -f .prettierrc ] || [ -f .prettierrc.json ] && EXISTING+=("prettier")
[ -f ruff.toml ] || grep -q "\[tool.ruff\]" pyproject.toml 2>/dev/null && EXISTING+=("ruff")
[ -f playwright.config.ts ] || [ -f playwright.config.js ] && EXISTING+=("playwright")
[ -f vitest.config.ts ] || [ -f vitest.config.js ] && EXISTING+=("vitest")
[ -f jest.config.js ] || [ -f jest.config.ts ] && EXISTING+=("jest")
[ -f pytest.ini ] || grep -q "\[tool.pytest" pyproject.toml 2>/dev/null && EXISTING+=("pytest")

# Build JSON array helper
json_array() {
  local arr=("$@")
  if [ ${#arr[@]} -eq 0 ]; then
    echo "[]"
  else
    printf '['
    for i in "${!arr[@]}"; do
      [ "$i" -gt 0 ] && printf ','
      printf '"%s"' "${arr[$i]}"
    done
    printf ']'
  fi
}

cat <<EOF
{
  "os": "$OS",
  "arch": "$ARCH",
  "languages": $(json_array "${LANGUAGES[@]}"),
  "package_managers": $(json_array "${PKG_MANAGERS[@]}"),
  "frameworks": $(json_array "${FRAMEWORKS[@]}"),
  "existing_tools": $(json_array "${EXISTING[@]}"),
  "has_docker": $HAS_DOCKER,
  "has_compose": $HAS_COMPOSE,
  "has_terraform": $HAS_TERRAFORM,
  "has_kubernetes": $HAS_KUBERNETES,
  "has_ansible": $HAS_ANSIBLE,
  "has_github_actions": $HAS_GHA,
  "has_gitlab_ci": $HAS_GITLAB_CI
}
EOF
