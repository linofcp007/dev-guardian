#!/usr/bin/env bash
# initial-scan.sh — Scan inicial em modo "report only" depois do guardian init.
# Não falha em findings, só mostra o estado atual.
#
# Cada contagem vem do relatório que o scanner escreveu NESTA execução, num
# diretório temporário próprio. Um scanner que não escreveu relatório, ou que
# saiu com um código de erro, aparece como "falhou" — nunca como 0 findings.
# (O gitleaks sai com 1 quando encontra segredos; a versão anterior só contava
# depois de `gitleaks … &&`, e por isso mostrava sempre "0 findings".)

set -uo pipefail  # sem -e: não para em findings
PROJECT="${1:-.}"
cd "$PROJECT" || exit 1

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ocorrencias <ficheiro> <padrão>: quantas vezes o padrão aparece (o JSON do
# Semgrep vem numa só linha, por isso `grep -c` contaria 1).
ocorrencias() {
  grep -o "$2" "$1" 2>/dev/null | wc -l | tr -d ' '
}

# resultado <exit> <exits-ok> <ficheiro> <padrão> <sufixo>
resultado() {
  local rc="$1" oks="$2" file="$3" pattern="$4" suffix="$5"
  case " $oks " in
    *" $rc "*)
      if [ -s "$file" ]; then
        echo "$(ocorrencias "$file" "$pattern") $suffix"
        return
      fi
      echo "falhou (sem relatório, exit $rc) — corre /guardian-scan"
      return
      ;;
  esac
  echo "falhou (exit $rc) — corre /guardian-scan"
}

echo "Estado inicial do projeto:"
echo ""

if command -v gitleaks >/dev/null; then
  printf '  Secrets: '
  # Fora de um repositório git o gitleaks lê "0 commits" e diz que está limpo.
  NOGIT=""
  git rev-parse --is-inside-work-tree >/dev/null 2>&1 || NOGIT="--no-git"
  # shellcheck disable=SC2086 # NOGIT é vazio ou uma só flag
  gitleaks detect $NOGIT --no-banner --report-format=json --report-path="$TMP/gitleaks.json" --redact >/dev/null 2>&1
  resultado "$?" "0 1" "$TMP/gitleaks.json" '"RuleID"' "findings"
fi

if command -v trivy >/dev/null; then
  printf '  Vulnerabilidades de dependências: '
  # Nunca o trivy.yaml do projeto (--config vazio: um trivy.yaml commitado
  # decidia o que o scan reporta), e nunca o check.trivy.dev: a verificação
  # de versão com telemetria só se desliga com AS DUAS variáveis.
  : > "$TMP/trivy-config.yaml"
  TRIVY_SKIP_VERSION_CHECK=true TRIVY_DISABLE_TELEMETRY=true \
    trivy fs --config "$TMP/trivy-config.yaml" --scanners vuln --severity HIGH,CRITICAL --quiet --format json --output "$TMP/trivy.json" . >/dev/null 2>&1
  resultado "$?" "0" "$TMP/trivy.json" '"VulnerabilityID"' "HIGH/CRITICAL"
  # O .trivyignore do projeto continua a valer (riscos aceites), mas nunca em silêncio.
  # Aqui não se conta o que suprimiu (a contagem acima veria também os achados
  # suprimidos); o scan_deps conta-os e nomeia-os.
  [ -f .trivyignore ] && echo "    (honra o .trivyignore do projeto: os ids listados lá não são contados; o scan_deps diz quantos achados suprimiu, e quais)"
fi

if command -v semgrep >/dev/null; then
  printf '  SAST (Semgrep): '
  # Modo UTF-8 do Python: sem ele, um ficheiro com nome não-ASCII faz o
  # Semgrep sair com 2 sem relatório no Windows (mcp/src/runners/semgrepRun.ts).
  # E sem a verificação de versão, que contacta os servidores da Semgrep em
  # cada execução (como em todas as execuções do servidor MCP).
  PYTHONUTF8=1 SEMGREP_ENABLE_VERSION_CHECK=0 semgrep --config=auto --quiet --json --output="$TMP/semgrep.json" . >/dev/null 2>&1
  resultado "$?" "0 1" "$TMP/semgrep.json" '"check_id"' "findings"
fi

echo ""
echo "Para detalhe completo: guardian scan"
