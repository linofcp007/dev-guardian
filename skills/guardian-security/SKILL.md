---
name: guardian-security
description: Complete security scan using open-source tools (Semgrep, Trivy, gitleaks, OWASP ZAP). EN triggers — use when the user asks "guardian scan", "audit security", "check for vulnerabilities", "scan for secrets", "any security holes?", "SAST scan", "DAST scan", "check dependencies", "check the container", "check IaC", "is this safe?", "quick pen test", "I'm worried about security", or any request related to finding security problems before they reach production. PT triggers — usa quando pedirem "guardian scan", "audita segurança", "vê se há vulnerabilidades", "scan de secrets", "tem buracos de segurança?", "scan de SAST/DAST", "verifica deps", "verifica container", "verifica IaC", "vê se isto está safe", "pen test rápido", "preocupado com a segurança".
---

# Guardian Security

Scan profundo de segurança. Combina vários scanners open-source e contextualiza os resultados — ao contrário de correr ferramentas a cega, esta skill correlaciona findings, despromove falsos positivos óbvios e prioriza pelo risco real.

## Tipos de scan

A skill suporta quatro tipos. Pergunta ao utilizador qual (ou faz `--all` se ele disser "tudo"):

| Tipo                    | O que faz                                                        | Ferramenta                       |
| ----------------------- | ---------------------------------------------------------------- | -------------------------------- |
| **SAST**                | Análise estática de código aplicacional                          | Semgrep + bandit/brakeman/gosec |
| **Secrets**             | Procura API keys, tokens, passwords no código e histórico Git    | gitleaks                         |
| **Dependencies**        | CVEs em bibliotecas/packages                                     | Trivy                            |
| **Container/IaC**       | Dockerfile, imagens, Terraform, Kubernetes                       | Trivy + Checkov                  |
| **DAST** (opcional)     | Scan runtime contra app a correr                                 | OWASP ZAP (baseline)             |

## Fluxo

### 1. Pré-requisitos

Antes de scanar, garante que as ferramentas estão instaladas. Se não estiverem, sugere correr `guardian init` primeiro. Verifica com:

```bash
bash ${CLAUDE_PLUGIN_ROOT}/scripts/scan/check-tools.sh
```

### 2. Executar scans

Corre `bash ${CLAUDE_PLUGIN_ROOT}/scripts/scan/full-security-scan.sh <project-path>`. Este script orquestra todos os scanners e produz output JSON unificado em `.guardian/reports/security-<timestamp>.json`.

Internamente:

```bash
# SAST
semgrep --config=auto --json --output=.guardian/sast.json .

# Secrets (incluindo histórico Git)
gitleaks detect --no-banner --report-format=json --report-path=.guardian/secrets.json

# Dependências
trivy fs --scanners vuln,license --format json --output .guardian/deps.json .

# Container (se houver Dockerfile)
[ -f Dockerfile ] && trivy config --format json --output .guardian/dockerfile.json Dockerfile

# IaC (se houver)
trivy config --format json --output .guardian/iac.json .
```

### 3. Triagem inteligente

Não despeja apenas os resultados brutos — isso é ruído. Para cada finding:

1. **Classifica severidade** real (não confiar 100% no CVSS):
   - `🔴 Critical` — RCE/SQLi/secrets vivos em produção/auth bypass
   - `🟡 High` — XSS/CSRF/SSRF, CVEs com PoC público, deps com vulnerability sem patch
   - `🟢 Medium` — code smell com risco residual, secrets em ficheiros de teste/exemplo
   - `ℹ️ Low/Info` — best-practices, falsos positivos óbvios

2. **Despromove falsos positivos comuns**:
   - Secrets em `examples/`, `*test*`, `fixtures/`, `*.md` → Low (mas mencionar)
   - CVEs em deps `dev`/`test` → reduzir um nível
   - Regras Semgrep com má reputação de FP no contexto → contextualizar
   - `console.log` ou `print` com dados → Info, não High

3. **Correlaciona** findings de diferentes scanners. Se Semgrep encontra "use of crypto X" e Trivy diz que a biblioteca X tem CVE, isso é um único problema com mais peso, não dois.

### 4. Apresentar relatório

Sempre nesta estrutura, em ordem decrescente de prioridade:

```
# Relatório de Segurança — <projeto>
<data> · <duração> · <ficheiros analisados>

## 🔴 Crítico (N) — bloqueia deploy

### 1. Secret exposto: AWS Access Key
- Ficheiro: src/config/aws.js:14
- Detalhe: chave AKIA... commitada
- Está no histórico Git desde commit abc123 (3 dias)
- Ação imediata:
  1. Revoga a chave AGORA na AWS Console
  2. `git filter-repo --invert-paths --path src/config/aws.js`
  3. Move para variável de ambiente
  4. Considera-a comprometida — assume que terceiros já a viram

### 2. SQL Injection em search endpoint
- Ficheiro: app/routes/search.py:42
- Padrão: f-string com input de utilizador em query SQL
- Risco: extração total da DB
- Fix sugerido: usar parameterized queries (mostra o diff)

## 🟡 Alto (N) — corrigir antes de release

[...]

## 🟢 Médio (N) — backlog

[...resumido, agrupado por categoria...]

## ℹ️ Despromovidos como falsos positivos prováveis (N)
[expandir se utilizador pedir]
```

### 5. Oferecer fix automático

Para coisas óbvias e reversíveis, oferece aplicar:

- Bumping de versão de deps com patch disponível (`npm update`, `pip install -U`, etc.)
- Substituir `crypto.createCipher` → `crypto.createCipheriv` (com diff a mostrar antes)
- Mover secret para `.env` + `.env.example` + atualizar `.gitignore`

**Nunca aplicar sem perguntar.** Mostra sempre o diff e pergunta "aplicar este fix?".

Em casos de **emergência absoluta** (chave de produção viva exposta), interrompe a conversa e diz claramente:

```
⛔ STOP — Esta chave parece estar VIVA e em PRODUÇÃO.
Antes de mais nada, revoga-a já:
  → <link direto ao painel de revogação se conseguires inferir o provider>
Depois voltamos a configurar tudo.
```

## Modos paranoid

Se o utilizador pedir explicitamente "paranoid" ou "full deep":

- Inclui histórico Git completo no gitleaks (`gitleaks detect` sobre todo o histórico, não só staged)
- Corre regras Semgrep adicionais: `p/r2c-security-audit`, `p/cwe-top-25`, `p/insecure-transport`
- Lista também CVEs com CVSS ≥ 4.0 (em vez do default ≥ 7.0)
- Adiciona threat modeling rápido com STRIDE para os entry-points principais
- Inclui análise de licenças (GPL em projeto comercial, etc.)
- Sugere DAST com ZAP se a app for web

## DAST (OWASP ZAP)

Se o utilizador pedir scan runtime:

1. Pergunta o URL (staging, dev local, etc.)
2. Confirma que tem autorização (nunca scanar terceiros)
3. Corre `zap-baseline.py -t <url> -r .guardian/zap-report.html`
4. Resume os findings, prioriza, sugere fixes

## Quando não correr scans completos

- Em commits triviais (1-2 linhas): só hooks pre-commit chegam
- Em ramos experimentais/spike: avisar que pode ser ruído
- Em monorepos enormes: oferecer scan parcial (só o diff vs main)

## Output persistente

Todos os relatórios ficam em `.guardian/reports/` (cria a pasta se não existir; adiciona ao `.gitignore`). Útil para comparar evolução temporal e medir se a postura de segurança está a melhorar.
