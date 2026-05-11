---
name: guardian
description: Main security, bugfix and code-quality router using open-source tools (Semgrep, Trivy, gitleaks, Renovate, OWASP ZAP, Playwright). Routes to specialized Guardian modules. Use whenever the user asks to initialize/protect/audit a project, configure security, scan vulnerabilities or secrets, review code before PR/commit/deploy, find bugs, improve quality, update dependencies, configure observability — or says "is this safe?", "any bugs?", "audit the project", "guardian init/scan/fix/review/audit", "before deploy/merge", "any secrets?". Usa também quando pedirem em PT para "auditar o projeto", "verificar vulnerabilidades", "proteger o repo", "está seguro?", "tem bugs?", "antes de deploy/merge", "tem secrets?", "atualizar dependências". Bilingual EN/PT. Stack-aware (Node/Python/PHP/Go/Rust/Ruby/Java). Pragmatic by default, paranoid when critical.
---

# Guardian — Security, Bugfix & Quality

Skill principal de proteção e qualidade de código. Faz routing para um de vários modos especializados conforme o que o utilizador precisa, usando exclusivamente ferramentas open-source (Semgrep, Trivy, gitleaks, Renovate, OWASP ZAP, Playwright, etc.).

## Filosofia

**Pragmático por defeito, paranoid quando crítico.**

- Não bloqueia trabalho por coisas cosméticas
- Alerta com clareza quando algo é genuinamente perigoso (secrets, RCE, SQL injection, supply chain, breaking de produção)
- Tenta fixar automaticamente o que dá; o resto reporta com prioridade clara
- Explica o porquê — o utilizador deve sair a perceber, não só a obedecer

## Comandos suportados

O utilizador pode invocar o Guardian de várias formas. Encaminha para o módulo certo:

| Invocação                                          | Módulo                          | Quando usar                                     |
| -------------------------------------------------- | ------------------------------- | ----------------------------------------------- |
| `guardian init`, "inicializa", "configura"         | `guardian-init`                 | Primeira vez num projeto                        |
| `guardian scan`, "audita", "vê se está seguro"     | `guardian-security`             | Scan completo de segurança                      |
| `guardian fix`, "corrige bugs", "fix automático"   | `guardian-bugfix`               | Encontrar e corrigir bugs                       |
| `guardian quality`, "qualidade", "tech debt"       | `guardian-quality`              | Code smells, dívida técnica                     |
| `guardian review`, "antes de PR", "antes de merge" | `guardian-review`               | Revisão profunda pré-PR/pré-deploy              |
| `guardian deps`, "atualiza dependências"           | `guardian-deps`                 | Renovate, vulnerabilidades de dependências      |
| `guardian observe`, "logs", "monitoring"           | `guardian-observability`        | Configurar logging, métricas, error tracking    |
| `guardian perf`, "performance", "load test"        | `guardian-performance`          | Performance budgets, testes de carga            |
| `guardian compliance`, "GDPR", "licenças"          | `guardian-compliance`           | Compliance, licenças, SBOM, privacy             |
| `guardian audit`, "relatório completo"             | Combina security + quality + deps | Relatório executivo                           |

Se o utilizador não diz explicitamente que modo quer, infere a partir do contexto. Em caso de ambiguidade, pergunta de forma curta — não assumas silenciosamente.

## Fluxo geral

1. **Detectar o stack** primeiro (sempre). Corre `bash ${CLAUDE_PLUGIN_ROOT}/scripts/detect/detect-stack.sh` no projeto. Isto identifica linguagens, package managers, frameworks e ferramentas já presentes. Sem isto, qualquer recomendação é genérica e potencialmente errada.

2. **Verificar o que já está configurado.** Não duplicar trabalho. Se já existe `.semgrep.yml`, `.gitleaks.toml`, `renovate.json`, `dependabot.yml`, `.pre-commit-config.yaml`, lê primeiro e respeita o que está lá.

3. **Routar para o módulo certo** com base na invocação (tabela acima).

4. **Reportar com priorização clara.** Os relatórios seguem sempre esta estrutura:
   - 🔴 **Crítico** — bloqueia deploy/merge (RCE, secrets expostos, SQL injection, vulnerabilidades exploráveis ativas)
   - 🟡 **Alto** — corrigir antes de release (XSS, CSRF, deps com CVE médio)
   - 🟢 **Médio/Baixo** — backlog (linting, code smells, refactors)
   - ℹ️ **Info** — observações úteis, não-acionáveis

5. **Oferecer fix sempre que possível.** Se podes corrigir tu próprio (bumping de versão, regex óbvio), pergunta antes de aplicar — exceto em modo emergência (secrets vivos no histórico, por exemplo, onde deves alertar imediatamente).

## Stacks suportadas

A detecção e instalação cobrem:

- **JavaScript/TypeScript** — npm, yarn, pnpm, bun (Node, Deno)
- **Python** — pip, poetry, uv, conda
- **PHP** — composer (inclui WordPress + Kadence)
- **Go** — go modules
- **Rust** — cargo
- **Ruby** — bundler
- **Java/Kotlin** — maven, gradle
- **Docker** — Dockerfile, docker-compose
- **IaC** — Terraform, Ansible, Kubernetes manifests
- **GitHub Actions** workflows

A skill consegue lidar com projetos polyglot (vários ao mesmo tempo).

## Ferramentas open-source usadas

| Categoria                      | Ferramenta principal       | Alternativa                |
| ------------------------------ | -------------------------- | -------------------------- |
| SAST (análise estática)        | Semgrep                    | SonarQube CE               |
| Scanning de dependências/CVEs  | Trivy                      | OWASP Dependency-Check     |
| Scanning de secrets            | gitleaks                   | TruffleHog                 |
| Containers/IaC                 | Trivy (mesma ferramenta)   | Checkov                    |
| Atualização de dependências    | Renovate                   | Dependabot (built-in)      |
| DAST (runtime)                 | OWASP ZAP                  | Nuclei                     |
| E2E testing                    | Playwright                 | Cypress                    |
| Load testing                   | k6                         | Artillery                  |
| SBOM                           | Syft                       | CycloneDX CLI              |
| Error tracking                 | GlitchTip / Sentry self-hosted | —                      |
| Metrics                        | Prometheus + Grafana       | —                          |

Detalhes de instalação em `scripts/install/`.

## Cross-platform

A skill funciona em Linux (Ubuntu/Debian principalmente), macOS (Intel e Apple Silicon) e Windows com WSL2. Os scripts detectam o OS e usam o package manager certo (`apt`, `brew`, `choco`/WSL).

## Quando NÃO usar esta skill

- Tarefas puramente conversacionais ou de design (sem código a inspecionar)
- Projetos que ainda não existem (primeiro escreve algo, depois corre `guardian init`)
- Quando o utilizador só pediu "lê este ficheiro" ou "explica este código" — isso não justifica scans completos

## Módulos disponíveis

Cada modo tem a sua própria skill com instruções detalhadas:

- `guardian-init` — bootstrap inicial de um projeto
- `guardian-security` — scans de segurança (SAST, secrets, deps)
- `guardian-bugfix` — encontrar e corrigir bugs
- `guardian-quality` — qualidade e dívida técnica
- `guardian-review` — revisão pré-PR/deploy
- `guardian-deps` — gestão de dependências
- `guardian-observability` — logs, métricas, alerting
- `guardian-performance` — performance budgets e load testing
- `guardian-compliance` — GDPR, licenças, SBOM

Carrega a skill correspondente quando precisares da lógica detalhada.
