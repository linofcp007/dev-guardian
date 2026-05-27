---
name: guardian
description: Main security, bugfix and code-quality router using open-source tools (Semgrep, Trivy, gitleaks, Renovate, OWASP ZAP, Playwright). Routes to specialized Guardian modules. Use whenever the user asks to initialize/protect/audit a project, configure security, scan vulnerabilities or secrets, review code before PR/commit/deploy, find bugs, improve quality, update dependencies, configure observability — or says "is this safe?", "any bugs?", "audit the project", "guardian init/scan/fix/review/audit", "before deploy/merge", "any secrets?". ALSO use for workflow moments — when the user says "before push", "about to push", "before deploy", "before release", "ship it", "just ran npm/pip/composer install", "I pulled main", "merged a PR", "weird behaviour in prod", "production blew up", "incident", "something is broken in prod", "leaked secret", "we exposed a key", "going to rollback", "is rollback safe?", "going on holiday hand off", "project health", "how is the project?", "trend", "tech debt", "what's our debt?", "are we within budget?", "generate report", "executive summary", "SOC 2 evidence", "changelog since last release", "what changed since v1.2", "scan this file", "scan this diff", "scan this branch" — route to the right module (guardian-prepush / predeploy / prerelease / handoff / postinstall / incoming / postfix / diff / file / branch / since / panic / leak / rollback / postmortem / wp / dotnet / docker / iac / llm / status / trend / debt / budget / report / soc2 / changelog). ALSO use for generic holistic checks when the user says "do a full checkup", "full project checkup", "check for errors", "check for issues", "check for problems", "diagnose this project", "tell me what's broken", "what's wrong with this code", "check everything", "health check", "is this project healthy?". Usa também quando pedirem em PT para "auditar o projeto", "verificar vulnerabilidades", "proteger o repo", "está seguro?", "tem bugs?", "antes de deploy/merge", "tem secrets?", "atualizar dependências", "faz um checkup", "checkup completo", "verifica por erros", "verifica por problemas", "vê o que está mal", "diagnóstico do projeto", "diz-me o que está mal", "verifica tudo", "o que pode estar partido?", "este projeto está saudável?", "antes de push/deploy/release", "vou fazer push", "vou em férias", "passa o projeto", "acabei de instalar deps", "puxei main", "rebentou em produção", "pânico", "incident", "vazou secret", "expusemos uma chave", "vou fazer rollback", "é seguro fazer rollback?", "estado do projeto", "tendência de findings", "qual é a dívida técnica?", "estou dentro do budget?", "gera relatório", "relatório executivo", "evidence SOC 2", "changelog desde a última release", "scan deste ficheiro", "scan do diff", "scan da branch", "audita o WordPress", "audita o .NET", "vê o Dockerfile", "vê o terraform", "tenho features de AI". Úsala también cuando pidan en ES "auditar el proyecto", "comprobar vulnerabilidades", "proteger el repo", "¿es seguro?", "¿tiene bugs?", "antes del despliegue/merge", "¿hay secretos?", "actualizar dependencias", "haz un chequeo", "chequeo completo", "diagnóstico del proyecto", "comprueba si hay errores", "comprueba si hay problemas", "dime qué está mal", "verifica todo", "¿qué puede estar roto?", "¿este proyecto está sano?", "antes del push/despliegue/release", "voy a hacer push", "me voy de vacaciones", "pasa el proyecto", "acabo de instalar deps", "tiré de main", "se cayó producción", "pánico", "incidente", "se filtró un secreto", "expusimos una clave", "voy a hacer rollback", "¿es seguro hacer rollback?", "estado del proyecto", "tendencia de findings", "¿cuál es la deuda técnica?", "¿estoy dentro del presupuesto?", "genera informe", "informe ejecutivo", "evidencia SOC 2", "changelog desde el último release", "escaneo de este archivo", "escaneo del diff", "escaneo de la rama", "audita el WordPress", "audita el .NET", "revisa el Dockerfile", "revisa el terraform", "tengo features de AI". Trilingual EN/PT/ES. Stack-aware (Node/Python/PHP/Go/Rust/Ruby/Java/.NET). Pragmatic by default, paranoid when critical. Always respond in the user's language.
---

# Guardian — Security, Bugfix & Quality

Skill principal de proteção e qualidade de código. Faz routing para um de vários modos especializados conforme o que o utilizador precisa, usando exclusivamente ferramentas open-source (Semgrep, Trivy, gitleaks, Renovate, OWASP ZAP, Playwright, etc.).

## Idioma da resposta

O Guardian opera em **EN, PT e ES**. Detecta o idioma da última mensagem do utilizador e responde sempre nesse idioma:

- Utilizador escreve em inglês → responde em inglês.
- Utilizador escreve em português → responde em português.
- Utilizador escreve en español → responde en español.

Termos técnicos universais (SAST, CVE, RCE, CI/CD, secrets, supply chain, etc.) mantêm-se em inglês mesmo em respostas PT/ES. Se o utilizador troca de idioma a meio da conversa, troca tu também. Em caso de mistura ambígua, segue o idioma da última instrução clara.

Os módulos especializados (`guardian-security`, `guardian-bugfix`, etc.) herdam esta regra — quando os invocares, mantém o idioma do utilizador.

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
| `guardian audit`, "relatório completo"             | `guardian-audit` (combo)        | Combina security + quality + deps               |

### Comandos adicionais (workflow moments)

|Comando|Routes / faz|
|---|---|
|`/guardian-prepush`|Scan rápido do diff + secrets check antes de `git push`|
|`/guardian-predeploy`|Gate completo antes de deploy (audit + env + compliance + CI)|
|`/guardian-prerelease`|Release readiness — changelog, SBOM diff, version bump|
|`/guardian-handoff`|Snapshot de handoff (debt + pendências + próximas ações)|
|`/guardian-postinstall`|Vet do que entrou após `npm/pip/composer install`|
|`/guardian-incoming`|Inspecciona código que outros mergearam ou que veio via pull|
|`/guardian-postfix`|Valida correção + regression-check da categoria|
|`/guardian-diff`|Scan rápido só do diff atual (staged + unstaged)|
|`/guardian-file`|Scan deep de um único ficheiro / pasta|
|`/guardian-branch`|Diff da branch atual contra main|
|`/guardian-since <ref>`|O que mudou desde tag/SHA/data|
|`/guardian-panic`|Modo triagem após incident em produção|
|`/guardian-leak`|Resposta a fuga de secrets — history scan + rotation checklist|
|`/guardian-rollback`|Decide se um rollback é seguro (DB migrations, schema, etc.)|
|`/guardian-postmortem`|Template estruturado de post-incident analysis|
|`/guardian-wp`|Audit focado em WordPress|
|`/guardian-dotnet`|Audit focado em C# / .NET|
|`/guardian-docker`|Audit focado em containers / Dockerfile|
|`/guardian-iac`|Audit focado em Terraform / Kubernetes / Ansible|
|`/guardian-llm`|Audit focado em features de AI / LLM (prompt injection, eval, custo)|
|`/guardian-status`|Dashboard do projeto (último scan, deltas, baseline, supressões)|
|`/guardian-trend`|Tendência de findings ao longo do tempo|
|`/guardian-debt`|Dívida técnica consolidada + top hotspots por ROI|
|`/guardian-budget`|Está dentro dos budgets de performance / custo / complexidade?|
|`/guardian-report`|Relatório markdown/PDF para stakeholders não-técnicos|
|`/guardian-soc2`|Evidence pack para auditoria SOC 2 / ISO 27001|
|`/guardian-changelog`|Gera changelog estruturado desde uma referência|
|`/g`, `/gs`, `/gf`, `/gr`, `/gq`|Atalhos curtos para `/guardian`, `/guardian-scan`, `/guardian-fix`, `/guardian-review`, `/guardian-quality`|

**Pedidos genéricos / checkup (catch-all).** Frases como *"faz um checkup completo"*, *"checkup"*, *"diagnóstico do projeto"*, *"verifica tudo"*, *"verifica por erros"*, *"verifica por problemas"*, *"vê o que está mal"*, *"diz-me o que está mal"*, *"o que pode estar partido?"*, *"este projeto está saudável?"* (e equivalentes EN: *"do a full checkup"*, *"check for errors/issues/problems"*, *"diagnose this project"*, *"tell me what's broken"*, *"is this project healthy?"*) devem ser tratadas como uma verificação holística: corre `guardian-security` + `guardian-bugfix` + `guardian-quality` + `guardian-deps` em sequência e apresenta um relatório consolidado (idêntico ao `guardian audit`, mas a incluir bugfix).

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
| Error tracking                 | GlitchTip                  | Sentry self-hosted         |
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
