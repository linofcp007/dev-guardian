---
name: guardian
description: Guardian router — picks the right dev-guardian command or skill for security, bugs, code quality, dependencies, compliance, performance and observability, all backed by the dev-guardian MCP tools and open-source scanners (Semgrep, Trivy, gitleaks). Use for a holistic checkup or when it is unclear which module fits. EN triggers — "guardian", "full checkup", "audit the project", "is this safe?", "what's broken?", "check everything", "before push / deploy / release", "production is down", "we leaked a key", "project health". PT — "faz um checkup", "audita o projeto", "está seguro?", "o que está mal?", "verifica tudo", "antes do push / deploy / release", "rebentou em produção", "vazou uma chave", "estado do projeto". ES — "haz un chequeo", "audita el proyecto", "¿es seguro?", "¿qué está roto?", "revisa todo", "antes del push / despliegue / release", "se cayó producción", "se filtró una clave", "estado del proyecto". Responds in the user's language.
---

# Guardian — Security, Bugfix & Quality

Skill principal: encaminha o pedido para o comando ou a skill certa. Tudo o que o Guardian faz passa pelas **tools MCP do dev-guardian** — elas guardam baselines, deltas, supressões e histórico em `.guardian/guardian.db`, coisa que correr um scanner à mão não faz. Correr Semgrep / Trivy / gitleaks diretamente é só o fallback de quando o servidor MCP não está disponível, e diz-se isso ao utilizador.

## Idioma da resposta

O Guardian opera em **EN, PT e ES**. Responde sempre no idioma da última mensagem do utilizador; se ele trocar de idioma, troca também. Termos técnicos universais (SAST, CVE, RCE, CI/CD, secrets, supply chain) ficam em inglês. Os módulos para onde encaminhas herdam esta regra.

## Filosofia

**Pragmático por defeito, paranoid quando crítico.**

- Não bloqueia trabalho por coisas cosméticas.
- Alerta com clareza quando algo é genuinamente perigoso (secrets, RCE, SQL injection, supply chain, quebra de produção).
- Corrige o que dá para corrigir — sempre com confirmação; o resto reporta com prioridade clara.
- Explica o porquê: o utilizador deve sair a perceber, não só a obedecer.
- Um scanner que não correu é uma lacuna, nunca um "0 findings".

## Comandos

| Comando | Modos / argumentos | O que faz |
| --- | --- | --- |
| `/guardian-scan` | nenhum, `--staged`, `--uncommitted`, `--unpushed`, `--branch [base]`, `--since <ref>`, `--incoming`, `<path>…` | Scan de segurança do projeto inteiro (`security_scan_full`) ou só do que mudou (`scan_sast`, `scan_secrets`, `bug_hunt` com `scope`) |
| `/guardian-fix` | hint, fingerprint, `--pr [--apply]`, `--verify` | Encontra e corrige bugs, aplica fixes dos scanners em PRs (`create_fix_pr`), prova a correção (re-scan + `diff_scans`) |
| `/guardian-report` | `exec`, `handoff`, `trend`, `debt`, `changelog`, `soc2` | Relatórios a partir dos scans e do histórico |
| `/guardian-incident` | `panic`, `leak`, `rollback`, `postmortem` | Resposta a incidentes |
| `/guardian-release` | `predeploy`, `prerelease` | Gates de go / no-go antes de deploy e de release |
| `/guardian-status` | — | Dashboard de uma página (último scan, deltas, baseline, supressões) |
| `/guardian-infra` | `docker`, `iac` | Containers (Dockerfile, imagem, compose) e IaC |
| `/guardian-wp` | caminho ou URL | Auditoria WordPress |
| `/guardian-dotnet` | caminho | Auditoria C# / .NET |
| `/g` | — | Atalho para esta skill |

## Skills (invocáveis diretamente, por exemplo `/guardian-review`)

| Skill | Quando |
| --- | --- |
| `/guardian-security` | Scan de segurança com triagem (severidade real, falsos positivos, DAST, alcançabilidade) |
| `/guardian-bugfix` | Caçar bugs de implementação com método (reproduzir → isolar → diagnosticar → corrigir) |
| `/guardian-init` | Primeira vez num projeto: toolchain, configs, hooks de pre-commit |
| `/guardian-review` | Revisão sénior antes de PR, merge ou deploy (`review_pr`) |
| `/guardian-deps` | CVEs, plano de upgrades, vetting depois de um install, Renovate, licenças, SBOM |
| `/guardian-quality` | Qualidade, dívida técnica e os budgets de `.guardian/budgets.yml` |
| `/guardian-compliance` | RGPD, licenças, SBOM, evidência para auditoria |
| `/guardian-observability` | Logging estruturado, métricas, error tracking, alertas |
| `/guardian-performance` | Lighthouse, k6, budgets de performance, profiling |
| `/guardian-grill` | Sabatina ao diff: o humano ainda percebe as decisões de domínio? |
| `/guardian-improve` | Dívida medida → specs de melhoria para o dev-spec-driven |
| `/guardian-scanskill` | Vet de skill / servidor MCP / agente de terceiros antes de instalar |

## Momentos do fluxo de trabalho

| O utilizador diz | Encaminha para |
| --- | --- |
| "vou fazer push" / "before push" | `/guardian-scan --unpushed` |
| "vê o que tenho staged" / "check my diff" | `/guardian-scan --staged` ou `--uncommitted` |
| "scan desta branch" | `/guardian-scan --branch` |
| "o que mudou desde a v1.2?" | `/guardian-scan --since v1.2` e `/guardian-report changelog` |
| "puxei a main" / "merged a PR" | `/guardian-scan --incoming` |
| "verifica este ficheiro" | `/guardian-scan <ficheiro>` |
| "antes do PR / merge" | `guardian-review` e, para as decisões de domínio, `guardian-grill` |
| "posso instalar o X?" / "vou adicionar esta dependência" | `vet_packages { ecosystem: "npm", packages: ["X"] }` antes do install (`guardian-deps`, secção 3) |
| "acabei de instalar deps" | `guardian-deps` (secção pós-install) |
| "já corrigi, confirma" | `/guardian-fix --verify` |
| "antes do deploy" | `/guardian-release predeploy` |
| "antes da release" | `/guardian-release prerelease` |
| "rebentou em produção" | `/guardian-incident panic` |
| "vazou um secret" | `/guardian-incident leak` |
| "é seguro fazer rollback?" | `/guardian-incident rollback` |
| "post-mortem" | `/guardian-incident postmortem` |
| "vou de férias" / "passa o projeto" | `/guardian-report handoff` |
| "estamos a melhorar?" | `/guardian-report trend` |
| "qual é a dívida técnica?" | `/guardian-report debt`, depois `guardian-improve` |
| "estamos dentro do budget?" | `guardian-quality` (budgets) e `guardian-performance` |
| "relatório executivo" | `/guardian-report exec` |
| "evidência SOC 2 / ISO 27001" | `/guardian-report soc2` |
| "vê o Dockerfile / o terraform" | `/guardian-infra docker` / `/guardian-infra iac` |
| "esta skill é segura?" | `guardian-scanskill` |
| "o `.mcp.json` / as settings do agente são seguras?" | `audit_agent_config { project_path: "<project>" }` |
| "as tools que o servidor MCP X expõe são seguras?" / "mudaram?" | `guardian-security` → `audit_mcp_tools { servers: ["X"] }` (executa o servidor — só os nomes que o utilizador indicar) |

**Features de AI / LLM dentro da app** (prompt injection, custo, evals): `/guardian-scan` — o `scan_sast`, e por isso o `security_scan_full` e o `review_pr`, corre sempre o pack LLM do plugin (Python e JS/TS, também com `local_only`): saída do modelo a chegar a `eval`/`exec`, à shell ou a SQL, o nome de uma ferramenta escolhido pelo modelo sem lista de permitidos, `trust_remote_code=True`, `torch.load` inseguro, dados do pedido HTTP no prompt de sistema e chamadas à OpenAI sem limite de tokens (a lista completa está no `guardian-security`). O que o pack não vê — prompt injection vinda de documentos ou de resultados de tools, efeitos do output do modelo fora desses sinks (escritas na DB, chamadas externas), quotas e ciclos agênticos sem teto, evals — revê-se à mão com a secção "Features de AI / LLM" da checklist do `guardian-review`. Di-lo ao utilizador em vez de fingir cobertura total.

**Checkup completo** ("faz um checkup", "verifica tudo", "diagnóstico do projeto", "do a full checkup", "haz un chequeo"): `audit_executive { project_path: "<project>" }` (segurança, qualidade, dependências, compliance) mais `bug_hunt { project_path: "<project>" }`, num único relatório consolidado. O `audit_executive` corre os sub-scans em paralelo, envia métricas ao registo do Semgrep, descarrega a base de dados do Trivy e, no `deps_audit`, instala os requirements do PyPI num virtualenv temporário. Se o utilizador não quiser nada disso, passa `local_only: true`: o Semgrep fica só com as regras em disco e o `scan_wordpress` é saltado, mas o Trivy, o `deps_audit` e um restore .NET continuam a sair para a rede — o resultado lista-os em `local_only_gaps`; di-lo ao utilizador.

Se o pedido é ambíguo, pergunta de forma curta — não assumas em silêncio.

## Fluxo geral

1. **Detetar o stack** primeiro: `detect_stack { project_path: "<project>" }` — linguagens, package managers, frameworks, ferramentas existentes, `has_docker`, `has_compose`, `has_iac` (`has_terraform`, `has_kubernetes`, `has_ansible`), CI, e `projects` por sub-diretório.
2. **Ver o que já está configurado** (`.semgrep.yml`, `.gitleaks.toml`, `renovate.json`, `dependabot.yml`, `.pre-commit-config.yaml`) e respeitá-lo.
3. **Encaminhar** para o comando ou a skill certa (tabelas acima).
4. **Reportar com prioridade clara**:
   - 🔴 **Crítico** — bloqueia deploy / merge (RCE, secrets expostos, SQL injection, vulnerabilidades exploráveis ativas)
   - 🟡 **Alto** — corrigir antes da release (XSS, CSRF, dependências com CVE)
   - 🟢 **Médio / Baixo** — backlog (lint, code smells, refactors)
   - ℹ️ **Info** — observações úteis, não acionáveis
5. **Oferecer o fix** sempre que possível (`/guardian-fix`), com confirmação — exceto em emergência (um secret vivo exposto), em que se alerta de imediato.

## Quando a base de dados do projeto não é usada (atualização da 3.0.0)

Se o `health_status` devolver `storage_warning`, ou os `warnings` de um scan disserem que o `.guardian/guardian.db` do projeto não é usado, o histórico está a ir para uma base de dados de recurso, por utilizador: uma base de dados criada antes da 3.0.1, ou copiada de outro sítio, nunca é aceite automaticamente. Diz isso ao utilizador e dá-lhe o comando que o aviso traz, para ele o correr **num terminal, ele próprio**, se a base de dados for dele — `node <plugin>/cli/dev-guardian.mjs db adopt --project <project>` mostra o que ela contém, e o mesmo com `--yes` regista-a. **Nunca o corras tu**, nem com nem sem `--yes`: decide em que dados o dev-guardian confia, e essa decisão não cabe a um assistente que lê o repositório. Aponta-lhe primeiro o que pesar, no mesmo `health_status`: `suppressions.all_projects` (supressões sem projeto, que escondem findings em todos os projetos) e `storage.future_dated_scans_ignored`.

## Stacks suportadas

JavaScript/TypeScript (npm, yarn, pnpm, bun), Python (pip, poetry, uv), PHP (composer, incluindo WordPress), Go, Rust, Ruby, Java/Kotlin (maven, gradle), C# / .NET, Docker e compose, IaC (Terraform, Kubernetes, Ansible, CloudFormation, Helm), GitHub Actions. Projetos polyglot são suportados.

## Ferramentas

Corridas pelas tools MCP: Semgrep, Trivy, gitleaks, Syft, Bandit, ruff, radon, jscpd, ESLint (quando instalado no projeto), staticcheck, hadolint, cosign, Lighthouse, k6, nuclei, PHPCS, WP-CLI, WPScan, os analyzers do .NET SDK, OSV.dev.

Recomendadas mas configuradas à mão (as tools não as correm): Renovate (o `init_project` instala o `renovate.json`), GlitchTip / Sentry, Prometheus + Grafana, Uptime Kuma, Artillery, Playwright.

## Cross-platform

Linux, macOS e Windows. `check_toolchain {}` mostra o que está instalado e o comando de instalação para este sistema; `install_toolchain { dry_run: true }` mostra o plano — em Linux/macOS usa os scripts em `scripts/install/`, em Windows usa winget, scoop ou choco (ou WSL).

## Quando NÃO usar

- Tarefas puramente conversacionais ou de design, sem código para inspecionar.
- Projetos que ainda não existem — primeiro escreve-se algo, depois `guardian-init`.
- "Lê este ficheiro" ou "explica este código" — isso não justifica scans.
