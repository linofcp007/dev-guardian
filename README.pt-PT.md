# dev-guardian

[English](README.md) · **Português (pt-PT)** · [Español](README.es.md)

Um conjunto open-source de segurança, deteção de bugs, qualidade de código, dependências, compliance, observabilidade e performance para o Claude Code e o Cowork — e, através do seu servidor MCP, para qualquer host de IA que fale MCP. Corre scanners open-source (Semgrep, Trivy, gitleaks, Syft, …), guarda cada resultado numa base de dados SQLite local, para que baselines, deltas e supressões sobrevivam entre sessões, e diz quando um scanner não correu em vez de reportar "0 findings". Também verifica skills e servidores MCP de terceiros, e os pacotes que um agente está prestes a instalar, antes de chegarem à tua máquina.

Trilingue: as skills e os comandos respondem em inglês, português ou espanhol, conforme a língua em que escreveres.

## O que inclui

- **13 skills** e **10 comandos** slash para o Claude Code / Cowork (abaixo).
- Um **servidor MCP** com **58 ferramentas** e **18 recursos**, em TypeScript sobre `node:sqlite`, entregue já compilado — referência completa em [docs/tools.md](docs/tools.md) (em inglês).
- **142 regras Semgrep em 10 packs** escritas para este projeto: classes de bugs para sete linguagens, um pack RGPD e um pack de inventário de rotas para nove linguagens — ver [docs/rule-packs.md](docs/rule-packs.md).
- **Hooks de proteção** que bloqueiam comandos de shell catastróficos, verificam pacotes no momento da instalação e avisam quando um segredo é escrito num ficheiro — ver [docs/hooks.md](docs/hooks.md).
- Uma **CLI** (`cli/dev-guardian.mjs`) para gates de CI, configuração de hosts, um resumo no terminal e um dashboard HTML.

## Requisitos

- **Node.js ≥ 22.13.** A base de dados é o `node:sqlite` embutido no Node, usado sem qualquer flag. Num Node mais antigo o servidor termina com `dev-guardian requires Node.js >= 22.13 (node:sqlite)`.
- **git.**
- **Os scanners que quiseres usar**, instalados à parte. `check_toolchain` diz o que está presente (e assinala o Trivy comprometido 0.69.4–0.69.6); `install_toolchain` ou `/guardian-init` instalam o resto. Um scanner em falta é reportado como lacuna de cobertura, nunca como resultado limpo.
- **Opcional: Docker.** Sem um `semgrep` nativo, `scan_sast` e `map_attack_surface` recorrem à imagem `semgrep/semgrep`.
- **Windows:** todos os scans correm nativamente, sem shell. Só é preciso um bash para o relatório de estado inicial do `init_project` e para o recurso ao WSL do `install_toolchain` quando não há winget, scoop nem choco. O dev-guardian procura primeiro o Git Bash, depois o WSL, depois qualquer `bash` no `PATH`.

Não é preciso `npm install`: o `mcp/dist/server.js` está no repositório como um bundle autónomo. Só os comandos `scan` e `baseline update` da CLI precisam de `npm ci --omit=dev` em `mcp/`, uma vez, para os seus pacotes de runtime.

## Início rápido (Claude Code)

```text
/plugin marketplace add https://github.com/linofcp007/dev-guardian
/plugin install dev-guardian@dev-guardian
```

Depois, no teu projeto:

```text
/guardian-init        deteta o stack, instala os scanners, escreve as configurações e os hooks de pre-commit
/guardian-scan        scan de segurança completo (ou --staged, --branch, --since …)
/guardian-status      estado do projeto num só ecrã
```

A partir de um clone local: `claude --plugin-dir /caminho/para/dev-guardian` para uma sessão, ou `/plugin marketplace add /caminho/para/dev-guardian` para o instalar. Todas as skills respondem também a linguagem natural — "audita o projeto", "isto pode ir para produção?", "vê se há vulnerabilidades".

## Comandos slash

| Comando | Modos | O que faz |
| --- | --- | --- |
| `/guardian-scan` | nenhum, `--staged`, `--uncommitted`, `--unpushed`, `--branch [base]`, `--since <ref>`, `--incoming`, caminhos | Scan de segurança do projeto inteiro, ou só do que mudou |
| `/guardian-fix` | pista, fingerprint, `--pr [--apply]`, `--verify` | Encontra e corrige bugs, abre PRs de correção verificados, prova uma correção com novo scan |
| `/guardian-report` | `exec`, `handoff`, `trend`, `debt`, `changelog`, `soc2` | Relatórios a partir do histórico de scans |
| `/guardian-incident` | `panic`, `leak`, `rollback`, `postmortem` | Resposta a incidentes |
| `/guardian-release` | `predeploy`, `prerelease` | Gates de go / no-go |
| `/guardian-status` | foco opcional (p. ex. "só segurança") | Último scan, deltas, baseline, supressões a expirar |
| `/guardian-infra` | `docker`, `iac` | Dockerfile, imagem, compose, Terraform, Kubernetes, CloudFormation, Helm |
| `/guardian-wp` | caminho da instalação ou URL do site | Auditoria WordPress |
| `/guardian-dotnet` | caminho do projeto ou da solução | Auditoria C# / .NET |
| `/g` | o que queres verificar | Atalho para a skill `guardian` (o router) |

A versão 2.0.0 tinha 48; o `CHANGELOG.md` indica, para cada nome antigo, o que o substitui.

## Skills

| Skill | Para |
| --- | --- |
| `/guardian` | Router: escolhe o comando ou a skill certa |
| `/guardian-security` | SAST, segredos, CVEs de dependências, IaC, DAST e alcançabilidade, com triagem |
| `/guardian-bugfix` | Bugs de implementação, encontrados e corrigidos com método |
| `/guardian-init` | Primeira utilização num projeto: toolchain, configurações, pre-commit |
| `/guardian-review` | Revisão ao nível de um sénior antes de um PR, merge ou deploy |
| `/guardian-deps` | Auditoria de CVEs, plano e PRs de upgrade, verificação de instalações, licenças, SBOM |
| `/guardian-quality` | Duplicação, complexidade, dívida técnica, `.guardian/budgets.yml` |
| `/guardian-compliance` | RGPD, licenças, SBOM, evidência para auditoria, modelos de banner de cookies e de política de privacidade |
| `/guardian-observability` | Logging estruturado e métricas |
| `/guardian-performance` | Lighthouse, k6, budgets de performance |
| `/guardian-grill` | Sabatina às decisões de um diff antes do merge |
| `/guardian-improve` | Transforma dívida técnica medida em specs de melhoria |
| `/guardian-scanskill` | Verifica uma skill, servidor MCP ou agente de terceiros antes de o instalar |

## O servidor MCP

| Área | Ferramentas |
| --- | --- |
| Scans de segurança | `security_scan_full`, `scan_sast`, `scan_secrets`, `scan_deps`, `scan_containers`, `scan_iac`, `review_pr` |
| Bugs e qualidade | `bug_hunt`, `quality_check`, `suggest_fix`, `create_fix_pr` |
| Dependências e cadeia de fornecimento | `deps_audit`, `deps_update_plan`, `vet_packages`, `generate_sbom`, `sbom_diff`, `export_vex`, `license_compatibility`, `scan_skill`, `audit_agent_config` |
| Superfície de ataque | `map_attack_surface`, `scan_dast`, `validate_finding` |
| Histórico e triagem | `diff_scans`, `set_baseline`, `suppress_finding`, `regression_alert`, `risk_score`, `prioritize_findings`, `triage_findings`, `health_status` |
| Relatórios | `audit_executive`, `report_export`, `compliance_check`, `compliance_evidence`, `create_github_issues` |
| Configuração e operação | `detect_stack`, `check_toolchain`, `install_toolchain`, `init_project`, `precommit_install`, `register_custom_rules`, `observability_setup`, `perf_check` |
| WordPress | `scan_wordpress`, `wp_audit`, `wp_vuln_check`, `wp_vuln_check_source`, `wp_plugin_check`, `wp_cron_audit`, `wp_rest_audit`, `wp_recommend_hardening`, `wp_describe_setup`, `bulk_audit_wordpress_sites` |
| C# / .NET | `scan_dotnet_secrets`, `dotnet_target_framework_check`, `dotnet_efcore_audit`, `dotnet_describe_setup` |

Os recursos (`guardian://scans/latest`, `guardian://findings/open`, `guardian://cves/active`, `guardian://surface/latest`, …) servem os resultados guardados em JSON. Tudo fica em `.guardian/guardian.db`; o servidor mantém `.guardian/` fora do git, exceto `.guardian/baseline.json`, que a CI precisa de ter no repositório.

## O que cada stack recebe

| Stack | Detetado | Regras de bugs (`bug_hunt`) | Rotas (`map_attack_surface`) | CVEs de dependências | Alcançabilidade (`validate_finding`) |
| --- | --- | --- | --- | --- | --- |
| JavaScript / TypeScript | sim | 13 regras | Express, NestJS | Trivy, `npm audit` | alcançável / inalcançável |
| Python | sim | 10 regras | Flask, FastAPI, Django | Trivy, `pip-audit` | alcançável / inalcançável |
| Go | sim | 9 regras | net/http, gin, chi | Trivy | alcançável / inalcançável |
| Rust | sim | 1 regra (sleep bloqueante numa `async fn`) | actix-web | Trivy | alcançável / inalcançável |
| Java | sim | 7 regras | Spring | Trivy (Maven; Gradle só com `gradle.lockfile`) | só alcançável / desconhecido |
| C# / .NET | sim | 11 regras | ASP.NET Core | Trivy, `dotnet list package --vulnerable` | só alcançável / desconhecido |
| PHP | sim, também sem `composer.json` | 6 regras | Laravel | Trivy (`composer.lock`) | só alcançável / desconhecido |
| WordPress | sim, com WooCommerce e Kadence | as regras PHP, mais `p/wordpress` no `scan_wordpress` | rotas REST | WPScan (URL ao vivo), feed da Wordfence (a partir do código) | como PHP |
| Ruby | sim | nenhuma — usa o RuboCop | rotas ao estilo Rails | Trivy (`Gemfile.lock`) | só alcançável / desconhecido |
| Kotlin | **só deteção** | — | — | — | — |

Para lá da tabela, o `scan_sast` corre o ruleset do registry do Semgrep (`--config=auto`), que escolhe regras para as linguagens que encontrar — Kotlin incluído — e o gitleaks procura segredos em qualquer projeto. Contentores e IaC (Dockerfile, imagens, compose, Terraform, Kubernetes, CloudFormation, Helm, workflows do GitHub Actions) ficam com o `scan_containers` e o `scan_iac`. "Só alcançável / desconhecido" quer dizer que a ferramenta nunca afirma que código é inalcançável numa linguagem que resolve código em runtime (autoload, anotações, contentores de DI). O .NET tem ainda quatro ferramentas dedicadas e o WordPress dez. O Trivy lê um lock file do Gradle em qualquer projeto, Kotlin incluído, e um build Gradle que não conseguiu ler é assinalado como lacuna de cobertura; para Kotlin não há regras de bugs nem extração de rotas.

**O Gradle e o Python precisam de um lock file para o Trivy.** O Trivy só lê as dependências do Gradle a partir do `gradle.lockfile`, e as do Python a partir do `poetry.lock`, do `uv.lock`, do `Pipfile.lock` ou de um `requirements.txt` com versões fixadas. Um `build.gradle` / `build.gradle.kts`, `pyproject.toml`, `setup.py` / `setup.cfg`, `Pipfile` ou `requirements*.txt` que não conseguiu ler é reportado como lacuna de cobertura (`trivy:gradle`, `trivy:python`, ou `trivy` ignorado quando não leu mais nada), nunca como um scan limpo. Para a fechar, gera o lock file. No Gradle, ativa primeiro `dependencyLocking { lockAllConfigurations() }` no build — sem isso, `gradle dependencies --write-locks` não escreve nada — e só depois corre esse comando. No Python, corre `poetry lock`, `uv lock` ou `pipenv lock`, ou fixa a versão de cada dependência no `requirements.txt`.

## Hooks de proteção

Carregados automaticamente com o plugin, sem dependências e em fail-open:

- **SessionStart** — um resumo curto da postura de segurança.
- **PostToolUse** em escritas — avisa, com uma pré-visualização mascarada, quando é escrito um segredo.
- **PreToolUse** em Bash e PowerShell — bloqueia comandos catastróficos (`rm -rf /`, `curl … | sh`, `iwr … | iex`, escrita direta em discos, fork bombs), avisa nos arriscados e verifica os pacotes antes de `npm`, `pnpm`, `yarn`, `bun`, `pip`, `uv`, `poetry`, `composer` ou `dotnet add package` os instalarem: um pacote malicioso é bloqueado, um inexistente só é bloqueado num comando de instalação simples e único.
- **PreToolUse** em escritas — recusa que um assistente edite a própria configuração dos hooks; opcionalmente bloqueia a escrita de um token de fornecedor.

O `.guardian/hooks.config.json` de um projeto só os pode tornar mais estritos; desligar um deles exige a configuração do utilizador ou uma variável de ambiente.

Detalhes, configuração e formas de desligar: [docs/hooks.md](docs/hooks.md). Os mesmos detetores correm no terminal com `node cli/dev-guardian.mjs check --file <caminho>` ou `--bash "<comando>"`.

## Outros hosts de IA

Cursor, Windsurf, GitHub Copilot, Codex CLI, Gemini CLI, Cline e Claude Desktop recebem o servidor MCP e um ficheiro de regras (sem skills, comandos nem hooks). Clona uma vez e depois corre a CLI **pelo caminho absoluto** a partir do teu projeto:

```text
git clone --depth 1 --branch v3.0.0 https://github.com/linofcp007/dev-guardian.git ~/tools/dev-guardian
node ~/tools/dev-guardian/cli/dev-guardian.mjs mcp-config cursor --write
node ~/tools/dev-guardian/cli/dev-guardian.mjs mcp-config all --write --update-mcp
```

O clone acima fixa a 3.0.0; para seguir uma versão posterior, clona antes a tag `vX.Y.Z` dela. `--update-mcp`, `--global` e `ci-init` precisam da 3.0.0 ou posterior — a 2.0.0 também escreve as configurações globais do Windsurf e do Claude Desktop com `mcp-config all --write`. A CLI preenche os caminhos absolutos, junta em vez de substituir e só gere um bloco delimitado dentro de ficheiros como o `AGENTS.md`; `--update-mcp` atualiza uma entrada desatualizada. Caminhos por host e snippets manuais: [docs/hosts.md](docs/hosts.md).

## CI

```text
npm ci --omit=dev --prefix ~/tools/dev-guardian/mcp                                  # uma vez: pacotes de runtime do scan
node ~/tools/dev-guardian/cli/dev-guardian.mjs ci-init github --write                # também gitlab, bitbucket
node ~/tools/dev-guardian/cli/dev-guardian.mjs baseline update --project .           # faz commit de .guardian/baseline.json
node ~/tools/dev-guardian/cli/dev-guardian.mjs scan --project . --fail-on high --sarif results.sarif
```

O `ci-init` gera um pipeline com cada action fixada por SHA de commit e cada scanner por versão e checksum. O `scan` termina com 0 quando passa, 1 quando um finding novo face à baseline atinge `--fail-on`, **2 quando um scanner não correu** (nunca leias isso como aprovado) e 3 num erro de utilização. Ver [docs/ci.md](docs/ci.md). Corre-os a partir do teu projeto, com o caminho do teu clone (a cópia do próprio plugin também serve). Para uma vista local: `status` e `dashboard` (uma página HTML autónoma, sem rede).

## Privacidade e rede

O dev-guardian não envia telemetria própria. Algumas ferramentas acedem à rede — o modo registry do Semgrep (que envia métricas de utilização à Semgrep Inc.; `local_only: true` evita-o) e a sua verificação de versão, a base de dados do Trivy, os feeds NuGet de um projeto .NET (o `scan_sast` restaura-o e compila-o, com ou sem `local_only`), o OSV, os registos de pacotes, CISA KEV / FIRST EPSS, a Wordfence e a verificação de segredos ao vivo, que é opcional. A lista completa, por ferramenta, está no [SECURITY.md](SECURITY.md). `GUARDIAN_OFFLINE=1` desliga as consultas que o dev-guardian faz por iniciativa própria (informação sobre ameaças, verificação de pacotes, verificação de segredos ao vivo, o feed da Wordfence); todas as variáveis de ambiente estão em [docs/env.md](docs/env.md).

## Resolução de problemas

**O servidor MCP não arranca.** `/mcp` no Claude Code mostra o estado do servidor. O Claude Code guarda o stderr de cada servidor na sua pasta de cache: `%LOCALAPPDATA%\claude-cli-nodejs\Cache\<projeto>\mcp-logs-<servidor>\` no Windows (a do plugin é `mcp-logs-plugin-dev-guardian-dev-guardian`) e — pela mesma convenção, não verificado aqui — `~/.cache/claude-cli-nodejs/…` no Linux e `~/Library/Caches/claude-cli-nodejs/…` no macOS. As causas habituais:

- Node anterior à 22.13 (ver Requisitos).
- Um `.mcp.json` de projeto que usa `${CLAUDE_PROJECT_DIR}`: o Claude Code não expande essa variável aí, e o `node` recebe o texto literal. Usa um caminho relativo; os servidores de projeto arrancam na raiz do projeto.

**`no_bash_shell`.** Só a instalação por omissão do `install_toolchain` em Linux e macOS precisa de bash, e ainda o relatório de estado do `init_project`. No Windows, instala o Git for Windows. No PowerShell, `bash` pode apontar para o stub do WSL em vez do Git Bash; o dev-guardian procura primeiro o Git Bash por si, mas um comando que escrevas à mão pode não o fazer.

**Cobertura `none` ou `partial`, ou o `scan` termina com 2.** Um scanner faltou, falhou ou não analisou nada. `tools_run` e `missing_tools` na resposta dizem qual; `check_toolchain` mostra o que está instalado. Resolve isso e volta a correr — um scan com lacunas nunca é servido da cache.

**`install_toolchain` com `elevation_allowed: true` falha com "sudo: a terminal is required to read the password".** Os passos de instalação correm destacados, sem terminal, por isso em Linux e macOS a elevação só funciona com sudo sem palavra-passe para esses comandos. Caso contrário, corre tu os comandos listados em `requires_elevation`. O SDK do .NET nunca é instalado automaticamente.

**O Semgrep envia métricas.** O `scan_sast` por omissão usa `--config=auto`, que o Semgrep só permite com métricas ligadas. Passa `local_only: true` (ou `--local-only` na CLI) para correr só as regras em disco com `--metrics=off`.

## Estrutura do repositório

```text
.claude-plugin/   plugin.json + marketplace.json
commands/         os 10 comandos slash
skills/           as 13 skills
hooks/            hooks.json + guardian-hook.mjs
cli/              dev-guardian.mjs (mcp-config, check, scan, baseline, ci-init, status, dashboard)
mcp/              o servidor MCP: src/, test/, dist/ (no repositório)
configs/          packs Semgrep, modelos de CI, configurações gitleaks/Renovate/pre-commit, modelos de compliance
host-rules/       modelos de regras para outros hosts
docs/             ferramentas, packs de regras, hooks, CI, hosts, ambiente (em inglês)
scripts/          install-linux.sh, install-macos.sh, initial-scan.sh
```

Contribuir: [CONTRIBUTING.md](CONTRIBUTING.md) e [CLAUDE.md](CLAUDE.md). Reportar vulnerabilidades: [SECURITY.md](SECURITY.md).

## Licença

MIT. Carlos Pereira · [prodigitalkey.com](https://prodigitalkey.com)
