# dev-guardian

[English](#english) · [Português](#português) · [Español](#español)

---

## English

All-in-one **100% open-source** plugin for Claude Code / Cowork. Handles security, bug detection and fixing, code quality, dependency management, observability, performance and compliance for any dev project. Stack-aware (Node, Python, PHP/WordPress, Go, Rust, Ruby, Java, **C# / .NET**), trilingual triggers (EN + PT + ES) — responds in the user's language.

Under the hood it ships a Claude Code plugin (11 skills + 12 slash commands) **and** an MCP server with **51 tools and 5 resources**, with persistent SQLite state for baselines, deltas and suppressions. It also vets **third-party AI skills / MCP servers / agents before you install them** — the supply-chain check for the agent ecosystem.

### Skills (Claude Code front-end)

| Skill                    | Slash command          | What it does                                              |
| ------------------------ | ---------------------- | --------------------------------------------------------- |
| `guardian`               | `/guardian`            | Main router — dispatches to the right module              |
| `guardian-init`          | `/guardian-init`       | Initial bootstrap — installs and configures everything    |
| `guardian-security`      | `/guardian-scan`       | SAST + secrets + CVEs + container + IaC                   |
| `guardian-bugfix`        | `/guardian-fix`        | Hunts and fixes implementation bugs                       |
| `guardian-quality`       | `/guardian-quality`    | Complexity, duplication, tech debt                        |
| `guardian-review`        | `/guardian-review`     | Deep pre-PR / pre-deploy review                           |
| `guardian-deps`          | `/guardian-deps`       | Renovate setup + CVE scan + supply chain                  |
| `guardian-observability` | `/guardian-observe`    | Structured logging, metrics, error tracking               |
| `guardian-performance`   | `/guardian-perf`       | Performance budgets, k6, Lighthouse                       |
| `guardian-compliance`    | `/guardian-compliance` | GDPR, licenses, SBOM, privacy policy                      |
| `guardian-scanskill`     | `/guardian-scanskill`  | Vet a 3rd-party skill / MCP server / agent before install |
| (combines 3 of them)     | `/guardian-audit`      | Executive report: security + quality + deps               |

You can also trigger everything via **natural language** (EN, PT or ES). Skills fire on descriptions — *"audit the project"*, *"check for vulnerabilities"*, *"before merge"*, *"audita o projeto"*, *"vê se há vulnerabilidades"*, *"antes de fazer merge"*, *"audita el proyecto"*, *"comprueba vulnerabilidades"*, *"antes del merge"*.

### MCP server (51 tools, 5 resources)

The plugin registers an MCP server on stdio that Claude Code launches automatically. The tools group into:

- **Cross-stack security** (10) — `security_scan_full`, `scan_sast`, `scan_deps`, `scan_secrets`, `scan_containers`, `scan_iac`, `deps_audit`, `bug_hunt`, `suggest_fix`, `register_custom_rules`
- **WordPress** (9) — `scan_wordpress` (Semgrep PHP + WP rule pack + Trivy + gitleaks + PHPCS-WPCS), `wp_audit` (live install: checksums + admins + config flags via WP-CLI), `wp_vuln_check` (WPScan DB), `wp_plugin_check`, `wp_cron_audit`, `wp_rest_audit`, `wp_recommend_hardening`, `wp_describe_setup`, `bulk_audit_wordpress_sites`
- **C# / .NET** (4 dedicated + branches) — `scan_dotnet_secrets`, `dotnet_target_framework_check`, `dotnet_efcore_audit`, `dotnet_describe_setup`; `scan_sast` runs `p/csharp` + parses security-code-scan output; `deps_update_plan` runs `dotnet list package --outdated`; `observability_setup` emits Serilog + prometheus-net templates
- **Quality, deps, prioritisation** (5) — `quality_check`, `deps_update_plan`, `triage_findings`, `prioritize_findings`, `risk_score`
- **Compliance & SBOM** (5) — `compliance_check` (GDPR/RGPD), `compliance_evidence`, `generate_sbom` (Syft), `sbom_diff`, `license_compatibility`
- **Observability & perf** (3) — `observability_setup` (Pino/structlog/Monolog/Serilog + Prometheus), `health_status`, `perf_check` (k6 / Lighthouse)
- **Lifecycle / PR / governance** (10) — `init_project`, `precommit_install`, `review_pr`, `set_baseline`, `diff_scans`, `regression_alert`, `report_export` (HTML / **SARIF 2.1.0** / Markdown / JSON), `create_github_issues`, `suppress_finding`, `audit_executive`
- **AI-agent supply chain** (1) — `scan_skill`: vet a third-party **skill / MCP server / agent before you install it**. Accepts a directory, file, `.zip`, or git/HTTP(S) URL and runs 16 threat categories (prompt injection, data exfiltration, privilege escalation, supply chain, excessive agency, output handling, system-prompt leakage, memory poisoning, tool misuse, rogue agent, trigger abuse, dangerous code, taint, signatures, MCP least-privilege, MCP tool poisoning), a **YARA-style signature engine**, taint-light source→sink, hidden-Unicode detection, and **OSV.dev** CVE lookups — rolled up into a **0-100 risk score** and a **SAFE → DO NOT INSTALL** verdict
- **Meta / host** (4) — `detect_stack`, `check_toolchain`, `install_toolchain`, `install_host_context`

**Resources** — `guardian://wp/audit/latest`, `guardian://wp/audit/{scan_id}`, `guardian://wp/cron`, `guardian://dotnet/target-frameworks`, `guardian://dotnet/efcore`.

**Storage** — SQLite at `.guardian/guardian.db`. Tables: `scans`, `findings`, `cves`, `baselines`, `suppressions`, `stack_snapshots`. Enables baseline tracking, scan-to-scan deltas, time-bounded suppressions, regression alerts.

### Open-source tools orchestrated

Semgrep · Trivy · OSV.dev · gitleaks · Renovate · OWASP ZAP · Playwright · Pino / structlog / Monolog / Serilog · Prometheus + Grafana · GlitchTip · Uptime Kuma · k6 · Artillery · Lighthouse · Syft · WPScan · WP-CLI · PHPCS + WPCS · security-code-scan · dotnet-outdated · ruff · bandit · jscpd · eslint · hadolint · shellcheck.

### Plugin installation

#### A) Via marketplace (recommended) — Claude Code CLI

```text
/plugin marketplace add https://github.com/linofcp007/dev-guardian
/plugin install dev-guardian@dev-guardian
```

Works with any git URL (HTTPS or SSH) or local folder path containing [`.claude-plugin/marketplace.json`](.claude-plugin/marketplace.json).

> ⚠️ **Claude Desktop app limitation.** The Desktop client currently rejects third-party marketplaces with `External plugin sources are not yet supported` (the feature is gated server-side). This is a Claude Desktop limitation, not a problem with this plugin — installing from any GitHub-hosted marketplace fails the same way today. Tracking issues: [anthropics/claude-code#41653](https://github.com/anthropics/claude-code/issues/41653) (remote sources), [anthropics/claude-code#52147](https://github.com/anthropics/claude-code/issues/52147) (local paths). Until parity ships, use option **B** below or install via the Claude Code CLI.

#### B) Manual folder copy (works everywhere)

Copy the whole folder to:

- **Linux / macOS**: `~/.claude/plugins/dev-guardian/`
- **Windows**: `%USERPROFILE%\.claude\plugins\dev-guardian\`

Then inside Claude Code, run `/plugin` and enable `dev-guardian`. Alternatively, add to your `~/.claude/settings.json`:

```json
{
  "enabledPlugins": { "dev-guardian@dev-guardian": true }
}
```

> The MCP server runs from `mcp/dist/`. On first install run `cd mcp && npm install && npm run build` once. The plugin manifest then launches it automatically via `node ${pluginDir}/mcp/dist/server.js`.
>
> `.sh` scripts in `scripts/` run natively on Linux/macOS. On Windows native you need **WSL2** or Git Bash; the skills/commands themselves work on any OS.

### Philosophy

- **Pragmatic by default** — doesn't block work over cosmetics
- **Paranoid when critical** — prod secrets, RCE, SQLi → halt and alert
- **Stack-aware** — detects your language and only configures what's relevant
- **Cross-platform** — Linux, macOS, Windows (with WSL)
- **Zero lock-in** — every tool used is open-source and self-hostable
- **Idempotent** — running `guardian init` twice doesn't duplicate anything
- **Graceful degradation** — missing scanners are reported, never crash a scan

### Supported stacks

JavaScript / TypeScript (Node, Next, React, Vue, Svelte, Angular), Python (Django, Flask, FastAPI), PHP (Laravel, Symfony, **WordPress + Kadence + WooCommerce + Tutor LMS**), **C# / .NET (ASP.NET Core, EF Core, central package management)**, Go, Rust, Ruby, Java / Kotlin, Docker, Terraform, Kubernetes, Ansible, GitHub Actions.

For languages not explicitly supported, the skills fall back to Semgrep `--config=auto` (covers 30+ languages) and generic secret rules.

### Repository structure

```text
dev-guardian/
├── .claude-plugin/
│   ├── plugin.json              # declares the MCP server + plugin metadata
│   └── marketplace.json
├── commands/                    # 12 slash commands
├── skills/                      # 11 skills (one per router target)
├── mcp/                         # MCP server (TypeScript + SQLite)
│   ├── src/                     # tools/, resources/, runners/, storage/, platform/
│   ├── test/                    # 280 unit + integration tests
│   ├── scripts/                 # smoke.mjs, smoke-wp-dotnet.mjs
│   └── dist/                    # built artifact (node dist/server.js)
├── scripts/
│   ├── detect/detect-stack.sh   # language/framework detection
│   ├── install/                 # install-linux.sh, install-macos.sh
│   └── scan/                    # full-security-scan, review-scan, etc.
├── configs/
│   ├── renovate/, gitleaks/, semgrep/, pre-commit/
├── host-rules/                  # AGENTS.md, cursor.mdc, copilot-instructions.md, …
└── README.md
```

### License

MIT — use it, modify it, share it freely.

### Author

Carlos Pereira · prodigitalkey.com

---

## Português

Plugin all-in-one **100% open-source** para Claude Code / Cowork. Faz segurança, deteção e correção de bugs, qualidade de código, gestão de dependências, observability, performance e compliance em qualquer projeto de desenvolvimento. Stack-aware (Node, Python, PHP/WordPress, Go, Rust, Ruby, Java, **C# / .NET**), triggers trilingues (EN + PT + ES) — responde no idioma do utilizador.

Por baixo do capot fornece um plugin Claude Code (11 skills + 12 slash commands) **e** um servidor MCP com **51 tools e 5 resources**, com estado persistente em SQLite para baselines, deltas e supressões. Também faz **vet de skills / MCP servers / agentes de terceiros antes de os instalares** — a verificação de supply-chain do ecossistema de agentes.

### Skills (front-end Claude Code)

| Skill                    | Slash command          | O que faz                                                |
| ------------------------ | ---------------------- | -------------------------------------------------------- |
| `guardian`               | `/guardian`            | Router principal — encaminha para o módulo certo         |
| `guardian-init`          | `/guardian-init`       | Bootstrap inicial — instala e configura tudo             |
| `guardian-security`      | `/guardian-scan`       | SAST + secrets + CVEs + container + IaC                  |
| `guardian-bugfix`        | `/guardian-fix`        | Caça e corrige bugs de implementação                     |
| `guardian-quality`       | `/guardian-quality`    | Complexidade, duplicação, tech debt                      |
| `guardian-review`        | `/guardian-review`     | Revisão profunda pré-PR / pré-deploy                     |
| `guardian-deps`          | `/guardian-deps`       | Renovate setup + scan de CVEs + supply chain             |
| `guardian-observability` | `/guardian-observe`    | Logging estruturado, métricas, error tracking            |
| `guardian-performance`   | `/guardian-perf`       | Performance budgets, k6, Lighthouse                      |
| `guardian-compliance`    | `/guardian-compliance` | RGPD, licenças, SBOM, privacy policy                     |
| `guardian-scanskill`     | `/guardian-scanskill`  | Vet de skill / MCP / agente antes de instalar            |
| (combina os 3)           | `/guardian-audit`      | Relatório executivo: security + quality + deps           |

Também podes invocar tudo em **linguagem natural** (PT, EN ou ES). As skills disparam por descrição — *"audita o projeto"*, *"vê se há vulnerabilidades"*, *"antes de fazer merge"*, *"audit the project"*, *"check for vulnerabilities"*, *"before merge"*, *"audita el proyecto"*, *"comprueba vulnerabilidades"*, *"antes del merge"*.

### Servidor MCP (51 tools, 5 resources)

O plugin regista um servidor MCP em stdio que o Claude Code arranca automaticamente. As tools agrupam-se em:

- **Segurança transversal** (10) — `security_scan_full`, `scan_sast`, `scan_deps`, `scan_secrets`, `scan_containers`, `scan_iac`, `deps_audit`, `bug_hunt`, `suggest_fix`, `register_custom_rules`
- **WordPress** (9) — `scan_wordpress` (Semgrep PHP + rule pack WP + Trivy + gitleaks + PHPCS-WPCS), `wp_audit` (instalação viva: checksums + admins + flags de config via WP-CLI), `wp_vuln_check` (WPScan DB), `wp_plugin_check`, `wp_cron_audit`, `wp_rest_audit`, `wp_recommend_hardening`, `wp_describe_setup`, `bulk_audit_wordpress_sites`
- **C# / .NET** (4 dedicadas + branches) — `scan_dotnet_secrets`, `dotnet_target_framework_check`, `dotnet_efcore_audit`, `dotnet_describe_setup`; `scan_sast` corre `p/csharp` + parse da saída do security-code-scan; `deps_update_plan` corre `dotnet list package --outdated`; `observability_setup` gera templates Serilog + prometheus-net
- **Qualidade, deps, priorização** (5) — `quality_check`, `deps_update_plan`, `triage_findings`, `prioritize_findings`, `risk_score`
- **Compliance & SBOM** (5) — `compliance_check` (RGPD/GDPR), `compliance_evidence`, `generate_sbom` (Syft), `sbom_diff`, `license_compatibility`
- **Observability & perf** (3) — `observability_setup` (Pino/structlog/Monolog/Serilog + Prometheus), `health_status`, `perf_check` (k6 / Lighthouse)
- **Lifecycle / PR / governance** (10) — `init_project`, `precommit_install`, `review_pr`, `set_baseline`, `diff_scans`, `regression_alert`, `report_export` (HTML / **SARIF 2.1.0** / Markdown / JSON), `create_github_issues`, `suppress_finding`, `audit_executive`
- **AI-agent supply chain** (1) — `scan_skill`: vet a third-party **skill / MCP server / agent before you install it**. Accepts a directory, file, `.zip`, or git/HTTP(S) URL and runs 16 threat categories (prompt injection, data exfiltration, privilege escalation, supply chain, excessive agency, output handling, system-prompt leakage, memory poisoning, tool misuse, rogue agent, trigger abuse, dangerous code, taint, signatures, MCP least-privilege, MCP tool poisoning), a **YARA-style signature engine**, taint-light source→sink, hidden-Unicode detection, and **OSV.dev** CVE lookups — rolled up into a **0-100 risk score** and a **SAFE → DO NOT INSTALL** verdict
- **Meta / host** (4) — `detect_stack`, `check_toolchain`, `install_toolchain`, `install_host_context`

**Resources** — `guardian://wp/audit/latest`, `guardian://wp/audit/{scan_id}`, `guardian://wp/cron`, `guardian://dotnet/target-frameworks`, `guardian://dotnet/efcore`.

**Storage** — SQLite em `.guardian/guardian.db`. Tabelas: `scans`, `findings`, `cves`, `baselines`, `suppressions`, `stack_snapshots`. Permite tracking de baseline, deltas scan-a-scan, supressões com expiração, alertas de regressão.

### Ferramentas open-source orquestradas

Semgrep · Trivy · OSV.dev · gitleaks · Renovate · OWASP ZAP · Playwright · Pino / structlog / Monolog / Serilog · Prometheus + Grafana · GlitchTip · Uptime Kuma · k6 · Artillery · Lighthouse · Syft · WPScan · WP-CLI · PHPCS + WPCS · security-code-scan · dotnet-outdated · ruff · bandit · jscpd · eslint · hadolint · shellcheck.

### Instalação do plugin

#### A) Via marketplace (recomendado) — Claude Code CLI

```text
/plugin marketplace add https://github.com/linofcp007/dev-guardian
/plugin install dev-guardian@dev-guardian
```

Funciona com qualquer URL git (HTTPS ou SSH) ou caminho local de uma pasta que contenha [`.claude-plugin/marketplace.json`](.claude-plugin/marketplace.json).

> ⚠️ **Limitação da app Claude Desktop.** O cliente Desktop rejeita atualmente marketplaces de terceiros com `External plugin sources are not yet supported` (a feature está bloqueada server-side). É uma limitação do Claude Desktop, não um problema deste plugin — qualquer marketplace alojado no GitHub falha hoje da mesma forma. Issues a acompanhar: [anthropics/claude-code#41653](https://github.com/anthropics/claude-code/issues/41653) (fontes remotas), [anthropics/claude-code#52147](https://github.com/anthropics/claude-code/issues/52147) (paths locais). Até a paridade chegar, usa a opção **B** abaixo ou instala via Claude Code CLI.

#### B) Cópia manual da pasta (funciona em qualquer lado)

Copia a pasta inteira para:

- **Linux / macOS**: `~/.claude/plugins/dev-guardian/`
- **Windows**: `%USERPROFILE%\.claude\plugins\dev-guardian\`

Depois, dentro do Claude Code, corre `/plugin` e ativa o `dev-guardian`. Em alternativa, adiciona ao teu `~/.claude/settings.json`:

```json
{
  "enabledPlugins": { "dev-guardian@dev-guardian": true }
}
```

> O servidor MCP corre a partir de `mcp/dist/`. Na primeira instalação corre uma vez `cd mcp && npm install && npm run build`. Depois o plugin arranca-o automaticamente via `node ${pluginDir}/mcp/dist/server.js`.
>
> Os scripts `.sh` em `scripts/` correm direto em Linux/macOS. No Windows nativo precisas de **WSL2** ou Git Bash; as skills/commands em si funcionam em qualquer SO.

### Filosofia

- **Pragmático por defeito** — não bloqueia trabalho por nada cosmético
- **Paranoid quando crítico** — secrets em produção, RCE, SQLi → interrompe e alerta
- **Stack-aware** — detecta a tua linguagem e configura só o relevante
- **Cross-platform** — Linux, macOS, Windows (com WSL)
- **Zero lock-in** — todas as ferramentas usadas são open-source e self-hostable
- **Idempotente** — correr `guardian init` 2 vezes não duplica nada
- **Degradação graciosa** — scanners em falta são reportados, nunca crasham um scan

### Stacks suportadas

JavaScript / TypeScript (Node, Next, React, Vue, Svelte, Angular), Python (Django, Flask, FastAPI), PHP (Laravel, Symfony, **WordPress + Kadence + WooCommerce + Tutor LMS**), **C# / .NET (ASP.NET Core, EF Core, central package management)**, Go, Rust, Ruby, Java / Kotlin, Docker, Terraform, Kubernetes, Ansible, GitHub Actions.

Para linguagens não suportadas explicitamente, as skills caiem para Semgrep `--config=auto` (cobre 30+ linguagens) e regras genéricas para secrets.

### Estrutura do repositório

```text
dev-guardian/
├── .claude-plugin/
│   ├── plugin.json              # declara o servidor MCP + metadata
│   └── marketplace.json
├── commands/                    # 12 slash commands
├── skills/                      # 11 skills (uma por destino do router)
├── mcp/                         # Servidor MCP (TypeScript + SQLite)
│   ├── src/                     # tools/, resources/, runners/, storage/, platform/
│   ├── test/                    # 280 testes unit + integration
│   ├── scripts/                 # smoke.mjs, smoke-wp-dotnet.mjs
│   └── dist/                    # artefacto compilado (node dist/server.js)
├── scripts/
│   ├── detect/detect-stack.sh   # deteção de linguagens/frameworks
│   ├── install/                 # install-linux.sh, install-macos.sh
│   └── scan/                    # full-security-scan, review-scan, etc.
├── configs/
│   ├── renovate/, gitleaks/, semgrep/, pre-commit/
├── host-rules/                  # AGENTS.md, cursor.mdc, copilot-instructions.md, …
└── README.md
```

### Licença

MIT — usa, modifica, partilha à vontade.

### Autor

Carlos Pereira · prodigitalkey.com

---

## Español

Plugin todo-en-uno **100% open-source** para Claude Code / Cowork. Cubre seguridad, detección y corrección de bugs, calidad de código, gestión de dependencias, observabilidad, rendimiento y cumplimiento para cualquier proyecto de desarrollo. Stack-aware (Node, Python, PHP/WordPress, Go, Rust, Ruby, Java, **C# / .NET**), triggers trilingües (EN + PT + ES) — responde en el idioma del usuario.

Bajo el capó incluye un plugin Claude Code (11 skills + 12 slash commands) **y** un servidor MCP con **51 herramientas y 5 recursos**, con estado persistente en SQLite para baselines, deltas y supresiones. También hace **vet de skills / MCP servers / agentes de terceros antes de instalarlos** — la verificación de supply-chain del ecosistema de agentes.

### Skills (front-end de Claude Code)

| Skill                    | Slash command          | Qué hace                                                 |
| ------------------------ | ---------------------- | -------------------------------------------------------- |
| `guardian`               | `/guardian`            | Router principal — dirige al módulo adecuado             |
| `guardian-init`          | `/guardian-init`       | Bootstrap inicial — instala y configura todo             |
| `guardian-security`      | `/guardian-scan`       | SAST + secretos + CVEs + contenedor + IaC                |
| `guardian-bugfix`        | `/guardian-fix`        | Caza y corrige bugs de implementación                    |
| `guardian-quality`       | `/guardian-quality`    | Complejidad, duplicación, deuda técnica                  |
| `guardian-review`        | `/guardian-review`     | Revisión profunda pre-PR / pre-despliegue                |
| `guardian-deps`          | `/guardian-deps`       | Setup de Renovate + escaneo de CVEs + supply chain       |
| `guardian-observability` | `/guardian-observe`    | Logging estructurado, métricas, error tracking           |
| `guardian-performance`   | `/guardian-perf`       | Performance budgets, k6, Lighthouse                      |
| `guardian-compliance`    | `/guardian-compliance` | RGPD/LOPD, licencias, SBOM, política de privacidad       |
| `guardian-scanskill`     | `/guardian-scanskill`  | Vet de skill / servidor MCP / agente antes de instalar   |
| (combina 3 de ellas)     | `/guardian-audit`      | Informe ejecutivo: seguridad + calidad + deps            |

También puedes invocarlo todo en **lenguaje natural** (ES, EN o PT). Las skills se disparan por descripción — *"audita el proyecto"*, *"comprueba vulnerabilidades"*, *"antes del merge"*, *"audit the project"*, *"check for vulnerabilities"*, *"before merge"*, *"audita o projeto"*, *"vê se há vulnerabilidades"*, *"antes de fazer merge"*.

### Servidor MCP (51 herramientas, 5 recursos)

El plugin registra un servidor MCP en stdio que Claude Code arranca automáticamente. Las herramientas se agrupan en:

- **Seguridad transversal** (10) — `security_scan_full`, `scan_sast`, `scan_deps`, `scan_secrets`, `scan_containers`, `scan_iac`, `deps_audit`, `bug_hunt`, `suggest_fix`, `register_custom_rules`
- **WordPress** (9) — `scan_wordpress` (Semgrep PHP + rule pack WP + Trivy + gitleaks + PHPCS-WPCS), `wp_audit` (instalación en vivo: checksums + admins + flags de configuración vía WP-CLI), `wp_vuln_check` (WPScan DB), `wp_plugin_check`, `wp_cron_audit`, `wp_rest_audit`, `wp_recommend_hardening`, `wp_describe_setup`, `bulk_audit_wordpress_sites`
- **C# / .NET** (4 dedicadas + ramas) — `scan_dotnet_secrets`, `dotnet_target_framework_check`, `dotnet_efcore_audit`, `dotnet_describe_setup`; `scan_sast` corre `p/csharp` + parsea la salida de security-code-scan; `deps_update_plan` corre `dotnet list package --outdated`; `observability_setup` genera plantillas Serilog + prometheus-net
- **Calidad, deps, priorización** (5) — `quality_check`, `deps_update_plan`, `triage_findings`, `prioritize_findings`, `risk_score`
- **Compliance & SBOM** (5) — `compliance_check` (RGPD/GDPR), `compliance_evidence`, `generate_sbom` (Syft), `sbom_diff`, `license_compatibility`
- **Observabilidad & rendimiento** (3) — `observability_setup` (Pino/structlog/Monolog/Serilog + Prometheus), `health_status`, `perf_check` (k6 / Lighthouse)
- **Lifecycle / PR / gobierno** (10) — `init_project`, `precommit_install`, `review_pr`, `set_baseline`, `diff_scans`, `regression_alert`, `report_export` (HTML / **SARIF 2.1.0** / Markdown / JSON), `create_github_issues`, `suppress_finding`, `audit_executive`
- **Cadena de suministro de agentes IA** (1) — `scan_skill`: audita una **skill / servidor MCP / agente de terceros antes de instalarlo**. Acepta un directorio, archivo, `.zip` o URL git/HTTP(S) y corre 16 categorías de amenaza (prompt injection, exfiltración de datos, escalada de privilegios, supply chain, agencia excesiva, manejo de salida, fuga del system-prompt, envenenamiento de memoria, mal uso de tools, agente rogue, abuso de triggers, código peligroso, taint, firmas, MCP least-privilege, MCP tool poisoning), un motor de **firmas estilo YARA**, taint-light source→sink, detección de Unicode oculto y lookups de CVE en **OSV.dev** — todo agregado en una **puntuación de riesgo 0-100** y un veredicto **SAFE → DO NOT INSTALL**
- **Meta / host** (4) — `detect_stack`, `check_toolchain`, `install_toolchain`, `install_host_context`

**Recursos** — `guardian://wp/audit/latest`, `guardian://wp/audit/{scan_id}`, `guardian://wp/cron`, `guardian://dotnet/target-frameworks`, `guardian://dotnet/efcore`.

**Almacenamiento** — SQLite en `.guardian/guardian.db`. Tablas: `scans`, `findings`, `cves`, `baselines`, `suppressions`, `stack_snapshots`. Permite tracking de baseline, deltas scan-a-scan, supresiones con caducidad, alertas de regresión.

### Herramientas open-source orquestadas

Semgrep · Trivy · OSV.dev · gitleaks · Renovate · OWASP ZAP · Playwright · Pino / structlog / Monolog / Serilog · Prometheus + Grafana · GlitchTip · Uptime Kuma · k6 · Artillery · Lighthouse · Syft · WPScan · WP-CLI · PHPCS + WPCS · security-code-scan · dotnet-outdated · ruff · bandit · jscpd · eslint · hadolint · shellcheck.

### Instalación del plugin

#### A) Vía marketplace (recomendado) — Claude Code CLI

```text
/plugin marketplace add https://github.com/linofcp007/dev-guardian
/plugin install dev-guardian@dev-guardian
```

Funciona con cualquier URL git (HTTPS o SSH) o ruta local de una carpeta que contenga [`.claude-plugin/marketplace.json`](.claude-plugin/marketplace.json).

> ⚠️ **Limitación de la app Claude Desktop.** El cliente Desktop rechaza actualmente marketplaces de terceros con `External plugin sources are not yet supported` (la funcionalidad está bloqueada server-side). Es una limitación de Claude Desktop, no un problema de este plugin — cualquier marketplace alojado en GitHub falla hoy de la misma forma. Issues a seguir: [anthropics/claude-code#41653](https://github.com/anthropics/claude-code/issues/41653) (fuentes remotas), [anthropics/claude-code#52147](https://github.com/anthropics/claude-code/issues/52147) (rutas locales). Hasta que llegue la paridad, usa la opción **B** abajo o instala vía el Claude Code CLI.

#### B) Copia manual de carpeta (funciona en todas partes)

Copia la carpeta entera a:

- **Linux / macOS**: `~/.claude/plugins/dev-guardian/`
- **Windows**: `%USERPROFILE%\.claude\plugins\dev-guardian\`

Luego, dentro de Claude Code, ejecuta `/plugin` y activa `dev-guardian`. Alternativamente, añade a tu `~/.claude/settings.json`:

```json
{
  "enabledPlugins": { "dev-guardian@dev-guardian": true }
}
```

> El servidor MCP corre desde `mcp/dist/`. En la primera instalación ejecuta una vez `cd mcp && npm install && npm run build`. Después el plugin lo arranca automáticamente vía `node ${pluginDir}/mcp/dist/server.js`.
>
> Los scripts `.sh` en `scripts/` corren directamente en Linux/macOS. En Windows nativo necesitas **WSL2** o Git Bash; las skills/commands en sí funcionan en cualquier SO.

### Filosofía

- **Pragmático por defecto** — no bloquea el trabajo por cuestiones cosméticas
- **Paranoico cuando es crítico** — secretos en producción, RCE, SQLi → detiene y alerta
- **Stack-aware** — detecta tu lenguaje y configura solo lo relevante
- **Multiplataforma** — Linux, macOS, Windows (con WSL)
- **Cero lock-in** — todas las herramientas usadas son open-source y self-hostable
- **Idempotente** — ejecutar `guardian init` dos veces no duplica nada
- **Degradación elegante** — escáneres ausentes se reportan, nunca tumban un scan

### Stacks soportados

JavaScript / TypeScript (Node, Next, React, Vue, Svelte, Angular), Python (Django, Flask, FastAPI), PHP (Laravel, Symfony, **WordPress + Kadence + WooCommerce + Tutor LMS**), **C# / .NET (ASP.NET Core, EF Core, central package management)**, Go, Rust, Ruby, Java / Kotlin, Docker, Terraform, Kubernetes, Ansible, GitHub Actions.

Para lenguajes no soportados explícitamente, las skills recurren a Semgrep `--config=auto` (cubre más de 30 lenguajes) y reglas genéricas para secretos.

### Estructura del repositorio

```text
dev-guardian/
├── .claude-plugin/
│   ├── plugin.json              # declara el servidor MCP + metadatos
│   └── marketplace.json
├── commands/                    # 12 slash commands
├── skills/                      # 11 skills (una por destino del router)
├── mcp/                         # Servidor MCP (TypeScript + SQLite)
│   ├── src/                     # tools/, resources/, runners/, storage/, platform/
│   ├── test/                    # 280 tests unit + integration
│   ├── scripts/                 # smoke.mjs, smoke-wp-dotnet.mjs
│   └── dist/                    # artefacto compilado (node dist/server.js)
├── scripts/
│   ├── detect/detect-stack.sh   # detección de lenguajes/frameworks
│   ├── install/                 # install-linux.sh, install-macos.sh
│   └── scan/                    # full-security-scan, review-scan, etc.
├── configs/
│   ├── renovate/, gitleaks/, semgrep/, pre-commit/
├── host-rules/                  # AGENTS.md, cursor.mdc, copilot-instructions.md, …
└── README.md
```

### Licencia

MIT — úsalo, modifícalo, compártelo libremente.

### Autoría

Carlos Pereira · prodigitalkey.com
