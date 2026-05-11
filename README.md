# dev-guardian

[English](#english) · [Português](#português)

---

## English

All-in-one **100% open-source** plugin for Claude Code / Cowork. Handles security, bug detection and fixing, code quality, observability and compliance for any dev project.

### What it does

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
| (combines 3 of them)     | `/guardian-audit`      | Executive report: security + quality + deps               |

You can also trigger everything via **natural language** (EN or PT) — skills fire from descriptions. Examples:

- English: *"audit the project"*, *"check for vulnerabilities"*, *"before merge"*
- Português: *"audita o projeto"*, *"vê se há vulnerabilidades"*, *"antes de fazer merge"*

### Tools used (all open-source)

- **Semgrep** — static analysis (SAST)
- **Trivy** — dependency, container and IaC vulnerabilities
- **gitleaks** — secrets scanning
- **Renovate** — automated dependency updates
- **OWASP ZAP** — DAST (optional)
- **Playwright** — E2E tests
- **k6** — load testing
- **Syft** — SBOM
- **Pino / structlog** — structured logging
- **GlitchTip** — self-hostable error tracking (Sentry SDK compatible)
- **Prometheus + Grafana** — metrics
- **Uptime Kuma** — uptime monitoring
- **ruff, bandit, jscpd, eslint, hadolint, shellcheck** — linters

### Plugin installation

#### A) Via marketplace (recommended, shareable)

Inside Claude Code:

```text
/plugin marketplace add https://github.com/linofcp007/dev-guardian
/plugin install dev-guardian@dev-guardian
```

Works with any git URL (HTTPS or SSH) or local folder path containing [`.claude-plugin/marketplace.json`](.claude-plugin/marketplace.json).

#### B) Manual folder copy

Copy the whole folder to:

- **Linux / macOS**: `~/.claude/plugins/dev-guardian/`
- **Windows**: `%USERPROFILE%\.claude\plugins\dev-guardian\`

Then inside Claude Code, run `/plugin` and enable `dev-guardian`. Alternatively, add to your `~/.claude/settings.json`:

```json
{
  "enabledPlugins": { "dev-guardian@dev-guardian": true }
}
```

> Note: `.sh` scripts in `scripts/` run natively on Linux/macOS. On Windows you need **WSL2** or Git Bash; the skills/commands themselves work on any OS.

### Typical usage — first project

```text
You: "I have a new project, set up all the security and quality stuff"

Claude (with dev-guardian):
  → runs guardian-init
  → detects the stack (Node + TS + Docker)
  → shows install plan
  → you approve
  → installs Semgrep, Trivy, gitleaks, Renovate, pre-commit
  → copies base configs
  → adds CI workflow
  → runs initial scan in report-only mode
  → shows status: "Red 0, Yellow 2, Green 14"
```

After that, you use the other modes as needed.

### Philosophy

- **Pragmatic by default** — doesn't block work over cosmetics
- **Paranoid when critical** — prod secrets, RCE, SQLi → halt and alert
- **Stack-aware** — detects your language and only configures what's relevant
- **Cross-platform** — Linux, macOS, Windows (with WSL)
- **Zero lock-in** — every tool used is open-source and self-hostable
- **Idempotent** — running `guardian init` twice doesn't duplicate anything

### Supported stacks

JavaScript/TypeScript (Node, Next, React, Vue, Svelte, Angular), Python (Django, Flask, FastAPI), PHP (Laravel, Symfony, WordPress + Kadence), Go, Rust, Ruby, Java/Kotlin, Docker, Terraform, Kubernetes, Ansible, GitHub Actions.

For languages not explicitly supported, the skill falls back to Semgrep `--config=auto` (covers 30+ languages) and generic secret rules.

### Plugin structure

```text
dev-guardian/
├── .claude-plugin/
│   └── plugin.json
├── commands/                     # 11 slash commands (/guardian, /guardian-init, …)
├── skills/                       # 10 skills, one per mode
│   ├── guardian/                 # main router
│   ├── guardian-init/
│   ├── guardian-security/
│   ├── guardian-bugfix/
│   ├── guardian-quality/
│   ├── guardian-review/
│   ├── guardian-deps/
│   ├── guardian-observability/
│   ├── guardian-performance/
│   └── guardian-compliance/
├── scripts/
│   ├── detect/detect-stack.sh    # language/framework detection
│   ├── install/                  # install-linux.sh, install-macos.sh
│   └── scan/                     # full-security-scan, review-scan, etc.
├── configs/
│   ├── renovate/renovate.json
│   ├── gitleaks/gitleaks.toml
│   ├── semgrep/base.yml
│   └── pre-commit/pre-commit-config.yaml
├── workflows/
│   └── github-actions/           # dev-guardian.yml, e2e.yml, zap-baseline.yml
└── README.md
```

### License

MIT — use it, modify it, share it freely.

### Author

Carlos Pereira · prodigitalkey.com

---

## Português

Plugin all-in-one **100% open-source** para Claude Code/Cowork. Faz segurança, deteção e correção de bugs, qualidade de código, observability e compliance em qualquer projeto de desenvolvimento.

### O que faz

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
| (combina os 3)           | `/guardian-audit`      | Relatório executivo: security + quality + deps           |

Também podes invocar tudo em **linguagem natural** (PT ou EN) — as skills disparam por descrição. Exemplos:

- Português: *"audita o projeto"*, *"vê se há vulnerabilidades"*, *"antes de fazer merge"*
- English: *"audit the project"*, *"check for vulnerabilities"*, *"before merge"*

### Ferramentas usadas (todas open-source)

- **Semgrep** — análise estática (SAST)
- **Trivy** — vulnerabilidades de deps, containers, IaC
- **gitleaks** — scanning de secrets
- **Renovate** — atualização automática de dependências
- **OWASP ZAP** — DAST (opcional)
- **Playwright** — testes E2E
- **k6** — load testing
- **Syft** — SBOM
- **Pino / structlog** — logging estruturado
- **GlitchTip** — error tracking self-hostable (compatível com Sentry SDK)
- **Prometheus + Grafana** — métricas
- **Uptime Kuma** — uptime monitoring
- **ruff, bandit, jscpd, eslint, hadolint, shellcheck** — linters

### Instalação do plugin

#### A) Via marketplace (recomendado, partilhável)

Dentro do Claude Code:

```text
/plugin marketplace add https://github.com/linofcp007/dev-guardian
/plugin install dev-guardian@dev-guardian
```

Funciona com qualquer URL git (HTTPS ou SSH) ou caminho local de uma pasta que contenha [`.claude-plugin/marketplace.json`](.claude-plugin/marketplace.json).

#### B) Cópia manual da pasta

Copia a pasta inteira para:

- **Linux / macOS**: `~/.claude/plugins/dev-guardian/`
- **Windows**: `%USERPROFILE%\.claude\plugins\dev-guardian\`

Depois, dentro do Claude Code, corre `/plugin` e ativa o `dev-guardian`. Em alternativa, adiciona ao teu `~/.claude/settings.json`:

```json
{
  "enabledPlugins": { "dev-guardian@dev-guardian": true }
}
```

> Nota: os scripts `.sh` em `scripts/` correm direto em Linux/macOS. No Windows nativo precisas de **WSL2** ou Git Bash; as skills/commands em si funcionam em qualquer SO.

### Uso típico — primeiro projeto

```text
Tu: "Tenho um projeto novo, configura-me tudo de segurança e qualidade"

Claude (com dev-guardian):
  → corre guardian-init
  → deteta o stack (Node + TS + Docker)
  → mostra plano de instalação
  → tu aprovas
  → instala Semgrep, Trivy, gitleaks, Renovate, pre-commit
  → copia configs base
  → adiciona workflow CI
  → corre scan inicial em modo report-only
  → mostra estado: "Vermelho 0, Amarelo 2, Verde 14"
```

Depois disso, podes usar os outros modos consoante a necessidade.

### Filosofia

- **Pragmático por defeito** — não bloqueia trabalho por nada cosmético
- **Paranoid quando crítico** — secrets em produção, RCE, SQLi → interrompe e alerta
- **Stack-aware** — detecta a tua linguagem e configura só o relevante
- **Cross-platform** — Linux, macOS, Windows (com WSL)
- **Zero lock-in** — todas as ferramentas usadas são open-source e self-hostable
- **Idempotente** — correr `guardian init` 2 vezes não duplica nada

### Stacks suportadas

JavaScript/TypeScript (Node, Next, React, Vue, Svelte, Angular), Python (Django, Flask, FastAPI), PHP (Laravel, Symfony, WordPress + Kadence), Go, Rust, Ruby, Java/Kotlin, Docker, Terraform, Kubernetes, Ansible, GitHub Actions.

Para linguagens não suportadas explicitamente, a skill tenta com Semgrep `--config=auto` (que cobre 30+ linguagens) e regras genéricas para secrets.

### Estrutura do plugin

```text
dev-guardian/
├── .claude-plugin/
│   └── plugin.json
├── commands/                     # 11 slash commands (/guardian, /guardian-init, …)
├── skills/                       # 10 skills, uma por modo
│   ├── guardian/                 # router principal
│   ├── guardian-init/
│   ├── guardian-security/
│   ├── guardian-bugfix/
│   ├── guardian-quality/
│   ├── guardian-review/
│   ├── guardian-deps/
│   ├── guardian-observability/
│   ├── guardian-performance/
│   └── guardian-compliance/
├── scripts/
│   ├── detect/detect-stack.sh    # deteção de linguagens/frameworks
│   ├── install/                  # install-linux.sh, install-macos.sh
│   └── scan/                     # full-security-scan, review-scan, etc.
├── configs/
│   ├── renovate/renovate.json
│   ├── gitleaks/gitleaks.toml
│   ├── semgrep/base.yml
│   └── pre-commit/pre-commit-config.yaml
├── workflows/
│   └── github-actions/           # dev-guardian.yml, e2e.yml, zap-baseline.yml
└── README.md
```

### Licença

MIT — usa, modifica, partilha à vontade.

### Autor

Carlos Pereira · prodigitalkey.com
