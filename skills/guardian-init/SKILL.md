---
name: guardian-init
description: Bootstrap a new project with the full open-source security and quality infrastructure (Semgrep, Trivy, gitleaks, Renovate, pre-commit, CI). EN triggers — use when the user says "guardian init", "set up the project", "protect the repo", "install everything", "security setup", "starting a new project", "how do I make this production-ready", "install dev-guardian here", "configure quality tools", or any equivalent on a project that has no security CI yet. PT triggers — usa quando o utilizador disser "guardian init", "configura o projeto", "protege o repo", "instala tudo", "setup de segurança", "vou começar um projeto novo", "como deixo isto pronto", "instala dev-guardian aqui", "configura ferramentas de qualidade". ES triggers — úsala cuando el usuario diga "guardian init", "configura el proyecto", "protege el repo", "instala todo", "setup de seguridad", "voy a empezar un proyecto nuevo", "¿cómo dejo esto listo para producción?", "instala dev-guardian aquí", "configura herramientas de calidad". Trilingual EN/PT/ES — respond in the user's language.
---

# Guardian Init

Inicializa um projeto com toda a infraestrutura de segurança, qualidade e CI usando ferramentas open-source. Detecta automaticamente o stack e instala apenas o que faz sentido para esse projeto.

## Fluxo

### 1. Detectar o stack

Corre o script de detecção:

```bash
bash ${CLAUDE_PLUGIN_ROOT}/scripts/detect/detect-stack.sh <project-path>
```

Output esperado: JSON com `languages`, `package_managers`, `frameworks`, `existing_tools`, `os`, `has_docker`, `has_iac`.

Lê o output para decidir o que instalar.

### 2. Mostrar plano ao utilizador

Antes de instalar/configurar qualquer coisa, apresenta um plano em formato curto:

```text
Detectei: Node.js + TypeScript (npm), Python (poetry), Dockerfile, GitHub Actions
Vou configurar:
  ✓ Semgrep (SAST para JS/TS + Python)
  ✓ Trivy (scan de deps + container)
  ✓ gitleaks (secrets, com pre-commit hook)
  ✓ Renovate (atualização de deps)
  ✓ pre-commit framework (orquestra hooks locais)
  ✓ Workflow CI: .github/workflows/dev-guardian.yml
  ✓ ESLint + ruff configurados para correrem em CI
Não vou tocar em: README, código aplicacional, configs existentes.
OK avançar?
```

Pergunta confirmação. Se o utilizador disser "só X e Y", instala só esses.

### 3. Instalar ferramentas (sistema)

Corre o instalador apropriado para o OS detectado:

- Linux (Ubuntu/Debian): `bash ${CLAUDE_PLUGIN_ROOT}/scripts/install/install-linux.sh`
- macOS: `bash ${CLAUDE_PLUGIN_ROOT}/scripts/install/install-macos.sh`
- Windows: instruir o utilizador a usar WSL2; correr o script Linux dentro do WSL

O instalador é idempotente — verifica antes de instalar, não duplica.

### 4. Configurar o projeto

Copia templates apropriados para o projeto:

| Ficheiro                             | Origem                                          | Notas                                  |
| ------------------------------------ | ----------------------------------------------- | -------------------------------------- |
| `.gitleaks.toml`                     | `configs/gitleaks/gitleaks.toml`                | Sempre                                 |
| `.semgrep.yml`                       | `configs/semgrep/<linguagem>.yml`               | Combina vários se polyglot             |
| `renovate.json`                      | `configs/renovate/renovate.json`                | Sempre (substitui Dependabot)          |
| `.pre-commit-config.yaml`            | `configs/pre-commit/<linguagem>.yaml`           | Combina hooks para todas as linguagens |
| `.github/workflows/dev-guardian.yml` | `workflows/github-actions/dev-guardian.yml`     | Workflow principal                     |
| `.github/workflows/e2e.yml`          | `workflows/github-actions/e2e.yml`              | Só se for webapp                       |

Antes de copiar qualquer ficheiro, verifica se já existe. Se sim, perguntar:

- Substituir (backup do antigo como `.bak`)
- Fazer merge (se o template é compatível com o que está)
- Ignorar (manter o existente)

### 5. Hook de pre-commit

Depois de copiar `.pre-commit-config.yaml`, corre:

```bash
pre-commit install
pre-commit install --hook-type commit-msg
```

Isto liga os hooks ao git local.

### 6. Validar instalação

Corre um scan inicial mas em modo "report only" — não bloqueia, só mostra o estado atual:

```bash
bash ${CLAUDE_PLUGIN_ROOT}/scripts/scan/initial-scan.sh
```

### 7. Relatório final

Apresenta:

```text
✅ Dev-Guardian instalado.

Estado atual do projeto:
  🔴 Crítico: 0
  🟡 Alto: 2 (deps com CVE — corrige com `guardian deps`)
  🟢 Médio: 14 (linting, code smells)

Próximos passos sugeridos:
  1. Corre `guardian deps` para atualizar dependências vulneráveis
  2. Liga Renovate no GitHub: github.com/apps/renovate (1 clique)
  3. Faz commit dos ficheiros gerados:
     git add .pre-commit-config.yaml .gitleaks.toml renovate.json .github/workflows/
     git commit -m "chore: setup dev-guardian"
```

## Detalhes por stack

### Node.js / TypeScript

Instala/configura:

- Semgrep com regras `p/javascript`, `p/typescript`, `p/owasp-top-ten`, `p/react` se React detectado
- ESLint + `@typescript-eslint` se TS detectado
- Trivy para `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- Pré-instala Playwright se for app web (com `playwright install --with-deps`)

### Python

Instala/configura:

- Semgrep com regras `p/python`, `p/django` ou `p/flask` se aplicável, `p/owasp-top-ten`
- `ruff` (lint + format, substitui flake8/black/isort)
- `bandit` como SAST específico de Python (complementa Semgrep)
- Trivy para `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock`

### PHP / WordPress

Instala/configura:

- Semgrep com regras `p/php` e regras custom para WordPress se detectado `wp-config.php`
- PHPStan ou Psalm (lint estático)
- Trivy para `composer.lock`
- Regras específicas para Kadence/WordPress se detectado o tema/plugin

### Go

- `staticcheck`, `gosec`
- Trivy para `go.sum`

### Rust

- `cargo audit`, `cargo deny`, `clippy`
- Trivy para `Cargo.lock`

### Ruby

- `brakeman` (segurança Rails)
- `rubocop` (lint)
- Trivy para `Gemfile.lock`

### Java / Kotlin

- SpotBugs + FindSecBugs
- Trivy para `pom.xml` / `build.gradle`

### Docker / IaC

- Trivy para `Dockerfile` e imagens
- Checkov para Terraform/Kubernetes/Ansible (instalar opcionalmente)

## Notas de portabilidade

- Nunca codifica caminhos absolutos. Usa `${CLAUDE_PLUGIN_ROOT}` para referências internas.
- Os scripts de instalação são bash mas detectam o package manager (`apt`, `brew`, `dnf`, `pacman`).
- Para Windows, falha cedo e indica WSL2.

## Resolução de problemas comuns

- **"sudo: command not found"** — o utilizador pode não ter sudo (container, VPS minimal). Os scripts oferecem alternativa "binário portátil em `~/.local/bin`" sem sudo.
- **"command not found: pre-commit"** — instalar via `pip install --user pre-commit` ou `pipx install pre-commit`.
- **Conflitos com Dependabot existente** — perguntar ao utilizador se quer migrar para Renovate (recomendado) ou manter ambos.
