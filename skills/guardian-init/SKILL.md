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

| Ficheiro                  | Origem                                      | Notas                            |
| ------------------------- | ------------------------------------------- | -------------------------------- |
| `.gitleaks.toml`          | `configs/gitleaks/gitleaks.toml`            | Sempre                           |
| `.semgrep.yml`            | `configs/semgrep/base.yml`                  | Regras próprias, multi-linguagem |
| `renovate.json`           | `configs/renovate/renovate.json`            | Sempre (substitui Dependabot)    |
| `.pre-commit-config.yaml` | `configs/pre-commit/pre-commit-config.yaml` | Cobre todas as linguagens        |

`base.yml` e `pre-commit-config.yaml` já vêm combinados para todas as
linguagens que este repositório suporta — não existe um ficheiro por
linguagem (`configs/semgrep/<linguagem>.yml`,
`configs/pre-commit/<linguagem>.yaml`) apesar do nome sugerir isso.

Não existe um template de workflow CI para copiar — este repositório não gera
ficheiros `.github/workflows/` (decisão de projeto: local-first, sem CI
recorrente a pagar; ver `CHANGELOG.md`, "Dropped the GitHub Actions CI
workflow"). A proteção equivalente é local: os hooks de pre-commit instalados
no passo 5, a tool `review_pr` (scan do diff antes de merge) e a tool
`create_github_issues` (findings viram issues sem precisar de Actions). Se o
utilizador pedir explicitamente um workflow CI, é preciso escrevê-lo de raiz —
não copiar de um template, porque não existe nenhum neste repositório.

Não copies os ficheiros à mão: chama `init_project`, que já faz tudo isto e —
ao contrário de um `cp` — deixa registo do que copiou.

### 4a. Proveniência: o que fica registado

Cada ficheiro copiado é registado em `.dev-guardian/configs.json` (destino,
origem, versão do plugin e hash do conteúdo no momento da cópia), e leva um
cabeçalho de comentário quando o formato permite. `renovate.json` é JSON e não
aceita comentários, por isso é o manifesto — e não o cabeçalho — o mecanismo
verdadeiro; o cabeçalho é só uma conveniência para quem abre o ficheiro.

Este manifesto **é para ir para o commit**, ao contrário de `.guardian/`, que
está no `.gitignore`: é o que permite que o clone de um colega e a CI saibam de
que baseline vem cada config.

`init_project` nunca substitui um ficheiro que já exista — mas, se o conteúdo
for byte a byte igual ao que distribuímos, adota-o no manifesto (não escreve
nada no ficheiro do utilizador). É assim que um projeto anterior a este
mecanismo passa a ser verificável.

### 4b. Configs desatualizadas: `refresh`

Uma correção a uma config distribuída não chegava a quem já tinha corrido o
init. Foi exatamente o que aconteceu com a regra `wp-unescaped-output` do
`base.yml`, que não conseguia dar match em nada e foi corrigida em `b51a2dc`.

A partir do registo de proveniência, qualquer scan compara os hashes e emite
**uma linha de aviso** — nunca um finding, nunca um erro, nunca bloqueante —
apenas em dois casos: distribuímos uma baseline mais recente e a cópia do
utilizador não mudou, ou mudaram os dois lados. Se o utilizador editou a sua
cópia e nós não mexemos na nossa, não se diz nada: é o caso esperado.

Para resolver, sempre nesta ordem:

```text
init_project(project_path=".", refresh=true, apply=false)   # mostra o que mudaria
init_project(project_path=".", refresh=true, apply=true)    # aplica
```

O que `apply=true` faz, por ficheiro:

| Situação                                     | Ação                                          |
| -------------------------------------------- | --------------------------------------------- |
| Não existe no projeto                        | Cria                                          |
| Existe e nunca foi tocado desde a instalação | Atualiza no sítio                             |
| Existe e foi editado, ou divergiu            | Escreve `<nome>.new` ao lado; não toca no teu |
| Proveniência desconhecida (sem manifesto)    | Igual ao anterior — nunca se adivinha         |

**Nenhuma flag substitui um ficheiro modificado.** Se aparecer um `.new`, o
passo seguinte é do utilizador: fazer o merge à mão e apagar o `.new` — o aviso
desaparece quando o `.new` deixar de existir.

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
  3. Faz commit dos ficheiros gerados (o manifesto vai junto — é o que
     permite avisar-te quando uma config distribuída for corrigida):
     git add .pre-commit-config.yaml .gitleaks.toml renovate.json .semgrep.yml \
             .dev-guardian/configs.json
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
