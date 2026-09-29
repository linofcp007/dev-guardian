---
name: guardian-init
description: Bootstrap a project with dev-guardian through its MCP tools — detect the stack, install the scanners (Semgrep, Trivy, gitleaks, Syft, pre-commit) on Linux, macOS or Windows, install the gitleaks / Semgrep / Renovate / pre-commit configs with provenance tracking (minimal, standard or paranoid profile), wire the git hooks, and report the first security status. EN triggers — "set up the project", "protect the repo", "install everything", "security setup", "starting a new project", "make this production-ready", "install dev-guardian here". PT — "configura o projeto", "protege o repo", "instala tudo", "setup de segurança", "vou começar um projeto novo", "como deixo isto pronto", "instala o dev-guardian aqui". ES — "configura el proyecto", "protege el repo", "instala todo", "setup de seguridad", "voy a empezar un proyecto nuevo", "¿cómo dejo esto listo para producción?". Respond in the user's language.
---

# Guardian Init

Inicializa um projeto com a infraestrutura de segurança e qualidade do dev-guardian. Tudo passa pelas tools MCP — ao contrário de um `cp` ou de um script à mão, deixam registo do que foi instalado e de onde veio.

## Fluxo

### 1. Detetar o stack

`detect_stack { project_path: "<project>" }` — corre em processo, sem shell. Devolve `languages`, `package_managers`, `frameworks`, `existing_tools`, `os`, `has_docker`, `has_compose`, `has_iac` (`has_terraform`, `has_kubernetes`, `has_ansible`), `has_github_actions`, `has_gitlab_ci` e `projects` (detalhe por sub-projeto, quando há manifestos aninhados).

### 2. Ver o que está instalado

`check_toolchain {}` — para cada scanner do catálogo: instalado ou não, versão, versão mínima esperada, versões comprometidas conhecidas (com o advisory), que tools MCP dependem dele e o comando de instalação para este sistema.

### 3. Mostrar o plano ao utilizador

Antes de instalar ou escrever qualquer coisa, um plano curto:

```text
Detetei: Node.js + TypeScript (npm), Python (poetry), Dockerfile
Vou instalar (em falta): trivy, gitleaks
Vou configurar no projeto (perfil standard):
  ✓ .gitleaks.toml            (secrets)
  ✓ .semgrep.yml              (regras próprias, multi-linguagem)
  ✓ renovate.json             (atualização de dependências)
  ✓ .pre-commit-config.yaml   (gitleaks, semgrep, ruff, hadolint, … como hooks)
Não toco em: README, código aplicacional, configs que já existam.
OK avançar?
```

Pergunta confirmação. Se o utilizador disser "só X e Y", faz só isso.

### 4. Instalar os scanners

`install_toolchain { dry_run: true }` mostra os comandos; depois, com aprovação, `install_toolchain {}`. Sem `tools`, instala o conjunto por omissão (semgrep, trivy, gitleaks, syft, pre-commit, mais ruff / bandit / jscpd quando o stack os pede); `tools: ["hadolint", "lighthouse"]` limita a esses.

- Linux e macOS: delega em `scripts/install/install-linux.sh` / `install-macos.sh` (detetam `apt`, `dnf`, `pacman`, `brew`).
- Windows: winget, scoop ou choco (ou WSL) — funciona nativamente, não é preciso mudar de sistema.
- O Syft, o Trivy e o gitleaks vêm sempre de uma release fixada, com o sha256 verificado antes de desempacotar — nunca "a mais recente". Em Windows, o ZIP é descarregado pelo PowerShell para `%USERPROFILE%\.local\bin`, que tem de estar no `PATH` (o instalador avisa se não estiver); winget, scoop e choco ficam como alternativa, na mesma versão.
- Passos que precisam de sudo / admin (apt, choco, `npm install -g`) só correm com `elevation_allowed: true`; sem isso aparecem em `requires_elevation`, para o utilizador correr.

### 5. Configurar o projeto

`init_project { project_path: "<project>", apply: false }` mostra a lista de ficheiros; com aprovação, `init_project { project_path: "<project>" }` (`apply` é `true` por omissão) copia-os.

| Perfil | Ficheiros |
| --- | --- |
| `minimal` | `.gitleaks.toml`, `renovate.json` |
| `standard` (omissão) | + `.semgrep.yml` (`configs/semgrep/base.yml`), `.pre-commit-config.yaml` |
| `paranoid` | os mesmos, mas o gitleaks sem allowlists de conteúdo (fixtures, placeholders, stopwords) e o Renovate sem automerge em lado nenhum, com 7 dias de idade mínima em vez de 3 |

`profile: "paranoid"` para projetos críticos. `base.yml` e `pre-commit-config.yaml` já vêm combinados para todas as linguagens suportadas — não há um ficheiro por linguagem.

Não existe template de workflow CI: o dev-guardian não gera `.github/workflows/` (local-first; ver `CHANGELOG.md`, "Dropped the GitHub Actions CI workflow"). A proteção equivalente é local — os hooks de pre-commit do passo 6, `review_pr` antes do merge e `create_github_issues` para transformar findings em issues. Se o utilizador pedir um workflow CI, escreve-se de raiz; o CLI do dev-guardian tem um modo headless próprio para isso (`node "${CLAUDE_PLUGIN_ROOT}/cli/dev-guardian.mjs" scan`, com exit codes para gate).

#### Proveniência: o que fica registado

Cada ficheiro copiado é registado em `.dev-guardian/configs.json` (destino, origem, versão do plugin e hash do conteúdo no momento da cópia), e leva um cabeçalho de comentário quando o formato o permite (`renovate.json` é JSON e não aceita comentários — aí só o manifesto conta).

Este manifesto **vai para o commit**, ao contrário de `.guardian/`, que está no `.gitignore`: é o que permite que o clone de um colega e a CI saibam de que baseline vem cada config.

`init_project` nunca substitui um ficheiro que já exista — mas, se o conteúdo for byte a byte igual ao distribuído, adota-o no manifesto (sem escrever no ficheiro do utilizador). É assim que um projeto anterior a este mecanismo passa a ser verificável.

#### Configs desatualizadas: `refresh`

Qualquer scan compara os hashes do manifesto e emite **uma linha de aviso** — nunca um finding, nunca um erro, nunca bloqueante — em dois casos: distribuímos uma baseline mais recente e a cópia do utilizador não mudou, ou mudaram os dois lados. Se o utilizador editou a cópia dele e a nossa não mudou, não se diz nada.

Para resolver, sempre por esta ordem:

```text
init_project(project_path=".", refresh=true, apply=false)   # mostra o que mudaria
init_project(project_path=".", refresh=true, apply=true)    # aplica
```

| Situação                                     | O que `apply=true` faz                        |
| -------------------------------------------- | --------------------------------------------- |
| Não existe no projeto                        | Cria                                          |
| Existe e nunca foi tocado desde a instalação | Atualiza no sítio                             |
| Existe e foi editado, ou divergiu            | Escreve `<nome>.new` ao lado; não toca no teu |
| Proveniência desconhecida (sem manifesto)    | Igual ao anterior — nunca se adivinha         |

**Nenhuma flag substitui um ficheiro modificado.** Se aparecer um `.new`, o passo seguinte é do utilizador: fazer o merge à mão e apagar o `.new` — o aviso desaparece quando o `.new` deixar de existir.

### 6. Ligar os hooks

`precommit_install { project_path: "<project>" }` — corre `pre-commit install` e instala também os hooks `commit-msg` e `pre-push`, reportando cada um (um hook que não instalou é dito, não escondido). Precisa do `pre-commit` no PATH (passo 4).

### 7. Estado inicial

A resposta do `init_project` já traz um primeiro resumo do estado de segurança (`initial_state`), com os secrets medidos no histórico **e** nos ficheiros ainda por commitar. Para o quadro completo, `security_scan_full { project_path: "<project>" }` — em modo de relatório, sem bloquear nada.

### 8. Relatório final

```text
✅ dev-guardian instalado.

Estado atual do projeto:
  🔴 Crítico: 0
  🟡 Alto: 2 (dependências com CVE — skill guardian-deps)
  🟢 Médio: 14 (lint, code smells)

Próximos passos sugeridos:
  1. Corrige as dependências vulneráveis (guardian-deps, ou /guardian-fix --pr)
  2. Liga o Renovate no GitHub: github.com/apps/renovate (1 clique)
  3. Faz commit dos ficheiros gerados (o manifesto vai junto — é o que
     permite avisar-te quando uma config distribuída for corrigida):
     git add .pre-commit-config.yaml .gitleaks.toml renovate.json .semgrep.yml \
             .dev-guardian/configs.json
     git commit -m "chore: setup dev-guardian"
```

## Por stack: o que as tools cobrem e o que fica por tua conta

| Stack | Coberto pelas tools MCP | Recomendação manual (as tools não instalam nem correm) |
| --- | --- | --- |
| JS / TS | Semgrep, `bugfix-js.yml`, Trivy nos lock files, jscpd, ESLint se já estiver em `node_modules` | ESLint + `@typescript-eslint` configurados no projeto |
| Python | Semgrep, `bugfix-py.yml`, Bandit, ruff, radon, Trivy, pip-audit (`deps_audit`) | — |
| PHP / WordPress | Semgrep, `bugfix-php.yml`, Trivy em `composer.lock`, PHPCS-WPCS (`scan_wordpress`) | PHPStan ou Psalm |
| Go | Semgrep, `bugfix-go.yml`, staticcheck (`quality_check`), Trivy em `go.sum` | gosec, govulncheck |
| Rust | Semgrep (uma regra, `bugfix-rs.yml`), Trivy em `Cargo.lock` | `cargo clippy`, `cargo audit`, `cargo deny` |
| Ruby | Semgrep (registry), Trivy em `Gemfile.lock` | brakeman, RuboCop |
| Java / Kotlin | Semgrep, `bugfix-java.yml`, Trivy em `pom.xml` / `build.gradle` | SpotBugs + FindSecBugs |
| C# / .NET | Semgrep, `bugfix-cs.yml`, analyzers do SDK, `dotnet list package --vulnerable`, `/guardian-dotnet` | — |
| Docker / IaC | Trivy (`scan_containers`, `scan_iac`), hadolint, cosign (assinatura da imagem), checks de compose | Checkov, se quiserem uma segunda opinião |

Nunca anuncies como instalado ou corrido algo da última coluna.

## Resolução de problemas comuns

- **Sem sudo** (container, VPS mínimo): `install_toolchain` reporta esses passos em `requires_elevation`; os scripts oferecem binários portáteis em `~/.local/bin`.
- **`pre-commit` não encontrado**: `install_toolchain { tools: ["pre-commit"] }`, ou `pipx install pre-commit`.
- **Dependabot já configurado**: pergunta se migra para o Renovate (recomendado) ou mantém os dois — detalhe na skill `guardian-deps`.
