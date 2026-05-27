---
name: guardian-deps
description: Dependency management — updates, CVEs, supply chain, licenses, Renovate/Dependabot setup. EN triggers — use when the user says "guardian deps", "update dependencies", "are deps secure?", "set up Renovate", "any CVEs?", "supply chain", "vulnerable libraries", "vulnerable packages", "update npm/pip", "review this Dependabot/Renovate PR", "outdated deps", "dependency audit", "blame a dep", "which lib broke the build?", "Renovate sent 17 PRs", "Dependabot spam". PT triggers — usa quando pedirem "guardian deps", "atualiza dependências", "estão seguras as deps?", "configura Renovate", "tem CVEs?", "supply chain", "vulnerabilidades nas libs", "packages vulneráveis", "atualizar npm/pip", "queres rever este PR do Dependabot/Renovate?", "deps desatualizadas", "auditoria de deps", "culpa de uma lib", "qual lib partiu o build?", "o Renovate enviou-me 17 PRs", "Dependabot fez spam". ES triggers — úsala cuando pidan "guardian deps", "actualiza dependencias", "¿las deps son seguras?", "configura Renovate", "¿tiene CVEs?", "supply chain", "librerías vulnerables", "paquetes vulnerables", "actualizar npm/pip", "¿revisas este PR de Dependabot/Renovate?", "deps desactualizadas", "auditoría de deps", "culpa a una lib", "¿qué librería rompió el build?", "Renovate me mandó 17 PRs", "Dependabot está spammeando". Trilingual EN/PT/ES — respond in the user's language.
---

# Guardian Deps

Gestão completa de dependências: atualizações automáticas, scanning de CVEs, supply chain protection, e gestão de licenças.

## Funções principais

1. **Configurar Renovate** (substituto open-source do Dependabot, mais inteligente)
2. **Scan de vulnerabilidades** em dependências instaladas
3. **Triagem de PRs** abertos por Renovate/Dependabot
4. **Audit de supply chain** (typosquatting, packages maliciosos)
5. **Licença compliance** (sem GPL em projeto comercial proprietário)
6. **Geração de SBOM** (Software Bill of Materials)

## Setup do Renovate

### 1. Detectar ecossistemas

Verifica que package managers o projeto usa: `package.json`, `requirements.txt`/`poetry.lock`/`uv.lock`/`Pipfile`, `composer.json`, `go.mod`, `Cargo.toml`, `Gemfile`, `pom.xml`/`build.gradle`, `Dockerfile`, GitHub Actions.

### 2. Copiar config base

Copia `${CLAUDE_PLUGIN_ROOT}/configs/renovate/renovate.json` para a raiz do projeto. A config base:

- Atualiza patches/minors automaticamente em PRs separados
- Agrupa updates devDependencies semanalmente
- Atualiza Dockerfiles e GitHub Actions
- Liga "vulnerability alerts" para abrir PRs imediatos em CVE críticos
- Auto-merge para patches em deps de teste/dev

### 3. Customizar

Pergunta ao utilizador:
- Auto-merge para que tipo de updates? (default: patch dev-deps)
- Que branches monitorar? (default: branch default)
- Frequência? (default: semanal)
- Há packages para ignorar? (e.g. `react@17` porque ainda não migraste)

Aplica customizações ao `renovate.json`.

### 4. Ativar no GitHub

Renovate corre como GitHub App. Instruir o utilizador:
1. Vai a `github.com/apps/renovate`
2. Click "Install"
3. Selecciona o repo
4. Pronto — abre PR de "Configure Renovate" automaticamente

Para self-hosted (sem GitHub.com), usa `renovate-runner` em CI.

### 5. Migrar de Dependabot

Se já existe `.github/dependabot.yml`:
- Pergunta se quer migrar (recomendado) ou correr em paralelo
- Se migrar: comenta o `dependabot.yml` (não apaga, para histórico) e ativa Renovate
- Avisa que terá de fechar PRs antigos do Dependabot manualmente

## Scan de vulnerabilidades

### Comando principal

```bash
trivy fs --scanners vuln --severity HIGH,CRITICAL --format table .
```

Para JSON estruturado:
```bash
trivy fs --scanners vuln --format json --output .guardian/deps-cves.json .
```

### Triagem de findings

Para cada CVE encontrado:

1. **Verifica se é exploitable no contexto**:
   - A função vulnerável é usada pelo teu código? (procura imports/calls)
   - O input chega de fonte não-confiável? (utilizador / web / API externa)
   - Se "não" para qualquer um → severidade reduzida

2. **Verifica patch disponível**:
   - Há versão `fixed`? Sugere update.
   - Não há? Procura workarounds documentados no advisory.

3. **Verifica se é dev-only**:
   - Sim → severidade reduzida, mas não ignorada (build chain attacks são reais)

### Apresentar

```
Vulnerabilidades de dependências — N findings

🔴 Crítico (exploitable no teu código):
  - lodash@4.17.20 — CVE-2021-23337 (prototype pollution)
    Usado em: src/utils/merge.js
    Fix: bump para >=4.17.21 (npm update lodash)

🟡 Alto (presente mas uso não confirmado):
  - axios@0.21.0 — CVE-2021-3749 (DoS via regex)
    Fix: bump para >=0.21.4

🟢 Médio (dev-only):
  - eslint-plugin-x@1.2 — divulgação de info
    Bumping não-urgente

ℹ️ Sem fix disponível ainda (monitorar):
  - some-lib@2.0 — CVE-2024-XXXX
```

### Aplicar fixes

Para updates patch/minor seguros, oferece:
```bash
# Node
npm update <package>

# Python
poetry update <package>
# ou pip install -U <package> && pip freeze > requirements.txt

# PHP
composer update <package>
```

Antes de aplicar, mostra que vai mudar e pergunta confirmação. Depois corre testes.

## Supply chain attacks

Vulnerabilidades conhecidas não são o único risco — packages legitimamente maliciosos também. Detecção open-source disponível:

- **`@socket/cli`** (Socket — tier free generoso) — apanha typosquatting, packages com install hooks suspeitos, maintainer changes
- **Verificar manualmente packages novos**:
  - É popular (>1k downloads/semana)?
  - Última publicação foi sã (não burst suspeito)?
  - Tem GitHub linked? Stars?
  - Install scripts não fazem nada esquisito?

Em projetos críticos, adicionar `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml` ao git (sempre — nunca confiar em lockfile local-only) e usar `npm ci`/`pnpm install --frozen-lockfile` em CI.

## Triagem de PRs do Renovate/Dependabot

Quando o utilizador pergunta "queres rever este PR?":

1. Lê o título — extrai package, from version, to version
2. Determina tipo: **patch**, **minor**, **major** (semver)
3. Para patch: muito provavelmente seguro. Verifica que CI passa, sugere merge.
4. Para minor: lê release notes. Procura "breaking" / "deprecated". Sugere merge se nada relevante.
5. Para major: lê o CHANGELOG completo. Procura usos no código das APIs alteradas. Lista breaking changes que afetam o teu código. Veredito pode ser:
   - "Pode fazer merge" (não usas as APIs alteradas)
   - "Atenção: usas X em N sítios, vais ter de mudar" (com diffs)
   - "Não merge ainda — incompatível com Y"

## Licença compliance

Para projetos comerciais proprietários:

```bash
# Node
npx license-checker --json > .guardian/licenses.json

# Python
pip-licenses --format=json --output-file .guardian/licenses.json
```

Sinaliza:
- 🔴 GPL/AGPL em projeto não-GPL (não pode misturar)
- 🟡 LGPL (OK em dynamic linking mas precisa cuidado)
- 🟢 MIT/Apache/BSD (OK na maioria dos contextos)

## SBOM

Gera Software Bill of Materials com Syft:

```bash
syft . -o cyclonedx-json > sbom.json
```

Útil para compliance e response rápido em emergências (ex: novo CVE crítico aparece — usas?).

## Frequência sugerida

- Scan de CVEs em CI: **a cada PR + nightly**
- Update batch via Renovate: **semanal**
- Audit de supply chain: **mensal**
- SBOM regenerada: **a cada release**

## Output persistente

Todos os relatórios em `.guardian/reports/deps-<timestamp>.json` para tracking histórico.
