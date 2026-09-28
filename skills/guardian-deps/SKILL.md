---
name: guardian-deps
description: Dependency management through the dev-guardian MCP tools — CVE audit, ordered upgrade plan, upgrade PRs, vetting what an install just added, supply-chain checks, licences, SBOM, Renovate. EN triggers — "update dependencies", "any CVEs?", "vulnerable packages", "outdated deps", "I just ran npm install", "what did that install add?", "review this Dependabot / Renovate PR", "set up Renovate", "supply chain". PT — "atualiza as dependências", "tem CVEs?", "packages vulneráveis", "deps desatualizadas", "acabei de instalar deps", "o que entrou com este install?", "revê este PR do Dependabot / Renovate", "configura o Renovate". ES — "actualiza las dependencias", "¿tiene CVEs?", "paquetes vulnerables", "deps desactualizadas", "acabo de instalar deps", "¿qué entró con este install?", "revisa este PR de Dependabot / Renovate", "configura Renovate". Respond in the user's language.
---

# Guardian Deps

Gestão de dependências: CVEs, plano de upgrades, vetting do que acabou de entrar, supply chain, licenças, SBOM e Renovate. Tudo passa pelas tools MCP do dev-guardian — são elas que guardam os CVEs em `.guardian/guardian.db`, e é daí que o plano de upgrades e o `create_fix_pr` os leem. Os comandos em bruto no fim são só o fallback de quando o servidor MCP não está disponível.

## 1. Scan de vulnerabilidades

- Auditoria completa: `deps_audit { project_path: "<project>" }` — Trivy fs (vuln + licença) e, conforme o stack, `npm audit`, `pip-audit` (num virtualenv **temporário**, com acesso à rede; o build de um sdist corre lá) e, para `.sln`/`.csproj`, `dotnet restore --locked-mode` + `dotnet list package --vulnerable` (o restore **executa o MSBuild do projeto**). Devolve os findings, os CVEs indexados e `bot_configured` (se já há Renovate ou Dependabot). Avisa o utilizador do que corre antes de o chamar.
- Rápido, só Trivy: `scan_deps { project_path: "<project>" }`.

### Triagem de cada CVE

1. **É explorável neste contexto?** A função vulnerável é usada pelo código (procura imports/calls)? O input chega de fonte não-confiável? Se "não" a qualquer uma → severidade reduzida. Com um snapshot de `map_attack_surface`, `validate_finding { project_path: "<project>", providers: ["dependency"] }` diz, por CVE de npm ou PyPI, se o package é importado por um ficheiro que uma rota alcança (`reachable`), só importado (`imported`) ou `unknown` — nunca `unreachable`: um package transitivo ou importado dinamicamente não aparece, e isso não é prova de que não é usado.
2. **Há versão corrigida?** Sim → entra no plano. Não → procura workarounds no advisory.
3. **É dev-only?** Reduz a severidade, mas não ignora (ataques à build chain são reais).
4. **Está explorado ativamente?** `prioritize_findings { project_path: "<project>" }` pesa os CVEs que estão no CISA KEV ou com EPSS alto (offline, não há boost — nunca inventado) e dá a cada CVE a decisão SSVC da CISA (`Act` / `Attend` / `Track*` / `Track`). Passa `mission_wellbeing` (`low` / `medium` / `high`) se o utilizador souber o peso do sistema; lê `ssvc.assumed` antes de citar a decisão — um ponto assumido é falta de dados, não um facto.

### Apresentar

```text
Vulnerabilidades de dependências — N findings

🔴 Crítico (explorável no teu código):
  - lodash@4.17.20 — CVE-2021-23337 (prototype pollution)
    Usado em: src/utils/merge.js
    Fix: >= 4.17.21

🟡 Alto (presente, uso não confirmado):
  - axios@0.21.0 — CVE-2021-3749 (ReDoS)
    Fix: >= 0.21.4

🟢 Médio (dev-only):
  - eslint-plugin-x@1.2 — divulgação de info

ℹ️ Sem fix disponível ainda (monitorizar):
  - some-lib@2.0 — CVE-2024-XXXX
```

## 2. Plano de upgrades e aplicação

1. `deps_update_plan { project_path: "<project>", prefer: "security" }` — plano ordenado por ecossistema (`package_name`, `installed_version`, `latest_version`, `cve_ids`, `upgrade_command`), classificado como security / patch / minor / major. Lê também:
   - `unplanned` — cada CVE que não ganhou passo, e porquê. Projetos **pnpm e yarn** caem aqui: não há comandos npm para eles, e o fix (`pnpm.overrides` / `resolutions`) aplica-se à mão;
   - `runner_failures` — cada comando de ecossistema que falhou, com o código (por exemplo NU1004, lock desatualizado, versus NU1301, feed inacessível).
2. Para aplicar os upgrades com prova: `create_fix_pr { project_path: "<project>", sources: ["deps"], apply: false }` — dry run numa worktree isolada (npm com `--ignore-scripts`, pins de pip editados no sítio), re-scan e diferencial de testes. Só com um "sim" explícito, `apply: true` abre o PR. Maven e gradle ficam de fora (o plano não os cobre).
3. Aplicação à mão, quando o utilizador prefere: usa o `upgrade_command` de cada entrada, mostra o que vai mudar, pede confirmação, corre os testes. Depois, `scan_deps { project_path: "<project>", force: true }` confirma que o CVE desapareceu.

## 3. Depois de um install (o que acabou de entrar)

Depois de `npm install`, `pip install`, `composer require`, `cargo add`, `gem install`, `dotnet add package`…:

1. Compara o lock file com o `HEAD` (`git diff HEAD -- package-lock.json` e equivalentes: `poetry.lock`, `uv.lock`, `composer.lock`, `Cargo.lock`, `Gemfile.lock`, `packages.lock.json`). Se não mudou, diz que não houve install real e para aí.
2. Para os packages novos ou alterados: `scan_deps { project_path: "<project>", packages: ["<package>"] }` — o Trivy lê o projeto todo e a resposta é filtrada a esses packages; `package_filter.not_found` diz quais não tinham nada.
3. Heurísticas de supply chain (secção 4) em cada package novo.
4. Licenças novas: `compliance_check { project_path: "<project>" }` e depois `license_compatibility { project_path: "<project>" }` — copyleft ou licença desconhecida (`undetermined`) num projeto fechado é sinal.
5. 🔴 se entrou algo sério; senão 🟢.

## 4. Supply chain

Vulnerabilidades conhecidas não são o único risco — packages maliciosos também. Nenhuma tool deteta typosquatting; é verificação tua:

- O nome é quase igual a um package popular? (typosquatting)
- É popular (> 1k downloads/semana)? Tem repositório ligado e historial?
- A última publicação foi sã (não um burst suspeito, não um maintainer novo)?
- Os install scripts (`postinstall`, `setup.py`) fazem algo esquisito?

`@socket/cli` (Socket, tier gratuito) ajuda com install hooks suspeitos e mudanças de maintainer, se o utilizador o quiser instalar. Lock files vão sempre para o git, e a CI usa `npm ci` / `pnpm install --frozen-lockfile`.

## 5. Renovate

- `init_project { project_path: "<project>", apply: false }` mostra os ficheiros que instalaria, `renovate.json` incluído; com `apply: true` instala-o (nunca por cima de um ficheiro existente — um igual ao distribuído é adotado no manifesto).
  - perfil `standard`: automerge de patches de dev-dependencies e de minors de tooling seguro (`@types`, eslint, prettier), sempre com **3 dias** de idade mínima; majors precisam de revisão;
  - perfil `paranoid` (`profile: "paranoid"`): **nenhum** automerge e **7 dias** de idade mínima.
- O Renovate corre como GitHub App: `github.com/apps/renovate` → Install → escolher o repo → ele abre o PR "Configure Renovate". Self-hosted: `renovate-runner` na CI.
- Já há `.github/dependabot.yml`? Pergunta se migra (comenta o ficheiro, não o apaga) ou se corre em paralelo; os PRs antigos do Dependabot fecham-se à mão.

## 6. Triagem de PRs do Renovate / Dependabot

1. `review_pr { project_path: "<project>", base_ref: "<base branch>", head_ref: "<PR branch>" }` — Semgrep e gitleaks sobre o diff, Trivy porque o manifesto mudou.
2. Tipo de update: **patch** (quase sempre seguro — CI verde, merge), **minor** (lê as release notes à procura de "breaking" / "deprecated"), **major** (lê o CHANGELOG, procura no código os usos das APIs alteradas).
3. Veredito: "pode fazer merge" / "atenção: usas X em N sítios, vais ter de mudar" (com diffs) / "não fazer merge ainda — incompatível com Y".

## 7. Licenças

`compliance_check { project_path: "<project>" }` (scan de licenças do Trivy) e depois `license_compatibility { project_path: "<project>" }`, que cruza a licença do projeto (sem licença declarada ou "proprietary" conta como proprietário) com as das dependências:

- 🔴 GPL / AGPL num projeto não-GPL
- 🟡 LGPL (OK em dynamic linking, cuidado com static linking)
- 🟢 MIT / Apache / BSD
- `undetermined` (expressões SPDX OR/AND, licenças não reconhecidas) nunca conta como compatível

## 8. SBOM

`generate_sbom { project_path: "<project>", format: "cyclonedx-json" }` (Syft; Trivy como fallback) — o ficheiro fica em `.guardian/reports/sbom-<scan>/` (`file_path`). Entre releases, `sbom_diff { project_path: "<project>" }` compara os dois SBOMs mais recentes. Útil para responder depressa a um CVE novo ("usamos a lib X?").

### VEX

`export_vex { project_path: "<project>" }` escreve um documento OpenVEX (ou CycloneDX com `format: "cyclonedx"`) em `.guardian/reports/vex-*/`, uma declaração por vulnerabilidade (CVE, ou o id GHSA/PYSEC próprio, com os aliases que o scanner deu) e versão do package, do scan de dependências mais recente. Nunca inventa um estado:

- `not_affected` só quando o utilizador o declarou: `suppress_finding` com `vex_status: "not_affected"` e uma `justification` OpenVEX (por exemplo `vulnerable_code_not_in_execute_path`), mais um `impact_statement` opcional. Pergunta sempre a justificação — não a escolhas tu;
- `affected` quando um ficheiro que uma rota alcança importa o package e carrega a versão vulnerável;
- `under_investigation` no resto; `fixed` nunca.

Corre antes `generate_sbom` (dá os purls) e `map_attack_surface` (dá a alcançabilidade), e mostra ao utilizador a lista `unknowns` — é o que o documento não sabe.

## Frequência sugerida

- Scan de CVEs: a cada PR que mexe em dependências e semanalmente
- Upgrades em lote via Renovate: semanal
- Vetting de supply chain: a cada dependência nova
- SBOM: a cada release

## Fallback sem servidor MCP

Só quando as tools não estão disponíveis — diz ao utilizador que assim não há histórico, baseline nem plano ligado aos CVEs:

```bash
trivy fs --scanners vuln --severity HIGH,CRITICAL --format table .
npm audit --json
pip-audit -r requirements.txt
npx license-checker --json --production
syft . -o cyclonedx-json > sbom.json
```
