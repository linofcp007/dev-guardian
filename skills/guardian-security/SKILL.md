---
name: guardian-security
description: Complete security scan using open-source tools (Semgrep, Trivy, gitleaks, nuclei). EN triggers — use when the user asks "guardian scan", "audit security", "check for vulnerabilities", "scan for secrets", "any security holes?", "SAST scan", "DAST scan", "check dependencies", "check the container", "check IaC", "is this safe?", "quick pen test", "I'm worried about security", "smells bad", "is this publishable?", "is this safe to ship?", or any request related to finding security problems before they reach production. PT triggers — usa quando pedirem "guardian scan", "audita segurança", "vê se há vulnerabilidades", "scan de secrets", "tem buracos de segurança?", "scan de SAST/DAST", "verifica deps", "verifica container", "verifica IaC", "vê se isto está safe", "pen test rápido", "preocupado com a segurança", "isto cheira-me mal", "publica-se isto?", "isto pode ir para produção?". ES triggers — úsala cuando pidan "guardian scan", "auditoría de seguridad", "comprueba vulnerabilidades", "escaneo de secretos", "¿hay agujeros de seguridad?", "escaneo SAST/DAST", "comprueba deps", "comprueba el contenedor", "comprueba IaC", "¿esto es seguro?", "pen test rápido", "preocupado por la seguridad", "huele mal", "¿se puede publicar esto?", "¿es seguro lanzarlo?". Trilingual EN/PT/ES — respond in the user's language.
---

# Guardian Security

Scan profundo de segurança. Combina vários scanners open-source e contextualiza os resultados — ao contrário de correr ferramentas a cega, esta skill correlaciona findings, despromove falsos positivos óbvios e prioriza pelo risco real.

## Tipos de scan

A skill suporta quatro tipos. Pergunta ao utilizador qual (ou faz `--all` se ele disser "tudo"):

| Tipo                    | O que faz                                                        | Ferramenta                       |
| ----------------------- | ---------------------------------------------------------------- | -------------------------------- |
| **SAST**                | Análise estática de código aplicacional                          | Semgrep + bandit/brakeman/gosec  |
| **Secrets**             | Procura API keys, tokens, passwords no código e histórico Git    | gitleaks                         |
| **Dependencies**        | CVEs em bibliotecas/packages                                     | Trivy                            |
| **Container/IaC**       | Dockerfile, imagens, Terraform, Kubernetes                       | Trivy + Checkov                  |
| **DAST** (opcional)     | Scan runtime contra app JÁ a correr                              | `scan_dast` (+ nuclei)           |

## Fluxo

### 1. Pré-requisitos

Antes de scanar, garante que as ferramentas estão instaladas. Se não estiverem, sugere correr `guardian init` primeiro. Verifica com:

```bash
bash ${CLAUDE_PLUGIN_ROOT}/scripts/scan/check-tools.sh
```

### 2. Executar scans

Corre `bash ${CLAUDE_PLUGIN_ROOT}/scripts/scan/full-security-scan.sh <project-path>`. Este script orquestra todos os scanners e produz output JSON unificado em `.guardian/reports/security-<timestamp>.json`.

Internamente:

```bash
# SAST — repara nos DOIS --config: ver a nota abaixo
semgrep --config=auto --config=.semgrep.yml --json --output=.guardian/sast.json .

# Secrets (incluindo histórico Git)
gitleaks detect --no-banner --report-format=json --report-path=.guardian/secrets.json

# Dependências
trivy fs --scanners vuln,license --format json --output .guardian/deps.json .

# Container (se houver Dockerfile)
[ -f Dockerfile ] && trivy config --format json --output .guardian/dockerfile.json Dockerfile

# IaC (se houver)
trivy config --format json --output .guardian/iac.json .
```

#### `--config=auto` não carrega o `.semgrep.yml` do projeto

Medido no semgrep 1.164.0, num projeto com o pack `base.yml` e uma linha de
`<?php echo $_GET['name'];`:

| Comando                | Findings |
| ---------------------- | -------- |
| `--config=<ficheiro>`  | 1        |
| `--config=auto`        | 0        |

As treze regras que o `init_project` instala como `.semgrep.yml` **não têm
consumidor** se só se passar `--config=auto`. É por isso que os dois `--config`
estão ali em cima, e é por isso que a tool `scan_sast` passou a carregar as
regras do projeto (do manifesto `.dev-guardian/configs.json`, ou dos nomes
convencionais). Prefere sempre a tool ao comando em bruto.

Um `--config` que o Semgrep não consiga carregar aborta a corrida **inteira**
(`paths.scanned: []`, exit 7), não só esse pack — por isso a tool valida a
estrutura do ficheiro antes de o passar, e reporta em `tools_run` o que
descartou. Uma regra que não compila é outro caso: exit 2, tudo scaneado,
perde-se essa regra e mais nada.

#### Privacidade: o modo por defeito envia telemetria

`--config=auto` vai buscar as regras ao registry do Semgrep e envia métricas de
uso à Semgrep Inc. **como condição** disso: `--metrics=off` em conjunto falha
com "Cannot create auto config when metrics are off". Não é evitável no modo
por defeito, e vale a pena dizê-lo ao utilizador quando ele pergunta se algo
sai da máquina.

Alternativa: `scan_sast` com `local_only: true` — sem registry, com
`--metrics=off`, só regras já em disco (o `.semgrep.yml` do projeto e o que
tenha sido registado com `register_custom_rules`). Menos regras que o modo por
defeito; nada sai da máquina. Sem regras locais, o scan é reportado como
skipped e não como resultado limpo.

### 3. Triagem inteligente

Não despeja apenas os resultados brutos — isso é ruído. Para cada finding:

1. **Classifica severidade** real (não confiar 100% no CVSS):
   - `🔴 Critical` — RCE/SQLi/secrets vivos em produção/auth bypass
   - `🟡 High` — XSS/CSRF/SSRF, CVEs com PoC público, deps com vulnerability sem patch
   - `🟢 Medium` — code smell com risco residual, secrets em ficheiros de teste/exemplo
   - `ℹ️ Low/Info` — best-practices, falsos positivos óbvios

2. **Despromove falsos positivos comuns**:
   - Secrets em `examples/`, `*test*`, `fixtures/`, `*.md` → Low (mas mencionar)
   - CVEs em deps `dev`/`test` → reduzir um nível
   - Regras Semgrep com má reputação de FP no contexto → contextualizar
   - `console.log` ou `print` com dados → Info, não High

3. **Correlaciona** findings de diferentes scanners. Se Semgrep encontra "use of crypto X" e Trivy diz que a biblioteca X tem CVE, isso é um único problema com mais peso, não dois.

### 4. Apresentar relatório

Sempre nesta estrutura, em ordem decrescente de prioridade:

```markdown
# Relatório de Segurança — <projeto>
<data> · <duração> · <ficheiros analisados>

## 🔴 Crítico (N) — bloqueia deploy

### 1. Secret exposto: AWS Access Key
- Ficheiro: src/config/aws.js:14
- Detalhe: chave AKIA... commitada
- Está no histórico Git desde commit abc123 (3 dias)
- Ação imediata:
  1. Revoga a chave AGORA na AWS Console
  2. `git filter-repo --invert-paths --path src/config/aws.js`
  3. Move para variável de ambiente
  4. Considera-a comprometida — assume que terceiros já a viram

### 2. SQL Injection em search endpoint
- Ficheiro: app/routes/search.py:42
- Padrão: f-string com input de utilizador em query SQL
- Risco: extração total da DB
- Fix sugerido: usar parameterized queries (mostra o diff)

## 🟡 Alto (N) — corrigir antes de release

[...]

## 🟢 Médio (N) — backlog

[...resumido, agrupado por categoria...]

## ℹ️ Despromovidos como falsos positivos prováveis (N)
[expandir se utilizador pedir]
```

### 5. Oferecer fix automático

Para coisas óbvias e reversíveis, oferece aplicar:

- Bumping de versão de deps com patch disponível (`npm update`, `pip install -U`, etc.)
- Substituir `crypto.createCipher` → `crypto.createCipheriv` (com diff a mostrar antes)
- Mover secret para `.env` + `.env.example` + atualizar `.gitignore`

**Nunca aplicar sem perguntar.** Mostra sempre o diff e pergunta "aplicar este fix?".

Em casos de **emergência absoluta** (chave de produção viva exposta), interrompe a conversa e diz claramente:

```text
⛔ STOP — Esta chave parece estar VIVA e em PRODUÇÃO.
Antes de mais nada, revoga-a já:
  → <link direto ao painel de revogação se conseguires inferir o provider>
Depois voltamos a configurar tudo.
```

## Modos paranoid

Se o utilizador pedir explicitamente "paranoid" ou "full deep":

- Inclui histórico Git completo no gitleaks (`gitleaks detect` sobre todo o histórico, não só staged)
- Corre regras Semgrep adicionais: `p/r2c-security-audit`, `p/cwe-top-25`, `p/insecure-transport`
- Lista também CVEs com CVSS ≥ 4.0 (em vez do default ≥ 7.0)
- Adiciona threat modeling rápido com STRIDE para os entry-points principais
- Inclui análise de licenças (GPL em projeto comercial, etc.)
- Sugere DAST (`scan_dast`) se a app for web **e estiver a correr**

## DAST (runtime) — `scan_dast`

Um pedido de "DAST scan" / "scan de DAST" / "escaneo DAST" resolve-se com a
tool MCP `scan_dast`. Não invoques scanners à mão: `scan_dast` guarda
baselines, faz diff e persiste histórico em SQLite, o que uma invocação
direta não faz.

`scan_dast` é o **passo seguinte** a `map_attack_surface` — probe o inventário
de rotas que este produziu, e recusa com `no_surface_snapshot` se não houver
inventário. A app tem de já estar a correr: esta tool nunca a arranca,
constrói ou pára.

1. Corre `map_attack_surface` primeiro, se ainda não houver snapshot.
2. Pergunta o URL da app **já em execução** (staging, dev local, etc.).
3. Confirma autorização. Alvos loopback (localhost / 127.0.0.0/8 / ::1) passam
   direto; qualquer outro host exige `authorized_target: true`, que o
   utilizador tem de atestar — nunca o definas por ele.
4. Corre `scan_dast` com `base_url`. Opcionalmente:
   - `auth_header_env` (recomendado) para probes autenticados — o nome da
     variável de ambiente, nunca o segredo em si;
   - `probe_rate_limit: true` para o burst de rate-limit;
   - `use_nuclei: true` para uma passagem adicional com **nuclei**, o scanner
     externo que este plugin instala (`install_toolchain`).
5. Lê o `coverage` antes dos findings: `partial` ou `none` significa que o scan
   não viu tudo, e um "0 findings" aí não é um resultado limpo.
6. Resume os findings, prioriza, sugere fixes — e diz que **um resultado limpo
   não é prova de segurança contra injeção**: o motor próprio não testa
   injeção, e os templates por defeito do nuclei testam a origem, não as rotas
   específicas do projeto.

Envelope de segurança (não o contornes): métodos só de leitura
(GET/HEAD/OPTIONS) salvo se `allow_write_methods` estiver ativo, e mesmo assim
com corpo vazio — mais o burst opcional de `probe_rate_limit`, a única
exceção, que envia POST a exatamente uma rota. Redirects nunca são seguidos.

## Alcançabilidade (estática) — `validate_finding`

Depois de triares os findings (Secção 3), `validate_finding` acrescenta um
sinal extra por finding — **nunca substitui a triagem acima, e nunca suprime
nem altera severidade sozinho**. Responde se algo fora do processo consegue
alcançar o ficheiro onde o finding vive, a partir de um grafo de imports com
raiz nas rotas que `map_attack_surface` já mapeou.

1. Corre `map_attack_surface` primeiro, se ainda não houver snapshot — sem
   ele, `validate_finding` recusa com `no_surface_snapshot`.
2. Corre `validate_finding` (sem `fingerprint` valida de uma vez todos os
   findings abertos — é o comportamento por omissão).
3. Lê o veredito por finding — `reachable` / `unreachable` / `unknown` — **ao
   lado** de `coverage_gaps`, nunca sozinho: uma contagem de vereditos sem os
   gaps ao lado não é uma resposta.
4. Usa isto como CONTEXTO na conversa com o utilizador ("este finding não
   parece alcançável por nenhuma rota, mas é uma leitura estática — quer
   mesmo assim mantê-lo como prioridade?"), nunca como justificação
   automática para o despromover na Secção 3.

Limites a respeitar sempre que apresentares um `unreachable`:

- **Nunca é emitido** para Ruby, Java, C# ou PHP — resolvem código em
  runtime (autoload / injeção por anotação / DI / service container), não
  por import.
- **Não vê imports dinâmicos** (`import(expr)`, `require(variable)`,
  reflection, registos de plugins) em nenhuma stack — nesses casos o
  `unreachable` pode estar errado, sem forma de o detetar.
- **Só conta rotas HTTP como ponto de entrada.** Um ficheiro chamado apenas
  por CLI, cron job ou consumidor de fila lê `unreachable`-por-rota — isso
  não é uma afirmação de que o código nunca corre.
- **Granularidade de ficheiro, não de função.** Um finding dentro de um
  helper nunca chamado, mas cujo ficheiro É importado, lê `reachable`.

## Quando não correr scans completos

- Em commits triviais (1-2 linhas): só hooks pre-commit chegam
- Em ramos experimentais/spike: avisar que pode ser ruído
- Em monorepos enormes: oferecer scan parcial (só o diff vs main)

## Output persistente

Todos os relatórios ficam em `.guardian/reports/` (cria a pasta se não existir; adiciona ao `.gitignore`). Útil para comparar evolução temporal e medir se a postura de segurança está a melhorar.
