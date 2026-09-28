---
name: guardian-quality
description: Code quality and tech debt through the quality_check MCP tool — duplication, complexity, smells, naming, refactor opportunities ranked by ROI — plus the quality and performance budgets in .guardian/budgets.yml. EN triggers — "is this clean?", "tech debt", "code smells", "too complex", "is this maintainable?", "is it worth refactoring?", "are we within budget?", "set quality budgets". PT — "isto está limpo?", "dívida técnica", "code smells", "está demasiado complexo", "vale a pena refazer?", "estamos dentro do budget?", "define budgets de qualidade". ES — "¿esto está limpio?", "deuda técnica", "code smells", "demasiado complejo", "¿vale la pena refactorizar?", "¿estamos dentro del presupuesto?", "define presupuestos de calidad". Respond in the user's language.
---

# Guardian Quality

Análise de qualidade de código com foco em legibilidade, manutenibilidade e dívida técnica. Não confundir com `guardian-bugfix` (procura bugs) ou `guardian-security` (procura vulnerabilidades) — esta skill foca em "é fácil entender, mudar e estender este código?".

## O que esta skill avalia

1. **Complexidade ciclomática** — funções demasiado intricadas
2. **Duplicação** — DRY violations, copy-paste programming
3. **Naming** — nomes confusos, abbreviations, magic numbers
4. **Tamanho** — funções/ficheiros/classes gigantes
5. **Coesão e acoplamento** — módulos que sabem demasiado uns dos outros
6. **Dead code** — código nunca chamado, imports não usados, branches inalcançáveis
7. **Comentários** — comentários obsoletos, TODOs antigos, ausência onde necessário
8. **Consistência** — estilo, padrões, conventions misturados
9. **Tipo de testes** — cobertura, qualidade dos asserts, testes lentos
10. **Documentação** — README desatualizado, docstrings em falta em APIs públicas

## Ferramentas

O que a tool `quality_check` corre: `jscpd` (duplicação, qualquer linguagem), `ruff` e `radon` (Python), ESLint (só se estiver configurado e instalado em `node_modules` — nunca via `npx`) e `staticcheck` (quando há `go.mod`). Um analisador aplicável que falta ou falha fica registado e a cobertura fica `partial`, nunca `full`.

Fora da tool — só sugestões para o utilizador correr, sem histórico nem baseline: `lizard` (complexidade multi-linguagem), `vulture` / `ts-prune` / `knip` (dead code), `coverage.py`, `c8` / `nyc`, `go test -cover` (coverage), `mutmut` / `stryker` (mutation testing).

## Fluxo

### 1. Baseline rápido

Antes de fazer recomendações, mede: `quality_check { project_path: "<project>" }`. Devolve findings classificados em `duplicate`, `complexity`, `smell` e `naming`; `categories: ["complexity", "duplicate"]` filtra a resposta (todos os findings ficam registados — `category_filter` conta o que ficou de fora). Só uma parte do projeto: `scope: { paths: ["src/api"] }` (a duplicação passa a ser medida só entre esses ficheiros, e os budgets, que são do projeto inteiro, não se avaliam).

### 2. Apresentar overview, não despejar tudo

Mostra um sumário primeiro:

```text
Qualidade — overview

Linhas: 23,418 · Ficheiros: 187 · Linguagens: TS, Py

Top 5 ficheiros com mais "smell":
  1. src/api/orders.ts        — 47 issues (complexidade alta, 412 linhas)
  2. src/utils/helpers.ts     — 32 issues (sem testes, 60% dead code suspeito)
  3. services/payment.py      — 28 issues (acoplamento alto)
  4. components/Modal.tsx     — 19 issues (props gigantes, lógica em JSX)
  5. lib/db/queries.py        — 14 issues (duplicação 38%)

Budgets (.guardian/budgets.yml): duplicação 6,1 % > 5 % 🔴 · complexidade máx. 14 ≤ 15 ✅
Coverage de testes: 42 % (medida pela suite do projeto, não pela tool)
TODOs antigos: 23 (alguns > 1 ano)
```

Pergunta onde focar antes de propor refactors gigantes. Para o ranking consolidado de hotspots por ROI (findings × severidade × churn), `/guardian-report debt`; para transformar os melhores em specs de melhoria, a skill `guardian-improve`.

### 3. Priorização

Não sugere refactorar tudo. Aplica esta heurística:

- **Refactor se**: muda muitas vezes (alto churn), tem muitos bugs históricos, bloqueia features novas
- **Deixa se**: funciona, raramente muda, ninguém mexe — refactorar é introduzir risco sem upside

Para identificar churn, lê `git log --since=6.months --name-only` e cruza com o que tem mais issues.

### 4. Tipos de proposta

#### Refactor pequeno (auto-aplicável com confirmação)

- Extrair função
- Renomear variável
- Eliminar dead code
- Substituir magic number por const

Mostra diff, pergunta "aplicar?".

#### Refactor médio (proposta + plano)

- Quebrar ficheiro grande em vários
- Substituir copy-paste por helper partilhado
- Reorganizar parâmetros (introduzir DTOs)

Propõe plano em fases, mostra antes/depois de uma fase, pede aprovação.

#### Refactor grande (apenas plano)

- Mudar arquitetura
- Migrar framework
- Reorganizar módulos top-level

Apenas escreve o plano (ADR — ver `engineering:architecture` se disponível). Não inicia sem aprovação explícita do utilizador para começar.

### 5. Testes — qualidade, não só quantidade

Coverage alta com testes maus é pior que coverage baixa. Para cada test file, avalia:

- Cada teste tem 1 assertion principal e clara?
- Há setup duplicado em vez de fixtures?
- Mocks/stubs estão a testar implementação em vez de comportamento?
- Há testes que nunca falham (passam mesmo com bugs)? — corre os testes com mutações (mutation testing com `mutmut` ou `stryker`).

### 6. Documentação

- README existe? Está atualizado (última mudança vs último commit no código)?
- APIs públicas têm docstrings/JSDoc com exemplos?
- Há um CHANGELOG?
- Setup steps no README ainda funcionam (correr os passos em cleanroom)?

Se faltar, propõe templates mínimos viáveis (não 50 páginas — útil é melhor que completo).

### 7. Performance smells

Embora performance profunda seja `guardian-performance`, esta skill apanha smells óbvios:

- N+1 queries (loop com query dentro)
- Re-renders desnecessários em React (faltam memos, deps mal definidas)
- Sorting/filtering em loops aninhados
- Regex compilada dentro de loop
- `SELECT *` em SQL
- I/O síncrono em código async

Aponta-os mas não obriga a corrigir — confirma com benchmark se faz diferença.

## Budgets — `.guardian/budgets.yml`

"Estamos dentro do budget?" responde-se com **um só ficheiro**, lido por duas tools: `quality_check` avalia a secção `quality` e `perf_check` (numa corrida Lighthouse) avalia a secção `perf`. Cada budget excedido vira um finding. Nenhum outro ficheiro de budget é lido pelo Guardian — `lighthouserc.json`, `size-limit` ou o campo `performance` do `package.json` são do próprio projeto e das ferramentas dele.

```yaml
# .guardian/budgets.yml — todos os campos são opcionais; menor é sempre melhor
quality:
  duplication_pct: 5    # % de linhas duplicadas no projeto (jscpd)
  complexity: 15        # complexidade ciclomática máxima de uma função (radon — só Python)
perf:
  lcp_ms: 2500          # Largest Contentful Paint
  inp_ms: 200           # Interaction to Next Paint (substituiu o FID como Core Web Vital)
  cls: 0.1              # Cumulative Layout Shift
  tbt_ms: 300           # Total Blocking Time
  bundle_size_kb: 1600  # peso total da página, KB
```

- **São estes os campos, e só estes.** Uma chave desconhecida, YAML partido ou um valor não numérico torna o ficheiro inválido, e isso é reportado como tal — no `quality_check`, um `tools_run` `budgets` com `failed` e o motivo; no `perf_check`, `budgets.status: invalid` — nunca como "sem budgets" nem como "dentro do budget".
- Não há budget de tamanho de ficheiro, de tamanho de função, de coverage nem de custo de inferência: se o utilizador os quer, são metas a acompanhar à mão (ou na suite de testes dele), não algo que uma tool avalia. Não digas que "o gate" os aplica.
- `complexity` só tem medição em projetos com `.py` (radon); noutros stacks fica sem medição e não é avaliado — diz isso em vez de "dentro do budget".
- Um scan com `scope` não avalia budgets (são do projeto inteiro).

**Propor budgets.** Chama `detect_stack { project_path: "<project>" }` e propõe valores para *esse* stack — um crate Rust, uma app React e um serviço de faturação não partilham limites. Se o projeto não está pronto para números absolutos, parte da medição atual (`quality_check`, `perf_check`) como teto: "não pior do que hoje". Escreve o ficheiro só depois de o utilizador aprovar os valores.

Veredito por budget: ✅ dentro / ⚠️ perto do limite / 🔴 acima (com o número medido e o limite).

## Formato de relatório

Sempre prioriza por impacto/esforço. Útil > completo. Estrutura:

```markdown
# Qualidade — <projeto>

## Quick wins (esforço baixo, ganho alto)
- [ ] Remover 240 linhas de dead code em src/utils/helpers.ts (auto)
- [ ] Extrair helper de validação duplicada em 4 ficheiros (auto)
- [ ] Adicionar tipo de retorno explícito em 12 funções TS (auto)

## Médio prazo (próximos sprints)
- [ ] Dividir src/api/orders.ts (412 linhas) em orders/, orderItems/, orderStatus/
- [ ] Subir coverage de payment.py de 28% → 70%

## Longo prazo (planeamento)
- [ ] Avaliar migração de Redux → Zustand (3 PRs a abrir uso de Redux em 6 meses)
```

## Não fazer

- Não sugerir refactor de código que funciona e ninguém mexe
- Não impor um estilo (tabs vs spaces, etc.) sem confirmar com o utilizador
- Não apagar comentários "porque parecem inúteis" — podem ter contexto histórico
- Não silenciar avisos de linter com `// eslint-disable` em massa
