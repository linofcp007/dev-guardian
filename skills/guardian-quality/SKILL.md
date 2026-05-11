---
name: guardian-quality
description: Code quality and tech-debt analysis — smells, complexity, duplication, naming, refactor opportunities. EN triggers — use when the user asks "guardian quality", "is this clean?", "tech debt", "refactor", "code smells", "too complex", "is this maintainable?", "how do I improve this code?", "quality review", "I need to clean this up", "this is messy", "too much code". PT triggers — usa quando pedirem "guardian quality", "isto está limpo?", "tech debt", "refactor", "code smells", "complexidade", "isto é maintainable?", "como melhoro este código?", "review de qualidade", "preciso de limpar isto", "está confuso", "demasiado código".
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

## Ferramentas open-source usadas

| Aspecto                | Ferramenta                                        |
| ---------------------- | ------------------------------------------------- |
| Complexidade           | `radon` (Python), `lizard` (multi-lang)           |
| Duplicação             | `jscpd` (multi-lang)                              |
| Lint                   | `ruff` (Py), `eslint` (JS), `golangci-lint` (Go)  |
| Dead code              | `vulture` (Py), `ts-prune` (TS), built-in (Go)    |
| Coverage               | `coverage.py`, `c8`/`nyc`, `go test -cover`       |
| Métricas globais       | SonarQube CE (opcional, mais setup)               |

## Fluxo

### 1. Baseline rápido

Antes de fazer recomendações, mede o estado atual:

```bash
bash ${CLAUDE_PLUGIN_ROOT}/scripts/scan/quality-scan.sh
```

Devolve JSON com métricas por ficheiro/função.

### 2. Apresentar overview, não despejar tudo

Mostra um sumário primeiro:

```
Qualidade — overview

Linhas: 23,418 · Ficheiros: 187 · Linguagens: TS, Py

Top 5 ficheiros com mais "smell":
  1. src/api/orders.ts        — 47 issues (complexidade alta, 412 linhas)
  2. src/utils/helpers.ts     — 32 issues (sem testes, 60% dead code suspeito)
  3. services/payment.py      — 28 issues (acoplamento alto)
  4. components/Modal.tsx     — 19 issues (props gigantes, lógica em JSX)
  5. lib/db/queries.py        — 14 issues (duplicação 38%)

Coverage de testes: 42% (queres subir? guardian quality --testing)
Dead code suspeito: 1,240 linhas (lista? --dead-code)
TODOs antigos: 23 (alguns > 1 ano)
```

Pergunta onde focar antes de propor refactors gigantes.

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

## Formato de relatório

Sempre prioriza por impacto/esforço. Útil > completo. Estrutura:

```
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
