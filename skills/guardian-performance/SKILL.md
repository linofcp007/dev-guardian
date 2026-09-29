---
name: guardian-performance
description: Performance through the perf_check MCP tool — Lighthouse Core Web Vitals checked against the perf budgets in .guardian/budgets.yml, k6 load tests — plus profiling and bottleneck hunting (N+1, slow queries, bundle size, memory leaks). EN triggers — "it's slow", "load test", "stress test", "benchmark", "Lighthouse", "Core Web Vitals", "N+1 queries", "bottleneck", "high cpu", "how much can this handle?". PT — "está lento", "teste de carga", "benchmark", "Lighthouse", "Core Web Vitals", "queries N+1", "estrangulamento", "cpu alto", "quanto aguenta isto?". ES — "está lento", "prueba de carga", "benchmark", "Lighthouse", "Core Web Vitals", "queries N+1", "cuello de botella", "cpu alta", "¿cuánto aguanta esto?". Respond in the user's language.
---

# Guardian Performance

Validação de performance contínua: define performance budgets, corre load tests, identifica regressões e bottlenecks.

## Princípios

1. **Performance budgets > otimização especulativa.** Define limites antes de medir.
2. **Mede em condições realistas**, não na tua máquina rápida.
3. **Regressão é pior que lentidão constante** — alertar quando algo degrada.
4. **Não otimizes o que não está a doer** — perfila primeiro.

## Medir com a tool

- **Frontend**: `perf_check { project_path: "<project>", target_url: "<url>" }` corre o Lighthouse (as cinco categorias por omissão; `lighthouse_categories: ["performance"]` para só a performance) e devolve as Core Web Vitals e o caminho do relatório JSON bruto. Se o Lighthouse não estiver instalado, `install_toolchain { tools: ["lighthouse"], dry_run: true }`.
- **Carga**: `perf_check { project_path: "<project>", k6_script_path: "<script.js>" }` corre um script k6 que já exista e devolve o número de pedidos, p95 / p99 e os thresholds do script. Se o k6 não estiver instalado, `install_toolchain { tools: ["k6"], dry_run: true }`.
- `target_url` e `k6_script_path` excluem-se: uma coisa de cada vez.

## Definir performance budgets

Os budgets de performance vivem na secção `perf` de `.guardian/budgets.yml` — o mesmo ficheiro que a skill `guardian-quality` usa para os budgets de qualidade. Uma corrida Lighthouse do `perf_check` lê-o e reporta cada budget excedido como finding; `budgets.status` na resposta diz `none`, `ok` ou `invalid` — um ficheiro inválido nunca passa por "dentro do budget".

```yaml
# .guardian/budgets.yml — secção perf (todos opcionais; menor é melhor)
perf:
  lcp_ms: 2500          # Largest Contentful Paint
  inp_ms: 200           # Interaction to Next Paint — o FID foi retirado das Core Web Vitals em março de 2024
  cls: 0.1              # Cumulative Layout Shift
  tbt_ms: 300           # Total Blocking Time
  bundle_size_kb: 1600  # peso total da página, KB
```

São estes os cinco campos, e só estes. Latências por endpoint (p95 / p99) não são um budget do ficheiro: são os **thresholds do próprio script k6** (secção seguinte), e o k6 falha a corrida quando não os cumpre. Os limites começam tolerantes; aperta-os à medida que melhoras.

## Load testing

### Ferramenta: k6 (Grafana)

Open-source, scripts em JavaScript, output exportável para Grafana.

```js
// load-test.js
import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '2m', target: 50 },    // ramp up
    { duration: '5m', target: 50 },    // sustained
    { duration: '2m', target: 100 },   // step up
    { duration: '5m', target: 100 },
    { duration: '2m', target: 0 },     // ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<200', 'p(99)<500'],
    http_req_failed: ['rate<0.01'],
  },
};

export default function () {
  const res = http.get('https://staging.example.com/api/products');
  check(res, { 'status 200': r => r.status === 200 });
  sleep(1);
}
```

Corre com `perf_check { project_path: "<project>", k6_script_path: "load-test.js" }` — devolve as métricas já interpretadas e o relatório bruto. `k6 run load-test.js` à mão é o fallback sem servidor MCP.

### Alternativa: Artillery (mais YAML, menos JS)

```yaml
config:
  target: https://staging.example.com
  phases:
    - duration: 300
      arrivalRate: 50
scenarios:
  - flow:
      - get:
          url: /api/products
```

`artillery run scenario.yml`.

### Quando correr

- **Em CI** após cada PR contra ambiente de teste — apanha regressões cedo
- **Antes de releases** importantes — confirma SLAs
- **Periodicamente** (nightly) em staging — deteta degradação lenta

## Profiling

### Backend Node.js

- **clinic.js** — diagnostic tool para Node. `clinic doctor -- node app.js`
- **Chrome DevTools** — `node --inspect app.js` e abre `chrome://inspect`
- **0x** — flame graphs

### Backend Python

- **py-spy** — sampling profiler, no overhead, podes anexar a processo a correr
- **scalene** — CPU + memória + GPU
- **cProfile** built-in

### Frontend web

- **Lighthouse CI** — corre Lighthouse em CI, falha se Core Web Vitals piorarem
- **web-vitals** library — recolhe métricas reais de utilizadores
- **WebPageTest** (público) — runs reais multi-localização

Para Lighthouse na CI do próprio projeto (o dev-guardian não gera workflows — é um exemplo para o utilizador adaptar, com um budget no formato do Lighthouse CI, que é independente de `.guardian/budgets.yml`):

```yaml
# .github/workflows/lighthouse.yml (escrito pelo utilizador)
- uses: treosh/lighthouse-ci-action@v11
  with:
    urls: |
      https://staging.example.com/
      https://staging.example.com/products
    budgetPath: ./lighthouse-budget.json
```

## Bottlenecks comuns e como caçar

### N+1 queries

Padrão: loop com query DB dentro.

```python
# 🐛 Bug — 1 + N queries
users = User.objects.all()
for user in users:
    print(user.profile.name)  # query por user

# ✅ Fix — 1 query
users = User.objects.select_related('profile').all()
```

Deteção:

- Django: `django-silk` ou `django-debug-toolbar`
- Node + Prisma/TypeORM: log queries em dev
- Geral: contar queries por request

### Queries lentas em DB

- Ativa slow query log (`log_min_duration_statement = 200ms` em Postgres)
- Use `EXPLAIN ANALYZE` em queries suspeitas
- Adiciona índices em colunas usadas em WHERE/ORDER BY/JOIN
- Cuidado com `SELECT *` em tabelas largas

### Render desnecessário em React

- `React DevTools Profiler` — flame chart
- `why-did-you-render` lib — alerta quando algo re-renderiza sem precisar
- Procura `useEffect` sem deps array ou com deps mal definidas

### Bundle size

```bash
# Vite
npm run build -- --report
# Webpack
npm install --save-dev webpack-bundle-analyzer
```

Procura libs gigantes (moment.js → day.js, lodash → lodash-es + tree-shake, etc.).

### Memory leaks (Node)

```bash
node --inspect app.js
# Em DevTools: Memory tab → Take heap snapshot, faz ações, take outro snapshot, compara
```

Suspeitos comuns:

- Event listeners sem `removeListener`
- Closures que capturam objetos grandes
- Caches sem limite (substituir por LRU)

## Performance regressions

Em CI, comparar tempo de testes selecionados ou de endpoints contra baseline:

```bash
# Exemplo simples — falha se ficou >10% mais lento
k6 run --out json=results.json load-test.js
node compare-vs-baseline.js results.json baseline.json --max-regression 10%
```

Ferramenta open-source: `hyperfine` para benchmark de comandos CLI.

## Output

Cada `perf_check` escreve o relatório JSON bruto em `.guardian/reports/perf-<id>/` e devolve o caminho absoluto. Ao contrário dos scans de segurança e qualidade, **não fica no histórico** da base de dados — não há `diff_scans` de performance. Para acompanhar a evolução, guarda os relatórios (ou os números) de cada release e compara-os tu, ou deixa os thresholds do k6 e os budgets do `.guardian/budgets.yml` fazerem de alarme.

## Quando NÃO otimizar

- Quando ninguém se queixa e não há SLA em risco
- Quando o ganho seria <10% e o código fica menos legível
- Quando é em código pouco chamado
- Quando há features mais valiosas em fila

A heurística é simples: **mede primeiro, otimiza só o que aparece no top do profiler**.
