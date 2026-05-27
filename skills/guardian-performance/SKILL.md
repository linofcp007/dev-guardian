---
name: guardian-performance
description: Performance budgets, load testing and profiling with open-source tools (k6, Artillery, Lighthouse). EN triggers — use when the user says "guardian perf", "it's slow", "load test", "stress test", "benchmark", "performance", "Lighthouse", "Core Web Vitals", "N+1 queries", "throughput", "tps", "bottleneck", "memory usage", "high cpu", "how much can this handle?". PT triggers — usa quando disserem "guardian perf", "está lento", "load test", "stress test", "benchmark", "performance", "Lighthouse", "Core Web Vitals", "N+1 queries", "throughput", "tps", "afunilamento", "bottleneck", "memória", "cpu alto", "quanto aguenta isto?". ES triggers — úsala cuando digan "guardian perf", "está lento", "load test", "stress test", "benchmark", "rendimiento", "Lighthouse", "Core Web Vitals", "queries N+1", "throughput", "tps", "cuello de botella", "memoria", "cpu alta", "¿cuánto aguanta esto?". Trilingual EN/PT/ES — respond in the user's language.
---

# Guardian Performance

Validação de performance contínua: define performance budgets, corre load tests, identifica regressões e bottlenecks.

## Princípios

1. **Performance budgets > otimização especulativa.** Define limites antes de medir.
2. **Mede em condições realistas**, não na tua máquina rápida.
3. **Regressão é pior que lentidão constante** — alertar quando algo degrada.
4. **Não otimizes o que não está a doer** — perfila primeiro.

## Definir performance budgets

Para apps web, propõe começar com:

```yaml
# .guardian/perf-budget.yml
endpoints:
  - path: /api/products
    p95_ms: 200
    p99_ms: 500
  - path: /api/checkout
    p95_ms: 400
    p99_ms: 1000

web_vitals:
  LCP_ms: 2500
  FID_ms: 100
  CLS: 0.1

bundle:
  max_js_kb: 250
  max_css_kb: 50
```

Os limites começam tolerantes. Aperta-os à medida que melhoras.

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

Corre com `k6 run load-test.js`.

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
- **Periodicamente** (nightly) em staging — detecta degradação lenta

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

Setup Lighthouse CI:

```yaml
# .github/workflows/lighthouse.yml (template em workflows/)
- uses: treosh/lighthouse-ci-action@v11
  with:
    urls: |
      https://staging.example.com/
      https://staging.example.com/products
    budgetPath: ./.guardian/lighthouse-budget.json
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

Detecção:

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
# Em DevTools: Memory tab → Take heap snapshot, faz acções, take outro snapshot, compara
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

Reports em `.guardian/reports/perf-<timestamp>.json`. Útil para gráficos histórico de evolução.

## Quando NÃO otimizar

- Quando ninguém se queixa e não há SLA em risco
- Quando o ganho seria <10% e o código fica menos legível
- Quando é em código pouco chamado
- Quando há features mais valiosas em fila

A heurística é simples: **mede primeiro, otimiza só o que aparece no top do profiler**.
