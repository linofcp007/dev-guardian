---
name: guardian-observability
description: Configure structured logging, metrics, error tracking and alerting with open-source tools (Pino, structlog, Prometheus, Grafana, GlitchTip, Uptime Kuma). EN triggers — use when the user says "guardian observe", "logs", "monitoring", "metrics", "error tracking", "Sentry", "Prometheus", "Grafana", "GlitchTip", "alerts", "I can't see what's happening in production", "I need visibility", "how do I know if it's broken", "instrument the app", "I need proper logs". PT triggers — usa quando disserem "guardian observe", "logs", "monitoring", "métricas", "error tracking", "Sentry", "Prometheus", "Grafana", "GlitchTip", "alertas", "porque não vejo o que se passa em produção", "preciso de visibilidade", "como sei se está partido", "instrumenta a app", "preciso de logs decentes". ES triggers — úsala cuando digan "guardian observe", "logs", "monitoreo", "métricas", "error tracking", "Sentry", "Prometheus", "Grafana", "GlitchTip", "alertas", "no veo lo que pasa en producción", "necesito visibilidad", "¿cómo sé si está roto?", "instrumenta la app", "necesito logs decentes". Trilingual EN/PT/ES — respond in the user's language.
---

# Guardian Observability

Configura logging estruturado, métricas e error tracking usando exclusivamente ferramentas open-source self-hostable. Princípio: instrumentar desde cedo é mais barato que debug às cegas depois.

## Stack recomendada (open-source)

| Função              | Ferramenta                  | Self-host                    |
| ------------------- | --------------------------- | ---------------------------- |
| Logs estruturados   | Loki + Grafana              | Sim, Docker compose simples  |
| Métricas            | Prometheus + Grafana        | Sim                          |
| Error tracking      | GlitchTip (compat. Sentry)  | Sim, mais leve que Sentry    |
| Distributed tracing | Jaeger ou Tempo             | Sim                          |
| Uptime / blackbox   | Uptime Kuma                 | Sim, UI bonita               |
| Alerting            | Alertmanager + Grafana      | Sim                          |
| All-in-one          | SigNoz                      | Sim, alternativa a Datadog   |

Para projetos pequenos solo, **SigNoz** ou **GlitchTip + Uptime Kuma** chega bem. Para infra mais séria, a stack Grafana (Loki + Mimir/Prometheus + Tempo) é o padrão.

## Fluxo

### 1. Diagnosticar o que falta

Pergunta ao utilizador (ou inspeciona o código):

- Há logging estruturado? (não `print()` ou `console.log` espalhados)
- Há captura de exceções não-tratadas para um serviço?
- Há métricas básicas (requests por endpoint, latência, error rate)?
- Há alertas configurados para quando algo parte?
- Há dashboards para o utilizador olhar?

Provavelmente faltam várias destas.

### 2. Logging estruturado

#### Node.js / TypeScript

Substitui `console.log` por **pino**:

```ts
import pino from 'pino';

const logger = pino({
  level: process.env.LOG_LEVEL ?? 'info',
  transport: process.env.NODE_ENV !== 'production'
    ? { target: 'pino-pretty' }
    : undefined,
});

logger.info({ userId, action: 'login' }, 'user logged in');
logger.error({ err, userId }, 'login failed');
```

Vantagens:

- JSON em produção (parseable por Loki/qualquer agregador)
- Pretty em desenvolvimento
- Fast (mais rápido que Winston)

#### Python

Usa **structlog**:

```python
import structlog

log = structlog.get_logger()
log.info("user_login", user_id=user.id)
log.error("login_failed", user_id=user.id, exc_info=True)
```

#### PHP

Usa **Monolog** com JSON formatter em produção.

#### Go

Usa **zerolog** ou `slog` (stdlib desde Go 1.21).

### 3. Error tracking

Setup GlitchTip (compatível com SDKs Sentry):

#### Self-host com Docker

```yaml
# docker-compose.yml (snippet)
glitchtip:
  image: glitchtip/glitchtip:latest
  environment:
    DATABASE_URL: postgres://...
    SECRET_KEY: <random>
    PORT: 8000
  ports:
    - "8000:8000"
```

Cria projeto, obtém DSN, instrumenta a app:

```ts
// Node
import * as Sentry from '@sentry/node';
Sentry.init({ dsn: process.env.GLITCHTIP_DSN, tracesSampleRate: 0.1 });
```

```python
# Python
import sentry_sdk
sentry_sdk.init(dsn=os.environ['GLITCHTIP_DSN'], traces_sample_rate=0.1)
```

A maioria dos frameworks tem auto-instrumentation: Express, FastAPI, Flask, Django, Laravel, etc.

### 4. Métricas

Para apps Node/Python/Go, instrumentar com **OpenTelemetry** ou cliente Prometheus nativo.

#### Métricas essenciais (RED method)

- **Rate** — requests por segundo, por endpoint
- **Errors** — taxa de erros por endpoint
- **Duration** — latência (p50, p95, p99)

#### Setup mínimo com Prometheus

```ts
// Node + prom-client
import client from 'prom-client';
client.collectDefaultMetrics();

const httpDuration = new client.Histogram({
  name: 'http_request_duration_seconds',
  help: 'HTTP request duration',
  labelNames: ['method', 'route', 'status'],
});

// expor /metrics
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', client.register.contentType);
  res.send(await client.register.metrics());
});
```

Configura Prometheus para fazer scrape do endpoint `/metrics`.

### 5. Dashboards (Grafana)

Templates JSON em `${CLAUDE_PLUGIN_ROOT}/configs/grafana/dashboards/`:

- `app-overview.json` — RED metrics
- `errors.json` — top errors
- `db-health.json` — connection pool, slow queries

Importa via UI ou provisioning.

### 6. Alertas

Setup mínimo (Alertmanager ou Grafana Alerts):

```yaml
# Regras úteis
- error_rate > 5% por mais de 5 minutos
- p95 latency > 1s por mais de 10 minutos
- /health não responde por 2 minutos
- disk usage > 85%
- memory usage > 90%
```

Output para Slack, email, ou ntfy.sh (open-source, free, simples).

### 7. Uptime monitoring

Setup Uptime Kuma — UI Bonita, fácil:

```bash
docker run -d --restart=always -p 3001:3001 -v uptime-kuma:/app/data --name uptime-kuma louislam/uptime-kuma:1
```

Adicionar monitors: HTTP do endpoint público, DNS, ping, etc.

## Não fazer

- Não loggar PII/secrets — secrets-redact no logger
- Não usar `level: debug` em produção sem sampling
- Não esquecer **log retention** — sem isso enches disco rápido
- Não criar 50 dashboards iguais — começa com 1 bom

## Custos zero a baixos

Toda esta stack corre num VPS modesto (4GB RAM, 2 CPU). Para apps pequenas, um único container `signoz/signoz` (~2GB RAM) cobre logs + métricas + tracing.

## Privacy/GDPR

Se a app tem utilizadores em UE:

- Self-host obriga zero data egress
- Em logs não guardar IPs/emails sem propósito legal
- Configurar retention adequada (90 dias normalmente OK)
- Documentar no privacy policy (`guardian-compliance` ajuda)
