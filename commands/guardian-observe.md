---
description: Logs, metrics, error tracking, alerts. Observability OSS.
---

Invoke the `guardian-observability` skill to set up or audit the observability stack.

Coverage:
- Structured logging (Pino, structlog, zerolog, slog, etc. depending on stack)
- Metrics (Prometheus client + Grafana dashboards)
- Error tracking (GlitchTip — Sentry-SDK-compatible — or self-hosted Sentry)
- Uptime checks (Uptime Kuma)
- Alerting rules

Stack-aware: only install what's relevant for the detected languages.

Hint (optional, e.g. "only error tracking", "add Prometheus"): $ARGUMENTS
