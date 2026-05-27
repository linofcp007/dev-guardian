/**
 * `observability_setup` — propose (and optionally apply) stack-appropriate
 * observability scaffolding.
 *
 * The proposals are stack-aware:
 *   - Node    → src/logger.ts (Pino) + src/metrics.ts (prom-client)
 *   - Python  → app/logging_config.py (structlog) + app/metrics.py (prometheus_client)
 *   - PHP     → app/Logger.php (Monolog) + monolog.config.php
 *   - Generic → docs/observability.md advisory (when no stack matched)
 *
 * Tools are configured, not vendored: each file references the runtime
 * package the project must install (`npm i pino`, `pip install structlog`,
 * etc.) — actual install is left to the user / their package manager.
 */

import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import type { DomainError, ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

interface Proposal {
  target: string;
  description: string;
  language: string;
  contents: string;
}

const tool: ToolModule = {
  name: 'observability_setup',
  title: 'Configure logging + metrics scaffolding',
  description:
    'Propose stack-appropriate observability files (Pino logger / structlog / Monolog, plus a ' +
    'Prometheus-compatible metrics module). When apply=true (default false), writes the files; ' +
    'otherwise returns proposals only.',
  inputSchema: {
    project_path: ProjectPath,
    apply: z
      .boolean()
      .optional()
      .describe('When true, write the proposed files to disk. Default: false (dry-run).'),
  },
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { project_path?: string; apply?: boolean };
  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    return failDomain('not_a_git_repo', (e as Error).message);
  }

  const apply = inp.apply ?? false;
  const stack = inferStack(projectPath, ctx);
  const proposals = buildProposals(stack);

  const written: Proposal[] = [];
  const skipped: Array<Proposal & { reason_skipped: string }> = [];
  const failed: Array<Proposal & { error: string }> = [];

  if (apply) {
    for (const p of proposals) {
      const abs = join(projectPath, p.target);
      if (existsSync(abs)) {
        skipped.push({ ...p, reason_skipped: 'already_exists' });
        continue;
      }
      try {
        mkdirSync(dirname(abs), { recursive: true });
        writeFileSync(abs, p.contents, 'utf8');
        written.push(p);
      } catch (e) {
        failed.push({ ...p, error: (e as Error).message });
      }
    }
  }

  return {
    ok: true,
    applied: apply,
    stack_inferred: stack,
    proposals: proposals.map((p) => ({
      target: p.target,
      description: p.description,
      language: p.language,
      size_bytes: Buffer.byteLength(p.contents, 'utf8'),
    })),
    files_written: written.map((p) => p.target),
    files_skipped: skipped.map((p) => ({
      target: p.target,
      reason_skipped: p.reason_skipped,
    })),
    files_failed: failed.map((p) => ({ target: p.target, error: p.error })),
  };
}

type Stack = 'node' | 'python' | 'php' | 'go' | 'rust' | 'java' | 'ruby' | 'generic';

function inferStack(projectPath: string, ctx: PluginContext): Stack {
  // Prefer the latest stack snapshot when available — it understands frameworks too.
  const snap = ctx.storage.stack.getLatest()?.snapshot;
  if (snap) {
    if (snap.languages?.includes('javascript') || snap.languages?.includes('typescript')) return 'node';
    if (snap.languages?.includes('python')) return 'python';
    if (snap.languages?.includes('php')) return 'php';
    if (snap.languages?.includes('go')) return 'go';
    if (snap.languages?.includes('rust')) return 'rust';
    if (snap.languages?.includes('java')) return 'java';
    if (snap.languages?.includes('ruby')) return 'ruby';
  }
  // Filesystem fallback.
  if (existsSync(join(projectPath, 'package.json'))) return 'node';
  if (
    existsSync(join(projectPath, 'pyproject.toml')) ||
    existsSync(join(projectPath, 'requirements.txt'))
  )
    return 'python';
  if (existsSync(join(projectPath, 'composer.json'))) return 'php';
  if (existsSync(join(projectPath, 'go.mod'))) return 'go';
  if (existsSync(join(projectPath, 'Cargo.toml'))) return 'rust';
  if (existsSync(join(projectPath, 'pom.xml')) || existsSync(join(projectPath, 'build.gradle')))
    return 'java';
  if (existsSync(join(projectPath, 'Gemfile'))) return 'ruby';
  return 'generic';
}

function buildProposals(stack: Stack): Proposal[] {
  switch (stack) {
    case 'node':
      return [
        { target: 'src/logger.ts', language: 'typescript', description: 'Pino structured logger', contents: NODE_LOGGER_TS },
        { target: 'src/metrics.ts', language: 'typescript', description: 'Prometheus metrics (prom-client)', contents: NODE_METRICS_TS },
      ];
    case 'python':
      return [
        { target: 'app/logging_config.py', language: 'python', description: 'structlog JSON logger', contents: PY_LOGGER_PY },
      ];
    case 'php':
      return [
        { target: 'app/Logger.php', language: 'php', description: 'Monolog logger factory', contents: PHP_LOGGER_PHP },
      ];
    case 'go':
      return [
        { target: 'internal/observ/logger.go', language: 'go', description: 'log/slog JSON logger', contents: GO_LOGGER_GO },
        { target: 'internal/observ/metrics.go', language: 'go', description: 'Prometheus client_golang registry', contents: GO_METRICS_GO },
      ];
    case 'rust':
      return [
        { target: 'src/observ.rs', language: 'rust', description: 'tracing + tracing-subscriber setup', contents: RUST_OBSERV_RS },
      ];
    case 'java':
      return [
        { target: 'src/main/resources/logback.xml', language: 'xml', description: 'Logback JSON encoder', contents: JAVA_LOGBACK_XML },
      ];
    case 'ruby':
      return [
        { target: 'config/initializers/observability.rb', language: 'ruby', description: 'SemanticLogger JSON appender', contents: RUBY_OBSERV_RB },
      ];
    default:
      return [
        { target: 'docs/observability.md', language: 'markdown', description: 'Advisory document — no stack autodetected', contents: GENERIC_ADVISORY_MD },
      ];
  }
}

// ---------------------------------------------------------------------- templates

const NODE_LOGGER_TS = `// Structured logger built on Pino.
// Install: \`npm i pino pino-pretty\`
import pino from 'pino';

export const logger = pino({
  level: process.env['LOG_LEVEL'] ?? 'info',
  transport: process.env['NODE_ENV'] === 'production'
    ? undefined
    : { target: 'pino-pretty', options: { colorize: true } },
});
`;

const NODE_METRICS_TS = `// Prometheus metrics endpoint.
// Install: \`npm i prom-client\`
import { collectDefaultMetrics, Counter, Histogram, register } from 'prom-client';

collectDefaultMetrics();

export const httpRequests = new Counter({
  name: 'http_requests_total',
  help: 'Total HTTP requests',
  labelNames: ['method', 'route', 'status'],
});

export const httpLatency = new Histogram({
  name: 'http_request_duration_seconds',
  help: 'HTTP request latency',
  labelNames: ['method', 'route'],
  buckets: [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
});

export async function metricsHandler(): Promise<string> {
  return register.metrics();
}
`;

const PY_LOGGER_PY = `# structlog JSON logger.
# Install: \`pip install structlog\`
import logging
import sys
import structlog

def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    )

log = structlog.get_logger()
`;

const PHP_LOGGER_PHP = `<?php
// Monolog logger factory.
// Install: \`composer require monolog/monolog\`
declare(strict_types=1);

use Monolog\\Handler\\StreamHandler;
use Monolog\\Level;
use Monolog\\Logger;
use Monolog\\Processor\\WebProcessor;

final class GuardianLogger
{
    public static function create(string $channel = 'app'): Logger
    {
        $logger = new Logger($channel);
        $logger->pushHandler(new StreamHandler('php://stdout', Level::Info));
        $logger->pushProcessor(new WebProcessor());
        return $logger;
    }
}
`;

const GENERIC_ADVISORY_MD = `# Observability

dev-guardian could not auto-detect a supported stack (Node / Python / PHP). Pick the path
that matches your runtime and follow the upstream getting-started guide:

- Node: https://github.com/pinojs/pino + https://github.com/siimon/prom-client
- Python: https://www.structlog.org + https://github.com/prometheus/client_python
- PHP: https://github.com/Seldaek/monolog + Prometheus exporter
- Go: log/slog stdlib + https://github.com/prometheus/client_golang
- Rust: tracing + https://github.com/prometheus/client_rust

Re-run \`observability_setup\` once a stack manifest (package.json, pyproject.toml,
composer.json) exists at the project root.
`;

const GO_LOGGER_GO = `// log/slog JSON logger (Go 1.21+, stdlib — no extra deps).
package observ

import (
	"log/slog"
	"os"
)

func NewLogger() *slog.Logger {
	level := slog.LevelInfo
	if os.Getenv("LOG_LEVEL") == "debug" {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     level,
		AddSource: true,
	}))
}
`;

const GO_METRICS_GO = `// Prometheus metrics.
// Install: \`go get github.com/prometheus/client_golang/prometheus\`
package observ

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var HTTPRequests = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "http_requests_total",
	Help: "Total HTTP requests.",
}, []string{"method", "route", "status"})

var HTTPLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "http_request_duration_seconds",
	Help:    "HTTP request latency in seconds.",
	Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
}, []string{"method", "route"})
`;

const RUST_OBSERV_RS = `// tracing + tracing-subscriber JSON output.
// Add to Cargo.toml:
//   tracing       = "0.1"
//   tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }
use tracing_subscriber::{fmt, EnvFilter};

pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt()
        .json()
        .with_env_filter(filter)
        .with_current_span(true)
        .init();
}
`;

const JAVA_LOGBACK_XML = `<?xml version="1.0" encoding="UTF-8"?>
<!-- Add to pom.xml: ch.qos.logback.contrib:logback-json-classic + logback-jackson -->
<configuration>
  <appender name="STDOUT_JSON" class="ch.qos.logback.core.ConsoleAppender">
    <encoder class="net.logstash.logback.encoder.LogstashEncoder">
      <includeMdc>true</includeMdc>
    </encoder>
  </appender>
  <root level="INFO">
    <appender-ref ref="STDOUT_JSON"/>
  </root>
</configuration>
`;

const RUBY_OBSERV_RB = `# SemanticLogger JSON output.
# In Gemfile: gem 'semantic_logger'
require 'semantic_logger'

SemanticLogger.default_level = ENV.fetch('LOG_LEVEL', 'info').to_sym
SemanticLogger.add_appender(io: $stdout, formatter: :json)

LOG = SemanticLogger['app']
`;

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
