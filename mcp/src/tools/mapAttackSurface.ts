/**
 * `map_attack_surface` — static inventory of what the application exposes.
 *
 * Standalone (no scan-tool factory): the output is structured metadata, not
 * Findings, and it must not create a row in `scans`. Same shape as
 * `detect_stack`.
 *
 * Failure policy: if Semgrep cannot run, NOTHING is persisted. A zero-route
 * snapshot written by a failed run would later be read by scan_dast and
 * risk_score as "this application exposes nothing" — the inverse of the
 * truth. "Zero because the scan failed" and "zero because there are none"
 * must stay distinguishable.
 */

import { join } from 'node:path';
import type { PluginContext } from '../context.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { runProcess } from '../runners/processRunner.js';
import { Force, ProjectPath } from '../schemas.js';
import { collectEnvVars } from '../surface/collectors/envVars.js';
import { collectPorts } from '../surface/collectors/ports.js';
import { extractSurface } from '../surface/extract.js';
import { resolveNodeMounts, type ImportRecord } from '../surface/resolvers/node.js';
import { resolveWordpressRoutes } from '../surface/resolvers/wordpress.js';
import { computeTreeHash } from '../treeHash/computeTreeHash.js';
import type {
  AttackSurfaceSnapshot,
  CoverageEntry,
  RouteRecord,
  ToolResult,
  ToolRun,
} from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';
import { ensureReportDir, readJsonSafe, scannerAvailable } from './scanHelpers.js';

const SAMPLE_SIZE = 20;
const WEBHOOK_PATTERN = /webhook|callback|hook/i;

/** Languages the rule pack covers, for honest `no_rules` reporting. */
const COVERED_LANGUAGES = new Set([
  'javascript', 'typescript', 'python', 'php', 'go', 'rust', 'ruby', 'java', 'csharp',
]);

const tool: ToolModule = {
  name: 'map_attack_surface',
  title: 'Map the application attack surface',
  description:
    'Statically extract the externally reachable surface of the project — HTTP routes ' +
    '(method, path, params, auth hint), referenced environment variables, and declared ' +
    'container ports — across all supported stacks. Persists a snapshot readable via ' +
    'guardian://surface/latest. Returns a summary plus a 20-route sample; read the ' +
    'resource for the full list.',
  inputSchema: {
    project_path: ProjectPath,
    force: Force,
  },
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { project_path?: string; force?: boolean };

  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    // `not_a_git_repo` is what detect_stack returns for an unusable
    // project_path (detectStack.ts:45-49), even though resolveProjectPath
    // actually rejects missing / non-directory / root-or-home paths. Keeping
    // the same code here means hosts and skills handle one failure, not two.
    // Do not "fix" this in isolation — it would desync the two tools.
    return { ok: false, error: { code: 'not_a_git_repo', message: (e as Error).message } };
  }

  const treeHash = await computeTreeHash(projectPath);

  if (inp.force !== true) {
    const cached = ctx.storage.surface.getByTreeHash(treeHash);
    if (cached) return summarize(cached.snapshot, cached.id, [
      { name: 'semgrep', status: 'skipped', reason: 'cached' },
    ]);
  }

  const semgrepBin = await scannerAvailable('semgrep');
  if (semgrepBin === null) {
    return {
      ok: true,
      routes_total: 0,
      by_language: [],
      coverage: [],
      snapshot_id: null,
      sample: [],
      env_vars_total: 0,
      ports: [],
      tools_run: [{ name: 'semgrep', status: 'skipped', reason: 'not_installed' }],
      missing_tools: ['semgrep'],
      note:
        'Semgrep is not installed, so no surface was mapped and nothing was persisted. ' +
        'Run install_toolchain, then retry.',
    };
  }

  const reportDir = ensureReportDir(projectPath, treeHash, 'surface');
  const outFile = join(reportDir, 'surface.json');
  const rulesPath = join(ctx.scriptsDir, '..', 'configs', 'semgrep', 'routes.yml');

  const run = await runProcess({
    command: 'semgrep',
    args: [
      '--config', rulesPath,
      '--json', '--output', outFile,
      '--quiet', '--no-git-ignore',
      projectPath,
    ],
    cwd: projectPath,
  });

  const raw = readJsonSafe(outFile);
  if (raw === null) {
    return {
      ok: true,
      routes_total: 0,
      by_language: [],
      coverage: [],
      snapshot_id: null,
      sample: [],
      env_vars_total: 0,
      ports: [],
      tools_run: [{ name: 'semgrep', status: 'failed', reason: 'no_output' }],
      missing_tools: [],
      note: 'Semgrep produced no parseable output; nothing was persisted.',
    };
  }

  const parsed: unknown = JSON.parse(raw);
  const toolRun: ToolRun = {
    name: 'semgrep',
    status: run.outcome === 'completed' ? 'ok' : 'failed',
  };

  const snapshot = buildSnapshot(parsed, projectPath, ctx, [toolRun]);
  const persisted = ctx.storage.surface.insert({
    project_path: projectPath,
    tree_hash: treeHash,
    snapshot,
  });

  return summarize(snapshot, persisted.id, [toolRun]);
}

function buildSnapshot(
  parsed: unknown,
  projectPath: string,
  ctx: PluginContext,
  toolsRun: ToolRun[],
): AttackSurfaceSnapshot {
  const { routes, mounts } = extractSurface(parsed);
  const imports = extractImports(parsed);

  const resolved = resolveWordpressRoutes(resolveNodeMounts(routes, mounts, imports));

  return {
    routes: resolved,
    env_vars: collectEnvVars(parsed),
    ports: collectPorts(projectPath),
    webhooks: resolved.filter((r) => WEBHOOK_PATTERN.test(r.path_resolved)),
    coverage: buildCoverage(resolved, ctx),
    tools_run: toolsRun,
    missing_tools: [],
  };
}

/** `guardian_kind: 'import'` matches, needed by the Node mount resolver. */
function extractImports(parsed: unknown): ImportRecord[] {
  const results = (parsed as { results?: unknown }).results;
  if (!Array.isArray(results)) return [];

  const out: ImportRecord[] = [];
  for (const raw of results) {
    const record = raw as {
      path?: string;
      extra?: {
        metadata?: { guardian_kind?: string };
        metavars?: Record<string, { abstract_content?: string }>;
      };
    };
    if (record.extra?.metadata?.guardian_kind !== 'import') continue;
    const symbol = record.extra.metavars?.['$SYMBOL']?.abstract_content;
    const modulePath = record.extra.metavars?.['$MODULE']?.abstract_content;
    const file = record.path;
    if (symbol === undefined || modulePath === undefined || file === undefined) continue;
    out.push({ symbol, module_file: resolveModuleFile(file, modulePath), file });
  }
  return out;
}

/**
 * Turn a specifier like `./routes/users` (imported from `src/app.ts`) into
 * the project-relative file `src/routes/users.ts`. Extension-less specifiers
 * are probed against the extensions Node resolves.
 */
function resolveModuleFile(importingFile: string, specifier: string): string {
  if (!specifier.startsWith('.')) return specifier;
  const dir = importingFile.split('/').slice(0, -1).join('/');
  const parts = `${dir}/${specifier}`.split('/');
  const stack: string[] = [];
  for (const part of parts) {
    if (part === '.' || part === '') continue;
    if (part === '..') stack.pop();
    else stack.push(part);
  }
  const base = stack.join('/');
  return /\.[cm]?[jt]sx?$/.test(base) ? base : `${base}.ts`;
}

function buildCoverage(routes: RouteRecord[], ctx: PluginContext): CoverageEntry[] {
  const detected = ctx.storage.stack.getLatest()?.snapshot.languages ?? [];
  const languages = new Set<string>([...detected, ...routes.map((r) => r.language)]);
  languages.delete('unknown');

  const entries: CoverageEntry[] = [];
  for (const language of [...languages].sort()) {
    const found = routes.filter((r) => r.language === language).length;
    const hasRules = COVERED_LANGUAGES.has(language);
    entries.push({
      language,
      detected: detected.includes(language),
      routes_found: found,
      status: !hasRules ? 'no_rules' : found > 0 ? 'ok' : 'no_matches',
    });
  }
  return entries;
}

function summarize(
  snapshot: AttackSurfaceSnapshot,
  snapshotId: number,
  toolsRun: ToolRun[],
): ToolResult<Record<string, unknown>> {
  const byLanguage = new Map<string, number>();
  for (const route of snapshot.routes) {
    byLanguage.set(route.language, (byLanguage.get(route.language) ?? 0) + 1);
  }

  return {
    ok: true,
    routes_total: snapshot.routes.length,
    by_language: [...byLanguage].map(([language, routes]) => ({ language, routes })),
    coverage: snapshot.coverage,
    snapshot_id: snapshotId,
    sample: snapshot.routes.slice(0, SAMPLE_SIZE),
    env_vars_total: snapshot.env_vars.length,
    ports: snapshot.ports,
    webhooks_total: snapshot.webhooks.length,
    tools_run: toolsRun,
    missing_tools: snapshot.missing_tools,
  };
}
