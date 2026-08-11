/**
 * `map_attack_surface` — static inventory of what the application exposes.
 *
 * Standalone (no scan-tool factory): the output is structured metadata, not
 * Findings, and it must not create a row in `scans`. Same shape as
 * `detect_stack`.
 *
 * Failure policy: if Semgrep cannot run — natively or via Docker — NOTHING
 * is persisted. A zero-route snapshot written by a failed run would later be
 * read by scan_dast and risk_score as "this application exposes nothing" —
 * the inverse of the truth. "Zero because the scan failed" and "zero because
 * there are none" must stay distinguishable. The same guarantee extends to a
 * Semgrep run that "succeeded" but produced no readable/parseable JSON: we
 * never let a parse exception escape uncaught (there is no try/catch at the
 * MCP dispatch site), and we never treat garbage output as zero routes.
 *
 * The one case where a non-zero Semgrep exit DOES get persisted: Semgrep
 * exits 1 when it *finds* matches (see `buildToolRun` below) — that is
 * success, not failure. A genuine failure (crash, bad config, timeout) still
 * blocks persistence only when it also failed to leave parseable JSON behind;
 * if it left partial-but-parseable JSON, that partial data is persisted with
 * a `failed` tools_run entry carrying the diagnostic.
 */

import { copyFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { DEFAULT_SEMGREP_IMAGE, toContainerPath } from '../runners/dockerScanner.js';
import { runProcess, type ProcessRunResult } from '../runners/processRunner.js';
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

const IncludeEnvVars = z
  .boolean()
  .optional()
  .default(true)
  .describe('Collect environment-variable names the code reads. Default: true.');

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
    include_env_vars: IncludeEnvVars,
  },
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { project_path?: string; force?: boolean; include_env_vars?: boolean };

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
    if (cached) {
      return summarize(
        cached.snapshot,
        cached.id,
        [{ name: 'semgrep', status: 'skipped', reason: 'cached' }],
        ctx,
      );
    }
  }

  const includeEnvVars = inp.include_env_vars !== false;
  const reportDir = ensureReportDir(projectPath, treeHash, 'surface');
  const outFile = join(reportDir, 'surface.json');
  const rulesPath = join(ctx.scriptsDir, '..', 'configs', 'semgrep', 'routes.yml');

  const invocation = await invokeSemgrep(projectPath, rulesPath, outFile, reportDir);
  if (invocation === null) {
    return degradedResult(
      [
        {
          name: 'semgrep',
          status: 'skipped',
          reason: 'not_installed (no docker fallback available)',
        },
      ],
      ['semgrep'],
      'Semgrep is not installed and no Docker fallback is available, so no surface was ' +
        'mapped and nothing was persisted. Run install_toolchain, then retry.',
      ctx,
    );
  }

  const { toolRun } = invocation;

  // `readJsonSafe` returns null only for a missing/unreadable file (see
  // scanHelpers.ts) — never for unparseable content. A file that exists but
  // holds truncated/garbage JSON (mid-write timeout, stale partial file from
  // a previous crash) reaches the JSON.parse below, which is guarded
  // separately.
  const raw = readJsonSafe(outFile);
  if (raw === null) {
    const failedToolRun: ToolRun = {
      ...toolRun,
      status: 'failed',
      reason: toolRun.reason ?? 'no_output',
    };
    return degradedResult(
      [failedToolRun],
      [],
      'Semgrep produced no readable output file; nothing was persisted.',
      ctx,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    // Precedent: detectStack.ts:73-79 catches JSON.parse the same way and
    // returns a degraded result instead of letting the SyntaxError escape.
    // There is no try/catch at the tool-dispatch site (tools/index.ts), so
    // an uncaught throw here would surface as an opaque MCP protocol error
    // and bypass this tool's documented "persist nothing" contract entirely.
    const failedToolRun: ToolRun = {
      name: 'semgrep',
      status: 'failed',
      reason: `unparseable output: ${(e as Error).message}`,
    };
    return degradedResult(
      [failedToolRun],
      [],
      'Semgrep output was not valid JSON; nothing was persisted.',
      ctx,
    );
  }

  const snapshot = buildSnapshot(parsed, projectPath, ctx, [toolRun], includeEnvVars);
  const persisted = ctx.storage.surface.insert({
    project_path: projectPath,
    tree_hash: treeHash,
    snapshot,
  });

  return summarize(snapshot, persisted.id, [toolRun], ctx);
}

/**
 * Run Semgrep against the routes rule pack, natively if it's on PATH,
 * otherwise via Docker. Returns null only when neither is available — the
 * caller treats that as "cannot run at all" and persists nothing.
 *
 * Mirrors scan_sast's Docker fallback (scanSast.ts:95-130): probe `docker`,
 * bind the project at `/src`, run the container, and check for real output.
 * We don't call `buildSemgrepDockerArgs` directly — it hardcodes
 * `--config=auto` with no hook for a custom rule pack — but we reuse the
 * same conventions from `runners/dockerScanner.js` it's built on
 * (`toContainerPath`, `DEFAULT_SEMGREP_IMAGE`, the `/src` bind-mount shape)
 * rather than inventing a second one. The rule pack lives outside the
 * project tree (in the dev-guardian install), so we stage a copy inside the
 * report dir — already inside the project, already inside the bind mount —
 * instead of adding a second `--mount`.
 */
async function invokeSemgrep(
  projectPath: string,
  rulesPath: string,
  outFile: string,
  reportDir: string,
): Promise<{ toolRun: ToolRun } | null> {
  const semgrepBin = await scannerAvailable('semgrep');
  if (semgrepBin !== null) {
    const run = await runProcess({
      command: 'semgrep',
      args: ['--config', rulesPath, '--json', '--output', outFile, '--quiet', projectPath],
      cwd: projectPath,
    });
    return { toolRun: buildToolRun(run) };
  }

  const dockerBin = await scannerAvailable('docker');
  if (dockerBin === null) return null;

  let containerRules: string;
  try {
    const stagedRules = join(reportDir, 'routes.yml');
    copyFileSync(rulesPath, stagedRules);
    containerRules = toContainerPath(projectPath, stagedRules);
  } catch (e) {
    return {
      toolRun: {
        name: 'semgrep',
        status: 'failed',
        reason: `docker: could not stage rule pack: ${(e as Error).message}`,
      },
    };
  }

  const image = process.env['GUARDIAN_SEMGREP_IMAGE'] || DEFAULT_SEMGREP_IMAGE;
  const containerOut = toContainerPath(projectPath, outFile);
  const run = await runProcess({
    command: 'docker',
    args: [
      'run', '--rm',
      '--mount', `type=bind,source=${projectPath},target=/src`,
      '-w', '/src',
      image, 'semgrep',
      '--config', containerRules,
      '--json', '--quiet', '--output', containerOut,
      '/src',
    ],
    cwd: projectPath,
  });
  return { toolRun: buildToolRun(run, `docker (${image})`) };
}

/**
 * Semgrep exits 1 when it *finds* matches — that is success, not failure.
 * Repo convention: scanSast.ts:87-94, bugHunt.ts:158, scanWordpress.ts
 * (semgrep-wp/gitleaks/etc.) all treat `outcome === 'completed' ||
 * exitCode === 1` as ok. Reading the raw outcome alone (as an earlier
 * version of this tool did) reports every successful route-finding run as
 * `failed`.
 */
function buildToolRun(run: ProcessRunResult, via?: string): ToolRun {
  const ok = run.outcome === 'completed' || run.exitCode === 1;
  if (ok) {
    return via ? { name: 'semgrep', status: 'ok', reason: `ran via ${via}` } : { name: 'semgrep', status: 'ok' };
  }
  const firstLine = run.stderr.split(/\r?\n/).find((l) => l.trim().length > 0);
  const reason = via ? `${via}: ${firstLine ?? 'fallback failed'}` : (firstLine ?? 'unknown');
  return { name: 'semgrep', status: 'failed', reason };
}

function buildSnapshot(
  parsed: unknown,
  projectPath: string,
  ctx: PluginContext,
  toolsRun: ToolRun[],
  includeEnvVars: boolean,
): AttackSurfaceSnapshot {
  const { routes, mounts } = extractSurface(parsed);
  const knownFiles = collectAllFiles(parsed);
  const imports = extractImports(parsed, knownFiles);

  const resolved = resolveWordpressRoutes(resolveNodeMounts(routes, mounts, imports));

  return {
    routes: resolved,
    env_vars: includeEnvVars ? collectEnvVars(parsed) : [],
    ports: collectPorts(projectPath),
    webhooks: resolved.filter((r) => WEBHOOK_PATTERN.test(r.path_resolved)),
    coverage: buildCoverage(resolved, ctx),
    tools_run: toolsRun,
    missing_tools: [],
  };
}

/** Every file path Semgrep reported a match in, across all `guardian_kind`s. */
function collectAllFiles(parsed: unknown): Set<string> {
  const results = (parsed as { results?: unknown }).results;
  const out = new Set<string>();
  if (!Array.isArray(results)) return out;
  for (const raw of results) {
    const path = (raw as { path?: unknown }).path;
    if (typeof path === 'string') out.add(path);
  }
  return out;
}

/** `guardian_kind: 'import'` matches, needed by the Node mount resolver. */
function extractImports(parsed: unknown, knownFiles: Set<string>): ImportRecord[] {
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
    // Semgrep's abstract_content keeps the source quoting (`'./routes/users'`,
    // not `./routes/users`) — same as $PATH/$PREFIX in extract.ts and $NAME
    // in envVars.ts. Without stripping it, `specifier.startsWith('.')` in
    // resolveModuleFile below never matches and mount resolution silently
    // never fires against real Semgrep output.
    const symbol = stripQuotes(record.extra.metavars?.['$SYMBOL']?.abstract_content);
    const modulePath = stripQuotes(record.extra.metavars?.['$MODULE']?.abstract_content);
    const file = record.path;
    if (symbol === undefined || modulePath === undefined || file === undefined) continue;
    out.push({ symbol, module_file: resolveModuleFile(file, modulePath, knownFiles), file });
  }
  return out;
}

function stripQuotes(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  return value.replace(/^['"`]|['"`]$/g, '');
}

function stripKnownExtension(path: string): string {
  return path.replace(/\.[cm]?[jt]sx?$/, '');
}

/**
 * Turn a specifier like `./routes/users` (imported from `src/app.ts`) into
 * the project-relative file the route was actually matched in, e.g.
 * `src/routes/users.ts`.
 *
 * We do NOT guess a single extension: a plain-JS project imports
 * `./routes/users` and the real file is `.js`; a TypeScript project under
 * this repo's own NodeNext convention imports `./routes/users.js` and the
 * real source file is `.ts`. Neither case is knowable from the specifier
 * text alone, and we have no filesystem access here. Instead we compare,
 * extension-insensitively, against the file paths Semgrep actually reported
 * matches in during this same run (`knownFiles`) and take the one whose
 * extension-stripped path matches. When nothing matches, we return the
 * normalised specifier path as our best-effort guess rather than fabricate
 * an extension.
 */
function resolveModuleFile(importingFile: string, specifier: string, knownFiles: Set<string>): string {
  if (!specifier.startsWith('.')) return specifier;
  const dir = importingFile.split('/').slice(0, -1).join('/');
  const parts = `${dir}/${specifier}`.split('/');
  const stack: string[] = [];
  for (const part of parts) {
    if (part === '.' || part === '') continue;
    if (part === '..') stack.pop();
    else stack.push(part);
  }
  const joined = stack.join('/');
  const base = stripKnownExtension(joined);

  for (const file of knownFiles) {
    if (stripKnownExtension(file) === base) return file;
  }
  return joined;
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

const NO_STACK_NOTE =
  'No stack snapshot found for this project — run detect_stack first for fuller coverage context.';

function summarize(
  snapshot: AttackSurfaceSnapshot,
  snapshotId: number,
  toolsRun: ToolRun[],
  ctx: PluginContext,
): ToolResult<Record<string, unknown>> {
  const byLanguage = new Map<string, number>();
  for (const route of snapshot.routes) {
    byLanguage.set(route.language, (byLanguage.get(route.language) ?? 0) + 1);
  }

  // Deterministic across runs: order by language then path before slicing,
  // rather than relying on Semgrep's (unspecified) match order.
  const sample = [...snapshot.routes]
    .sort(
      (a, b) =>
        a.language.localeCompare(b.language) || a.path_resolved.localeCompare(b.path_resolved),
    )
    .slice(0, SAMPLE_SIZE);

  const stackDetected = ctx.storage.stack.getLatest() !== null;

  return {
    ok: true,
    routes_total: snapshot.routes.length,
    by_language: [...byLanguage].map(([language, routes]) => ({ language, routes })),
    coverage: snapshot.coverage,
    snapshot_id: snapshotId,
    sample,
    env_vars_total: snapshot.env_vars.length,
    ports: snapshot.ports,
    webhooks_total: snapshot.webhooks.length,
    tools_run: toolsRun,
    missing_tools: snapshot.missing_tools,
    stack_detected: stackDetected,
    ...(stackDetected ? {} : { note: NO_STACK_NOTE }),
  };
}

/**
 * Shared shape for every "Semgrep could not produce a usable result" exit —
 * unavailable, no output, unparseable output. All three must persist
 * nothing (see the module doc comment) and must return the same field set
 * as `summarize` so a consumer never sees `undefined` on the fields it reads
 * hardest (e.g. `webhooks_total`) just because this run happened to degrade.
 */
function degradedResult(
  toolsRun: ToolRun[],
  missingTools: string[],
  note: string,
  ctx: PluginContext,
): ToolResult<Record<string, unknown>> {
  return {
    ok: true,
    routes_total: 0,
    by_language: [],
    coverage: [],
    snapshot_id: null,
    sample: [],
    env_vars_total: 0,
    ports: [],
    webhooks_total: 0,
    tools_run: toolsRun,
    missing_tools: missingTools,
    stack_detected: ctx.storage.stack.getLatest() !== null,
    note,
  };
}
