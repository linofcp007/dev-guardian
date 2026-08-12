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
 * exits 1 when it *finds* matches (see `buildToolRun` in `surface/scanSemgrep.ts`) — that is
 * success, not failure. A genuine failure (crash, bad config, timeout) still
 * blocks persistence only when it also failed to leave parseable JSON behind;
 * if it left partial-but-parseable JSON, that partial data is persisted with
 * a `failed` tools_run entry carrying the diagnostic.
 *
 * The same guarantee covers a fourth failure mode: Semgrep reporting matches
 * whose content we cannot read. Current versions redact `extra.metavars`
 * unless the user has run `semgrep login`, so the captures are rebuilt from
 * the matched byte range (see `surface/recoverMetavars.ts`). If Semgrep
 * reported matches and not one could be recovered, that is a broken
 * toolchain, not a project without routes — nothing is persisted.
 */

import { readFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { Force, ProjectPath } from '../schemas.js';
import { collectEnvVars } from '../surface/collectors/envVars.js';
import { collectPorts } from '../surface/collectors/ports.js';
import { extractSurface, languageFromPath } from '../surface/extract.js';
import {
  recoverMetavars,
  type RecoveryOutcome,
  type SourceMap,
} from '../surface/recoverMetavars.js';
import { resolveNodeMounts, type ImportRecord } from '../surface/resolvers/node.js';
import { resolveWordpressRoutes } from '../surface/resolvers/wordpress.js';
import { invokeSemgrep } from '../surface/scanSemgrep.js';
import { computeTreeHash } from '../treeHash/computeTreeHash.js';
import type {
  AttackSurfaceSnapshot,
  CoverageEntry,
  RouteRecord,
  ToolResult,
  ToolRun,
} from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';
import { ensureReportDir, readJsonSafe } from './scanHelpers.js';

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
  // No "auth hint" in this description on purpose: `auth_hint` exists on every
  // RouteRecord but no rule can populate it yet, so it is always 'unknown'
  // (see normalizeAuth in surface/extract.ts). Advertising a constant as a
  // feature is how an agent ends up reasoning from it.
  description:
    'Statically extract the externally reachable surface of the project — HTTP routes ' +
    '(method, path, params), referenced environment variables, and declared ' +
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
      return summarize(cached.snapshot, cached.id, cachedToolsRun(cached.snapshot), ctx);
    }
  }

  const includeEnvVars = inp.include_env_vars !== false;
  const reportDir = ensureReportDir(projectPath, treeHash, 'surface');
  const outFile = join(reportDir, 'surface.json');
  const rulesPath = join(ctx.scriptsDir, '..', 'configs', 'semgrep', 'routes.yml');

  const invocation = await invokeSemgrep({ projectPath, rulesPath, outFile, reportDir });
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

  // Rebuild the captures modern Semgrep redacts, before anything downstream
  // looks for them. Reading the files is the impure half and belongs here;
  // `recoverMetavars` itself is pure and takes the text.
  const recovery = recoverMetavars(parsed, readSources(parsed, projectPath));
  if (recovery.intact === 0 && recovery.recovered === 0 && recovery.unrecoverable > 0) {
    return degradedResult(
      [toolRun, unreadableMatchesToolRun(recovery)],
      [],
      unreadableMatchesNote(recovery),
      ctx,
    );
  }

  const toolsRun = [toolRun, ...recoveryToolRun(recovery)];
  const snapshot = buildSnapshot(
    recovery.json,
    projectPath,
    ctx,
    toolsRun,
    includeEnvVars,
    recovery.unreadableRouteFiles,
  );
  const persisted = ctx.storage.surface.insert({
    project_path: projectPath,
    tree_hash: treeHash,
    snapshot,
  });

  return summarize(snapshot, persisted.id, toolsRun, ctx);
}

/** Name used for the recovery step in `tools_run`; it is not a real binary. */
const RECOVERY_STEP = 'semgrep-metavar-recovery';

/**
 * Source text of every file Semgrep reported a match in, keyed by the `path`
 * value verbatim so `recoverMetavars` can look it up without re-deriving it.
 *
 * Semgrep reports absolute paths when handed an absolute target (which this
 * tool does) and relative ones when handed a relative target, so both are
 * resolved. A file that cannot be read is simply absent from the map — the
 * recovery counts it `unrecoverable` rather than guessing.
 */
function readSources(parsed: unknown, projectPath: string): SourceMap {
  const sources = new Map<string, string>();
  for (const path of collectAllFiles(parsed)) {
    try {
      const buffer = readFileSync(isAbsolute(path) ? path : join(projectPath, path));
      const text = buffer.toString('utf8');
      // Offsets are byte offsets into the file as it sits on disk. Bytes that
      // are not valid UTF-8 decode to U+FFFD, which re-encodes to a different
      // length and shifts every later offset — so a file that does not
      // round-trip is dropped rather than sliced at the wrong place.
      if (Buffer.byteLength(text, 'utf8') !== buffer.length) continue;
      sources.set(path, text);
    } catch {
      // Unreadable / deleted since the scan: absent from the map, by design.
    }
  }
  return sources;
}

/**
 * Make a recovered run visible instead of silent — including the partial case,
 * where some routes are real and some matches were lost. Persisted with the
 * snapshot, so `cachedToolsRun` keeps reporting it on later cache hits.
 * Emitted only when there was something to recover: a run against an older
 * (or logged-in) Semgrep is `intact` throughout and says nothing new.
 */
/**
 * How to get the unreadable matches back. Named wherever a loss is reported,
 * because the fix is not obvious and the obvious guess — "this tool needs a
 * Semgrep account" — is wrong: all thirteen route families are rebuilt from
 * byte offsets and work on any version, logged in or not.
 *
 * A loss therefore no longer means "this rule family cannot be read". It means
 * the source could not be read at the offsets Semgrep reported — the file was
 * deleted or rewritten mid-scan, is not valid UTF-8, or the span carried no
 * capture. Logging in still fixes it, by making the captures arrive directly so
 * the file never has to be re-read; that is why the remedy is still named.
 */
const REDACTION_REMEDY =
  'this Semgrep version redacts match content unless you run `semgrep login`, so the ' +
  'captures are rebuilt by re-reading the source at the reported byte offsets, and that ' +
  'read failed for these matches. Either log in, or use a Semgrep older than ~1.100, and ' +
  'the captures arrive directly. dev-guardian does not require an account — every route ' +
  'family is rebuilt from byte offsets either way';

function recoveryToolRun(recovery: RecoveryOutcome): ToolRun[] {
  if (recovery.recovered === 0 && recovery.unrecoverable === 0) return [];
  const base =
    `recovered ${recovery.recovered} redacted match(es) from byte offsets` +
    (recovery.intact > 0 ? `; ${recovery.intact} already carried metavariables` : '');
  if (recovery.unrecoverable === 0) {
    return [{ name: RECOVERY_STEP, status: 'ok', reason: base }];
  }
  return [
    {
      name: RECOVERY_STEP,
      status: 'failed',
      reason:
        `${base}; ${recovery.unrecoverable} match(es) could not be read and are MISSING ` +
        `from the surface (see coverage[].unreadable_matches for which languages) — ` +
        `${REDACTION_REMEDY}`,
    },
  ];
}

function unreadableMatchesToolRun(recovery: RecoveryOutcome): ToolRun {
  return {
    name: RECOVERY_STEP,
    status: 'failed',
    reason:
      `no match content: all ${recovery.unrecoverable} match(es) lacked metavariables ` +
      'and none could be recovered from the reported byte offsets',
  };
}

function unreadableMatchesNote(recovery: RecoveryOutcome): string {
  return (
    `Semgrep reported ${recovery.unrecoverable} match(es) and not one could be read, so no ` +
    'surface was mapped and nothing was persisted — a zero-route snapshot here would read as ' +
    '"this application exposes nothing", the inverse of what was measured. Cause: ' +
    `${REDACTION_REMEDY}. Every match failing this way at once usually means the working ` +
    'tree changed under the scan, or the files are not valid UTF-8 — check that the project ' +
    'was not being written to while the scan ran, then re-run.'
  );
}

/**
 * What a cache hit reports as `tools_run`.
 *
 * The cache marker must not erase the run that produced the snapshot. There
 * is exactly one case where a failing run still persists — Semgrep exited
 * non-zero but left parseable JSON, persisted with a `failed` entry carrying
 * the diagnostic. Reporting a bare `{semgrep, skipped, cached}` on every
 * later call for the same tree hash would let that warning survive one call
 * and then vanish, so a snapshot that is empty *because the scan died* would
 * read as "this application exposes nothing" — verbatim the falsehood this
 * tool exists to prevent (see the module doc comment).
 */
function cachedToolsRun(snapshot: AttackSurfaceSnapshot): ToolRun[] {
  const marker: ToolRun = { name: 'semgrep', status: 'skipped', reason: 'cached' };
  const persisted = snapshot.tools_run.map((run) => ({
    ...run,
    reason:
      run.reason === undefined ? 'from the cached run' : `${run.reason} (from the cached run)`,
  }));
  return [marker, ...persisted];
}

function buildSnapshot(
  parsed: unknown,
  projectPath: string,
  ctx: PluginContext,
  toolsRun: ToolRun[],
  includeEnvVars: boolean,
  unreadableRouteFiles: readonly string[],
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
    coverage: buildCoverage(resolved, ctx, unreadableRouteFiles),
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
 * Semgrep reports paths in the host's native separator: on Windows a match in
 * `node-express/routes/users.js` comes back as
 * `C:\project\node-express\routes\users.js`. An import specifier is always
 * POSIX-ish (`./routes/users.js`), so the two are only comparable once the
 * reported path is normalised. Without this, `resolveModuleFile` below split a
 * Windows path into a single segment, matched no known file, and every mounted
 * router silently degraded to `path_partial` — mount resolution was dead on
 * Windows while looking healthy everywhere else.
 */
function toPosixPath(path: string): string {
  return path.replace(/\\/g, '/');
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
 *
 * The comparison is separator-insensitive, but the value returned on a hit is
 * the known file *verbatim*: it is later looked up against `RouteRecord.file`,
 * which carries Semgrep's spelling unchanged.
 */
function resolveModuleFile(importingFile: string, specifier: string, knownFiles: Set<string>): string {
  if (!specifier.startsWith('.')) return specifier;
  const dir = toPosixPath(importingFile).split('/').slice(0, -1).join('/');
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
    if (stripKnownExtension(toPosixPath(file)) === base) return file;
  }
  return joined;
}

/**
 * Per-language coverage.
 *
 * `unreadable` exists so that a language whose routes Semgrep matched but we
 * could not read never reports `no_matches`. The two are opposite facts — "we
 * looked and there is nothing" versus "there is something and we could not read
 * it" — and collapsing them is the "this application exposes nothing" falsehood
 * this tool is built to avoid.
 *
 * No rule family is refused any more (surface/recoverMetavars.ts), so this is
 * now the genuinely-unreadable case only: source that changed under the scan,
 * is not valid UTF-8, or offsets that land past end-of-file. Rare, and still
 * not something to round down to zero.
 */
function buildCoverage(
  routes: RouteRecord[],
  ctx: PluginContext,
  unreadableRouteFiles: readonly string[],
): CoverageEntry[] {
  const detected = ctx.storage.stack.getLatest()?.snapshot.languages ?? [];

  // One entry per lost route, so the count is routes-not-shown, not files.
  const unreadableByLanguage = new Map<string, number>();
  for (const file of unreadableRouteFiles) {
    const language = languageFromPath(file);
    if (language === 'unknown') continue;
    unreadableByLanguage.set(language, (unreadableByLanguage.get(language) ?? 0) + 1);
  }

  const languages = new Set<string>([
    ...detected,
    ...routes.map((r) => r.language),
    ...unreadableByLanguage.keys(),
  ]);
  languages.delete('unknown');

  const entries: CoverageEntry[] = [];
  for (const language of [...languages].sort()) {
    const found = routes.filter((r) => r.language === language).length;
    const unreadable = unreadableByLanguage.get(language) ?? 0;
    const hasRules = COVERED_LANGUAGES.has(language);
    entries.push({
      language,
      detected: detected.includes(language),
      routes_found: found,
      unreadable_matches: unreadable,
      // `unreadable` outranks `ok`: a language with some routes read and some
      // lost is not fully covered, and saying `ok` would hide the gap.
      status: unreadable > 0 ? 'unreadable' : !hasRules ? 'no_rules' : found > 0 ? 'ok' : 'no_matches',
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
