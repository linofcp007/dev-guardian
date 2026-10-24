/**
 * govulncheck (golang.org/x/vuln) over a project's Go modules — `deps_audit`.
 * Trivy already reports every vulnerable module a `go.mod` / `go.sum`
 * requires; govulncheck adds what Trivy cannot know: whether the project's
 * code CALLS the vulnerable function. Measured on govulncheck v1.9.0 (Go
 * 1.26.10, 2026-10-24), and deciding every argument below:
 *
 *   - `-format json` streams pretty-printed JSON objects, one key each:
 *     `config`, `progress`, `SBOM`, `osv` (an entry of the Go vulnerability
 *     database) and `finding` (`{ osv, fixed_version, trace }`). A finding
 *     comes at the level it was found at: `trace[0]` with a `function` is a
 *     vulnerable symbol the project's code reaches (the trace runs from it to
 *     the project's own call, each frame `{ module, package, function,
 *     position: { filename, line } }`, `filename` relative to its module's
 *     root); with only a `package`, a vulnerable package imported but not
 *     called; with only a `module`, one required and not imported. Only the
 *     first is a finding here: the other two are Trivy's, and the run's
 *     reason counts them.
 *   - The database gives no severity (`osv.severity` is absent): the finding
 *     takes Trivy's for the same CVE or GHSA when Trivy reported it
 *     (`deps_audit`'s dedupe), and is `medium` otherwise.
 *   - Exit 0 whether or not something was found; exit 1 for a failure, with
 *     the reason on stderr. ONE package that does not type-check fails the
 *     whole run (`loading packages: … undefined: x`, no finding at all), and
 *     an unreachable database fails it too (`creating client: …`).
 *   - `./...` stays inside the module it runs in: a nested module (its own
 *     `go.mod`) is not analysed. So govulncheck runs once per module
 *     directory ({@link goModuleDirs}), with `GOWORK=off` (each module's own
 *     requirements, as it builds on its own), and a module that failed is
 *     named — never a clean run.
 *   - It needs the Go toolchain (`go list`), which may download the
 *     modules; `GOFLAGS`' `-mod=mod` runs as `-mod=readonly`, as for gosec.
 */

import { join } from 'node:path';
import type { PartialParse, ToolRun } from '../types.js';
import { scannerAvailable } from '../tools/scanHelpers.js';
import { goToolEnv } from './gosecRun.js';
import { runProcess, type ProcessRunResult } from './processRunner.js';
import { asArray, getProp, getString, toPosixPath } from './scannerParsers/index.js';

/** The `tools_run` name of the govulncheck pass. */
const GOVULNCHECK = 'govulncheck';

/** A module govulncheck could not analyse (a package that does not type-check, the database unreachable). */
const GOVULNCHECK_MODULE_FAILED = 'Module not analysed';

/** The directory names `go` never treats as part of a module tree (beside `.` and `_` prefixes). */
const NOT_MODULES = new Set(['vendor', 'testdata']);

/** The directories of `files` (project-relative) that hold a `go.mod`, `.` for the root, sorted. */
export function goModuleDirs(files: readonly string[]): string[] {
  const dirs = new Set<string>();
  for (const raw of files) {
    const segments = toPosixPath(raw).split('/');
    if (segments.pop() !== 'go.mod') continue;
    if (segments.some((s) => NOT_MODULES.has(s) || s.startsWith('.') || s.startsWith('_'))) continue;
    dirs.add(segments.length === 0 ? '.' : segments.join('/'));
  }
  return [...dirs].sort();
}

/**
 * The JSON objects of a govulncheck `-format json` stream — pretty-printed
 * objects one after another, not one per line — or null when the text is not
 * such a stream.
 */
export function govulncheckMessages(text: string): unknown[] | null {
  const out: unknown[] = [];
  let depth = 0;
  let start = -1;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === '{') {
      if (depth === 0) start = i;
      depth += 1;
    } else if (ch === '}') {
      depth -= 1;
      if (depth < 0) return null;
      if (depth === 0) {
        try {
          out.push(JSON.parse(text.slice(start, i + 1)));
        } catch {
          return null;
        }
      }
    } else if (depth === 0 && ch !== undefined && !/\s/.test(ch)) {
      return null;
    }
  }
  return depth === 0 ? out : null;
}

/** The first line of govulncheck's stderr that says what went wrong. */
function failureOf(stderr: string): string {
  const lines = stderr.split(/\r?\n/).map((l) => l.trim()).filter((l) => l !== '');
  // `loading packages:` is followed by the go error itself (`file:line:col: msg`).
  const goError = lines.find((l) => /^\S+\.go:\d+:\d+: /.test(l));
  const head = lines[0] ?? 'govulncheck failed';
  return goError !== undefined && goError !== head ? `${head} ${goError}` : head;
}

interface ModuleRun {
  ok: boolean;
  reason?: string;
  report?: string;
  /** How many vulnerable symbols called, packages imported, modules required (the last two: not findings). */
  counts?: { called: number; imported: number; required: number };
}

/** One module's run, judged (see the module comment). */
export function judgeGovulncheck(run: Pick<ProcessRunResult, 'outcome' | 'exitCode' | 'stdout' | 'stderr'>): ModuleRun {
  if (run.outcome === 'cancelled' || run.outcome === 'timed_out' || run.outcome === 'output_too_large') {
    return { ok: false, reason: `did not finish (${run.outcome})` };
  }
  if (run.exitCode !== 0) return { ok: false, reason: `exit ${String(run.exitCode)}: ${failureOf(run.stderr)}` };
  const messages = govulncheckMessages(run.stdout);
  if (messages === null || !messages.some((m) => getProp(m, 'config') !== undefined)) {
    return { ok: false, reason: 'govulncheck wrote no JSON report' };
  }
  const called = new Set<string>();
  const imported = new Set<string>();
  const required = new Set<string>();
  for (const m of messages) {
    const finding = getProp(m, 'finding');
    const osv = getString(finding, 'osv');
    if (osv === undefined) continue;
    const first = asArray(getProp(finding, 'trace'))[0];
    if (getString(first, 'function') !== undefined) called.add(osv);
    else if (getString(first, 'package') !== undefined) imported.add(osv);
    else required.add(osv);
  }
  // A vulnerability is counted at the most precise level it reached.
  for (const id of called) {
    imported.delete(id);
    required.delete(id);
  }
  for (const id of imported) required.delete(id);
  return { ok: true, report: run.stdout, counts: { called: called.size, imported: imported.size, required: required.size } };
}

interface GovulncheckPass {
  /** Null when the files hold no Go module (no entry at all). */
  toolRun: ToolRun | null;
  missing: string[];
  /** Each module's report with its directory — the parser places the findings with it. */
  reports: Array<{ moduleDir: string; report: string }>;
  cancelled: boolean;
}

/**
 * govulncheck once per module directory among `files` (project-relative,
 * under `projectPath`). `ok` with the modules it could not analyse named
 * (`partially_parsed`, and `govulncheck` in `missing`), `failed` when no
 * module could be analysed, `skipped` when govulncheck or Go is absent.
 */
export async function govulncheckModules(args: {
  projectPath: string;
  files: readonly string[];
  env: NodeJS.ProcessEnv;
  signal: AbortSignal;
  onLog?: (line: string) => void;
}): Promise<GovulncheckPass> {
  const modules = goModuleDirs(args.files);
  if (modules.length === 0) return { toolRun: null, missing: [], reports: [], cancelled: false };
  if (!(await scannerAvailable(GOVULNCHECK))) {
    const missing = [GOVULNCHECK, ...((await scannerAvailable('go')) ? [] : ['go'])];
    return { toolRun: { name: GOVULNCHECK, status: 'skipped', reason: 'not_installed' }, missing, reports: [], cancelled: false };
  }
  if (!(await scannerAvailable('go'))) {
    return {
      toolRun: { name: GOVULNCHECK, status: 'skipped', reason: 'the Go toolchain (go) is not on PATH — govulncheck loads every package through it' },
      missing: ['go'],
      reports: [],
      cancelled: false,
    };
  }
  const { env, note } = goToolEnv(args.env);
  const reports: GovulncheckPass['reports'] = [];
  const failed: PartialParse[] = [];
  const totals = { called: 0, imported: 0, required: 0 };
  let cancelled = false;
  for (const dir of modules) {
    if (args.signal.aborted) {
      cancelled = true;
      break;
    }
    const run = await runProcess({
      command: 'govulncheck',
      args: ['-format', 'json', './...'],
      cwd: dir === '.' ? args.projectPath : join(args.projectPath, ...dir.split('/')),
      env: { ...env, GOWORK: 'off' },
      signal: args.signal,
      ...(args.onLog ? { onLog: args.onLog } : {}),
      stdoutCapBytes: 50 * 1024 * 1024,
    });
    if (run.outcome === 'cancelled') {
      cancelled = true;
      break;
    }
    const judged = judgeGovulncheck(run);
    const goMod = dir === '.' ? 'go.mod' : `${dir}/go.mod`;
    if (!judged.ok || judged.report === undefined) {
      failed.push({ file: goMod, type: GOVULNCHECK_MODULE_FAILED, message: judged.reason ?? 'failed' });
      continue;
    }
    reports.push({ moduleDir: dir, report: judged.report });
    totals.called += judged.counts?.called ?? 0;
    totals.imported += judged.counts?.imported ?? 0;
    totals.required += judged.counts?.required ?? 0;
  }
  const notes = note !== null ? [note] : [];
  if (cancelled) return { toolRun: { name: GOVULNCHECK, status: 'failed', reason: 'cancelled' }, missing: [], reports, cancelled };
  if (reports.length === 0) {
    const why = failed.map((f) => `${f.file}: ${f.message}`).slice(0, 3).join('; ');
    return { toolRun: { name: GOVULNCHECK, status: 'failed', reason: [`no module could be analysed — ${why}`, ...notes].join('; ') }, missing: [], reports, cancelled };
  }
  const reason = [
    `${reports.length} of ${modules.length} module(s) analysed: ${totals.called} vulnerability(ies) the code calls; ` +
      `${totals.imported} in packages it imports and ${totals.required} in modules it requires are not called (Trivy reports those)`,
    ...(failed.length > 0
      ? [`partial: ${failed.length} module(s) not analysed — ${failed.map((f) => `${f.file}: ${f.message}`).slice(0, 3).join('; ')}`]
      : []),
    ...notes,
  ].join('; ');
  const toolRun: ToolRun = { name: GOVULNCHECK, status: 'ok', reason };
  if (failed.length > 0) toolRun.partially_parsed = failed;
  return { toolRun, missing: failed.length > 0 ? [GOVULNCHECK] : [], reports, cancelled };
}
