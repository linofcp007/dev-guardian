/**
 * gosec (securego/gosec) over a project's Go packages — `scan_sast` (whole
 * project or a scope) and `review_pr` (the changed packages).
 *
 * gosec loads each package through the Go toolchain (`go list`, then the
 * type checker and an SSA build for its SSA rules, the taint rules
 * G701–G710 among them): without
 * `go` on PATH every package fails to load, and a module whose dependencies
 * are not in the module cache is downloaded by `go`, as any build of it
 * would. What follows was measured on gosec 2.30.0 (golang:1.25-alpine,
 * 2026-10-24) and decides every argument below:
 *
 *   - `./...` is never passed. gosec's own walk skips every directory whose
 *     name STARTS with `vendor` or `.git` — `vendored/`, `vendors/`,
 *     `vendor-api/` — with nothing in the report to say so, and
 *     `-exclude-dir` adds to that list rather than replacing it. The
 *     package directories are listed here instead ({@link goPackageDirs}, from
 *     the files a scan reads: `.guardianignore` applied, `vendor/` and the
 *     directories `go` itself ignores left out) and passed after `--`, which
 *     gosec takes for what they are (a `-dash/` directory, a space).
 *   - A FILE given as a target is analysed as nothing at all (`Stats.files:
 *     0`, exit 0): only directories are passed.
 *   - `-quiet` is never passed: with it, a run that finds no issue writes no
 *     report — a syntax error included — which reads as a crash.
 *   - `-no-fail`: exit 0 with issues; the report decides
 *     ({@link checkGosecReport}). `-log` keeps the per-file log lines out of
 *     the output the runner caps.
 *   - A package that does not type-check (a dependency not downloaded, a
 *     compile error) is still read by the AST rules, but its SSA build — and
 *     with it every SSA rule, taint included — is skipped; the report says so only under
 *     `Golang errors`. Each such file is named, never a clean result.
 *   - A file the platform's build constraints leave out (`//go:build
 *     windows` on Linux, `//go:build ignore`) is not counted in `Stats.files`
 *     and named nowhere: the run's reason says how many of the listed files
 *     gosec analysed.
 *   - Test files (`_test.go`) are not analysed (gosec's default), and are not
 *     listed here either.
 */

import type { PartialParse, ToolRun } from '../types.js';
import { scannerAvailable } from '../tools/scanHelpers.js';
import { scanFileBatches } from './fileBatchScan.js';
import type { ProcessOutcome } from './processRunner.js';
import { asArray, getNumber, getProp, getString, parseInputAsJson, toPosixPath, toRelativeIfPossible } from './scannerParsers/index.js';

/** The `tools_run` name of a gosec pass. */
export const GOSEC = 'gosec';

/** The `missing_tools` name when the Go toolchain gosec loads packages through is absent. */
const GO_TOOLCHAIN = 'go';

/** A file gosec could not parse: what the CI gate's `--accept-partial-parse` accepts. */
export const GOSEC_SYNTAX_ERROR = 'Syntax error';

/** A file of a package that did not type-check: its package's SSA and taint rules did not run. */
export const GOSEC_TYPE_ERROR = 'Type error';

/** A package directory `go` could not load at all: nothing in it was analysed. */
export const GOSEC_PACKAGE_NOT_LOADED = 'Package not loaded';

/** The directory names `go` never treats as packages of a `./...` (beside `.` and `_` prefixes). */
const NOT_PACKAGES = new Set(['vendor', 'testdata']);

/**
 * The Go package directories of `files` (project-relative, `/`-separated —
 * what a scan reads), `.` for the root, sorted; and how many non-test `.go`
 * files they hold. A directory `go` ignores (`vendor`, `testdata`, a name
 * starting with `.` or `_`), and a file it ignores (`_x.go`, `.x.go`, a
 * `_test.go`), are left out at any depth.
 */
export function goPackageDirs(files: readonly string[]): { dirs: string[]; goFiles: number } {
  const dirs = new Set<string>();
  let goFiles = 0;
  for (const raw of files) {
    const file = toPosixPath(raw);
    const segments = file.split('/');
    const name = segments.pop() ?? '';
    if (!name.endsWith('.go') || name.endsWith('_test.go') || name.startsWith('.') || name.startsWith('_')) continue;
    if (segments.some((s) => NOT_PACKAGES.has(s) || s.startsWith('.') || s.startsWith('_'))) continue;
    dirs.add(segments.length === 0 ? '.' : segments.join('/'));
    goFiles += 1;
  }
  return { dirs: [...dirs].sort(), goFiles };
}

/** Whether `file` (project-relative) is a Go source gosec would read — {@link goPackageDirs}' test. */
export function isGoSource(file: string): boolean {
  return goPackageDirs([file]).goFiles === 1;
}

/** A message of gosec's `Golang errors` that the Go parser wrote, not the type checker. */
function isSyntaxMessage(message: string): boolean {
  return /\bsyntax error\b|^(expected|missing|illegal|unexpected)\b/i.test(message.trim());
}

/** `path/to/a.go:3:9: message` lines of a compile summary (the `""` entry). */
const SUMMARY_LINE = /^(.+?\.go):(\d+):(\d+): (.*)$/;

interface GosecCheck {
  ok: boolean;
  reason?: string;
  scanned?: number;
  partial?: PartialParse[];
}

/**
 * One gosec report, judged: `ok` with the files it analysed (`Stats.files`),
 * or a failure with the reason. `Golang errors` make it partial, one entry
 * per file (see the module comment): {@link GOSEC_SYNTAX_ERROR} for what the
 * parser could not read, {@link GOSEC_TYPE_ERROR} for a file of a package
 * that did not type-check, {@link GOSEC_PACKAGE_NOT_LOADED} for a package
 * directory `go` could not load. The compile summary under the `""` key
 * repeats the per-file entries and is read only for a file they do not name.
 * A report that analysed nothing while it names errors failed (the Go
 * toolchain missing, a `go.mod` asking for a newer Go); no report, an exit
 * other than 0 or 1, or an unfinished run failed too.
 */
export function checkGosecReport(args: { raw: string | null; exitCode: number | null; outcome: ProcessOutcome }): GosecCheck {
  if (args.outcome === 'cancelled' || args.outcome === 'timed_out' || args.outcome === 'output_too_large') {
    return { ok: false, reason: `gosec did not finish (${args.outcome})` };
  }
  if (args.exitCode !== 0 && args.exitCode !== 1) return { ok: false, reason: `exit ${String(args.exitCode)}` };
  const root = args.raw === null ? null : parseInputAsJson(args.raw);
  const stats = getProp(root, 'Stats');
  const scanned = getNumber(stats, 'files');
  if (root === null || typeof root !== 'object' || scanned === undefined) return { ok: false, reason: 'gosec wrote no JSON report' };

  const errors = getProp(root, 'Golang errors');
  const entries = errors !== null && typeof errors === 'object' ? Object.entries(errors) : [];
  const partial: PartialParse[] = [];
  const add = (file: string, type: string, message: string): void => {
    if (!partial.some((p) => p.file === file && p.type === type)) partial.push({ file, type, message: message.split(/\r?\n/)[0] ?? message });
  };
  const fileKeys = entries.map(([key]) => toPosixPath(key)).filter((k) => k.endsWith('.go'));
  for (const [key, list] of entries) {
    const messages = asArray(list).map((e) => getString(e, 'error') ?? '').filter((m) => m !== '');
    if (key === '') continue;
    const first = messages[0] ?? 'error';
    if (toPosixPath(key).endsWith('.go')) {
      add(key, messages.some(isSyntaxMessage) ? GOSEC_SYNTAX_ERROR : GOSEC_TYPE_ERROR, first);
    } else {
      add(key, GOSEC_PACKAGE_NOT_LOADED, first.replace(/^loading files from package "[^"]*": err: /, ''));
    }
  }
  // The compile summary, for a file no entry of its own names.
  const unattributed: string[] = [];
  for (const [key, list] of entries) {
    if (key !== '') continue;
    for (const e of asArray(list)) {
      const lines = (getString(e, 'error') ?? '').split(/\r?\n/).filter((l) => l.trim() !== '' && !l.startsWith('#'));
      for (const line of lines) {
        const m = SUMMARY_LINE.exec(line.trim());
        const file = m?.[1];
        if (m === null || file === undefined) {
          unattributed.push(line.trim());
          continue;
        }
        const named = toPosixPath(file);
        if (fileKeys.some((k) => k === named || k.endsWith(`/${named}`))) continue;
        const message = m[4] ?? line;
        add(named, isSyntaxMessage(message) ? GOSEC_SYNTAX_ERROR : GOSEC_TYPE_ERROR, message);
      }
    }
  }
  if (unattributed.length > 0) {
    return { ok: false, scanned, reason: `gosec reported an error it names no file for: ${unattributed.slice(0, 3).join('; ')}` };
  }
  if (scanned === 0 && partial.length > 0) {
    const said = [...new Set(partial.map((p) => p.message))].slice(0, 2).join('; ');
    return { ok: false, scanned, reason: `gosec analysed no file: ${said}` };
  }
  return partial.length > 0 ? { ok: true, scanned, partial } : { ok: true, scanned };
}

/** `Stats.files` of each report, summed: the Go files gosec analysed. */
function filesAnalysed(reports: readonly string[]): number {
  let total = 0;
  for (const raw of reports) total += getNumber(getProp(parseInputAsJson(raw), 'Stats'), 'files') ?? 0;
  return total;
}

/**
 * The environment the Go toolchain runs with under gosec and govulncheck
 * (`runners/govulncheckRun.ts`): the caller's, except a `GOFLAGS`
 * `-mod=mod`, which lets `go` rewrite the project's `go.mod` and `go.sum` —
 * replaced by `-mod=readonly` (Go's own default), and said so.
 */
export function goToolEnv(env: NodeJS.ProcessEnv): { env: NodeJS.ProcessEnv; note: string | null } {
  const flags = env['GOFLAGS'];
  if (flags === undefined || !/(^|\s)-mod=mod(\s|$)/.test(flags)) return { env, note: null };
  return {
    env: { ...env, GOFLAGS: flags.replace(/(^|\s)-mod=mod(?=\s|$)/g, '$1-mod=readonly') },
    note: "GOFLAGS' -mod=mod was run as -mod=readonly, so go cannot rewrite go.mod or go.sum",
  };
}

/** A few of `items` named, the rest counted. */
function nameAFew(items: readonly string[], max = 5): string {
  const shown = items.slice(0, max).join('; ');
  return items.length > max ? `${shown}; +${items.length - max} more` : shown;
}

/** The reason a run's partial files give, by what each kind of error cost. */
function describeGosecPartial(partial: readonly PartialParse[]): string {
  const parts: string[] = [];
  const of = (type: string): PartialParse[] => partial.filter((p) => p.type === type);
  const syntax = of(GOSEC_SYNTAX_ERROR);
  const types = of(GOSEC_TYPE_ERROR);
  const notLoaded = of(GOSEC_PACKAGE_NOT_LOADED);
  if (syntax.length > 0) {
    parts.push(`partial: ${syntax.length} file(s) only partly parsed — findings in the unparsed spans may be missing (${nameAFew(syntax.map((p) => `${p.file}: ${p.message}`))})`);
  }
  if (types.length > 0) {
    parts.push(
      `partial: ${types.length} file(s) in packages that did not type-check — their packages' SSA rules (the taint rules G701–G710 among them) did not run; ` +
        `make them build (\`go mod download\`) for those (${nameAFew(types.map((p) => `${p.file}: ${p.message}`))})`,
    );
  }
  if (notLoaded.length > 0) {
    parts.push(`partial: ${notLoaded.length} package(s) not loaded — nothing in them was analysed (${nameAFew(notLoaded.map((p) => `${p.file}: ${p.message}`))})`);
  }
  return parts.join('; ');
}

interface GosecPass {
  /** The `tools_run` entry; null when the files hold no Go package (no entry at all). */
  toolRun: ToolRun | null;
  /** Names for `missing_tools`: `gosec` (absent, or ran with a gap) or `go` (the toolchain is absent). */
  missing: string[];
  /** Every report that parsed, failed batches' included. */
  reports: string[];
  cancelled: boolean;
}

/**
 * gosec over the packages of `files` (project-relative, under `cwd`) — the
 * one pass scan_sast and review_pr run. See the module comment for the
 * arguments; the run is `ok` with its partial files named (and `gosec` in
 * `missing`), `failed` with the reason, or `skipped` when gosec or the Go
 * toolchain is absent, or when it analysed none of the listed files.
 */
export async function gosecOnPackages(args: {
  files: readonly string[];
  cwd: string;
  reportDir: string;
  env: NodeJS.ProcessEnv;
  signal: AbortSignal;
  onLog?: (line: string) => void;
}): Promise<GosecPass> {
  const { dirs, goFiles } = goPackageDirs(args.files);
  if (dirs.length === 0) return { toolRun: null, missing: [], reports: [], cancelled: false };
  if (!(await scannerAvailable(GOSEC))) {
    const missing = [GOSEC, ...((await scannerAvailable(GO_TOOLCHAIN)) ? [] : [GO_TOOLCHAIN])];
    return { toolRun: { name: GOSEC, status: 'skipped', reason: 'not_installed' }, missing, reports: [], cancelled: false };
  }
  if (!(await scannerAvailable(GO_TOOLCHAIN))) {
    return {
      toolRun: {
        name: GOSEC,
        status: 'skipped',
        reason: 'the Go toolchain (go) is not on PATH — gosec loads every package through it, so nothing could be analysed',
      },
      missing: [GO_TOOLCHAIN],
      reports: [],
      cancelled: false,
    };
  }
  const { env, note } = goToolEnv(args.env);
  const run = await scanFileBatches({
    name: GOSEC,
    command: 'gosec',
    args: ['-fmt=json', '-no-fail'],
    reportArgs: (f) => [`-out=${f}`, `-log=${f.replace(/\.json$/, '.log')}`],
    files: dirs,
    cwd: args.cwd,
    reportDir: args.reportDir,
    reportPrefix: GOSEC,
    env,
    signal: args.signal,
    ...(args.onLog ? { onLog: args.onLog } : {}),
    check: checkGosecReport,
  });
  const notes = note !== null ? [note] : [];
  const toolRun: ToolRun = { ...run.toolRun };
  if (toolRun.status !== 'ok') {
    if (notes.length > 0) toolRun.reason = [toolRun.reason, ...notes].filter((s) => s !== undefined).join('; ');
    return { toolRun, missing: [], reports: run.reports, cancelled: run.cancelled };
  }
  const analysed = filesAnalysed(run.reports);
  const listed = `${dirs.length} package director${dirs.length === 1 ? 'y' : 'ies'}, ${goFiles} Go file(s)`;
  if (analysed === 0) {
    return {
      toolRun: {
        name: GOSEC,
        status: 'skipped',
        reason:
          `${listed}: gosec analysed none of them — the platform's build constraints (GOOS/GOARCH tags, ` +
          '//go:build ignore) left every one out; Semgrep still read them',
      },
      missing: [GOSEC],
      reports: run.reports,
      cancelled: run.cancelled,
    };
  }
  const left = goFiles - analysed;
  toolRun.reason = [
    `${listed}: ${analysed} analysed`,
    ...(left > 0
      ? [`${left} left out by the platform's build constraints (GOOS/GOARCH tags, //go:build ignore) or cgo — Semgrep still read them`]
      : []),
    ...(run.partial.length > 0 ? [describeGosecPartial(run.partial)] : []),
    ...notes,
  ].join('; ');
  if (run.partial.length > 0) toolRun.partially_parsed = run.partial;
  return { toolRun, missing: run.partial.length > 0 ? [GOSEC] : [], reports: run.reports, cancelled: run.cancelled };
}

/**
 * `raw` with only the issues in files `keep` accepts (project-relative to
 * `cwd`): gosec reports every file of a package it was handed, and review_pr
 * asks about the changed files alone.
 */
export function gosecIssuesIn(raw: string, cwd: string, keep: (file: string) => boolean): string {
  const root = parseInputAsJson(raw);
  if (root === null || typeof root !== 'object') return raw;
  const issues = asArray(getProp(root, 'Issues')).filter((issue) => {
    const file = getString(issue, 'file');
    return file !== undefined && keep(toRelativeIfPossible(file, cwd));
  });
  return JSON.stringify({ ...root, Issues: issues });
}
