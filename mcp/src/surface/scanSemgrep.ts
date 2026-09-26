import { copyFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import {
  buildSemgrepDockerArgs,
  DEFAULT_SEMGREP_IMAGE,
  toContainerPath,
} from '../runners/dockerScanner.js';
import { runProcess, type ProcessRunResult } from '../runners/processRunner.js';
import { countFilesWithExtension, PROJECT_WALK_EXCLUDE } from '../runners/projectFiles.js';
import { checkSemgrepReport, pythonUtf8Env } from '../runners/semgrepReport.js';
import { asArray, getProp, getString, parseInputAsJson, toRelativeIfPossible } from '../runners/scannerParsers/index.js';
import { scannerAvailable } from '../tools/scanHelpers.js';
import type { ToolRun } from '../types.js';
import { ROUTE_PACK_EXTENSIONS } from './extract.js';

export interface SemgrepRunOptions {
  projectPath: string;
  rulesPath: string;
  outFile: string;
  reportDir: string;
}

export interface SemgrepInvocation {
  /** The PROCESS verdict alone (exit code, outcome) — never the report's; see {@link judgeSurfaceReport}. */
  toolRun: ToolRun;
  /** The process that ran, or null when the Docker fallback could not even stage the rules. */
  run: ProcessRunResult | null;
  /** `docker (<image>)` when the Docker fallback ran it, else null. */
  via: string | null;
}

/**
 * Run Semgrep against the routes rule pack, natively if it's on PATH,
 * otherwise via Docker. Returns null only when neither is available — the
 * caller treats that as "cannot run at all" and persists nothing.
 *
 * Mirrors scan_sast's Docker fallback: probe `docker`, bind the project at
 * `/src`, run the container, and check for real output. The argv comes from
 * the shared `buildSemgrepDockerArgs` — this tool only differs in
 * `--config`, which the builder takes as an option, so the mount shape, the
 * output rewriting and anything added there later apply here too. The rule
 * pack lives outside the project tree (in the dev-guardian install), so we
 * stage a copy inside the report dir — already inside the project, already
 * inside the bind mount — instead of adding a second `--mount`.
 */
export async function invokeSemgrep(options: SemgrepRunOptions): Promise<SemgrepInvocation | null> {
  const { projectPath, rulesPath, outFile, reportDir } = options;
  const semgrepBin = await scannerAvailable('semgrep');
  if (semgrepBin !== null) {
    const run = await runProcess({
      command: 'semgrep',
      args: ['--config', rulesPath, '--json', '--output', outFile, '--quiet', projectPath],
      cwd: projectPath,
      // UTF-8 mode, like every other Semgrep call site: otherwise the locale
      // codec reads the rule pack and writes `--output`
      // (runners/semgrepReport.ts#pythonUtf8Env).
      env: pythonUtf8Env(process.env),
    });
    return { toolRun: buildToolRun(run), run, via: null };
  }

  const dockerBin = await scannerAvailable('docker');
  if (dockerBin === null) return null;

  const image = process.env['GUARDIAN_SEMGREP_IMAGE'] || DEFAULT_SEMGREP_IMAGE;
  const via = `docker (${image})`;
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
      run: null,
      via,
    };
  }

  const run = await runProcess({
    command: 'docker',
    args: buildSemgrepDockerArgs({
      projectPath,
      outFileHost: outFile,
      image,
      configs: [containerRules],
    }),
    cwd: projectPath,
  });
  return { toolRun: buildToolRun(run, via), run, via };
}

/**
 * The PROCESS half of the verdict. Semgrep exits 1 when it *finds* matches —
 * that is success, not failure; scan_sast, bug_hunt and scan_wordpress all
 * treat `outcome === 'completed' || exitCode === 1` as a clean exit. Reading
 * the raw outcome alone (as an earlier version of this tool did) reported
 * every successful route-finding run as `failed`.
 *
 * A clean exit is necessary and never sufficient: {@link judgeSurfaceReport}
 * decides whether the run actually scanned.
 */
export function buildToolRun(run: ProcessRunResult, via?: string): ToolRun {
  const ok = run.outcome === 'completed' || run.exitCode === 1;
  if (ok) {
    return via ? { name: 'semgrep', status: 'ok', reason: `ran via ${via}` } : { name: 'semgrep', status: 'ok' };
  }
  const firstLine = run.stderr.split(/\r?\n/).find((l) => l.trim().length > 0);
  const reason = via ? `${via}: ${firstLine ?? 'fallback failed'}` : (firstLine ?? 'unknown');
  return { name: 'semgrep', status: 'failed', reason };
}

/**
 * Semgrep's built-in default ignore, applied when the scan root has NO
 * `.semgrepignore` of its own. Source: Semgrep's documentation, "Ignore
 * files, folders, and code" → "Define ignored files and folders in
 * .semgrepignore" (https://semgrep.dev/docs/ignoring-files-folders-code): the
 * default file lists `node_modules/`, `build/`, `dist/`, `vendor/`, `.env/`,
 * `.venv/`, `.tox/`, `*.min.js`, `.npm/`, `.yarn/`, `test/`, `tests/`,
 * `*_test.go`, `.semgrep` and `.semgrep_logs/` (plus `:include .gitignore`,
 * not mirrored here — a file ignored only by `.gitignore` still counts, the
 * conservative direction). Measured on 1.176.1 with the routes pack: without
 * a `.semgrepignore` it skipped test/, tests/ and deep/test/ at any depth,
 * foo_test.go, build/, dist/, vendor/ and *.min.js, and scanned testdata/,
 * spec/ and __tests__/; with an empty `.semgrepignore` it skipped none of
 * them. Hidden directories (`.env/`, `.venv/`, …) are skipped by the walk
 * already.
 */
const SEMGREP_DEFAULT_IGNORED_DIRS: readonly string[] = [
  'node_modules', 'build', 'dist', 'vendor', 'test', 'tests',
];
const SEMGREP_DEFAULT_IGNORED_SUFFIXES: readonly string[] = ['.min.js', '_test.go'];

/**
 * How many files in a routes-pack language Semgrep would actually be handed
 * in `projectPath` — the `targets` {@link judgeSurfaceReport} judges
 * "scanned 0" against, and 0 means not applicable.
 *
 * With no `.semgrepignore`, Semgrep's own default ignore applies, so its
 * paths are not targets: a Terraform module whose only Go code is its
 * Terratest suite under `test/` has nothing Semgrep would scan, and counting
 * it read as "scanned 0 of 1" — a gap and an exit 2 on every CI run. With a
 * `.semgrepignore`, Semgrep ignores nothing by default, and the user's own
 * ignore excluding every route file IS a real gap, so those files count.
 * Both walks keep {@link PROJECT_WALK_EXCLUDE} (dependencies, build output).
 */
export function countRouteTargets(projectPath: string): number {
  if (existsSync(join(projectPath, '.semgrepignore'))) {
    return countFilesWithExtension(projectPath, ROUTE_PACK_EXTENSIONS);
  }
  return countFilesWithExtension(
    projectPath,
    ROUTE_PACK_EXTENSIONS,
    new Set([...PROJECT_WALK_EXCLUDE, ...SEMGREP_DEFAULT_IGNORED_DIRS]),
    (name) => SEMGREP_DEFAULT_IGNORED_SUFFIXES.some((suffix) => name.endsWith(suffix)),
  );
}

/**
 * - `ok`: the run scanned files and reported no error — its routes are the
 *   project's surface.
 * - `partial`: a clean exit that scanned files, where EVERY `errors[]` entry
 *   is a problem confined to one target file (a warn-level
 *   `PartialParsing`, a syntax error in one file). Partial coverage, not a
 *   failure: the snapshot persists, Semgrep reads `ok` and is also named in
 *   `missing_tools` (ran, with a narrower gap inside it), and the files are
 *   listed. Refusing a whole WordPress snapshot over one `const NAMESPACE`
 *   warning left scan_dast probing nothing on real PHP projects.
 * - `scanned_nothing`: route-language targets exist, yet a clean run with no
 *   error scanned none of them (a `.semgrepignore` over the sources; a rule
 *   file the locale codec could not read loads as nothing, prints no error
 *   and exits 0). A gap: `skipped`, Semgrep named missing, nothing persisted.
 *   (A project with NO route-language file never gets here — the caller
 *   reports that as not applicable without running Semgrep.)
 * - `failed`: everything fatal — an unclean exit, an error that is not tied
 *   to one target file (a rule or config error, a `level: error` entry with
 *   no target, one naming the rule file itself), or per-file errors on a run
 *   that scanned nothing. Nothing persisted.
 */
export type SurfaceReportVerdict = 'ok' | 'partial' | 'scanned_nothing' | 'failed';

/** A file Semgrep could only partly read, as its report names it (not yet project-relative). */
export interface ReportedPartialParse {
  file: string;
  type: string;
  message: string;
}

/**
 * Error types that describe the rules or the configuration, never one target
 * file — fatal wherever they appear, even when the entry carries a path.
 */
const CONFIG_ERROR_TYPE = /rule|config|yaml|schema|plugin|SemgrepError|fatal/i;

/**
 * Global Constraint 3 for the surface scan, as the controller ruled it for
 * I3: the report is judged by the one Semgrep judge every other call site
 * uses (`runners/semgrepReport.ts` — exit code, `paths.scanned`, `errors[]`),
 * never by the exit code alone, and a per-file parse problem is partial
 * coverage rather than a failure. `raw` is the report text (the caller has
 * already refused a missing or unparseable one); `targets` is how many files
 * in a routes-pack language the project holds, so "scanned 0" is judged
 * against what there was to scan. With `projectPath`, the partly parsed files
 * are named relative to it.
 */
export function judgeSurfaceReport(args: {
  run: ProcessRunResult;
  raw: string;
  via: string | null;
  targets: number;
  projectPath?: string;
}): { verdict: SurfaceReportVerdict; toolRun: ToolRun; partial?: ReportedPartialParse[] } {
  const { run, raw, via, targets, projectPath } = args;
  const check = checkSemgrepReport({ raw, exitCode: run.exitCode, outcome: run.outcome, targets });
  if (check.ok) return { verdict: 'ok', toolRun: buildToolRun(run, via ?? undefined) };

  const prefix = via !== null ? `${via}: ` : '';
  const exitClean = run.outcome === 'completed' || run.exitCode === 1;
  if (exitClean && check.scanned === 0 && check.errors === 0) {
    return {
      verdict: 'scanned_nothing',
      toolRun: {
        name: 'semgrep',
        status: 'skipped',
        reason:
          `${prefix}semgrep scanned 0 of ${targets} file(s) in a routes-pack language — every one is ` +
          'excluded (.semgrepignore, .gitignore) or the rule file loaded nothing',
      },
    };
  }
  if (exitClean && check.scanned > 0 && check.errors > 0) {
    const partial = perFileErrors(raw)?.map((p) => ({ ...p, file: toRelativeIfPossible(p.file, projectPath) })) ?? null;
    if (partial !== null) {
      const listed = partial.map((p) => `${p.type}: ${p.file}`).join('; ');
      return {
        verdict: 'partial',
        partial,
        toolRun: {
          name: 'semgrep',
          status: 'ok',
          reason:
            `${via !== null ? `ran via ${via}; ` : ''}partial: ${partial.length} file(s) only partly parsed — ` +
            `routes in the unparsed spans may be missing (${listed})`,
        },
      };
    }
  }
  const stderr = run.stderr.split(/\r?\n/).find((l) => l.trim().length > 0);
  const detail = [check.reason ?? 'semgrep failed', ...(stderr !== undefined ? [stderr] : [])].join('; ');
  return { verdict: 'failed', toolRun: { name: 'semgrep', status: 'failed', reason: `${prefix}${detail}` } };
}

/**
 * Every `errors[]` entry as a per-file problem, or null when any one of them
 * is not: a config/rule error type, no target file named, or the file named
 * is a YAML file (the routes pack itself — the pack reads no YAML target).
 * The file comes from the entry's `path`, else its first span, else the
 * location list inside a `["PartialParsing", [...]]` type.
 */
function perFileErrors(raw: string): ReportedPartialParse[] | null {
  const errors = asArray(getProp(parseInputAsJson(raw), 'errors'));
  const out: ReportedPartialParse[] = [];
  for (const entry of errors) {
    const rawType = getProp(entry, 'type');
    const type =
      typeof rawType === 'string' ? rawType : Array.isArray(rawType) && typeof rawType[0] === 'string' ? rawType[0] : null;
    if (type === null || CONFIG_ERROR_TYPE.test(type)) return null;
    const file = targetFileOf(entry, rawType);
    if (file === null || /\.ya?ml$/i.test(file)) return null;
    const message = getString(entry, 'message') ?? type;
    out.push({ file, type, message: message.split(/\r?\n/)[0] ?? message });
  }
  return out.length > 0 ? out : null;
}

function targetFileOf(entry: unknown, rawType: unknown): string | null {
  const path = getString(entry, 'path');
  if (path !== undefined && path.length > 0) return path;
  const span = asArray(getProp(entry, 'spans'))[0];
  const spanFile = span === undefined ? undefined : getString(span, 'file');
  if (spanFile !== undefined && spanFile.length > 0) return spanFile;
  if (Array.isArray(rawType)) {
    const location = asArray(rawType[1])[0];
    const locationPath = location === undefined ? undefined : getString(location, 'path');
    if (locationPath !== undefined && locationPath.length > 0) return locationPath;
  }
  return null;
}
