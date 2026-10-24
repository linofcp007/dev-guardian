/**
 * cppcheck over a project's C and C++ — `scan_sast` (whole project or a
 * scope). Measured on cppcheck 2.22.0, 2.17.1 (Debian trixie), 2.13 (Ubuntu
 * 24.04) and 2.10 (Debian bookworm), 2026-10-24; what decides every argument
 * below:
 *
 *   - 2.13 at least ({@link CPPCHECK_MIN_VERSION}), checked with `--version`
 *     before the run: 2.10 skips a file whose every configuration reaches an
 *     `#error` without a word — no result, no information, the file listed as
 *     read — so an older cppcheck is a named gap, never a run.
 *   - Only `--enable=warning` (with `error`, always on) is reported: the
 *     style, performance and portability checks are quality, not this
 *     scan's. `information` and `missingInclude` are enabled for what they
 *     SAY ABOUT COVERAGE, never as findings.
 *   - The report is XML v2 (`--xml --xml-version=2 --output-file`). SARIF
 *     lists a result's locations defect-LAST, folds `warning` into `error`
 *     and drops `inconclusive`. A run that was killed leaves the XML without
 *     its closing `</results>`: an incomplete report is a failure.
 *   - cppcheck analyses less than it was asked, and says so only in places:
 *       * `syntaxError` / `unknownMacro`: the analysis of that file ENDED there
 *         — the file is named (`Syntax error`, `Unknown macro`);
 *       * `noValidConfiguration` (information): the file was not analysed at
 *         all (an `#error` in a header in every configuration — on redis 91 of
 *         134 files, because system headers are not read); a
 *         `preprocessorErrorDirective` located IN a translation unit (its own
 *         `#error`, which every configuration reaches); `missingFile`: a
 *         compile database entry that is not on disk — each named
 *         `Not analysed`;
 *       * a path in `--file-list` that does not exist is skipped with exit 0
 *         and no message at all: the `--cppcheck-build-dir`'s `files.txt`
 *         (`vuln.a1:::src/vuln.c` on 2.22, `vuln.a1::src/vuln.c` before) lists
 *         what was read, and a requested file absent from it is named
 *         `Not read`;
 *       * `toomanyconfigs` (only 12 `#ifdef` configurations checked) and
 *         `checkLevelNormal` / `normalCheckLevelMaxBranches` (a function too
 *         complex for the normal level): checked, less deeply — counted in
 *         the reason, never a gap, as Semgrep's taint timeouts: a mid-size C
 *         project has them in many files, and `--force` / the exhaustive
 *         level cost minutes per file (measured: 4m33s on one function);
 *       * `missingInclude`: a project header it did not find — counted.
 *   - A header (`.h`, `.hpp`) is analysed through the files that include it,
 *     never alone (cppcheck reads an explicit `.h` as C). The translation
 *     units are listed in a file (`--file-list`), never on the command line.
 *   - A `compile_commands.json` at the root or in `build/` is the project's
 *     own description of its build (defines, include paths): `--project`
 *     uses it, and it is named. The translation units it does not list
 *     (its `files.txt` names those it does) are then checked in a second
 *     run, from the file list: a database that leaves a file out — or a pull
 *     request that takes one out of it — never leaves that file unchecked. A
 *     database cannot be combined with a file list, so a scope runs without
 *     it, and says so.
 *   - `-D` is never passed: one define narrows the analysis to that single
 *     configuration (measured: 1 of 20 bugs found).
 */

import { availableParallelism } from 'node:os';
import { join } from 'node:path';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import type { PartialParse, ToolRun } from '../types.js';
import { presentInProject } from '../platform/projectFs.js';
import { scannerAvailable } from '../tools/scanHelpers.js';
import { runProcess, type ProcessRunResult } from './processRunner.js';
import { nameRepoConfig } from './repoConfig.js';
import { toPosixPath, toRelativeIfPossible } from './scannerParsers/index.js';

/** The `tools_run` name of the cppcheck pass. */
const CPPCHECK = 'cppcheck';

/** The C and C++ translation units cppcheck collects from a directory (headers and template parts excepted). */
const TRANSLATION_UNIT = /\.(c|cc|cpp|cxx|c\+\+)$/i;

/** How long one run may take: a mid-size C project took two minutes on 24 cores. */
const CPPCHECK_TIMEOUT_MS = 20 * 60_000;

/** The oldest cppcheck that reports a file it did not analyse (see the module comment). */
export const CPPCHECK_MIN_VERSION = '2.13';

/** The project's own build description, where CMake and Bear put it. */
const COMPILE_DATABASES = ['compile_commands.json', 'build/compile_commands.json'];

/** Ids that report coverage, not a defect — never findings. */
export const CPPCHECK_COVERAGE_IDS: ReadonlySet<string> = new Set([
  'syntaxError',
  'unknownMacro',
  'noValidConfiguration',
  'missingFile',
  'preprocessorErrorDirective',
  'toomanyconfigs',
  'checkLevelNormal',
  'normalCheckLevelMaxBranches',
  'missingInclude',
  'missingIncludeSystem',
  'checkersReport',
  'unmatchedSuppression',
  'internalError',
  'internalAstError',
  'cppcheckError',
  'premium-invalidLicense',
]);

/** The project-relative C/C++ translation units among `files`. */
export function cppSources(files: readonly string[]): string[] {
  return files.map(toPosixPath).filter((f) => TRANSLATION_UNIT.test(f)).sort();
}

/** One `<error>` of an XML v2 report. */
export interface CppcheckError {
  id: string;
  severity: string;
  msg: string;
  verbose: string;
  cwe?: string;
  inconclusive: boolean;
  file0?: string;
  locations: Array<{ file: string; line?: number; column?: number; info?: string }>;
}

const ENTITIES: Readonly<Record<string, string>> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };

function decode(text: string): string {
  return text.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (whole, name: string) => {
    if (name.startsWith('#x') || name.startsWith('#X')) return String.fromCodePoint(Number.parseInt(name.slice(2), 16));
    if (name.startsWith('#')) return String.fromCodePoint(Number.parseInt(name.slice(1), 10));
    return ENTITIES[name.toLowerCase()] ?? whole;
  });
}

function attributes(tag: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const m of tag.matchAll(/([\w:-]+)="([^"]*)"/g)) {
    if (m[1] !== undefined && m[2] !== undefined) out.set(m[1], decode(m[2]));
  }
  return out;
}

/**
 * An XML v2 report: its `<error>` elements, and whether it is complete — a
 * killed run streams the elements it reached and never closes `</results>`.
 */
export function parseCppcheckXml(xml: string): { complete: boolean; errors: CppcheckError[] } {
  const complete = /<\/errors>\s*<\/results>\s*$/.test(xml);
  const errors: CppcheckError[] = [];
  for (const m of xml.matchAll(/<error\s([^>]*?)(\/>|>([\s\S]*?)<\/error>)/g)) {
    const a = attributes(m[1] ?? '');
    const id = a.get('id');
    if (id === undefined) continue;
    const locations = [...(m[3] ?? '').matchAll(/<location\s([^>]*?)\/>/g)].map((l) => {
      const la = attributes(l[1] ?? '');
      const line = Number(la.get('line'));
      const column = Number(la.get('column'));
      const loc: CppcheckError['locations'][number] = { file: la.get('file') ?? '' };
      if (Number.isInteger(line) && line > 0) loc.line = line;
      if (Number.isInteger(column) && column > 0) loc.column = column;
      const info = la.get('info');
      if (info !== undefined) loc.info = info;
      return loc;
    });
    const error: CppcheckError = {
      id,
      severity: a.get('severity') ?? 'error',
      msg: a.get('msg') ?? id,
      verbose: a.get('verbose') ?? a.get('msg') ?? id,
      inconclusive: a.get('inconclusive') === 'true',
      locations,
    };
    const cwe = a.get('cwe');
    if (cwe !== undefined && cwe !== '' && cwe !== '0') error.cwe = cwe;
    const file0 = a.get('file0');
    if (file0 !== undefined && file0 !== '') error.file0 = file0;
    errors.push(error);
  }
  return { complete, errors };
}

/** The file an error is about: its first location's, else its translation unit. */
function fileOf(e: CppcheckError): string {
  return e.locations[0]?.file || e.file0 || '';
}

/** The paths `--cppcheck-build-dir`'s `files.txt` lists (`vuln.a1:::src/vuln.c`, `vuln.a1::src/vuln.c`), `/`-separated. */
export function filesRead(filesTxt: string): Set<string> {
  const out = new Set<string>();
  for (const line of filesTxt.split(/\r?\n/)) {
    const m = /^.*?\.a\d+:::?(.+)$/.exec(line.trim());
    if (m?.[1] !== undefined) out.add(toPosixPath(m[1].trim()).replace(/^\.\//, ''));
  }
  return out;
}

/** `Cppcheck 2.22.0` → `[2, 22]`; null when the output names no version. */
export function cppcheckVersion(output: string): [number, number] | null {
  const m = /Cppcheck\s+(\d+)\.(\d+)/i.exec(output);
  return m === null ? null : [Number(m[1]), Number(m[2])];
}

function atLeast(version: [number, number], min: string): boolean {
  const [major, minor] = min.split('.').map(Number);
  return version[0] > (major ?? 0) || (version[0] === (major ?? 0) && version[1] >= (minor ?? 0));
}

interface CppcheckJudgement {
  ok: boolean;
  reason?: string;
  partial: PartialParse[];
  notes: string[];
  /** The files checked less deeply, and those that include a project header cppcheck did not find (project-relative). */
  shallower: string[];
  noInclude: string[];
}

/** The reason's notes on files checked less deeply, never gaps (see the module comment). */
function limitNotes(shallower: readonly string[], noInclude: readonly string[]): string[] {
  const notes: string[] = [];
  if (shallower.length > 0) {
    notes.push(
      `${shallower.length} file(s) checked less deeply (only some #ifdef configurations, or a function too complex for the ` +
        `normal check level) — not a gap: ${shallower.slice(0, 3).join(', ')}${shallower.length > 3 ? ', …' : ''}`,
    );
  }
  if (noInclude.length > 0) {
    notes.push(`${noInclude.length} file(s) include a project header cppcheck did not find (its macros and types were unknown there)`);
  }
  return notes;
}

/** One run, judged (see the module comment). `requested`: the file list, when one was passed. */
export function judgeCppcheck(args: {
  run: Pick<ProcessRunResult, 'outcome' | 'exitCode' | 'stdout' | 'stderr'>;
  xml: string | null;
  filesTxt: string | null;
  requested: readonly string[] | null;
  projectPath: string;
}): CppcheckJudgement {
  const { run } = args;
  const failed = (reason: string): CppcheckJudgement => ({ ok: false, reason, partial: [], notes: [], shallower: [], noInclude: [] });
  if (run.outcome === 'cancelled' || run.outcome === 'timed_out' || run.outcome === 'output_too_large') {
    return failed(`did not finish (${run.outcome})`);
  }
  if (run.exitCode !== 0) {
    // cppcheck writes its own errors (a bad option, nothing to check) to stdout.
    const said = `${run.stdout}\n${run.stderr}`.split(/\r?\n/).map((l) => l.trim()).find((l) => l !== '' && !/^Checking |files? checked/.test(l));
    return failed(`exit ${String(run.exitCode)}${said ? `: ${said}` : ''}`);
  }
  if (args.xml === null) return failed('cppcheck wrote no XML report');
  const report = parseCppcheckXml(args.xml);
  if (!report.complete) return failed('the XML report is incomplete (the run was cut short)');

  const partial: PartialParse[] = [];
  const add = (file: string, type: string, message: string): void => {
    const rel = toRelativeIfPossible(file, args.projectPath);
    if (!partial.some((p) => p.file === rel && p.type === type)) partial.push({ file: rel, type, message });
  };
  const shallower = new Set<string>();
  const noInclude = new Set<string>();
  for (const e of report.errors) {
    if (e.id === 'syntaxError') add(fileOf(e), 'Syntax error', e.msg);
    else if (e.id === 'unknownMacro') add(fileOf(e), 'Unknown macro', e.msg);
    else if (e.id === 'noValidConfiguration' || e.id === 'missingFile') add(fileOf(e), 'Not analysed', e.msg);
    else if (e.id === 'preprocessorErrorDirective' && TRANSLATION_UNIT.test(fileOf(e))) add(fileOf(e), 'Not analysed', e.msg);
    else if (e.id === 'internalError' || e.id === 'internalAstError' || e.id === 'cppcheckError') add(fileOf(e), 'Internal error', e.msg);
    else if (e.id === 'toomanyconfigs' || e.id === 'checkLevelNormal' || e.id === 'normalCheckLevelMaxBranches') {
      shallower.add(toRelativeIfPossible(fileOf(e), args.projectPath) || '(a file)');
    } else if (e.id === 'missingInclude') noInclude.add(toRelativeIfPossible(fileOf(e), args.projectPath) || '(a file)');
  }
  if (args.requested !== null) {
    const read = filesRead(args.filesTxt ?? '');
    for (const f of args.requested) {
      if (!read.has(f)) add(f, 'Not read', 'cppcheck did not read it (missing from its build directory’s files.txt)');
    }
  }
  return { ok: true, partial, notes: limitNotes([...shallower], [...noInclude]), shallower: [...shallower], noInclude: [...noInclude] };
}

interface CppcheckPass {
  toolRun: ToolRun | null;
  missing: string[];
  /** The XML reports with something in them (one per cppcheck run). */
  reports: string[];
  cancelled: boolean;
}

interface CppcheckRun {
  run: ProcessRunResult;
  xml: string | null;
  filesTxt: string | null;
}

/** The compile database to use, project-relative, or null. */
function compileDatabase(projectPath: string): string | null {
  return COMPILE_DATABASES.find((f) => presentInProject(projectPath, f)) ?? null;
}

/**
 * cppcheck over the C/C++ translation units among `files` (project-relative):
 * through the compile database, then over those it does not list, or from
 * the list alone. `scoped`: a scope's files — never the compile database.
 * No entry when there is no translation unit; `skipped` when cppcheck is not
 * installed; `ok` with the files it could not analyse named (`partially_parsed`,
 * and `cppcheck` in `missing`), or `failed` with the reason.
 */
export async function cppcheckSources(args: {
  projectPath: string;
  files: readonly string[];
  scoped: boolean;
  reportDir: string;
  env: NodeJS.ProcessEnv;
  signal: AbortSignal;
  onLog?: (line: string) => void;
}): Promise<CppcheckPass> {
  const sources = cppSources(args.files);
  if (sources.length === 0) return { toolRun: null, missing: [], reports: [], cancelled: false };
  if (!(await scannerAvailable(CPPCHECK))) {
    return { toolRun: { name: CPPCHECK, status: 'skipped', reason: 'not_installed' }, missing: [CPPCHECK], reports: [], cancelled: false };
  }
  const probe = await runProcess({ command: 'cppcheck', args: ['--version'], cwd: args.projectPath, env: args.env, signal: args.signal, timeoutMs: 30_000 });
  const version = cppcheckVersion(`${probe.stdout}\n${probe.stderr}`);
  if (version === null || !atLeast(version, CPPCHECK_MIN_VERSION)) {
    const found = version === null ? 'its version could not be read' : `it is ${version.join('.')}`;
    return {
      toolRun: {
        name: CPPCHECK,
        status: 'skipped',
        reason:
          `cppcheck ${CPPCHECK_MIN_VERSION} or newer is needed and ${found}: an older one skips a file it cannot ` +
          'configure without saying so (Debian bookworm ships 2.10)',
      },
      missing: [CPPCHECK],
      reports: [],
      cancelled: probe.outcome === 'cancelled',
    };
  }
  const database = compileDatabase(args.projectPath);
  const useDatabase = database !== null && !args.scoped;
  const runs: CppcheckRun[] = [];
  const judged: CppcheckJudgement[] = [];
  // The translation units the database does not list are checked too, from
  // the file list: a database that left a file out — or a pull request that
  // took one out of it — never leaves that file unchecked without a word.
  let rest = sources;
  if (useDatabase) {
    const db = await cppcheckOnce(args, 'cppcheck', `--project=${join(args.projectPath, ...database.split('/'))}`);
    runs.push(db);
    judged.push(judgeCppcheck({ ...db, requested: null, projectPath: args.projectPath }));
    const inDatabase = new Set([...filesRead(db.filesTxt ?? '')].map((f) => toRelativeIfPossible(f, args.projectPath)));
    rest = sources.filter((f) => !inDatabase.has(f));
  }
  if (rest.length > 0 && judged.every((j) => j.ok)) {
    const name = useDatabase ? 'cppcheck-rest' : 'cppcheck';
    const list = join(args.reportDir, `${name}-files.txt`);
    writeFileSync(list, `${rest.join('\n')}\n`, 'utf8');
    const listed = await cppcheckOnce(args, name, `--file-list=${list}`);
    runs.push(listed);
    judged.push(judgeCppcheck({ ...listed, requested: rest, projectPath: args.projectPath }));
  }
  const cancelled = runs.some((r) => r.run.outcome === 'cancelled');
  const reports = runs.flatMap((r) => (r.xml !== null && parseCppcheckXml(r.xml).errors.length > 0 ? [r.xml] : []));
  const failure = judged.find((j) => !j.ok);
  if (failure !== undefined) {
    return { toolRun: { name: CPPCHECK, status: 'failed', reason: failure.reason ?? 'cppcheck failed' }, missing: [], reports, cancelled };
  }
  const partial = judged.flatMap((j) => j.partial);
  const from = !useDatabase
    ? `${sources.length} translation unit(s)${args.scoped && database !== null ? ` (from the scope's files: ${database} is not used for a scope)` : ''}`
    : rest.length > 0
      ? `the translation units of ${database}, and ${rest.length} it does not list,`
      : `the translation units of ${database}`;
  const reason = [
    `${from} checked (error and warning checks)`,
    ...(partial.length > 0
      ? [
          `partial: ${partial.length} file(s) not analysed or cut short — ` +
            partial.slice(0, 5).map((p) => `${p.type}: ${p.file}`).join('; ') +
            (partial.length > 5 ? '; …' : ''),
        ]
      : []),
    ...limitNotes([...new Set(judged.flatMap((j) => j.shallower))], [...new Set(judged.flatMap((j) => j.noInclude))]),
  ].join('; ');
  const toolRun: ToolRun = { name: CPPCHECK, status: 'ok', reason };
  if (partial.length > 0) toolRun.partially_parsed = partial;
  // The compile database it was handed, named (`runners/repoConfig.ts`).
  return {
    toolRun: useDatabase ? await nameRepoConfig(toolRun, args.projectPath, 'cppcheck') : toolRun,
    missing: partial.length > 0 ? [CPPCHECK] : [],
    reports,
    cancelled,
  };
}

/** One cppcheck run over `target` (`--project=…` or `--file-list=…`), its report and build directory named `name`. */
async function cppcheckOnce(
  args: { projectPath: string; reportDir: string; env: NodeJS.ProcessEnv; signal: AbortSignal; onLog?: (line: string) => void },
  name: string,
  target: string,
): Promise<CppcheckRun> {
  const buildDir = join(args.reportDir, `${name}-build`);
  mkdirSync(buildDir, { recursive: true });
  const out = join(args.reportDir, `${name}.xml`);
  const run = await runProcess({
    command: 'cppcheck',
    args: [
      `-j${String(Math.max(1, Math.min(availableParallelism(), 8)))}`,
      '-q',
      '--enable=warning,information,missingInclude',
      '--inconclusive',
      '--inline-suppr',
      '--suppress=missingIncludeSystem',
      `--cppcheck-build-dir=${buildDir}`,
      '--xml',
      '--xml-version=2',
      `--output-file=${out}`,
      target,
    ],
    cwd: args.projectPath,
    env: args.env,
    signal: args.signal,
    ...(args.onLog ? { onLog: args.onLog } : {}),
    timeoutMs: CPPCHECK_TIMEOUT_MS,
  });
  const read = (path: string): string | null => {
    try {
      return readFileSync(path, 'utf8');
    } catch {
      return null;
    }
  };
  return { run, xml: read(out), filesTxt: read(join(buildDir, 'files.txt')) };
}
