/**
 * detekt over a project's Kotlin — `quality_check` (whole project or a
 * scope). Measured on detekt 1.23.8 (its Maven Central jar) on Temurin
 * 21.0.12, Windows, 2026-10-24, over seeded files and Okio (313 files), and
 * deciding every argument below:
 *
 *   - No file name on its command line. `--input` is split on commas and
 *     semicolons; an `@argument file` is split on whitespace too (a
 *     `with space/A.kt` line became two arguments, and detekt exited); and the
 *     Java launcher reads Windows' command line in its ANSI code page, so a
 *     `日本.kt` handed over arrived as `??.kt` and failed the whole run. So
 *     detekt walks the project itself — `--input .`, from the project — with
 *     Java's own file API, which read `日本.kt` and a path with a space, and
 *     leaves out the build output and the tools' and dependencies'
 *     directories ({@link DETEKT_EXCLUDES}: matched below the input, so a
 *     project inside a `build/` folder of its own is still read, measured).
 *     Its report is then kept to the Kotlin the scan lists — `.guardianignore`
 *     applied, a scope's files only — as Semgrep's walk keeps to git's files;
 *     the factory drops anything outside a scope too.
 *   - Every other path it is handed is relative to the project: its report
 *     and dev-guardian's configuration in the report directory.
 *   - `--report sarif:<file>`: its SARIF names each rule with its rule set
 *     (`detekt.complexity.LongMethod`), which decides the finding's kind.
 *   - Exit 0 is clean and 2 is "issues above `maxIssues`" (by default any) —
 *     the report is written either way; 1 is an unexpected error and 3 an
 *     invalid configuration: a failure.
 *   - Configuration: dev-guardian's own first ({@link DETEKT_BASE_CONFIG}),
 *     then the project's `config/detekt/detekt.yml` (the Gradle plugin's
 *     default place) or root `detekt.yml` when there is one inside the project
 *     — YAML, which runs nothing (detekt reads it with snakeyaml-engine: a
 *     `!!java.io.FileOutputStream [...]` tag in it was refused, "could not
 *     determine a constructor", exit 1, no file written), named on the run —
 *     over detekt's defaults (`--build-upon-default-config`). Ours turns off
 *     `MagicNumber` (1 437 of Okio's 1 986 findings) and `MaxLineLength`
 *     (formatting), which the project's file turns back on if it says so; and
 *     config validation: one unknown property in the project's file (a rule a
 *     newer detekt renamed) made the whole run exit 3 with no report.
 *   - A file the Kotlin parser cannot read whole is analysed in part without
 *     a word: detekt reported findings in the readable part of a broken file
 *     and no error. scan_sast's Semgrep pass reads the same files and names
 *     each one it could not parse.
 *   - No type resolution (`--classpath`): the rules that need it do not run,
 *     which detekt says only in its debug output.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { findFileOnPath } from '../platform/binaryPath.js';
import { presentInProject, realpathInProject } from '../platform/projectFs.js';
import { ensureUserBinOnPath } from '../platform/userBin.js';
import { scannerAvailable } from '../tools/scanHelpers.js';
import type { ToolRun } from '../types.js';
import { runProcess, type ProcessRunResult } from './processRunner.js';
import { honouredFiles, withProjectConfig } from './repoConfig.js';
import { asArray, getProp, getString, parseInputAsJson, toPosixPath, toRelativeIfPossible } from './scannerParsers/index.js';

/** The `tools_run` name of the detekt pass, and the missing-tools name of the Java runtime it (and SpotBugs) runs on. */
const DETEKT = 'detekt';
const JAVA_RUNTIME = 'java';

/** The jar `install_toolchain` puts in the per-user tools directory. */
const DETEKT_JAR = 'detekt-cli.jar';

/** The project's own configuration, the first of these that exists inside the project. */
const DETEKT_PROJECT_CONFIGS: readonly string[] = ['config/detekt/detekt.yml', 'detekt.yml'];

/** What detekt's walk of the project leaves out (`--excludes`, matched below `--input .`). */
export const DETEKT_EXCLUDES: readonly string[] = [
  '**/build/**',
  '**/target/**',
  '**/.gradle/**',
  '**/.idea/**',
  '**/.git/**',
  '**/.guardian/**',
  '**/node_modules/**',
  '**/vendor/**',
];

/** dev-guardian's configuration, read first (see the module comment). */
export const DETEKT_BASE_CONFIG = [
  'config:',
  '  validation: false',
  'style:',
  '  MagicNumber:',
  '    active: false',
  '  MaxLineLength:',
  '    active: false',
  '',
].join('\n');

/**
 * The environment a Java scanner (detekt, SpotBugs) runs in: on Linux with no
 * UTF-8 locale (`LC_ALL`, `LC_CTYPE`, `LANG` — none set in a container),
 * `LC_ALL=C.UTF-8`. Java takes the encoding of file names from the locale, and
 * without one it was ASCII: measured in `node:22-trixie`, detekt's walk stopped
 * at a `日本.kt` ("Malformed input or input contains unmappable characters")
 * and the run failed; with `C.UTF-8` it read it. macOS and Windows name files
 * their own way.
 */
export function javaUtf8Env(env: NodeJS.ProcessEnv, platform: NodeJS.Platform = process.platform, base: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  if (platform !== 'linux') return env;
  const merged = { ...base, ...env };
  const locale = merged['LC_ALL'] || merged['LC_CTYPE'] || merged['LANG'] || '';
  return /utf-?8/i.test(locale) ? env : { ...env, LC_ALL: 'C.UTF-8' };
}

/** The project's Kotlin among `files` (project-relative): `.kt` and `.kts`. */
export function kotlinSources(files: readonly string[]): string[] {
  return files.map(toPosixPath).filter((f) => /\.kts?$/i.test(f)).sort();
}

/** The detekt jar on the PATH, the per-user tools directory included; null when there is none. */
export function findDetekt(env: NodeJS.ProcessEnv = process.env): string | null {
  return findFileOnPath(DETEKT_JAR, env);
}

interface DetektJudgement {
  ok: boolean;
  reason?: string;
  /** The SARIF report, when it is sound. */
  report?: string;
}

/** One run, judged (see the module comment). */
export function judgeDetekt(args: { run: Pick<ProcessRunResult, 'outcome' | 'exitCode' | 'stdout' | 'stderr'>; report: string | null }): DetektJudgement {
  const { run } = args;
  if (run.outcome === 'cancelled' || run.outcome === 'timed_out' || run.outcome === 'output_too_large') {
    return { ok: false, reason: `did not finish (${run.outcome})` };
  }
  if (run.exitCode === null) return { ok: false, reason: `did not run${firstLine(run.stderr) !== undefined ? `: ${firstLine(run.stderr) ?? ''}` : ''}` };
  if (run.exitCode !== 0 && run.exitCode !== 2) {
    const said = firstLine(`${run.stderr}\n${run.stdout}`);
    const what = run.exitCode === 3 ? 'the configuration is invalid' : `exit ${String(run.exitCode)}`;
    return { ok: false, reason: `${what}${said !== undefined ? `: ${said.slice(0, 300)}` : ''}` };
  }
  if (args.report === null) return { ok: false, reason: 'detekt wrote no report' };
  const run0 = asArray(getProp(parseInputAsJson(args.report), 'runs'))[0];
  if (getString(getProp(getProp(run0, 'tool'), 'driver'), 'name') !== 'detekt') {
    return { ok: false, reason: 'the report is not a detekt SARIF (the run was cut short)' };
  }
  return { ok: true, report: args.report };
}

function firstLine(text: string): string | undefined {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .find((l) => l !== '');
}

/** `file:///C:/p/A.kt` → `C:\p\A.kt`; anything else as written. */
function uriPath(uri: string): string {
  if (!uri.startsWith('file:')) return uri;
  try {
    return fileURLToPath(uri);
  } catch {
    return uri;
  }
}

/**
 * The SARIF report with only the results in `listed` (project-relative,
 * compared case-insensitively on Windows), and how many were left out — the
 * Kotlin detekt's walk found that the scan does not read.
 */
export function keepListed(report: string, projectPath: string, listed: readonly string[], platform: NodeJS.Platform = process.platform): { report: string; left: number } {
  const key = (p: string): string => (platform === 'win32' ? p.toLowerCase() : p);
  const keep = new Set(listed.map(key));
  let root: unknown;
  try {
    root = JSON.parse(report);
  } catch {
    return { report, left: 0 };
  }
  let left = 0;
  for (const run of asArray(getProp(root, 'runs'))) {
    const results = getProp(run, 'results');
    if (!Array.isArray(results) || run === null || typeof run !== 'object') continue;
    (run as Record<string, unknown>)['results'] = results.filter((r: unknown) => {
      const uri = getString(getProp(getProp(asArray(getProp(r, 'locations'))[0], 'physicalLocation'), 'artifactLocation'), 'uri');
      const rel = uri === undefined ? '' : toPosixPath(toRelativeIfPossible(uriPath(uri), projectPath));
      const kept = keep.has(key(rel));
      if (!kept) left += 1;
      return kept;
    });
  }
  return { report: JSON.stringify(root), left };
}

interface DetektPass {
  toolRun: ToolRun | null;
  missing: string[];
  /** The SARIF report, kept to the listed files, when the run was sound. */
  report: string | null;
  cancelled: boolean;
}

const NONE: DetektPass = { toolRun: null, missing: [], report: null, cancelled: false };

/** `abs` relative to the project, `/`-separated — what detekt is handed instead of the absolute path. */
function fromProject(projectPath: string, abs: string): string {
  const rel = relative(projectPath, abs);
  return rel === '' || rel.startsWith('..') || isAbsolute(rel) ? abs : rel.split('\\').join('/');
}

/**
 * detekt over the project, its findings kept to the Kotlin among `files`
 * (project-relative: what the scan reads, or a scope's). No entry when there
 * is none; `skipped` when detekt or Java is not there; `ok`, or `failed` with
 * the reason.
 */
export async function detektFiles(args: {
  projectPath: string;
  files: readonly string[];
  /** A scope's file count: the walk is the whole project's, and the reason says so. */
  scopeFiles?: number;
  reportDir: string;
  env: NodeJS.ProcessEnv;
  signal: AbortSignal;
  onLog?: (line: string) => void;
}): Promise<DetektPass> {
  const sources = kotlinSources(args.files);
  if (sources.length === 0) return NONE;
  ensureUserBinOnPath();
  const skipped = (reason: string, missing: string): DetektPass => ({
    toolRun: { name: DETEKT, status: 'skipped', reason },
    missing: [missing],
    report: null,
    cancelled: false,
  });
  const jar = findDetekt();
  if (jar === null) return skipped('not_installed', DETEKT);
  if (!(await scannerAvailable(JAVA_RUNTIME))) return skipped('java is not installed: detekt runs on Java 11 or newer', JAVA_RUNTIME);

  const base = join(args.reportDir, 'detekt-base.yml');
  writeFileSync(base, DETEKT_BASE_CONFIG, 'utf8');
  // The project's own, when it is a file inside the project (never through a link out of it).
  const own = DETEKT_PROJECT_CONFIGS.find((c) => presentInProject(args.projectPath, c) && realpathInProject(args.projectPath, c) !== null);
  const out = join(args.reportDir, 'detekt.sarif');
  const run = await runProcess({
    command: 'java',
    args: [
      '-jar',
      jar,
      '--input',
      '.',
      '--excludes',
      DETEKT_EXCLUDES.join(','),
      '--report',
      `sarif:${fromProject(args.projectPath, out)}`,
      '--config',
      [fromProject(args.projectPath, base), ...(own !== undefined ? [own] : [])].join(','),
      '--build-upon-default-config',
      '--parallel',
    ],
    cwd: args.projectPath,
    env: javaUtf8Env(args.env),
    signal: args.signal,
    ...(args.onLog ? { onLog: args.onLog } : {}),
  });
  let written: string | null = null;
  try {
    written = readFileSync(out, 'utf8');
  } catch {
    written = null;
  }
  const cancelled = run.outcome === 'cancelled';
  const judged = judgeDetekt({ run, report: written });
  if (!judged.ok || judged.report === undefined) {
    return { toolRun: { name: DETEKT, status: 'failed', reason: judged.reason ?? 'detekt failed' }, missing: [], report: null, cancelled };
  }
  const kept = keepListed(judged.report, args.projectPath, sources);
  const reason = [
    `${sources.length} Kotlin file(s) analysed, without type resolution` +
      (args.scopeFiles !== undefined ? ` — the project walked for a scope of ${args.scopeFiles} file(s); only the scope's findings kept` : ''),
    ...(kept.left > 0 ? [`${kept.left} finding(s) in Kotlin the scan does not read (generated, ignored) left out`] : []),
  ].join('; ');
  const toolRun: ToolRun = { name: DETEKT, status: 'ok', reason };
  // The project's own detekt.yml — the one handed over — named (`runners/repoConfig.ts`).
  const named = own === undefined ? toolRun : withProjectConfig(toolRun, (await honouredFiles(args.projectPath, 'detekt')).filter((f) => f.path === own));
  return { toolRun: named, missing: [], report: kept.report, cancelled };
}
