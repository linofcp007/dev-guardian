/**
 * SpotBugs with FindSecBugs over a project's compiled Java and Kotlin —
 * `scan_sast`. Measured on SpotBugs 4.10.5 and FindSecBugs 1.14.0 on Temurin
 * 21.0.12, Windows, 2026-10-24, over a seeded Maven layout, and deciding every
 * argument below:
 *
 *   - It reads bytecode, so it runs only where the project was built: each
 *     module's `target/classes` (Maven) and `build/classes/<java|kotlin|
 *     scala|groovy>/main` (Gradle), found by a bounded walk that enters no
 *     link ({@link classDirs}). scan_sast never builds a Java project — that
 *     would run its build scripts — so a project with Java or Kotlin sources
 *     and no classes is `skipped`, said so, and no gap: Semgrep reads the
 *     sources either way. Classes older than the newest source are noted.
 *     Bytecode is read, never run.
 *   - Its security findings only: an include filter keeps the `SECURITY`
 *     and `MALICIOUS_CODE` categories (FindSecBugs' patterns are
 *     `SECURITY`), at `-effort:max`. SpotBugs' correctness and style patterns
 *     — `==` on strings, an ignored return value — are not a security scan's.
 *   - FindSecBugs loads from SpotBugs' own `plugin/` directory, where
 *     `install_toolchain` puts it: handed again with `-pluginList`, every
 *     detector was registered twice, with a warning each. A SpotBugs without
 *     it ran only SpotBugs' own few security patterns: a narrower gap, named.
 *   - `-sarif -output <file>` (`-sarif:<file>` wrote to stdout): each result
 *     names its source relative to the `-sourcepath` root it was found under
 *     (`originalUriBaseIds`), and its rule's CWE and category. Without
 *     `-quiet` the report records what SpotBugs could not see —
 *     `spotbugs-missing-classes`: the project's dependencies, which are not
 *     on its classpath; calls into them are unknown to it, which is noted.
 *   - Exit 0 whatever it found (no `-exitcode`) — a class it could not read
 *     too (a corrupt one, a class-file version it does not know): the run
 *     exits 0 and its report says `executionSuccessful: false`, the class in
 *     `toolExecutionNotifications`. Each is named `Not analysed`, partial.
 *     A run that could not open its input exits 1 with no report: a failure.
 *     A class directory holding no `.class` (resources only) is not a build
 *     SpotBugs could read — it refused it the same way — and is left out.
 */

import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { delimiter, join } from 'node:path';
import { listProjectDirOrNull, realpathInProject } from '../platform/projectFs.js';
import { ensureUserBinOnPath, spotbugsHome, spotbugsJar } from '../platform/userBin.js';
import { scannerAvailable } from '../tools/scanHelpers.js';
import type { PartialParse, ToolRun } from '../types.js';
import { javaUtf8Env } from './detektRun.js';
import { runProcess, type ProcessRunResult } from './processRunner.js';
import { asArray, getProp, getString, parseInputAsJson, toPosixPath, toRelativeIfPossible } from './scannerParsers/index.js';

/** The `tools_run` name of the SpotBugs pass. */
export const SPOTBUGS = 'spotbugs';
const JAVA_RUNTIME = 'java';

/** How long one run may take: `-effort:max` over a large project. */
const SPOTBUGS_TIMEOUT_MS = 30 * 60_000;

/** The sources compiled to the bytecode it reads. */
const JVM_SOURCE = /\.(java|kt|scala|groovy)$/i;

/** Directories the walk for classes never enters. */
const NOT_A_MODULE = new Set(['.git', '.hg', '.svn', 'node_modules', '.gradle', '.idea', '.mvn', '.guardian', 'vendor', 'src']);

/** How deep the walk looks for a module, and how many directories it lists at most. */
const MAX_DEPTH = 6;
const MAX_DIRS = 20_000;

/** The include filter: SpotBugs' security categories only. */
export const SECURITY_FILTER = [
  '<?xml version="1.0" encoding="UTF-8"?>',
  '<FindBugsFilter>',
  '  <Match><Bug category="SECURITY"/></Match>',
  '  <Match><Bug category="MALICIOUS_CODE"/></Match>',
  '</FindBugsFilter>',
  '',
].join('\n');

/** Whether `files` (project-relative) hold Java, Kotlin, Scala or Groovy. */
export function hasJvmSource(files: readonly string[]): boolean {
  return files.some((f) => JVM_SOURCE.test(f));
}

interface ClassDirs {
  /** Project-relative, `/`-separated: the class directories found. */
  dirs: string[];
  /** Project-relative: the source roots of their modules (`src/main/java`, …). */
  sourceRoots: string[];
}

/** Whether `rel` is a directory inside the project (no link out of it). */
function isProjectDir(root: string, rel: string): boolean {
  const real = realpathInProject(root, rel);
  if (real === null) return false;
  try {
    return statSync(real).isDirectory();
  } catch {
    return false;
  }
}

/**
 * The class directories of the project's modules and their source roots
 * (see the module comment): breadth-first from the root, at most
 * {@link MAX_DEPTH} directories down and {@link MAX_DIRS} listed, never into
 * a link, `src/` or a tool's own directory.
 */
export function classDirs(projectPath: string): ClassDirs {
  const out: ClassDirs = { dirs: [], sourceRoots: [] };
  const queue: Array<{ rel: string; depth: number }> = [{ rel: '', depth: 0 }];
  let listed = 0;
  while (queue.length > 0 && listed < MAX_DIRS) {
    const { rel, depth } = queue.shift() ?? { rel: '', depth: 0 };
    const entries = listProjectDirOrNull(projectPath, rel === '' ? '.' : rel);
    listed++;
    if (entries === null) continue;
    const at = (name: string): string => (rel === '' ? name : `${rel}/${name}`);
    let module = false;
    for (const e of entries) {
      if (e.kind !== 'directory') continue;
      if (e.name === 'target') {
        if (isProjectDir(projectPath, at('target/classes'))) {
          out.dirs.push(at('target/classes'));
          module = true;
        }
        continue;
      }
      if (e.name === 'build') {
        for (const lang of ['java', 'kotlin', 'scala', 'groovy']) {
          const dir = at(`build/classes/${lang}/main`);
          if (isProjectDir(projectPath, dir)) {
            out.dirs.push(dir);
            module = true;
          }
        }
        continue;
      }
      if (NOT_A_MODULE.has(e.name) || depth + 1 > MAX_DEPTH) continue;
      queue.push({ rel: at(e.name), depth: depth + 1 });
    }
    if (module) {
      for (const lang of ['java', 'kotlin', 'scala', 'groovy']) {
        const src = at(`src/main/${lang}`);
        if (isProjectDir(projectPath, src)) out.sourceRoots.push(src);
      }
    }
  }
  out.dirs.sort();
  out.sourceRoots.sort();
  return out;
}

/** The newest modification time among the `.class` files under `dirs` (bounded), or null when there is none. */
function newestClass(projectPath: string, dirs: readonly string[]): number | null {
  let newest: number | null = null;
  let seen = 0;
  const stack = dirs.map((d) => realpathInProject(projectPath, d)).filter((d): d is string => d !== null);
  while (stack.length > 0 && seen < 200_000) {
    const dir = stack.pop() ?? '';
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      seen++;
      const path = join(dir, e.name);
      if (e.isDirectory()) stack.push(path);
      else if (e.isFile() && e.name.endsWith('.class')) {
        try {
          const t = statSync(path).mtimeMs;
          if (newest === null || t > newest) newest = t;
        } catch {
          // Gone since it was listed.
        }
      }
    }
  }
  return newest;
}

/** The JVM sources among `files` under `roots` modified after `since` (at most a few named). */
function sourcesNewerThan(projectPath: string, files: readonly string[], roots: readonly string[], since: number): string[] {
  const newer: string[] = [];
  for (const f of files) {
    if (!JVM_SOURCE.test(f) || !roots.some((r) => f.startsWith(`${r}/`))) continue;
    const real = realpathInProject(projectPath, f);
    if (real === null) continue;
    try {
      // A second's slack: a build writes its classes just after it reads the sources.
      if (statSync(real).mtimeMs > since + 1000) newer.push(f);
    } catch {
      // Gone since it was listed.
    }
  }
  return newer;
}

interface SpotbugsJudgement {
  ok: boolean;
  reason?: string;
  report?: string;
  /** What SpotBugs said it could not see, besides the missing classes. */
  notes: string[];
  /** The classes it could not analyse (`toolExecutionNotifications`), as their path under their class directory. */
  partial: PartialParse[];
}

/** `Invalid class resource com/x/A.class in C:\p\target\classes:com/x/A.class` → `C:\p\target\classes\com/x/A.class`; else the message's own class. */
function notifiedClass(text: string): string {
  const resource = / in (.+):([^:]+\.class)$/.exec(text);
  if (resource !== null) return join(resource[1] ?? '', resource[2] ?? '');
  const named = /([\w$/.-]+\.class|[\w$]+(?:\/[\w$]+)+)/.exec(text);
  return named?.[1] ?? text.slice(0, 120);
}

/** One run, judged (see the module comment). */
export function judgeSpotbugs(args: { run: Pick<ProcessRunResult, 'outcome' | 'exitCode' | 'stdout' | 'stderr'>; report: string | null }): SpotbugsJudgement {
  const { run } = args;
  if (run.outcome === 'cancelled' || run.outcome === 'timed_out' || run.outcome === 'output_too_large') {
    return { ok: false, reason: `did not finish (${run.outcome})`, notes: [], partial: [] };
  }
  if (run.exitCode !== 0) {
    const said = `${run.stderr}\n${run.stdout}`
      .split(/\r?\n/)
      .map((l) => l.trim())
      .find((l) => /Exception|Error|error/.test(l));
    return { ok: false, reason: `exit ${String(run.exitCode)}${said !== undefined ? `: ${said.slice(0, 300)}` : ''}`, notes: [], partial: [] };
  }
  if (args.report === null) return { ok: false, reason: 'SpotBugs wrote no report', notes: [], partial: [] };
  const run0 = asArray(getProp(parseInputAsJson(args.report), 'runs'))[0];
  if (getString(getProp(getProp(run0, 'tool'), 'driver'), 'name') !== 'SpotBugs') {
    return { ok: false, reason: 'the report is not a SpotBugs SARIF (the run was cut short)', notes: [], partial: [] };
  }
  const notes: string[] = [];
  const partial: PartialParse[] = [];
  for (const invocation of asArray(getProp(run0, 'invocations'))) {
    for (const n of asArray(getProp(invocation, 'toolExecutionNotifications'))) {
      if (getString(n, 'level') === 'note') continue;
      const text = getString(getProp(n, 'message'), 'text') ?? 'analysis error';
      const file = notifiedClass(text);
      // `Error scanning com/x/A for …` after `Invalid class resource com/x/A.class in …`: the same class.
      const same = (p: PartialParse): boolean => p.file === file || toPosixPath(p.file).endsWith(`/${file}.class`);
      if (!partial.some(same)) partial.push({ file, type: 'Not analysed', message: text.slice(0, 300) });
    }
    for (const n of asArray(getProp(invocation, 'toolConfigurationNotifications'))) {
      const id = getString(getProp(n, 'descriptor'), 'id') ?? '';
      const text = getString(getProp(n, 'message'), 'text') ?? id;
      if (id === 'spotbugs-missing-classes') {
        const count = (/\[(.*)\]/.exec(text)?.[1] ?? '').split(',').filter((c) => c.trim() !== '').length;
        notes.push(
          `${count > 0 ? `${count} class(es)` : 'classes'} the code calls were not on SpotBugs' classpath (its dependencies): ` +
            'flows through them are unknown to it',
        );
      } else notes.push(`SpotBugs said: ${text.slice(0, 200)}`);
    }
  }
  return { ok: true, report: args.report, notes, partial };
}

interface SpotbugsPass {
  toolRun: ToolRun | null;
  missing: string[];
  report: string | null;
  cancelled: boolean;
}

const NONE: SpotbugsPass = { toolRun: null, missing: [], report: null, cancelled: false };

/** The FindSecBugs jar in SpotBugs' `plugin/` directory, or null. */
function findSecBugsPlugin(home: string): string | null {
  try {
    const jar = readdirSync(join(home, 'plugin')).find((n) => /^findsecbugs-plugin.*\.jar$/i.test(n));
    return jar === undefined ? null : join(home, 'plugin', jar);
  } catch {
    return null;
  }
}

/**
 * SpotBugs over the project's class directories, whatever a scope holds —
 * they are the whole project's bytecode, and the caller keeps the findings
 * inside its scope. No entry when the project has no JVM source and no
 * classes; `skipped`, no gap, when it has sources but no classes; `skipped`
 * and a gap when SpotBugs or Java is not there; `ok`, or `failed` with the
 * reason.
 */
export async function spotbugsClasses(args: {
  projectPath: string;
  /** What the scan reads (project-relative): its JVM sources say whether the project is one, and how old its classes are. */
  files: readonly string[];
  reportDir: string;
  env: NodeJS.ProcessEnv;
  signal: AbortSignal;
  onLog?: (line: string) => void;
}): Promise<SpotbugsPass> {
  const all = classDirs(args.projectPath);
  // A directory with no `.class` in it (resources only): SpotBugs refuses it (see the module comment).
  const newestBy = new Map(all.dirs.map((d) => [d, newestClass(args.projectPath, [d])]));
  const found = { ...all, dirs: all.dirs.filter((d) => newestBy.get(d) !== null) };
  if (found.dirs.length === 0) {
    if (!hasJvmSource(args.files)) return NONE;
    return {
      toolRun: {
        name: SPOTBUGS,
        status: 'skipped',
        reason:
          'no compiled classes (target/classes, build/classes/*/main): SpotBugs reads bytecode — build the project ' +
          '(mvn compile, gradle classes) to add its security patterns; scan_sast never builds it. Semgrep read the sources',
      },
      missing: [],
      report: null,
      cancelled: false,
    };
  }
  ensureUserBinOnPath();
  const skipped = (reason: string, missing: string): SpotbugsPass => ({
    toolRun: { name: SPOTBUGS, status: 'skipped', reason },
    missing: [missing],
    report: null,
    cancelled: false,
  });
  const jar = spotbugsJar();
  const home = spotbugsHome();
  if (jar === null || home === null) return skipped('not_installed', SPOTBUGS);
  if (!(await scannerAvailable(JAVA_RUNTIME))) return skipped('java is not installed: SpotBugs runs on Java 11 or newer', JAVA_RUNTIME);
  const plugin = findSecBugsPlugin(home);
  const filter = join(args.reportDir, 'spotbugs-security.xml');
  writeFileSync(filter, SECURITY_FILTER, 'utf8');
  const out = join(args.reportDir, 'spotbugs.sarif');
  const abs = (rel: string): string => join(args.projectPath, ...rel.split('/'));
  const run = await runProcess({
    command: 'java',
    args: [
      '-jar',
      jar,
      '-textui',
      '-effort:max',
      '-include',
      filter,
      '-nested:false',
      '-sarif',
      '-output',
      out,
      ...(found.sourceRoots.length > 0 ? ['-sourcepath', found.sourceRoots.map(abs).join(delimiter)] : []),
      ...found.dirs.map(abs),
    ],
    cwd: args.projectPath,
    // File names in UTF-8 on Linux with no locale (`runners/detektRun.ts#javaUtf8Env`).
    env: javaUtf8Env(args.env),
    signal: args.signal,
    ...(args.onLog ? { onLog: args.onLog } : {}),
    timeoutMs: SPOTBUGS_TIMEOUT_MS,
  });
  let report: string | null = null;
  try {
    report = readFileSync(out, 'utf8');
  } catch {
    report = null;
  }
  const judged = judgeSpotbugs({ run, report });
  const cancelled = run.outcome === 'cancelled';
  if (!judged.ok) {
    return { toolRun: { name: SPOTBUGS, status: 'failed', reason: judged.reason ?? 'SpotBugs failed' }, missing: [], report: null, cancelled };
  }
  const times = found.dirs.map((d) => newestBy.get(d) ?? null).filter((t): t is number => t !== null);
  const newest = times.length > 0 ? Math.max(...times) : null;
  const partial = judged.partial.map((p) => ({ ...p, file: toPosixPath(toRelativeIfPossible(p.file, args.projectPath)) }));
  const stale = newest === null ? [] : sourcesNewerThan(args.projectPath, args.files.map(toPosixPath), found.sourceRoots, newest);
  const reason = [
    `${found.dirs.length} class director${found.dirs.length === 1 ? 'y' : 'ies'} read (${found.dirs.slice(0, 3).join(', ')}${found.dirs.length > 3 ? ', …' : ''}), security patterns only`,
    ...(plugin === null ? [`FindSecBugs is not in ${join(home, 'plugin')}: only SpotBugs' own security patterns ran — install_toolchain installs both`] : []),
    ...judged.notes,
    ...(stale.length > 0
      ? [`${stale.length} source file(s) changed after the last build (${stale.slice(0, 3).join(', ')}${stale.length > 3 ? ', …' : ''}): rebuild for SpotBugs to read them`]
      : []),
    ...(partial.length > 0
      ? [`partial: ${partial.length} class(es) SpotBugs could not analyse (${partial.slice(0, 3).map((p) => p.file).join(', ')}${partial.length > 3 ? ', …' : ''})`]
      : []),
  ].join('; ');
  const toolRun: ToolRun = { name: SPOTBUGS, status: 'ok', reason };
  if (partial.length > 0) toolRun.partially_parsed = partial;
  return {
    toolRun,
    missing: plugin === null || partial.length > 0 ? [SPOTBUGS] : [],
    report,
    cancelled,
  };
}
