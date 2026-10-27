/**
 * How the secrets history pass has git show the history (3.7.0). gitleaks
 * reads `git log -p -U0` and nothing else, so a change git leaves out of that
 * log is read by no pass. Two did, on a push — where no full-content pass runs
 * (`ci/runScans.ts`) — each measured with gitleaks 8.30.1 on git 2.47.3
 * (node:22-trixie) and 2.56.0 (Windows), a one-line AWS key read by nothing,
 * exit 0:
 *
 *   - a file git reads as binary by its CONTENT — a NUL byte in its first
 *     8000 bytes: "Binary files differ". 3.6.1 stopped the tree's
 *     `.gitattributes` from deciding (`git.ts#withoutTreeAttributes`); the
 *     content still did. An attributes file of `* diff` makes git diff every
 *     file as text — the `diff` attribute SET is "text, even with NUL bytes" —
 *     and the key was found. It is handed to git as `core.attributesFile`,
 *     through the environment, so nothing is written in the repository.
 *   - a merge commit's own change: `git log -p` prints no diff for a merge,
 *     so a line neither parent has (an "evil merge") is in none. With
 *     `--diff-merges=remerge` (git 2.36 and later) git re-merges the parents
 *     and shows how the commit differs from that: exactly what the merge
 *     itself added — a key a side branch added is read once, at its own
 *     commit, never again at the merge (`-m` read the evil key twice;
 *     `--diff-merges=first-parent` re-reads the whole branch at the merge,
 *     under the merge's commit, where `.gitleaksignore`'s
 *     `<commit>:<file>:<rule>:<line>` entries no longer match it).
 *
 * What each costs, measured on node:22-trixie (Pillow: 21,823 commits, 6,411
 * merges, many binary test files; flask: 5,603 and 1,737; git's own history:
 * 85,828 and 21,575), the findings the same but for what was hidden:
 *
 *   - Text for EVERY file is not bounded: Pillow's peak went from 321 MB to
 *     790 MB (`--text`), and five commits of a 90 MiB and a 20 MiB random
 *     file from 281 MB and 2.7 s to 1 GB and 16 s — gitleaks scans up to 40
 *     files at once, each held whole. So a path that holds a blob over
 *     {@link TEXT_LIMIT_BYTES} in any commit is left to git's own judgement
 *     (`!diff`: unspecified, so text unless it looks binary — never `-diff`,
 *     which would hide a large TEXT file git reads today): Pillow (56 such
 *     paths) then peaked at 337 MB, remerge-diff included, against 322 MB
 *     with neither. Each line of an
 *     attributes file costs every path git looks up (1,000 lines took
 *     Pillow's `git log -p` from 6.1 s to 9.0 s, 5,000 to 30 s), so past
 *     {@link MAX_LARGE_PATHS} no file is read as text and the run says so.
 *   - Remerge-diff re-merges every merge: git took 4.8 s for Pillow's beside
 *     the 9.9 s of its commits' log, 2.9 s beside 1.8 s for flask's — and
 *     666 s and 1.2 GB beside 87 s for git's, whose merges mostly carry a
 *     change of their own (13,543 of them: listing those first, with `--cc`,
 *     took 144 s and saved little). So the merges are a pass of their own
 *     (`gitleaksScan.ts`), `git log --merges`, under a scanner's own timeout
 *     (`GUARDIAN_SCAN_TIMEOUT_MS`, 10 min by default): one that does not
 *     finish is a named gap, and the commits' pass stands.
 *
 * Remerge-diff writes the merges it recomputes into a temporary object
 * directory inside `.git/objects` (`tmp_objdir`), removed when git exits: in
 * a repository the scan cannot write — a read-only clone — git printed
 * "unable to create temporary object directory" and gitleaks scanned 0
 * commits. So git's object directory is a scratch directory of the scan's,
 * and the repository's own objects an alternate (`GIT_OBJECT_DIRECTORY`,
 * `GIT_ALTERNATE_OBJECT_DIRECTORIES`): the read-only repository then scanned
 * in full, and the scratch directory was empty when git was done.
 *
 * What stays out of the log is named on the run ({@link HistoryView.limits}),
 * when the walk has it: an octopus merge's own change (remerge-diff shows
 * none — measured, a key only an octopus merge added was read by no pass);
 * what a git older than 2.36 (no remerge-diff: merges) or 2.40 (no
 * `GIT_ATTR_SOURCE`: the tree's attributes apply) cannot show; the paths
 * left to git's judgement. Not named, because the repository chose it:
 * `$GIT_DIR/info/attributes`, which outranks the attributes file (measured:
 * its `* -diff` made the NUL file binary again) — never in a fresh clone, but
 * in a repository delivered with its `.git/`. The user's own attributes file
 * is replaced for the pass, so a textconv driver it maps a path to is not
 * applied: the pass reads what was committed.
 *
 * A remerge-diff of a file whose merge had a conflict carries a `remerge
 * CONFLICT` line in its header, which gitleaks' diff parser does not know: it
 * names the file `b/<path>` (the `+++` line, unstripped) — see
 * `gitleaksScan.ts#withRemergePaths`.
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { delimiter, join } from 'node:path';
import { tmpdir } from 'node:os';
import { applyGitSafety } from '../platform/gitSafety.js';
import { git, withoutTreeAttributes } from './git.js';

/** A path with a blob larger than this in any commit is not forced to text. */
export const TEXT_LIMIT_BYTES = 1024 * 1024;
/** More such paths than this: no file is forced to text (each is a line of the attributes file). */
const MAX_LARGE_PATHS = 256;
/** The `git log` option that shows a merge commit's own change. */
export const REMERGE_DIFF = '--diff-merges=remerge';

export interface HistoryView {
  /** The environment the commits' pass runs with: every file as text, but the large paths. */
  env: NodeJS.ProcessEnv;
  /**
   * The merges' pass — `git log --merges` {@link REMERGE_DIFF}, run apart from
   * the commits' — and its environment (`env`'s, with the scratch object
   * directory); null when there is none to run: the walk has no merge, or
   * git cannot show their changes (named in `limits`).
   */
  merges: { env: NodeJS.ProcessEnv; count: number | null } | null;
  /** What git still leaves out of the log here, one sentence each; empty when nothing. */
  limits: readonly string[];
  /** Removes the scratch directory. Never throws: what it could not remove, or null. */
  remove: () => string | null;
}

/**
 * The view for the history `walk` (`git log` revisions: `--all`, a range,
 * `--since=`) of the repository at `cwd`, over `env` — see the module
 * comment. Never throws: a part git cannot set up is left out and named in
 * `limits`; the pass then reads the history as it did before.
 */
export async function openHistoryView(cwd: string, env: NodeJS.ProcessEnv, walk: readonly string[]): Promise<HistoryView> {
  const limits: string[] = [];
  const base = await withoutTreeAttributes(cwd, env);
  const version = await gitVersion(cwd, base);
  const shown = version === null ? 'its version could not be read' : `this git is ${version.join('.')}`;
  if (version === null || !atLeast(version, 2, 40)) {
    limits.push(`the working tree's .gitattributes applied to every commit's change — a binary or -diff there hides it (GIT_ATTR_SOURCE needs git 2.40; ${shown})`);
  }
  let scratch: string;
  try {
    scratch = mkdtempSync(join(tmpdir(), 'guardian-history-'));
  } catch (e) {
    limits.push(
      `files git reads as binary by their content, and merge commits' own changes, were not read (no scratch directory: ${message(e)})`,
    );
    return { env: base, merges: null, limits, remove: () => null };
  }
  const remove = (): string | null => {
    try {
      rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      return null;
    } catch (e) {
      return `the history pass's scratch directory ${scratch} could not be removed (${message(e)})`;
    }
  };

  const config: Array<readonly [string, string]> = [];
  const large = await largeBlobPaths(cwd, base, walk);
  if ('why' in large) {
    limits.push(`files git reads as binary by their content (a NUL byte) were not read: ${large.why}`);
  } else {
    const attributes = join(scratch, 'attributes');
    try {
      writeFileSync(attributes, ['* diff', ...large.paths.map(unspecifiedDiff), ''].join('\n'));
      config.push(['core.attributesFile', attributes]);
      if (large.paths.length > 0) {
        limits.push(
          `${large.paths.length} path(s) holding a file over 1 MiB in some commit were read as git decides: not when it reads them as binary`,
        );
      }
    } catch (e) {
      limits.push(`files git reads as binary by their content (a NUL byte) were not read (${message(e)})`);
    }
  }

  const commitsEnv = config.length === 0 ? base : applyGitSafety({ config, vars: {}, notApplied: [], refused: null }, base);

  // A count git cannot make reads as "some": the merges' pass runs, and says what it read.
  const count = await countWalk(cwd, base, walk, '--merges');
  if (count === 0) return { env: commitsEnv, merges: null, limits, remove };
  const some = count === null ? 'merge commits' : `${count} merge commit(s)`;
  if (version === null || !atLeast(version, 2, 36)) {
    limits.push(`${some}' own changes were not read (--diff-merges=remerge needs git 2.36; ${shown})`);
    return { env: commitsEnv, merges: null, limits, remove };
  }
  let vars: Record<string, string>;
  try {
    vars = await scratchObjects(cwd, base, env, join(scratch, 'objects'));
  } catch (e) {
    limits.push(`${some}' own changes were not read (git's object directory: ${message(e)})`);
    return { env: commitsEnv, merges: null, limits, remove };
  }
  const octopus = await countWalk(cwd, base, walk, '--min-parents=3');
  if (octopus !== 0) {
    limits.push(`${octopus === null ? 'octopus merges' : `${octopus} octopus merge(s)`}' own changes were not read (remerge-diff shows none for a merge of three or more parents)`);
  }
  const mergesEnv = applyGitSafety({ config, vars, notApplied: [], refused: null }, base);
  return { env: commitsEnv, merges: { env: mergesEnv, count }, limits, remove };
}

/**
 * The environment a `git show` of the commits the history pass read needs
 * to show a merge as it read it (`--diff-merges=remerge`, a scratch object
 * directory — see the module comment), or null where git has no
 * remerge-diff or the directory cannot be made: then show no merge's diff
 * at all. Over `env` without the tree's attributes, as the pass reads.
 * `remove` deletes the scratch directory; it never throws.
 */
export async function openRemergeEnv(cwd: string, env: NodeJS.ProcessEnv): Promise<{ env: NodeJS.ProcessEnv; remove: () => string | null } | null> {
  const base = await withoutTreeAttributes(cwd, env);
  const version = await gitVersion(cwd, base);
  if (version === null || !atLeast(version, 2, 36)) return null;
  let scratch: string;
  try {
    scratch = mkdtempSync(join(tmpdir(), 'guardian-history-'));
  } catch {
    return null;
  }
  const remove = (): string | null => {
    try {
      rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      return null;
    } catch (e) {
      return `scratch directory ${scratch} not removed (${message(e)})`;
    }
  };
  try {
    const vars = await scratchObjects(cwd, base, env, join(scratch, 'objects'));
    return { env: applyGitSafety({ config: [], vars, notApplied: [], refused: null }, base), remove };
  } catch {
    remove();
    return null;
  }
}

/**
 * `GIT_OBJECT_DIRECTORY` at `odb` (made here) and `GIT_ALTERNATE_OBJECT_DIRECTORIES`
 * naming the repository's own object directory (`--git-path objects`, which
 * honours a `GIT_OBJECT_DIRECTORY` of `env`'s) before any alternates `env`
 * names. Throws when git cannot name the directory.
 */
async function scratchObjects(cwd: string, base: NodeJS.ProcessEnv, env: NodeJS.ProcessEnv, odb: string): Promise<Record<string, string>> {
  const objects = await git(cwd, ['rev-parse', '--path-format=absolute', '--git-path', 'objects'], undefined, base);
  const dir = objects.stdout.trim();
  if (objects.exitCode !== 0 || dir === '') throw new Error(firstLine(objects.stderr) || `exit ${objects.exitCode}`);
  mkdirSync(odb);
  const others = envValue(env, 'GIT_ALTERNATE_OBJECT_DIRECTORIES');
  return {
    GIT_OBJECT_DIRECTORY: odb,
    GIT_ALTERNATE_OBJECT_DIRECTORIES: [alternate(dir), ...(others !== undefined && others !== '' ? [others] : [])].join(delimiter),
  };
}

/**
 * The repository-relative paths that hold a blob over {@link TEXT_LIMIT_BYTES}
 * in the commits `walk` reaches — merges included, against their first
 * parent, so a large file only a merge adds is one — or why they cannot be
 * listed. One listing of every object's size (Pillow: 106,006 objects, 0.19 s,
 * 5.4 MB), and the walk's raw diffs only when one is large (1.6 s, 4.2 MB).
 */
async function largeBlobPaths(cwd: string, env: NodeJS.ProcessEnv, walk: readonly string[]): Promise<{ paths: string[] } | { why: string }> {
  const objects = await git(cwd, ['cat-file', '--batch-all-objects', '--unordered', '--batch-check=%(objecttype) %(objectsize) %(objectname)'], undefined, env);
  if (objects.exitCode !== 0) return { why: `git could not list the repository's objects (${firstLine(objects.stderr) || `exit ${objects.exitCode}`})` };
  const large = new Set<string>();
  for (const line of objects.stdout.split('\n')) {
    const [type, size, id] = line.split(' ');
    if (type === 'blob' && id !== undefined && Number(size) > TEXT_LIMIT_BYTES) large.add(id);
  }
  if (large.size === 0) return { paths: [] };
  const raw = await git(cwd, ['log', ...walk, '--full-history', '--diff-merges=first-parent', '--raw', '-z', '--no-abbrev', '--no-renames', '--format=', '--'], undefined, env);
  if (raw.exitCode !== 0) return { why: `git could not list the paths of the files over 1 MiB (${firstLine(raw.stderr) || `exit ${raw.exitCode}`})` };
  const paths = new Set<string>();
  const parts = raw.stdout.split('\0');
  for (let i = 0; i < parts.length; i += 1) {
    const head = parts[i] ?? '';
    if (!head.startsWith(':')) continue;
    // `:<old mode> <new mode> <old id> <new id> <status>`, then the path.
    const [, , before = '', after = ''] = head.split(' ');
    const path = parts[i + 1];
    i += 1;
    if (path !== undefined && path !== '' && (large.has(before) || large.has(after))) paths.add(path);
  }
  if ([...paths].some((p) => p.includes('�'))) return { why: 'a path holding a file over 1 MiB is not UTF-8, and no attributes line can name it' };
  if (paths.size > MAX_LARGE_PATHS) {
    return { why: `${paths.size} paths hold a file over 1 MiB in some commit — more than ${MAX_LARGE_PATHS}, each a line git would match against every path` };
  }
  return { paths: [...paths].sort() };
}

/**
 * The attributes line leaving `path` (repository-relative) to git's own
 * judgement: anchored at the root, its glob characters escaped, and C-quoted
 * when it holds what ends or opens a pattern (whitespace, `"`) or a control
 * character (measured: `"/big nul.bin" !diff` read as unspecified).
 */
export function unspecifiedDiff(path: string): string {
  const pattern = `/${path.replace(/[\\*?[\]]/g, '\\$&')}`;
  if (!/[\s"\u0000-\u001f\u007f]/.test(pattern)) return `${pattern} !diff`;
  const quoted = pattern
    .replace(/[\\"]/g, '\\$&')
    .replace(/[\u0000-\u001f\u007f]/g, (c) => `\\${c.charCodeAt(0).toString(8).padStart(3, '0')}`);
  return `"${quoted}" !diff`;
}

/**
 * How many commits of `walk` `filter` (`--merges`, `--min-parents=3`) keeps,
 * or null when git cannot say. A walk with no revision of its own (a lone
 * `--since=`) is HEAD's, as gitleaks' `git log` reads it.
 */
async function countWalk(cwd: string, env: NodeJS.ProcessEnv, walk: readonly string[], filter: string): Promise<number | null> {
  const hasRevision = walk.some((t) => t === '--all' || t.includes('..'));
  const r = await git(cwd, ['rev-list', '--count', filter, ...walk, ...(hasRevision ? [] : ['HEAD']), '--'], undefined, env);
  const n = Number(r.stdout.trim());
  return r.exitCode === 0 && Number.isInteger(n) ? n : null;
}

/** An entry of `GIT_ALTERNATE_OBJECT_DIRECTORIES`: C-quoted when it holds the separator or opens with `"`, as git reads it. */
function alternate(dir: string): string {
  return dir.includes(delimiter) || dir.startsWith('"') ? `"${dir.replace(/[\\"]/g, '\\$&')}"` : dir;
}

/** `git version`'s major and minor (`git version 2.56.0.windows.2`, `2.39.5 (Apple Git-154)`), or null. */
async function gitVersion(cwd: string, env: NodeJS.ProcessEnv): Promise<[number, number] | null> {
  const r = await git(cwd, ['version'], undefined, env);
  const m = /git version (\d+)\.(\d+)/.exec(r.stdout);
  return r.exitCode === 0 && m?.[1] !== undefined && m[2] !== undefined ? [Number(m[1]), Number(m[2])] : null;
}

function atLeast(version: readonly [number, number], major: number, minor: number): boolean {
  return version[0] > major || (version[0] === major && version[1] >= minor);
}

/** `name` in `env`, case-insensitively on Windows as the OS reads it. */
function envValue(env: NodeJS.ProcessEnv, name: string): string | undefined {
  if (process.platform !== 'win32') return env[name];
  const key = Object.keys(env).find((k) => k.toUpperCase() === name);
  return key === undefined ? undefined : env[key];
}

function firstLine(text: string): string {
  return text.split(/\r?\n/).find((l) => l.trim().length > 0)?.trim() ?? '';
}

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
