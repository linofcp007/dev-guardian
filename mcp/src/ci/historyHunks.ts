/**
 * Whether gitleaks' history pass read a line of the working tree in a hunk —
 * for the CI gate's full-content secrets pass (`ci/runScans.ts`), which takes
 * a one-line secret only where the history pass could not have judged it.
 *
 * The history pass reads `git log -p -U0 --full-history --all`: every line a
 * commit adds, in that commit's hunk, judged with what applies only to
 * history (`.gitleaksignore`'s `<commit>:…` entries, a `.gitleaks.toml`
 * allowlist of commits). Except where git prints no hunk — each measured with
 * gitleaks 8.30.1 and git 2.56, a one-line key read by no pass, exit 0:
 *
 *   - a merge commit's own change: `git log -p` prints no diff for a merge,
 *     so a line neither parent has (an "evil merge") is in none;
 *   - a file git reads as binary — by its content (a NUL byte), or by the
 *     working tree's `.gitattributes` (`binary`, `-diff`), which git applies
 *     to every commit's diff: "Binary files differ". The history pass reads
 *     no attributes of the tree any more (`GIT_ATTR_SOURCE`,
 *     `runners/gitleaksScan.ts`), but a git older than 2.40, or the content
 *     itself, still hides one.
 *
 * `git blame` names the commit that added the line, following the file's
 * renames (a key in a file renamed since it was committed was read where it
 * was added) — with no `blame.ignoreRevsFile`, which would blame a line a
 * listed commit changed on an older one. The line was read when that commit
 * has at most one parent and its diff of the file is text (`git diff-tree
 * --numstat`: `-` for binary). That diff is judged with the tree's
 * attributes — never more lenient than the history pass, which reads fewer.
 * A line no commit holds, a blame or a diff git cannot make, a path it
 * quotes: not read — the finding is kept (never a silent drop).
 */

import { git, splitNul } from '../runners/git.js';
import type { Finding } from '../types.js';

/** At most this many lines are looked up per run; the rest are kept. */
const MAX_LINES = 200;

/** The commit that added a line of the working tree, and the file's path in it (repository-relative). */
interface LineOrigin {
  commit: string;
  file: string;
}

/**
 * The findings of `findings` (one-line full-content gitleaks findings of the
 * project at `projectPath`) whose line the history pass read in a hunk.
 */
export async function readInHistoryHunks(projectPath: string, findings: readonly Finding[]): Promise<Set<Finding>> {
  const out = new Set<Finding>();
  const parents = new Map<string, Promise<number | null>>();
  const textDiffs = new Map<string, Promise<boolean>>();
  for (const f of findings.slice(0, MAX_LINES)) {
    const path = f.file_path;
    if (f.line_start === undefined || path === undefined || path === '') continue;
    const origin = await originOf(projectPath, path, f.line_start);
    if (origin === null) continue;
    let counted = parents.get(origin.commit);
    if (counted === undefined) {
      counted = parentCount(projectPath, origin.commit);
      parents.set(origin.commit, counted);
    }
    const count = await counted;
    if (count === null || count > 1) continue;
    const key = `${origin.commit}\0${origin.file}`;
    let text = textDiffs.get(key);
    if (text === undefined) {
      text = isTextDiff(projectPath, origin);
      textDiffs.set(key, text);
    }
    if (await text) out.add(f);
  }
  return out;
}

/** `git blame` of line `line` of `path` (project-relative) as the working tree holds it, or null. */
async function originOf(projectPath: string, path: string, line: number): Promise<LineOrigin | null> {
  const r = await git(projectPath, [
    '-c',
    'core.quotePath=false',
    'blame',
    '--porcelain',
    '--ignore-revs-file=',
    '-L',
    `${line},${line}`,
    '--',
    path,
  ]);
  if (r.exitCode !== 0) return null;
  const lines = r.stdout.split('\n');
  const commit = /^([0-9a-f]{40,64}) /.exec(lines[0] ?? '')?.[1];
  // Uncommitted: all zeros. A name git still quotes (a `"`, a control character) is not guessed at.
  if (commit === undefined || /^0+$/.test(commit)) return null;
  const file = lines.find((l) => l.startsWith('filename '))?.slice('filename '.length);
  if (file === undefined || file === '' || file.startsWith('"')) return null;
  return { commit, file };
}

/** How many parents `commit` has, or null when git cannot say. */
async function parentCount(projectPath: string, commit: string): Promise<number | null> {
  const r = await git(projectPath, ['rev-list', '--parents', '-n', '1', commit, '--']);
  const ids = r.stdout.trim().split(/\s+/);
  return r.exitCode === 0 && ids[0] === commit ? ids.length - 1 : null;
}

/** Whether `origin.commit`'s diff of `origin.file` is text — what `git log -p` prints as a hunk. */
async function isTextDiff(projectPath: string, origin: LineOrigin): Promise<boolean> {
  const r = await git(projectPath, [
    'diff-tree',
    '--no-commit-id',
    '--numstat',
    '-z',
    '-r',
    '--root',
    '--no-renames',
    origin.commit,
    '--',
    `:(top,literal)${origin.file}`,
  ]);
  if (r.exitCode !== 0) return false;
  const entry = splitNul(r.stdout)[0];
  return entry !== undefined && /^\d+\t\d+\t/.test(entry);
}
