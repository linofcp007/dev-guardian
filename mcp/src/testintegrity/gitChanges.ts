/**
 * The change set `detect.ts` judges, read from git: the files a change
 * touches between a base commit and a target — another commit (a branch
 * reviewed without checking it out), the index (what is staged) or the
 * working tree (a branch with its uncommitted work, untracked files
 * included when asked) — and, for the files that matter (test files,
 * package.json, Rust sources), each one's added and removed lines and its
 * text before and after.
 *
 * Every listing is `-z` and `--relative` (paths relative to the project,
 * which may be a subdirectory of its repository), with renames detected
 * (`-M`, so a moved test file is not a deleted one), no external diff driver
 * and no textconv: a repository's own drivers never run here. One `-U0` diff
 * per file, so a path git would quote in a header is never parsed out of one.
 * Bounded: at most {@link MAX_FILES} files are read, each at most
 * {@link MAX_TEXT_BYTES}; past either the run says what it left out.
 */

import { readProjectText } from '../platform/projectFs.js';
import { git, resolveCommit, splitNul } from '../runners/git.js';
import type { Finding, ToolRun } from '../types.js';
import { detectTestWeakening, isRelevantPath, TEST_INTEGRITY_TOOL, type ChangedFile, type DiffLine } from './detect.js';

/** What the base is compared with. */
type ChangeTarget =
  | { kind: 'worktree'; untracked: boolean }
  | { kind: 'index' }
  | { kind: 'commit'; sha: string };

/** The most relevant files whose diff and texts are read. */
const MAX_FILES = 500;
/** A file over this is judged on its diff alone (no assertion count). */
const MAX_TEXT_BYTES = 2 * 1024 * 1024;

/** `git diff`'s arguments for `base` against `target`, before `--`. */
function diffRange(base: string, target: ChangeTarget): string[] {
  if (target.kind === 'index') return ['--cached', base];
  if (target.kind === 'commit') return [base, target.sha];
  return [base];
}

/** The merge base of `a` and `b`, or null. */
async function mergeBase(cwd: string, a: string, b: string): Promise<string | null> {
  const r = await git(cwd, ['merge-base', '--end-of-options', a, b]);
  if (r.exitCode !== 0) return null;
  const sha = r.stdout.trim();
  return /^[0-9a-f]{40,64}$/.test(sha) ? sha : null;
}

interface Listed {
  status: ChangedFile['status'];
  path: string;
  oldPath?: string;
  /** Listed by `ls-files --others`: in no diff, every line of it is new. */
  untracked?: boolean;
}

/** `--name-status -z` output: `M\0path\0`, `R100\0old\0new\0`, `C75\0src\0copy\0`. */
function parseNameStatus(stdout: string): Listed[] {
  const parts = splitNul(stdout);
  const out: Listed[] = [];
  for (let i = 0; i < parts.length; ) {
    const code = parts[i] ?? '';
    const letter = code.charAt(0);
    if (letter === 'R' || letter === 'C') {
      const oldPath = parts[i + 1] ?? '';
      const path = parts[i + 2] ?? '';
      i += 3;
      // A copy leaves its source in place: the copy is an added file.
      out.push(letter === 'R' ? { status: 'renamed', path, oldPath } : { status: 'added', path });
      continue;
    }
    const path = parts[i + 1] ?? '';
    i += 2;
    if (letter === 'A') out.push({ status: 'added', path });
    else if (letter === 'D') out.push({ status: 'deleted', path });
    else if (letter === 'M' || letter === 'T') out.push({ status: 'modified', path });
  }
  return out;
}

/** The added lines (new numbers) and removed lines (the new-file line their hunk lands on) of a `-U0` diff. */
export function parseUnifiedZero(diff: string): { added: DiffLine[]; removed: DiffLine[] } {
  const added: DiffLine[] = [];
  const removed: DiffLine[] = [];
  let newLine = 0;
  let inHunk = false;
  for (const raw of diff.split('\n')) {
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/.exec(line);
    if (hunk !== null) {
      const start = Number(hunk[1]);
      // `+n,0`: nothing added — the removed lines sat after line n.
      newLine = hunk[2] === '0' ? start + 1 : start;
      inHunk = true;
      continue;
    }
    if (!inHunk) continue;
    if (line.startsWith('+')) {
      added.push({ line: newLine, text: line.slice(1) });
      newLine += 1;
    } else if (line.startsWith('-')) {
      removed.push({ line: Math.max(1, newLine), text: line.slice(1) });
    } else if (line.startsWith('diff --git')) {
      inHunk = false;
    }
  }
  return { added, removed };
}

/** A file's text at a revision (`<rev>:./<path>`), or null. */
async function showAt(cwd: string, rev: string, path: string): Promise<string | null> {
  const r = await git(cwd, ['show', '--no-textconv', `${rev}:./${path}`]);
  if (r.exitCode !== 0 || r.stdout.length > MAX_TEXT_BYTES) return null;
  return r.stdout;
}

async function textAfter(cwd: string, target: ChangeTarget, path: string): Promise<string | null> {
  if (target.kind === 'commit') return showAt(cwd, target.sha, path);
  if (target.kind === 'index') return showAt(cwd, '', path);
  const r = readProjectText(cwd, path, MAX_TEXT_BYTES);
  return r.status === 'ok' ? r.text : null;
}

interface ChangeSetRead {
  changes: ChangedFile[];
  /** Relevant files past {@link MAX_FILES}, not read. */
  skipped: number;
}

/**
 * The change set from `base` (a commit id) to `target`, its relevant files
 * read. `member`, when given, keeps only the paths a scope covers. Throws
 * with git's message when the listing fails.
 */
export async function readChangeSet(
  cwd: string,
  base: string,
  target: ChangeTarget,
  member?: (path: string) => boolean,
): Promise<ChangeSetRead> {
  const r = await git(cwd, ['diff', '-z', '--name-status', '-M', '--relative', '--no-ext-diff', ...diffRange(base, target), '--']);
  if (r.exitCode !== 0) {
    throw new Error(`git diff could not list the changes: ${r.stderr.split(/\r?\n/).find((l) => l.trim() !== '') ?? `exit ${r.exitCode}`}`);
  }
  const listed = parseNameStatus(r.stdout);
  if (target.kind === 'worktree' && target.untracked) {
    const u = await git(cwd, ['ls-files', '-z', '--others', '--exclude-standard']);
    if (u.exitCode === 0) for (const path of splitNul(u.stdout)) listed.push({ status: 'added', path, untracked: true });
  }
  if (target.kind === 'worktree' && target.untracked) await pairUntrackedMoves(cwd, base, listed);
  const relevant = listed.filter(
    (l) => (isRelevantPath(l.path) || (l.oldPath !== undefined && isRelevantPath(l.oldPath))) && (member === undefined || member(l.path) || (l.oldPath !== undefined && member(l.oldPath))),
  );
  const changes: ChangedFile[] = [];
  for (const l of relevant.slice(0, MAX_FILES)) {
    const before = l.status === 'added' ? null : await showAt(cwd, base, l.oldPath ?? l.path);
    if (l.status === 'deleted') {
      changes.push({ status: 'deleted', path: l.path, added: [], removed: [], before, after: null });
      continue;
    }
    const after = await textAfter(cwd, target, l.path);
    let lines: { added: DiffLine[]; removed: DiffLine[] };
    if (l.untracked === true && after !== null) {
      // Untracked: in no diff. Every line is new — or, for a file moved from a
      // deleted one (`pairUntrackedMoves`), every line its old text lacks.
      lines = l.oldPath !== undefined && before !== null ? lineChanges(before, after) : { added: numbered(after), removed: [] };
    } else {
      const paths = l.oldPath !== undefined ? [l.oldPath, l.path] : [l.path];
      const d = await git(cwd, ['diff', '-U0', '--no-color', '--no-ext-diff', '--no-textconv', '-M', '--relative', ...diffRange(base, target), '--', ...paths]);
      lines = d.exitCode === 0 ? parseUnifiedZero(d.stdout) : { added: [], removed: [] };
    }
    changes.push({
      status: l.status,
      path: l.path,
      ...(l.oldPath !== undefined ? { oldPath: l.oldPath } : {}),
      ...lines,
      before,
      after,
    });
  }
  return { changes, skipped: Math.max(0, relevant.length - MAX_FILES) };
}

/** Every line of `text`, numbered from 1. */
function numbered(text: string): DiffLine[] {
  return text.split(/\r?\n/).map((line, i) => ({ line: i + 1, text: line }));
}

/**
 * The lines `after` adds to `before` and the ones it drops, compared as a
 * multiset of trimmed lines (a moved block is not new): what a move with
 * edits changed, without git's own diff of an untracked file.
 */
function lineChanges(before: string, after: string): { added: DiffLine[]; removed: DiffLine[] } {
  const left = new Map<string, number>();
  for (const l of before.split(/\r?\n/)) left.set(l.trim(), (left.get(l.trim()) ?? 0) + 1);
  const right = new Map<string, number>();
  const added: DiffLine[] = [];
  for (const l of numbered(after)) {
    const key = l.text.trim();
    right.set(key, (right.get(key) ?? 0) + 1);
    const n = left.get(key) ?? 0;
    if (n > 0) left.set(key, n - 1);
    else added.push(l);
  }
  const removed: DiffLine[] = [];
  for (const l of numbered(before)) {
    const key = l.text.trim();
    const n = right.get(key) ?? 0;
    if (n > 0) right.set(key, n - 1);
    else removed.push({ line: 1, text: l.text });
  }
  return { added, removed };
}

/** How much of `a`'s lines `b` holds, 0 to 1 (trimmed, blank lines left out). */
function similarity(a: string, b: string): number {
  const count = new Map<string, number>();
  const linesA = a.split(/\r?\n/).map((l) => l.trim()).filter((l) => l !== '');
  for (const l of linesA) count.set(l, (count.get(l) ?? 0) + 1);
  let shared = 0;
  const linesB = b.split(/\r?\n/).map((l) => l.trim()).filter((l) => l !== '');
  for (const l of linesB) {
    const n = count.get(l) ?? 0;
    if (n > 0) {
      shared += 1;
      count.set(l, n - 1);
    }
  }
  return shared / Math.max(1, linesA.length, linesB.length);
}

/**
 * An unstaged move — the file deleted from the index's view, its new path
 * untracked — is in no diff as a rename: it read as a deleted test file plus
 * an untracked file whose every line, an old `it.skip` included, was new.
 * Each untracked relevant file is paired with the deleted relevant file whose
 * base text it shares at least half its lines with (git's own rename
 * threshold), the best first; the pair becomes one `renamed` entry, in place
 * of both. Bounded: at most {@link MAX_FILES} of each side are compared.
 */
async function pairUntrackedMoves(cwd: string, base: string, listed: Listed[]): Promise<void> {
  const deleted = listed.filter((l) => l.status === 'deleted' && isRelevantPath(l.path)).slice(0, MAX_FILES);
  const fresh = listed.filter((l) => l.untracked === true && isRelevantPath(l.path)).slice(0, MAX_FILES);
  if (deleted.length === 0 || fresh.length === 0) return;
  const oldTexts = new Map<string, string>();
  for (const d of deleted) {
    const text = await showAt(cwd, base, d.path);
    if (text !== null) oldTexts.set(d.path, text);
  }
  const taken = new Set<string>();
  for (const f of fresh) {
    const r = readProjectText(cwd, f.path, MAX_TEXT_BYTES);
    if (r.status !== 'ok') continue;
    let best: { path: string; score: number } | null = null;
    for (const [path, text] of oldTexts) {
      if (taken.has(path)) continue;
      const score = similarity(text, r.text);
      if (score >= 0.5 && (best === null || score > best.score)) best = { path, score };
    }
    if (best === null) continue;
    taken.add(best.path);
    f.status = 'renamed';
    f.oldPath = best.path;
  }
  for (let i = listed.length - 1; i >= 0; i -= 1) {
    const l = listed[i];
    if (l !== undefined && l.status === 'deleted' && taken.has(l.path)) listed.splice(i, 1);
  }
}

interface TestIntegrityResult {
  toolRun: ToolRun;
  /** The pass's gap (the change set could not be read) as its `missing_tools` name; empty without one. */
  missing: string[];
  findings: Finding[];
}

/**
 * The check over the change from `base` (a ref or commit; its merge base
 * with `head` is what is compared, as `base...head`) to `target`: null when
 * the change touches no test file, package.json or Rust source — the check
 * does not apply. When the two share no history git can see (a shallow clone
 * that fetched the base alone) the run is `skipped` with the reason, never
 * judged against the base's tip, and no gap. A base that names no commit, or
 * a change set git cannot list, is a failed run, never a clean one.
 */
export async function runTestIntegrityCheck(
  cwd: string,
  opts: { base: string; head?: string; target: ChangeTarget; member?: (path: string) => boolean; label?: string },
): Promise<TestIntegrityResult | null> {
  const fail = (reason: string): TestIntegrityResult => ({
    toolRun: { name: TEST_INTEGRITY_TOOL, status: 'failed', reason },
    missing: [TEST_INTEGRITY_TOOL],
    findings: [],
  });
  const label = opts.label ?? opts.base;
  const from = await mergeBase(cwd, opts.base, opts.head ?? 'HEAD');
  if (from === null) {
    if ((await resolveCommit(cwd, opts.base)) === null) return fail(`${label} names no commit: the change could not be read`);
    // A shallow clone that fetched the base alone: compared with the base's
    // tip, every change the base made since the fork would read reversed (a
    // test it added as deleted, a skip it removed as added). Not judged, and
    // said — no history to read is no gap of the change.
    return {
      toolRun: {
        name: TEST_INTEGRITY_TOOL,
        status: 'skipped',
        reason: `no merge base of ${label} and ${opts.head ?? 'HEAD'} in this clone (a shallow fetch?): the change cannot be told from the base's own, so it was not read — fetch the history between them`,
      },
      missing: [],
      findings: [],
    };
  }
  let read: ChangeSetRead;
  try {
    read = await readChangeSet(cwd, from, opts.target, opts.member);
  } catch (e) {
    return fail(e instanceof Error ? e.message : String(e));
  }
  if (read.changes.length === 0) return null;
  const findings = detectTestWeakening(read.changes);
  const where =
    opts.target.kind === 'index' ? 'the staged changes' : opts.target.kind === 'commit' ? opts.target.sha.slice(0, 12) : 'the working tree';
  const notes = read.skipped > 0 ? [`${read.skipped} more changed test file(s) past the first ${MAX_FILES} were not read`] : [];
  return {
    toolRun: {
      name: TEST_INTEGRITY_TOOL,
      status: 'ok',
      reason: [`compared ${read.changes.length} changed test file(s) and manifest(s) from ${from.slice(0, 12)} to ${where}`, ...notes].join('; '),
    },
    missing: read.skipped > 0 ? [TEST_INTEGRITY_TOOL] : [],
    findings,
  };
}
