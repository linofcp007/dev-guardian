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
 *
 * The same change is read again, its own way, by the suppressions pass
 * ({@link runSuppressionCheck}, `suppressions.ts`): one `git diff -G`
 * listing of the files whose added or removed lines hold a directive's
 * token, then a `-U0` diff and the text of each one listed. Its bounds and a
 * failed listing are notes, never a gap: nothing it adds gates a scan.
 */

import { createHash } from 'node:crypto';
import { readProjectText } from '../platform/projectFs.js';
import {
  git,
  mergeBase,
  parseNameStatus,
  resolveCommit,
  splitNul,
  type GitResult,
  type GitRunner,
  type NameStatusEntry,
} from '../runners/git.js';
import type { Finding, ToolRun } from '../types.js';
import { detectTestWeakening, isRelevantPath, NOT_TESTS, TEST_INTEGRITY_TOOL, type ChangedFile, type DiffLine } from './detect.js';
import {
  detectSuppressions,
  mayHoldSuppression,
  PICKAXE_ERE,
  SUPPRESSIONS_TOOL,
  suppressionLanguageOf,
  type SuppressionCounts,
  type SuppressionFile,
} from './suppressions.js';

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

/** A listed change (`runners/git.ts#parseNameStatus`), or an untracked file. */
interface Listed extends NameStatusEntry {
  /** Listed by `ls-files --others`: in no diff, every line of it is new. */
  untracked?: boolean;
}

/**
 * The added lines (new numbers) and removed lines (the new-file line their hunk lands on) of a `-U0` diff. A
 * context line still counts a line, so a diff with context reads the same: `GIT_DIFF_OPTS` overrides `-U`, and
 * `diff.interHunkContext` fuses hunks across kept lines.
 */
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
    } else if (line.startsWith(' ') || line === '') {
      // A kept line (`diff.suppressBlankEmpty` prints a blank one empty).
      newLine += 1;
    }
  }
  return { added, removed };
}

/** A file's text at a revision (`<rev>:./<path>`), or null. */
async function showAt(cwd: string, rev: string, path: string, run: GitRunner = git): Promise<string | null> {
  const r = await run(cwd, ['show', '--no-textconv', `${rev}:./${path}`]);
  if (r.exitCode !== 0 || r.stdout.length > MAX_TEXT_BYTES) return null;
  return r.stdout;
}

async function textAfter(cwd: string, target: ChangeTarget, path: string, run: GitRunner = git): Promise<string | null> {
  if (target.kind === 'commit') return showAt(cwd, target.sha, path, run);
  if (target.kind === 'index') return showAt(cwd, '', path, run);
  const r = readProjectText(cwd, path, MAX_TEXT_BYTES);
  return r.status === 'ok' ? r.text : null;
}

interface ChangeSetRead {
  changes: ChangedFile[];
  /** Relevant files past {@link MAX_FILES}, not read. */
  skipped: number;
  /** What the read left out, said in the run's reason. */
  notes: string[];
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
  const listed: Listed[] = parseNameStatus(r.stdout);
  if (target.kind === 'worktree' && target.untracked) {
    const u = await git(cwd, ['ls-files', '-z', '--others', '--exclude-standard']);
    if (u.exitCode === 0) for (const path of splitNul(u.stdout)) listed.push({ status: 'added', path, untracked: true });
  }
  const notes: string[] = [];
  if (target.kind === 'worktree' && target.untracked) {
    const cut = await pairUntrackedMoves(cwd, base, listed);
    if (cut !== null) notes.push(cut);
  }
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
  return { changes, skipped: Math.max(0, relevant.length - MAX_FILES), notes };
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

/** The most line-by-line comparisons one change set makes to find its moves; past it, a note. */
export const MAX_PAIR_COMPARISONS = 20_000;

/** A file's non-blank lines, trimmed, counted once: what a pair compares. */
interface LineCounts {
  counts: Map<string, number>;
  total: number;
  /** The hash of those lines in order: two files with the same one are the same file, moved. */
  hash: string;
}

function lineCounts(text: string): LineCounts {
  const counts = new Map<string, number>();
  const digest = createHash('sha256');
  let total = 0;
  for (const raw of text.split(/\r?\n/)) {
    const l = raw.trim();
    if (l === '') continue;
    counts.set(l, (counts.get(l) ?? 0) + 1);
    digest.update(l).update('\n');
    total += 1;
  }
  return { counts, total, hash: digest.digest('hex') };
}

/** How much the two share, 0 to 1: shared lines over the longer one's. */
function similarity(a: LineCounts, b: LineCounts): number {
  const [small, large] = a.counts.size <= b.counts.size ? [a, b] : [b, a];
  let shared = 0;
  for (const [line, n] of small.counts) shared += Math.min(n, large.counts.get(line) ?? 0);
  return shared / Math.max(1, a.total, b.total);
}

const baseName = (p: string): string => p.slice(p.lastIndexOf('/') + 1);

/**
 * Which untracked file is a move of which deleted one, in three passes over
 * every file:
 *
 *   1. the same text (its lines, trimmed, in order — a hash, no comparison):
 *      a file moved whole is paired wherever it went and whatever its name,
 *      same-name copies first — never a blank file, which is no one's copy;
 *   2. the deleted files with the same base name (a moved directory) whose
 *      text it shares at least half its lines with (git's own rename
 *      threshold), the best;
 *   3. the same over the deleted files of other names.
 *
 * Passes 2 and 3 share one budget of {@link MAX_PAIR_COMPARISONS}
 * comparisons; a pair the line counts alone rule out costs none. `capped`
 * counts every file whose search the budget cut — midway or before it began.
 * Each text is counted once. Pure: texts in, pairs out.
 */
export function pairMoves(
  oldTexts: ReadonlyMap<string, string>,
  fresh: ReadonlyArray<{ path: string; text: string }>,
): { pairs: Map<string, string>; capped: number } {
  const old = [...oldTexts].map(([path, text]) => ({ path, name: baseName(path), lines: lineCounts(text) }));
  const news = fresh.map((f) => ({ path: f.path, name: baseName(f.path), lines: lineCounts(f.text) }));
  const taken = new Set<string>();
  const pairs = new Map<string, string>();
  const pair = (f: (typeof news)[number], o: (typeof old)[number]): void => {
    taken.add(o.path);
    pairs.set(f.path, o.path);
  };

  // 1. The same text, under the same name first, then under any. Never a
  // blank one: every empty file has that hash, and none is a move of another
  // (an empty test file deleted stays deleted). Passes 2 and 3 never pair one
  // either: it shares no line.
  const byHash = new Map<string, typeof old>();
  for (const o of old) if (o.lines.total > 0) byHash.set(o.lines.hash, [...(byHash.get(o.lines.hash) ?? []), o]);
  for (const sameName of [true, false]) {
    for (const f of news) {
      if (pairs.has(f.path) || f.lines.total === 0) continue;
      const o = (byHash.get(f.lines.hash) ?? []).find((c) => !taken.has(c.path) && (!sameName || c.name === f.name));
      if (o !== undefined) pair(f, o);
    }
  }

  // 2 and 3. By the lines they share, under one budget.
  const byName = new Map<string, typeof old>();
  for (const o of old) byName.set(o.name, [...(byName.get(o.name) ?? []), o]);
  let budget = MAX_PAIR_COMPARISONS;
  const cut = new Set<string>();
  const search = (f: (typeof news)[number], candidates: Iterable<(typeof old)[number]>, skipName: string | null): void => {
    let best: { o: (typeof old)[number]; score: number } | null = null;
    for (const o of candidates) {
      if (taken.has(o.path) || o.name === skipName) continue;
      // At most min/max of the lines can be shared: under half, no look.
      if (Math.min(o.lines.total, f.lines.total) * 2 < Math.max(o.lines.total, f.lines.total)) continue;
      if (budget <= 0) {
        cut.add(f.path);
        break;
      }
      budget -= 1;
      const score = similarity(o.lines, f.lines);
      if (score >= 0.5 && (best === null || score > best.score)) best = { o, score };
      if (best !== null && best.score >= 1) break;
    }
    if (best !== null) pair(f, best.o);
  };
  for (const f of news) if (!pairs.has(f.path)) search(f, byName.get(f.name) ?? [], null);
  for (const f of news) if (!pairs.has(f.path)) search(f, old, f.name);
  return { pairs, capped: cut.size };
}

/**
 * An unstaged move — the file deleted from the index's view, its new path
 * untracked — is in no diff as a rename: it read as a deleted test file plus
 * an untracked file whose every line, an old `it.skip` included, was new.
 * Each untracked relevant file paired with a deleted one ({@link pairMoves})
 * becomes one `renamed` entry, in place of both. At most {@link MAX_FILES}
 * of each side are read. Returns the note to give when the pairing was cut.
 */
async function pairUntrackedMoves(cwd: string, base: string, listed: Listed[]): Promise<string | null> {
  const deleted = listed.filter((l) => l.status === 'deleted' && isRelevantPath(l.path)).slice(0, MAX_FILES);
  const fresh = listed.filter((l) => l.untracked === true && isRelevantPath(l.path)).slice(0, MAX_FILES);
  if (deleted.length === 0 || fresh.length === 0) return null;
  const oldTexts = new Map<string, string>();
  for (const d of deleted) {
    const text = await showAt(cwd, base, d.path);
    if (text !== null) oldTexts.set(d.path, text);
  }
  const freshTexts: Array<{ path: string; text: string }> = [];
  for (const f of fresh) {
    const r = readProjectText(cwd, f.path, MAX_TEXT_BYTES);
    if (r.status === 'ok') freshTexts.push({ path: f.path, text: r.text });
  }
  const { pairs, capped } = pairMoves(oldTexts, freshTexts);
  const taken = new Set(pairs.values());
  for (const f of fresh) {
    const from = pairs.get(f.path);
    if (from === undefined) continue;
    f.status = 'renamed';
    f.oldPath = from;
  }
  for (let i = listed.length - 1; i >= 0; i -= 1) {
    const l = listed[i];
    if (l !== undefined && l.status === 'deleted' && taken.has(l.path)) listed.splice(i, 1);
  }
  return capped > 0
    ? `the search for moved test files stopped after ${MAX_PAIR_COMPARISONS} comparisons: ${capped} untracked file(s) were not compared with every deleted one (a file moved unchanged is still paired)`
    : null;
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
  const notes = [
    ...read.notes,
    ...(read.skipped > 0 ? [`${read.skipped} more changed test file(s) past the first ${MAX_FILES} were not read`] : []),
  ];
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

// ---------------------------------------------------------------------------
// The suppressions pass (`suppressions.ts`): its own listing, its own name.
// ---------------------------------------------------------------------------

/** What the suppressions pass read of a change. */
interface SuppressionRead {
  files: SuppressionFile[];
  /** No file to read: none listed by `-G` (after the language, `NOT_TESTS` and scope filters), none untracked, nothing left out. */
  empty: boolean;
  /** Files it could not read (a failed diff, an untracked file over the bound): their lines were not judged. */
  unread: number;
  /** What a bound or a failed listing left out. */
  notes: string[];
}

function firstLineOf(r: GitResult): string {
  return r.stderr.split(/\r?\n/).find((l) => l.trim() !== '') ?? `exit ${r.exitCode}`;
}

/**
 * The change's files that may add a suppression: one `git diff -G` listing
 * of the files whose added or removed lines hold a token (`PICKAXE_ERE` —
 * the same work as one `-U0` diff of the range: git diffs every pair once),
 * a deletion included (its removed directives carry the added ones), then
 * one `-U0` diff per candidate and its text after the change — read only
 * when an added line holds a token. Untracked files (a worktree target that
 * asks for them) are read from disk and kept when they hold one. At most
 * `cap` of each are read; past that, a note.
 */
async function readSuppressionChanges(
  cwd: string,
  from: string,
  target: ChangeTarget,
  member: ((path: string) => boolean) | undefined,
  run: GitRunner,
  cap: number,
): Promise<SuppressionRead | { error: string }> {
  const range = diffRange(from, target);
  const listing = await run(cwd, ['diff', '-z', '--name-status', '-M', '--relative', '--no-ext-diff', '--no-textconv', '-G', PICKAXE_ERE, ...range, '--']);
  if (listing.exitCode !== 0) return { error: firstLineOf(listing) };
  const wanted = (p: string): boolean => suppressionLanguageOf(p) !== null && !NOT_TESTS.test(p) && (member === undefined || member(p));
  const listed = parseNameStatus(listing.stdout).filter((l) => wanted(l.path) || (l.oldPath !== undefined && wanted(l.oldPath)));
  const files: SuppressionFile[] = [];
  const notes: string[] = [];
  let unread = 0;
  for (const l of listed.slice(0, cap)) {
    const paths = l.oldPath !== undefined ? [l.oldPath, l.path] : [l.path];
    const d = await run(cwd, ['diff', '-U0', '--no-color', '--no-ext-diff', '--no-textconv', '-M', '--relative', ...range, '--', ...paths]);
    if (d.exitCode !== 0) {
      unread += 1;
      continue;
    }
    const lines = parseUnifiedZero(d.stdout);
    // A file whose added lines hold no token adds nothing to judge: its text is not read (its removals still carry).
    const judged = l.status !== 'deleted' && lines.added.some((a) => mayHoldSuppression(a.text));
    const after = judged ? await textAfter(cwd, target, l.path, run) : null;
    files.push({ path: l.path, added: judged ? lines.added : [], removed: lines.removed, after });
  }
  if (listed.length > cap) notes.push(`${listed.length - cap} more changed file(s) with a suppression token past the first ${cap} were not read`);
  let fresh = 0;
  if (target.kind === 'worktree' && target.untracked) {
    const u = await run(cwd, ['ls-files', '-z', '--others', '--exclude-standard']);
    if (u.exitCode !== 0) {
      notes.push(`the untracked files could not be listed (${firstLineOf(u)}): none was read for suppressions`);
    } else {
      const untracked = splitNul(u.stdout).filter(wanted);
      for (const path of untracked.slice(0, cap)) {
        const t = readProjectText(cwd, path, MAX_TEXT_BYTES);
        if (t.status !== 'ok') {
          unread += 1;
          continue;
        }
        if (!mayHoldSuppression(t.text)) continue;
        fresh += 1;
        files.push({ path, added: numbered(t.text), removed: [], after: t.text });
      }
      if (untracked.length > cap) notes.push(`${untracked.length - cap} more untracked file(s) past the first ${cap} were not read for suppressions`);
    }
  }
  return { files, empty: listed.length === 0 && fresh === 0 && unread === 0 && notes.length === 0, unread, notes };
}

/** What the suppressions pass gives its caller: its `tools_run` entry, its findings, and its notes (never a gap). */
interface SuppressionResult {
  toolRun: ToolRun;
  findings: Finding[];
  /** What a bound or a failed listing left out: the CLI's `coverage_notes`, never `missing_tools` (nothing new gates). */
  notes: string[];
}

function suppressionSummary(c: SuppressionCounts, from: string, where: string): string {
  const head = `read ${c.files} changed file(s) with a suppression token from ${from.slice(0, 12)} to ${where}`;
  const carried = c.carried > 0 ? `; ${c.carried} kept or moved from a removed line (not new)` : '';
  if (c.added === 0) return `${head}: no suppression added${carried}`;
  const parts = [
    `${c.reported} with no reason reported`,
    `${c.named} naming the rule(s) they silence`,
    `${c.reasoned} with a reason`,
  ].filter((p) => !p.startsWith('0 '));
  return `${head}: ${c.added} suppression(s) added — ${parts.join(', ')}${carried}`;
}

/**
 * The suppressions pass over the change from `base` (its merge base with
 * `head`) to `target` — see `suppressions.ts`. Null when the change has no
 * file to read (none whose diff holds a token, no untracked one): the pass
 * does not apply. It never gates: a base with no merge base, or a change git
 * cannot list, is `skipped` with the reason; a bound that leaves files
 * unread is a note. `git` and `maxFiles`: a test's counting runner and a
 * smaller bound.
 */
export async function runSuppressionCheck(
  cwd: string,
  opts: {
    base: string;
    head?: string;
    target: ChangeTarget;
    member?: (path: string) => boolean;
    label?: string;
    git?: GitRunner;
    maxFiles?: number;
  },
): Promise<SuppressionResult | null> {
  const run = opts.git ?? git;
  const label = opts.label ?? opts.base;
  const head = opts.head ?? 'HEAD';
  const skipped = (reason: string, notes: string[]): SuppressionResult => ({
    toolRun: { name: SUPPRESSIONS_TOOL, status: 'skipped', reason },
    findings: [],
    notes,
  });
  const from = await mergeBase(cwd, opts.base, head, run);
  if (from === null) {
    // The test-integrity pass says the same, as a gap or a skip: this one adds neither a gap nor a note.
    const why = (await resolveCommit(cwd, opts.base)) === null ? `${label} names no commit` : `no merge base of ${label} and ${head} in this clone`;
    return skipped(`${why}: the change was not read for suppressions`, []);
  }
  const read = await readSuppressionChanges(cwd, from, opts.target, opts.member, run, opts.maxFiles ?? MAX_FILES);
  if ('error' in read) {
    const note = `the change could not be listed for suppressions (${read.error}): no file was read for them`;
    return skipped(note, [note]);
  }
  if (read.empty) return null;
  const { findings, counts } = detectSuppressions(read.files);
  const unread = counts.unread + read.unread;
  const notes = [...read.notes, ...(unread > 0 ? [`${unread} changed file(s) over ${MAX_TEXT_BYTES / (1024 * 1024)} MiB or unreadable were not read for suppressions`] : [])];
  const where =
    opts.target.kind === 'index' ? 'the staged changes' : opts.target.kind === 'commit' ? opts.target.sha.slice(0, 12) : 'the working tree';
  return {
    toolRun: { name: SUPPRESSIONS_TOOL, status: 'ok', reason: [suppressionSummary(counts, from, where), ...notes].join('; ') },
    findings,
    notes,
  };
}
