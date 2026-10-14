/**
 * What a gitleaks finding's secret IS, and when it came in, for one gate run
 * — the value as an HMAC under a key this process draws once and never
 * writes anywhere (review 10 finding 5, review 11 finding 2).
 *
 * The CI gate's tolerant key (`fingerprint/findingIdentity.ts#gateMatchKeys`)
 * keys a secret by (rule, path, occurrence). With the values read, the
 * occurrence is the secret's place among its file's distinct values, in the
 * order they were introduced (commit, then line): every commit that touched
 * the secret's line, the working-tree copy and a move to another line share
 * one key, a value replaced in place or added above is another — and the
 * baseline's entries are matched one to one (`ci/baseline.ts`).
 *
 * The scans run gitleaks with `--redact`, and the database never holds a
 * secret or its hash. So the value is read back here, in memory, from where
 * the finding says it is — the line at that commit (`git cat-file blob
 * <commit>:<path>`) for a history finding, the working-tree file for the
 * files pass — and cut out of the line where gitleaks' own report says it
 * matched ({@link secretFromLine}):
 *
 *   - the report's `StartColumn` / `EndColumn` locate the match, in bytes —
 *     one column late on every line of a fragment but its first (gitleaks
 *     counts from the newline before the line), so both places are tried,
 *     and where both read as a secret the fragments decide: in history the
 *     first added line of each hunk of `git log -p -U0`, in a file its
 *     first line;
 *   - the redacted `Match` is the match with the secret replaced by
 *     `REDACTED`: what is around the secret must be what the line holds;
 *   - the report's `Entropy` is the secret's Shannon entropy as gitleaks
 *     computed it: the candidate must have it.
 *
 * Exactly one candidate passing is the value; none or two is not. A finding
 * the report holds two secrets for (two on one line, one finding) is the
 * set of them. A comment appended to a baselined secret's line, or the same
 * value on another line, is the same value (each made the gate exit 1 when
 * the whole line was the value). A finding the report does not locate — no
 * report, a multi-line match (a private key), an ambiguous cut — falls back
 * to its whole lines, whitespace removed (review 10's rule): stricter, never a
 * silent match. Every value is HMAC'd under {@link RUN_KEY}: comparable
 * within this process, useless outside it. Nothing is stored; the values
 * live in `WeakMap`s beside the finding objects the gate is handed.
 *
 * When a secret came in: the committer time of a history finding's commit
 * (`git show -s --format=%ct`), `Infinity` for the working tree.
 *
 * A value that cannot be read (a commit or file gone, over
 * {@link MAX_BLOB_BYTES}, past {@link MAX_BLOBS}) is undefined: that finding
 * matches the baseline by its exact identity only, never a silent match.
 */

import { createHmac, randomBytes } from 'node:crypto';
import { isAbsolute, join } from 'node:path';
import { parseJsonBounded } from '../platform/boundedJson.js';
import { readProjectText } from '../platform/projectFs.js';
import { readSmallTextFile } from '../hooks/configFile.js';
import { git } from '../runners/git.js';
import type { Finding } from '../types.js';

/** Drawn once per process; never written, logged or returned. */
const RUN_KEY = randomBytes(32);

/** The largest file whose line is read (a blob, or a working-tree file). */
const MAX_BLOB_BYTES = 16 * 1024 * 1024;

/** At most this many distinct (commit, path) blobs read per run; the rest are unknown. */
const MAX_BLOBS = 2_000;

/** The largest gitleaks report read for its columns. */
const MAX_REPORT_BYTES = 64 * 1024 * 1024;

/** The reports a gitleaks pass writes into its scan's report directory (`runners/gitleaksScan.ts`). */
const REPORT_FILES = ['secrets-history.json', 'secrets-working-tree.json', 'secrets.json'];

/** Commits per `git show` call. */
const COMMIT_BATCH = 100;

const values = new WeakMap<object, string>();
const introduced = new WeakMap<object, number>();
/** The findings {@link rememberSecretValues} tried to read, read or not. */
const attempted = new WeakSet<object>();

/** The finding's secret as this run's HMAC, or undefined when it was not read. */
export function secretValueOf(finding: object): string | undefined {
  return values.get(finding);
}

/**
 * When the finding's secret came in: its commit's time (ms), `Infinity` for
 * one no commit holds, undefined when not known.
 */
export function secretIntroducedAt(finding: object): number | undefined {
  return introduced.get(finding);
}

/**
 * Whether {@link rememberSecretValues} went over any finding of `findings` —
 * the gate's set. Without it (a caller that never read the values) the gate
 * compares none, as before 3.4.
 */
export function secretValuesRead(findings: readonly object[]): boolean {
  return findings.some((f) => attempted.has(f));
}

/** `rule=<id>;commit=<sha>` → the sha; null for a files-pass locator. */
function commitOf(snippet: string | undefined): string | null {
  const m = /;commit=([0-9a-f]{7,64})$/i.exec(snippet ?? '');
  return m?.[1] ?? null;
}

/** Lines `from`..`to` (1-based) of `text`, every whitespace removed; null when out of range. */
function linesOf(text: string, from: number, to: number): string | null {
  const lines = text.split(/\r?\n/);
  if (from < 1 || from > lines.length) return null;
  return lines.slice(from - 1, Math.max(from, Math.min(to, lines.length))).join('\n').replace(/\s+/g, '');
}

/** Line `n` (1-based) of `text`, its line ending removed; null when out of range. */
function lineAt(text: string, n: number): string | null {
  const lines = text.split('\n');
  const line = lines[n - 1];
  return n >= 1 && line !== undefined ? line.replace(/\r$/, '') : null;
}

function hmac(text: string): string {
  return createHmac('sha256', RUN_KEY).update(text).digest('hex');
}

/** One located match of a gitleaks report. */
interface ReportMatch {
  startColumn: number;
  endColumn: number;
  /** The redacted match: the secret replaced by `REDACTED`. */
  match: string;
  /** The secret's Shannon entropy, as gitleaks computed it; undefined when the report has none. */
  entropy?: number;
}

/**
 * Shannon entropy exactly as gitleaks computes it (`detect/utils.go`): per
 * character, divided by the length in BYTES.
 */
function gitleaksEntropy(text: string): number {
  if (text === '') return 0;
  const counts = new Map<string, number>();
  for (const ch of text) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  const inv = 1 / Buffer.byteLength(text, 'utf8');
  let entropy = 0;
  for (const count of counts.values()) {
    const freq = count * inv;
    entropy -= freq * Math.log2(freq);
  }
  return entropy;
}

/**
 * The secret a report match locates on `line`, or null when it is not one
 * cut (see the module comment). The match is tried where `StartColumn` says
 * and one byte earlier; a cut must read as the redacted match around a
 * secret, with the reported entropy. When both do \u2014 a secret whose last
 * character occurs once in it reads with the entropy of the same secret one
 * byte to the left, its opening quote in place of that character \u2014 gitleaks'
 * own rule decides: `firstOfFragment` (the line was the first of what
 * gitleaks scanned as one piece) is where `StartColumn` is exact, and every
 * other line is one column late. Unknown (undefined): no cut.
 */
export function secretFromLine(line: string, m: ReportMatch, firstOfFragment?: boolean): string | null {
  const parts = m.match.split('REDACTED');
  if (parts.length !== 2) return null;
  const [before = '', after = ''] = parts;
  const bytes = Buffer.from(line, 'utf8');
  const length = m.endColumn - m.startColumn + 1;
  if (!Number.isInteger(length) || length <= before.length + after.length) return null;
  const cut = (start: number): string | null => {
    if (start < 0 || start + length > bytes.length) return null;
    const text = bytes.subarray(start, start + length).toString('utf8');
    if (text.includes('\uFFFD') || !text.startsWith(before) || !text.endsWith(after)) return null;
    const secret = text.slice(before.length, text.length - after.length);
    if (secret === '' || `${before}${'REDACTED'}${after}` !== m.match) return null;
    if (m.entropy !== undefined && Math.abs(Math.fround(gitleaksEntropy(secret)) - m.entropy) > 1e-4) return null;
    return secret;
  };
  const exact = cut(m.startColumn - 1);
  const late = cut(m.startColumn - 2);
  if (exact === null || late === null) return exact ?? late;
  if (exact === late) return exact;
  return firstOfFragment === undefined ? null : firstOfFragment ? exact : late;
}

/** `rule`, commit ('' for none), lines and project-relative path: how a report entry finds its finding. */
function locationKey(rule: string, commit: string, start: number, end: number, path: string): string {
  return JSON.stringify([rule, commit.toLowerCase(), start, end, path.split('\\').join('/')]);
}

/** Every single-line match the gitleaks reports in `reportDirs` hold, by {@link locationKey}. */
function readReportMatches(reportDirs: readonly string[], prefix: string): Map<string, ReportMatch[]> {
  const out = new Map<string, ReportMatch[]>();
  for (const dir of new Set(reportDirs)) {
    for (const name of REPORT_FILES) {
      const text = readSmallTextFile(join(dir, name), MAX_REPORT_BYTES);
      if (text === undefined) continue;
      const parsed = parseJsonBounded(text);
      if (!parsed.ok || !Array.isArray(parsed.value)) continue;
      for (const item of parsed.value as unknown[]) {
        if (item === null || typeof item !== 'object') continue;
        const e = item as Record<string, unknown>;
        const { RuleID: rule, File: file, StartLine: start, EndLine: end, StartColumn: sc, EndColumn: ec, Match: match } = e;
        if (typeof rule !== 'string' || typeof file !== 'string' || typeof match !== 'string') continue;
        if (typeof start !== 'number' || typeof end !== 'number' || typeof sc !== 'number' || typeof ec !== 'number') continue;
        if (start !== end) continue; // a match over several lines is read as its lines
        const commit = typeof e['Commit'] === 'string' ? e['Commit'] : '';
        let path = file.split('\\').join('/');
        while (path.startsWith('./')) path = path.slice(2);
        // A history report's paths are the repository's; the findings are the project's.
        if (commit !== '' && prefix !== '') {
          if (!path.startsWith(prefix)) continue;
          path = path.slice(prefix.length);
        }
        const key = locationKey(rule, commit, start, end, path);
        const entropy = typeof e['Entropy'] === 'number' ? e['Entropy'] : undefined;
        const list = out.get(key) ?? [];
        list.push({ startColumn: sc, endColumn: ec, match, ...(entropy !== undefined ? { entropy } : {}) });
        out.set(key, list);
      }
    }
  }
  return out;
}

/**
 * The first added line of each hunk of a `-U0` patch, per file it adds to
 * (the `+++ b/<path>` side; a rename is its new path). A path git had to
 * quote (a tab, a newline, a quote in it) is skipped: its hunks are unknown.
 */
export function hunkStartsByPath(patch: string): Map<string, Set<number>> {
  const out = new Map<string, Set<number>>();
  let current: Set<number> | null = null;
  for (const line of patch.split('\n')) {
    if (line.startsWith('+++ ')) {
      // git appends a tab to a name holding a space (for patch(1)).
      const name = line.slice(4).replace(/\t$/, '').replace(/\r$/, '');
      current = null;
      if (name.startsWith('b/')) {
        const path = name.slice(2);
        current = out.get(path) ?? new Set<number>();
        out.set(path, current);
      }
      continue;
    }
    if (line.startsWith('diff ')) current = null;
    const m = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/.exec(line);
    if (m !== null && current !== null && m[2] !== '0') current.add(Number(m[1]));
  }
  return out;
}

/** The committer time (ms) of each commit git knows, of `commits`. */
async function commitTimes(projectPath: string, commits: readonly string[]): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  for (let i = 0; i < commits.length; i += COMMIT_BATCH) {
    const batch = commits.slice(i, i + COMMIT_BATCH);
    const r = await git(projectPath, ['show', '-s', '--no-notes', '--format=%H %ct', ...batch.map((c) => `${c}^{commit}`), '--']);
    // A commit git does not know fails the batch: ask for each alone.
    if (r.exitCode !== 0) {
      if (batch.length === 1) continue;
      for (const one of batch) {
        const single = await git(projectPath, ['show', '-s', '--no-notes', '--format=%H %ct', `${one}^{commit}`, '--']);
        if (single.exitCode === 0) parseTimes(single.stdout, out);
      }
      continue;
    }
    parseTimes(r.stdout, out);
  }
  return out;
}

function parseTimes(stdout: string, out: Map<string, number>): void {
  for (const line of stdout.split(/\r?\n/)) {
    const m = /^([0-9a-f]{7,64}) (\d+)$/i.exec(line.trim());
    if (m?.[1] !== undefined && m[2] !== undefined) out.set(m[1].toLowerCase(), Number(m[2]) * 1000);
  }
}

/**
 * Read and remember the value, and when it came in, of every gitleaks
 * finding of `findings` (the gate's set, `projectPath` the scanned project).
 * `reportDirs`: where the run's gitleaks reports are, for their columns
 * (without them, every value is its lines). Never throws: what it cannot read
 * is left unknown.
 */
export async function rememberSecretValues(
  projectPath: string,
  findings: readonly Finding[],
  opts: { reportDirs?: readonly string[] } = {},
): Promise<void> {
  const leaks = findings.filter((f) => f.tool.toLowerCase() === 'gitleaks');
  if (leaks.length === 0) return;
  let prefix = '';
  if ((opts.reportDirs ?? []).length > 0) {
    const r = await git(projectPath, ['rev-parse', '--show-prefix']);
    prefix = r.exitCode === 0 ? r.stdout.trim() : '';
  }
  const matches = readReportMatches(opts.reportDirs ?? [], prefix);

  const blobs = new Map<string, Promise<string | null>>();
  const blob = (commit: string, path: string): Promise<string | null> => {
    const key = `${commit}\n${path}`;
    let text = blobs.get(key);
    if (text === undefined) {
      if (blobs.size >= MAX_BLOBS) return Promise.resolve(null);
      text = git(projectPath, ['cat-file', 'blob', `${commit}:./${path}`]).then((r) =>
        r.exitCode === 0 && r.stdout.length <= MAX_BLOB_BYTES ? r.stdout : null,
      );
      blobs.set(key, text);
    }
    return text;
  };
  const tree = new Map<string, string | null>();
  const working = (path: string): string | null => {
    if (!tree.has(path)) {
      const r = readProjectText(projectPath, path, MAX_BLOB_BYTES);
      tree.set(path, r.status === 'ok' ? r.text : null);
    }
    return tree.get(path) ?? null;
  };

  // The lines that began a piece gitleaks scanned: in history, the first added
  // line of each hunk of `git log -p -U0` (what gitleaks reads); in a file,
  // its first line. Where StartColumn is exact (see `secretFromLine`).
  // One `git show -M` of the whole commit, no pathspec: a pathspec turns a
  // rename into a whole new file, every line its own first — so a renamed
  // file with an edit on a baselined secret's line was cut one column off and
  // read as a new secret (review 12, finding 12).
  const hunks = new Map<string, Promise<Map<string, Set<number>> | null>>();
  const hunkStarts = async (commit: string, path: string): Promise<Set<number> | null> => {
    let byPath = hunks.get(commit);
    if (byPath === undefined) {
      if (hunks.size >= MAX_BLOBS) return null;
      byPath = git(projectPath, [
        '-c',
        'core.quotePath=false',
        'show',
        '--format=',
        '--no-color',
        '--no-ext-diff',
        '-M',
        '-U0',
        '--relative',
        commit,
      ]).then((r) => (r.exitCode === 0 ? hunkStartsByPath(r.stdout) : null));
      hunks.set(commit, byPath);
    }
    return (await byPath)?.get(path) ?? null;
  };

  const commits = [...new Set(leaks.map((f) => commitOf(f.snippet)).filter((c): c is string => c !== null))];
  const times = await commitTimes(projectPath, commits);

  for (const f of leaks) {
    attempted.add(f);
    const commit = commitOf(f.snippet);
    if (commit === null) introduced.set(f, Number.POSITIVE_INFINITY);
    else {
      const at = times.get(commit.toLowerCase()) ?? [...times].find(([sha]) => sha.startsWith(commit.toLowerCase()))?.[1];
      if (at !== undefined) introduced.set(f, at);
    }
    if (f.line_start === undefined) continue;
    const path = (f.file_path ?? '').split('\\').join('/');
    if (path === '' || isAbsolute(path) || path === '..' || path.startsWith('../')) continue;
    try {
      const text = commit !== null ? await blob(commit, path) : working(path);
      if (text === null) continue;
      const end = f.line_end ?? f.line_start;
      const located = matches.get(locationKey(f.rule_id ?? '', commit ?? '', f.line_start, end, path)) ?? [];
      const line = end === f.line_start ? lineAt(text, f.line_start) : null;
      let first: boolean | undefined;
      if (located.length > 0 && line !== null) {
        if (commit === null) first = f.line_start === 1;
        else first = (await hunkStarts(commit, path))?.has(f.line_start);
      }
      const secrets = line === null ? [] : located.map((m) => secretFromLine(line, m, first));
      if (located.length > 0 && secrets.every((s): s is string => s !== null)) {
        // The secret(s) themselves: a comment on the line, or a move, is the same value.
        values.set(f, hmac(`secret\n${[...new Set(secrets)].sort().join('\n')}`));
        continue;
      }
      const lines = linesOf(text, f.line_start, end);
      if (lines !== null) values.set(f, hmac(`lines\n${lines}`));
    } catch {
      /* unknown — that finding matches by its exact identity only */
    }
  }
}
