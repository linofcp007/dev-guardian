/**
 * The one place a raw secret value is read from disk — for
 * `scan_secrets verify_live`, and only there.
 *
 * Every other gitleaks run in this codebase uses `--redact`, and the parser
 * strips `Match`/`Secret` besides. Verification needs the value itself, so a
 * verifying run omits `--redact` — but ONLY into a report file inside a
 * private directory made for that one scan:
 *
 *   - `mkdtemp` under the OS temp directory; on POSIX the directory is 0700
 *     and each report file is created 0600 BEFORE gitleaks writes it (gitleaks
 *     truncates an existing file and keeps its mode). On Windows the
 *     per-user temp directory (`%LOCALAPPDATA%\Temp`) is the protection: its
 *     ACL admits only the user, SYSTEM and Administrators, and POSIX mode
 *     bits mean nothing there.
 *   - Each raw report is read once, by {@link sanitizeGitleaksReport}, and
 *     deleted straight after; the directory is removed when the scan's
 *     gitleaks passes are done (`runners/gitleaksScan.ts`, in `finally`).
 *     A directory a killed process left behind is swept by the next one
 *     ({@link sweepStaleReportDirs}).
 *   - What the rest of the scan sees — the parser input, the report kept
 *     under `.guardian/reports` — is the sanitized text: each value replaced
 *     by `REDACTED` in the fields that CARRY values, as `--redact` does, and
 *     every other field byte-identical. Only the values of rules
 *     `verify_live` can check survive, in memory, aligned with the report's
 *     items.
 *
 * ---- Which fields, and against which values ------------------------------
 *
 * gitleaks' own `Finding.Redact` rewrites `Line` (never serialized), `Match`
 * and `Secret`, each with that finding's OWN value. The locator fields —
 * `RuleID`, `Description`, `File`, `SymlinkFile`, `Commit`, `Fingerprint`,
 * the positions, `Author`/`Email`/`Date` — are never touched: they are what
 * the finding's path, fingerprint and identity are made of. The first
 * version scrubbed every string of every item against every value, which was
 * both quadratic (6000 items: 66 s, with the MCP server frozen) and wrong: a
 * custom rule reporting `Secret: "test"` turned `test/fixtures/fake.env` into
 * `REDACTED/fixtures/fake.env`, moving the finding and slipping it past
 * `.guardianignore`.
 *
 * So, per item:
 *
 *   - `Secret` → `REDACTED`.
 *   - `Match` → its own value, and the value of every finding whose span
 *     overlaps it, directly or through a chain of overlapping spans (same
 *     file and commit) → `REDACTED`. Another finding's value can only be
 *     inside a match that overlaps it. A sort + sweep merges the spans into
 *     runs that overlap, and each match is scrubbed of its run's values in
 *     ONE pass over it (`makeScrubber`): scrubbed value by value, 4000
 *     findings overlapping one region took 5.9 s — the count squared.
 *     Overlapping occurrences of two values become one `REDACTED`, so no
 *     fragment of either survives. A match whose group has an item with no
 *     position cannot be placed and is withheld whole, as is the match of an
 *     item with no value.
 *   - `Message` (the commit message, which gitleaks does not redact) and
 *     `Tags` → the values found in that commit / that item → `REDACTED`.
 *   - `Line` and `Fragment`, should a gitleaks version serialize them (the
 *     whole source line / file) → withheld whole.
 */

import { chmodSync, closeSync, lstatSync, mkdtempSync, openSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/** What gitleaks `--redact` writes in place of a value. */
export const REDACTED = 'REDACTED';

/** A `guardian-verify-*` directory untouched this long belongs to a scan that died. */
export const STALE_AFTER_MS = 6 * 60 * 60 * 1000;

const PREFIX = 'guardian-verify-';
const POSIX = process.platform !== 'win32';

export interface PrivateReportDir {
  dir: string;
  /** A fresh, empty, owner-only report file in the directory; its path. */
  pathFor(name: string): string;
  /** Removes the directory and all it holds; the error code when that failed, else null. */
  remove(): string | null;
}

/** See the module comment. Throws when no private directory can be made — the caller then does not capture. */
export function openPrivateReportDir(): PrivateReportDir {
  sweepStaleReportDirs();
  const dir = mkdtempSync(join(tmpdir(), PREFIX));
  // mkdtemp already creates 0700 on POSIX; stated, not assumed.
  if (POSIX) chmodSync(dir, 0o700);
  return {
    dir,
    pathFor(name: string): string {
      const path = join(dir, name);
      closeSync(openSync(path, 'w', 0o600));
      if (POSIX) chmodSync(path, 0o600);
      return path;
    },
    remove(): string | null {
      try {
        rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
        return null;
      } catch (e) {
        const code = typeof e === 'object' && e !== null ? (e as { code?: unknown }).code : undefined;
        return typeof code === 'string' ? code : 'unknown error';
      }
    },
  };
}

/**
 * Remove the `guardian-verify-*` directories a killed scan left in `root`: a
 * real directory (never a symlink or junction), owned by this user on POSIX,
 * untouched for {@link STALE_AFTER_MS}. Never throws; returns how many went.
 */
export function sweepStaleReportDirs(root: string = tmpdir(), now: number = Date.now()): number {
  let names: string[];
  try {
    names = readdirSync(root);
  } catch {
    return 0;
  }
  const uid = POSIX && typeof process.getuid === 'function' ? process.getuid() : null;
  let removed = 0;
  for (const name of names) {
    if (!name.startsWith(PREFIX)) continue;
    try {
      const path = join(root, name);
      const st = lstatSync(path);
      if (st.isSymbolicLink() || !st.isDirectory()) continue;
      if (uid !== null && st.uid !== uid) continue;
      if (now - st.mtimeMs < STALE_AFTER_MS) continue;
      rmSync(path, { recursive: true, force: true });
      removed += 1;
    } catch {
      // Someone else's, in use, or gone already: not this sweep's business.
    }
  }
  return removed;
}

export interface SanitizedReport {
  /** The report as `--redact` would have written it. */
  text: string;
  /** Per report item, the raw value when its rule is one `keep` accepts, else null. */
  secrets: Array<string | null>;
}

/** A finding's span, widened by a column each way against off-by-one positions. */
interface Span {
  startLine: number;
  startCol: number;
  endLine: number;
  endCol: number;
}

/**
 * Split an unredacted gitleaks report into its sanitized text and the raw
 * values of the rules `keep` accepts — see the module comment for what is
 * redacted where. Null when the text is not a JSON array: it is then never
 * passed on or written anywhere, since it may hold raw values in a shape this
 * cannot clean.
 */
export function sanitizeGitleaksReport(text: string, keep: (ruleId: string) => boolean): SanitizedReport | null {
  let root: unknown;
  try {
    root = JSON.parse(text);
  } catch {
    return null;
  }
  if (!Array.isArray(root)) return null;
  const items: unknown[] = root;

  const own = items.map((item) => {
    const s = stringField(item, 'Secret');
    return s !== null && s.length > 0 ? s : null;
  });
  const secrets = items.map((item, n) => {
    const rule = stringField(item, 'RuleID');
    return rule !== null && keep(rule) ? (own[n] ?? null) : null;
  });

  // Runs of overlapping matches, per file and commit: one scrubber per run.
  const scrubberOf: Array<((text: string) => string) | null> = items.map(() => null);
  const groups = new Map<string, number[]>();
  const unplaceable = new Set<string>();
  items.forEach((item, n) => {
    const key = `${stringField(item, 'File') ?? ''}\u0000${stringField(item, 'Commit') ?? ''}`;
    if (spanOf(item) === null) {
      unplaceable.add(key);
      return;
    }
    const list = groups.get(key);
    if (list === undefined) groups.set(key, [n]);
    else list.push(n);
  });
  for (const members of groups.values()) {
    const placed = members.flatMap((n) => {
      const span = spanOf(items[n]);
      return span === null ? [] : [{ n, span }];
    });
    placed.sort((a, b) => a.span.startLine - b.span.startLine || a.span.startCol - b.span.startCol);
    let run: number[] = [];
    let runEnd: Span | null = null;
    const closeRun = (): void => {
      const scrub = makeScrubber(run.flatMap((n) => own[n] ?? []));
      for (const n of run) scrubberOf[n] = scrub;
      run = [];
    };
    for (const current of placed) {
      if (runEnd !== null && endsBefore(runEnd, current.span)) closeRun();
      if (run.length === 0 || runEnd === null || endsLater(current.span, runEnd)) runEnd = current.span;
      run.push(current.n);
    }
    closeRun();
  }

  // The values of each commit, for its message.
  const byCommit = new Map<string, Set<string>>();
  items.forEach((item, n) => {
    const value = own[n];
    if (value == null) return;
    const commit = stringField(item, 'Commit') ?? '';
    const set = byCommit.get(commit);
    if (set === undefined) byCommit.set(commit, new Set([value]));
    else set.add(value);
  });
  const messageCache = new Map<string, string>();
  const cleanMessage = (commit: string, message: string): string => {
    const cacheKey = `${commit}\u0000${message}`;
    const cached = messageCache.get(cacheKey);
    if (cached !== undefined) return cached;
    const found = [...(byCommit.get(commit) ?? [])].filter((v) => message.includes(v));
    const clean = replaceAll(message, found);
    messageCache.set(cacheKey, clean);
    return clean;
  };

  const clean = items.map((item, n) => {
    if (!isRecord(item)) return item;
    const c: Record<string, unknown> = { ...item };
    const value = own[n] ?? null;
    const key = `${stringField(item, 'File') ?? ''}\u0000${stringField(item, 'Commit') ?? ''}`;
    if ('Secret' in c) c['Secret'] = REDACTED;
    if (typeof c['Match'] === 'string') {
      const scrub = scrubberOf[n] ?? null;
      c['Match'] =
        value === null || unplaceable.has(key) || spanOf(item) === null || scrub === null
          ? REDACTED
          : scrub(c['Match']);
    }
    if (typeof c['Message'] === 'string' && c['Message'].length > 0) {
      c['Message'] = cleanMessage(stringField(item, 'Commit') ?? '', c['Message']);
    }
    if (Array.isArray(c['Tags']) && value !== null) {
      c['Tags'] = c['Tags'].map((t: unknown) => (typeof t === 'string' ? replaceAll(t, [value]) : t));
    }
    if ('Line' in c) c['Line'] = REDACTED;
    if ('Fragment' in c) c['Fragment'] = REDACTED;
    return c;
  });
  return { text: JSON.stringify(clean), secrets };
}

/** Every occurrence of every needle → `REDACTED`, longest needle first. */
function replaceAll(text: string, needles: Iterable<string>): string {
  const sorted = [...new Set(needles)].filter((n) => n.length > 0).sort((a, b) => b.length - a.length);
  let out = text;
  for (const n of sorted) if (out.includes(n)) out = out.split(n).join(REDACTED);
  return out;
}

/** One UTF-16 code unit per trie edge: an edge's key is `node * EDGE + unit`. */
const EDGE = 0x10000;

/**
 * A function that replaces every occurrence of any of `values` in a text by
 * `REDACTED`, in one pass over the text however many values there are
 * (Aho-Corasick over UTF-16 code units — the units `includes` compares). At
 * each position the longest value ending there marks its span; spans that
 * overlap merge into one `REDACTED`, so no fragment of any value survives,
 * and spans that merely touch stay apart, as a value repeated back to back
 * always did. Building costs about the values' total length.
 */
function makeScrubber(values: readonly string[]): (text: string) => string {
  const at = (a: readonly number[], i: number): number => a[i] ?? 0;
  const edges = new Map<number, number>();
  const parent = [0];
  const unit = [0];
  const depth = [0];
  /** The length of the longest value that is a suffix of the node's string; 0 for none. */
  const longest = [0];
  for (const v of values) {
    let node = 0;
    for (let i = 0; i < v.length; i++) {
      const c = v.charCodeAt(i);
      let child = edges.get(node * EDGE + c);
      if (child === undefined) {
        child = parent.length;
        edges.set(node * EDGE + c, child);
        parent.push(node);
        unit.push(c);
        depth.push(i + 1);
        longest.push(0);
      }
      node = child;
    }
    if (node !== 0) longest[node] = v.length;
  }
  if (parent.length === 1) return (text) => text;

  // Failure links, shallowest node first: each one's parent and every
  // shorter suffix are settled before it.
  const fail = parent.map(() => 0);
  const order = parent.map((_, n) => n).sort((a, b) => at(depth, a) - at(depth, b));
  for (const v of order) {
    const p = at(parent, v);
    if (v === 0 || p === 0) continue;
    const c = at(unit, v);
    let f = at(fail, p);
    while (f !== 0 && !edges.has(f * EDGE + c)) f = at(fail, f);
    const target = edges.get(f * EDGE + c) ?? 0;
    fail[v] = target;
    if (at(longest, v) === 0) longest[v] = at(longest, target);
  }

  return (text) => {
    const spans: Array<{ start: number; end: number }> = [];
    let node = 0;
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);
      let next = edges.get(node * EDGE + c);
      while (next === undefined && node !== 0) {
        node = at(fail, node);
        next = edges.get(node * EDGE + c);
      }
      node = next ?? 0;
      const length = at(longest, node);
      if (length === 0) continue;
      let start = i + 1 - length;
      for (let last = spans.at(-1); last !== undefined && last.end > start; last = spans.at(-1)) {
        start = Math.min(start, last.start);
        spans.pop();
      }
      spans.push({ start, end: i + 1 });
    }
    if (spans.length === 0) return text;
    let out = '';
    let pos = 0;
    for (const s of spans) {
      out += text.slice(pos, s.start) + REDACTED;
      pos = s.end;
    }
    return out + text.slice(pos);
  };
}

function spanOf(item: unknown): Span | null {
  const startLine = numberField(item, 'StartLine');
  const endLine = numberField(item, 'EndLine');
  const startCol = numberField(item, 'StartColumn');
  const endCol = numberField(item, 'EndColumn');
  if (startLine === null || endLine === null || startCol === null || endCol === null) return null;
  return { startLine, startCol: startCol - 1, endLine, endCol: endCol + 1 };
}

/** `a` ends strictly before `b` starts. */
function endsBefore(a: Span, b: Span): boolean {
  return a.endLine < b.startLine || (a.endLine === b.startLine && a.endCol < b.startCol);
}

/** `a` ends strictly after `b` ends. */
function endsLater(a: Span, b: Span): boolean {
  return a.endLine > b.endLine || (a.endLine === b.endLine && a.endCol > b.endCol);
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function stringField(v: unknown, key: string): string | null {
  if (!isRecord(v)) return null;
  const x = v[key];
  return typeof x === 'string' ? x : null;
}

function numberField(v: unknown, key: string): number | null {
  if (!isRecord(v)) return null;
  const x = v[key];
  return typeof x === 'number' && Number.isFinite(x) ? x : null;
}
