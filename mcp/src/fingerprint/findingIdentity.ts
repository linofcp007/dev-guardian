/**
 * Line-independent finding identity.
 *
 * `fingerprint` (`./findingFingerprint.ts`) hashes `line_start`/`line_end`
 * and the snippet, so inserting ONE line above a finding made it a different
 * finding to everything that compares findings across scans. Each of these
 * was reproduced: a suppression lapsed and the finding came back as open; the
 * CI gate reported it as new; `diff_scans` and `regression_alert` saw one new
 * plus one resolved; and `create_fix_pr` judged an UNFIXED target "resolved"
 * because the autofix above it had moved it down a line. Trivy's snippet also
 * carries the fixed version, so the advisory database learning about a fix
 * did the same to a dependency finding. `dast/analyze.ts` had already
 * documented and avoided this for its own findings.
 *
 * `identity` is what those comparisons key on now:
 *
 *     sha256(tool | rule_id | normalised relative path | contentKey | occurrence)
 *
 *   - **contentKey** is a hash of WHAT the finding flags, never of where:
 *       - a dependency finding: `package@installed_version` — never the fixed
 *         version (see {@link dependencyCoordinates});
 *       - a finding on source lines: those lines' text, whitespace-collapsed
 *         (so re-indenting or a CRLF checkout changes nothing), read from the
 *         file on disk;
 *       - otherwise the scanner's snippet, whitespace-collapsed — which is
 *         also what a finding with no file keys on, together with its target
 *         (`file_path` holds the image or lockfile Trivy names);
 *       - nothing at all when none of those exists.
 *   - **occurrence** tells apart findings that agree on everything else — the
 *     same rule on two identical lines of one file — by their order in the
 *     file. Moving both down keeps both identities.
 *
 * **Why the lines are read from disk even when there IS a snippet.** The
 * snippet is not reliably the source text of the lines. Semgrep ≥ ~1.120
 * without `semgrep login` reports the literal string "requires login"; Bandit's
 * `code` prefixes every line with its line number (so a one-line shift changes
 * it — the very bug); Trivy's misconfiguration snippet is the rule's
 * Resolution text; and every snippet is clamped to 1 KB, so a long match
 * hashed from the snippet on one machine and from the file on another would
 * disagree. The file is the one source that is the same for every scanner and
 * every machine, so it wins, and the snippet is the fallback for a file that
 * cannot be read (with Bandit's and gosec's line numbers stripped from it, and never the
 * "requires login" placeholder). The one exception is a gitleaks finding that names a
 * commit: its lines live in history, not in the working tree (which may hold
 * anything at that line number today), and `rule=…;commit=…` is already a
 * stable, line-independent locator.
 *
 * **Secrets are never keyed on their line — not even hashed.** The identity
 * is committed to `.guardian/baseline.json`, and a fast unsalted hash of a
 * line such as `DB_PASSWORD=<value>` is an offline oracle: guess a
 * low-entropy value, hash, compare. So a credential finding
 * ({@link isCredentialFinding}: `subcategory: 'secret'`, or a rule/subcategory
 * that names a password, secret, credential or key) has its content keyed on
 * `secret` + its rule id, plus gitleaks' commit locator when it has one —
 * nothing derived from the value, so rotating the secret in place keeps the
 * identity, and the occurrence alone keeps two secrets of one rule in one
 * file apart — with their count, so a secret added above another never takes
 * its identity, and a suppression with it ({@link sharedSecretCount}). For every other finding, the text read from disk is hashed and
 * dropped: never written to the finding, the database or a response.
 *
 * `fingerprint` is untouched and stays each row's per-scan key. Everything
 * that matches across scans uses the identity first and falls back to the
 * fingerprint where either side predates it ({@link indexFindings}), which is
 * how a 2.0.x suppression or `baseline.json` keeps working.
 */

import { createHash } from 'node:crypto';
import { realpathSync } from 'node:fs';
import { readProjectBytes } from '../platform/projectFs.js';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { normalizePathPosix } from './findingFingerprint.js';

/** What modern Semgrep puts in `extra.lines` without `semgrep login`. */
export const REDACTED_SNIPPET = 'requires login';

/**
 * Part of every identity's hash. Changing the recipe changes every identity
 * ever stored, so it is versioned rather than silently different.
 */
const IDENTITY_VERSION = 1;

/** A file bigger than this is not read for its lines; the snippet stands in. */
const MAX_SOURCE_BYTES = 8 * 1024 * 1024;

/** Reads a finding's file (a path relative to the project) or returns null. */
type SourceReader = (filePath: string) => string | null;

/** The fields identity reads — structural, so any finding-shaped value works. */
export interface IdentitySubject {
  tool: string;
  rule_id?: string;
  subcategory?: string;
  file_path?: string;
  line_start?: number;
  line_end?: number;
  snippet?: string;
}

interface AssignIdentityOptions {
  /** Canonical project root: absolute paths inside it are made relative. */
  projectPath?: string;
  /** Where source lines come from. Without one, only snippets are used. */
  readSource?: SourceReader;
}

/**
 * Every finding of ONE scan, with `identity` and `content_key` set. The
 * occurrence is counted within the batch, so the batch must be the whole scan
 * — the scan-tool factory calls this once, after every parser and the
 * cross-parser dedupe have run.
 *
 * A fingerprint that repeats in the batch is one finding (the database keeps
 * one row per fingerprint and scan): every copy gets the first copy's
 * identity and none of them advances the occurrence.
 *
 * Content is computed file by file (findings sorted by path), holding one
 * file's lines at a time: a scan with thousands of findings across thousands
 * of files reads each file once and never holds more than one in memory.
 */
export function assignIdentities<T extends IdentitySubject & { fingerprint: string }>(
  findings: readonly T[],
  opts: AssignIdentityOptions = {},
): Array<T & { identity: string; content_key: string }> {
  const located = findings.map((finding, index) => ({
    finding,
    index,
    location: locate(finding.file_path, opts.projectPath),
  }));

  const contentKeys = new Map<number, string>();
  let currentPath: string | null = null;
  let currentLines: string[] | null = null;
  const linesOf = (readable: string): string[] | null => {
    if (readable !== currentPath) {
      currentPath = readable;
      const text = opts.readSource === undefined ? null : opts.readSource(readable);
      currentLines = text === null ? null : text.split(/\r\n|\r|\n/);
    }
    return currentLines;
  };
  const byPath = [...located].sort((a, b) =>
    compareStrings(a.location.readable ?? '', b.location.readable ?? ''),
  );
  for (const { finding, index, location } of byPath) {
    contentKeys.set(index, sha256(contentSource(finding, location.readable, linesOf)));
  }

  const keyed = located.map(({ finding, index, location }) => ({
    finding,
    index,
    tool: finding.tool.toLowerCase(),
    rule: finding.rule_id ?? '',
    path: location.key,
    contentKey: contentKeys.get(index) ?? sha256('none'),
  }));
  const identities = identitiesOf(keyed);

  return keyed.map((k) => ({
    ...k.finding,
    identity: identities.get(k.index) ?? '',
    content_key: k.contentKey,
  }));
}

/**
 * The identity recipe for findings whose content key is already known —
 * {@link assignIdentities}' second half, shared with {@link rekeyStoredIdentities}
 * so a re-keyed stored row gets exactly the identity a fresh scan would.
 */
function identitiesOf<T extends IdentitySubject & { fingerprint: string }>(
  keyed: ReadonlyArray<{ finding: T; index: number; tool: string; rule: string; path: string; contentKey: string }>,
): Map<number, string> {
  const groups = new Map<string, Array<(typeof keyed)[number]>>();
  for (const k of keyed) {
    const group = JSON.stringify([k.tool, k.rule, k.path, k.contentKey]);
    const members = groups.get(group);
    if (members === undefined) groups.set(group, [k]);
    else members.push(k);
  }

  // Order within a group: by position, then — for two findings on the same
  // line range — by their snippet, which moves with them. Not by fingerprint
  // first: it hashes the line number, so on a shift two such findings could
  // swap order and with it identities. The fingerprint only breaks ties
  // between findings whose snippet is equal too (then it rarely differs).
  const snippetOrder = (f: IdentitySubject): string => sha256(f.snippet ?? '');
  const identities = new Map<number, string>();
  for (const members of groups.values()) {
    members.sort(
      (a, b) =>
        (a.finding.line_start ?? 0) - (b.finding.line_start ?? 0) ||
        (a.finding.line_end ?? 0) - (b.finding.line_end ?? 0) ||
        compareStrings(snippetOrder(a.finding), snippetOrder(b.finding)) ||
        compareStrings(a.finding.fingerprint, b.finding.fingerprint) ||
        a.index - b.index,
    );
    const byFingerprint = new Map<string, string>();
    const together = sharedSecretCount(members.map((m) => m.finding));
    let occurrence = 0;
    for (const m of members) {
      let identity = byFingerprint.get(m.finding.fingerprint);
      if (identity === undefined) {
        const recipe: unknown[] = [IDENTITY_VERSION, m.tool, m.rule, m.path, m.contentKey, occurrence];
        if (together !== null) recipe.push({ secrets: together });
        identity = sha256(JSON.stringify(recipe));
        occurrence += 1;
        byFingerprint.set(m.finding.fingerprint, identity);
      }
      identities.set(m.index, identity);
    }
  }
  return identities;
}

/**
 * How many secrets one (tool, rule, path) credential group holds, when that
 * is more than one and the group can still grow; else null, and the identity
 * is the plain recipe.
 *
 * A credential's identity holds nothing of its value (the module comment),
 * so its occurrence — its place by line — is all that tells two secrets of
 * one rule in one file apart. Counted by line alone, a real key added ABOVE
 * a suppressed fixture key took occurrence 0, the identity the suppression
 * named, and was hidden in its place. With the count in the recipe, adding
 * or removing a secret of the group re-keys every secret in it: a
 * suppression of one of them lapses and it is shown again — the safe
 * direction — and none moves onto the newcomer. A lone secret keeps the plain
 * recipe, and so its identity through a line shift or a rotation in place.
 * A group whose secrets one commit holds (gitleaks' history locator) is
 * fixed for good, nothing can join it, and it keeps the plain recipe too.
 */
function sharedSecretCount(group: ReadonlyArray<IdentitySubject & { fingerprint: string }>): number | null {
  const first = group[0];
  if (first === undefined || !isCredentialFinding(first) || isHistoryLocator(first)) return null;
  // A repeated fingerprint is one finding (see `assignIdentities`).
  const secrets = new Set(group.map((f) => f.fingerprint)).size;
  return secrets > 1 ? secrets : null;
}

/** A stored finding row, as {@link rekeyStoredIdentities} re-keys it. */
interface StoredIdentityRow extends IdentitySubject {
  fingerprint: string;
  content_key?: string;
}

/**
 * Identities for the stored findings of ONE scan, after their `rule_id`
 * changed (`storage/localRuleIds.ts`: a local rule's path prefix removed):
 * the same recipe as {@link assignIdentities}, with each row's stored content
 * key — except a credential finding's, which IS its rule id
 * (`secret\n<rule id>`, see `contentSource`) and is recomputed. A row with
 * no content key (stored before identities existed) gets none. Returns the
 * new identity and content key per row, in input order.
 */
export function rekeyStoredIdentities(
  rows: readonly StoredIdentityRow[],
  projectPath?: string,
): Array<{ identity: string | null; content_key: string | null }> {
  const keyed = rows.flatMap((finding, index) => {
    if (finding.content_key === undefined) return [];
    const contentKey = isCredentialFinding(finding) && finding.tool.toLowerCase() !== 'gitleaks'
      ? sha256(`secret\n${finding.rule_id ?? ''}`)
      : finding.content_key;
    return [{
      finding,
      index,
      tool: finding.tool.toLowerCase(),
      rule: finding.rule_id ?? '',
      path: locate(finding.file_path, projectPath).key,
      contentKey,
    }];
  });
  const identities = identitiesOf(keyed);
  const contentKeys = new Map(keyed.map((k) => [k.index, k.contentKey]));
  return rows.map((_, index) => ({
    identity: identities.get(index) ?? null,
    content_key: contentKeys.get(index) ?? null,
  }));
}

/**
 * A reader confined to one project: a path that resolves outside it — `..`,
 * an absolute path elsewhere, a symlink pointing out — reads as null, as does
 * anything missing, unreadable, not a file or over {@link MAX_SOURCE_BYTES}.
 * No cache: {@link assignIdentities} asks for each file once.
 */
export function makeSourceReader(projectPath: string): SourceReader {
  const root = realOrResolved(projectPath);
  return (filePath: string): string | null => {
    // `platform/projectFs.ts` judges containment and the file on the opened
    // descriptor — a `stat` then a read could be handed a different file.
    // Bytes, decoded as `readFileSync(…, 'utf8')` did: a byte-order mark is
    // kept, so no stored identity moves.
    const r = readProjectBytes(root, filePath, MAX_SOURCE_BYTES);
    return r.status === 'ok' ? r.bytes.toString('utf8') : null;
  };
}

/**
 * `package` and installed version of a dependency finding, from the snippet
 * each dependency scanner writes: Trivy `pkg@installed->fixed` (a CVE),
 * npm audit `pkg@range`, WPScan `component:slug@version`. The name is
 * everything before the LAST `@` of the coordinate, which keeps scoped npm
 * names (`@babel/core`) whole. Trivy's `->fixed` is cut off here, and that is
 * the point: the fixed version is a property of the advisory database, not of
 * the project, and it used to change the finding's key when the database
 * learned of a fix. A finding with a line is source code, whatever its
 * snippet looks like.
 */
export function dependencyCoordinates(
  f: Pick<IdentitySubject, 'tool' | 'subcategory' | 'snippet' | 'line_start'>,
): { name: string; version: string } | null {
  if (f.line_start !== undefined || f.snippet === undefined) return null;
  if (f.tool.toLowerCase() === 'wpscan') {
    const prefix = 'component:';
    if (!f.snippet.startsWith(prefix)) return null;
    return splitCoordinate(f.snippet.slice(prefix.length), true);
  }
  if (f.subcategory !== 'cve' && f.subcategory !== 'dependency') return null;
  const arrow = f.snippet.indexOf('->');
  return splitCoordinate(arrow >= 0 ? f.snippet.slice(0, arrow) : f.snippet, false);
}

/**
 * What `create_fix_pr`'s verification asks "is this target still there?" by:
 * a target is resolved only when NO finding of the re-scan has the same key.
 *
 *   - source finding: (tool, rule_id, path, content_key) — the identity minus
 *     its occurrence. With the occurrence, fixing the first of two identical
 *     lines would renumber the second into the first one's identity and call
 *     the fixed one present and the unfixed one gone;
 *   - dependency finding: (rule_id — the CVE or advisory —, package). The
 *     installed version is exactly what an upgrade changes, so an upgrade
 *     that is not enough must still read as present.
 *
 * Null for a source finding stored before identities existed: the caller
 * then falls back to the fingerprint.
 */
export function resolutionKey(f: IdentitySubject & { content_key?: string }): string | null {
  const dependency = dependencyCoordinates(f);
  if (dependency !== null) {
    return JSON.stringify(['dependency', f.rule_id ?? null, dependency.name.toLowerCase()]);
  }
  if (f.content_key === undefined) return null;
  return JSON.stringify([
    'content',
    f.tool.toLowerCase(),
    f.rule_id ?? null,
    locate(f.file_path, undefined).key,
    f.content_key,
  ]);
}

/** Anything a match can be made on. */
interface MatchableFinding {
  fingerprint: string;
  identity?: string;
}

interface FindingIndex<T> {
  /** The indexed item that `f` is — see {@link indexFindings}. */
  find(f: MatchableFinding): T | undefined;
  has(f: MatchableFinding): boolean;
  /**
   * Index `item` too, exactly as if it had been in the list: an index that
   * grows with the list it answers for, instead of one rebuilt per batch.
   */
  add(item: T): void;
}

/**
 * Cross-scan matching: identity first, fingerprint as the fallback.
 *
 * `f` matches an item when their identities are equal, or — only when one of
 * the two has no identity (a row stored before schema 7, a v1 baseline entry,
 * a tool that computes none) — when their fingerprints are equal. Two
 * identities that differ are two findings even if the fingerprints agree:
 * that is the same rule on the same line whose code changed under a redacted
 * snippet, and calling it unchanged would hide the change.
 */
export function indexFindings<T extends MatchableFinding>(items: readonly T[]): FindingIndex<T> {
  const byIdentity = new Map<string, T>();
  const byFingerprint = new Map<string, T[]>();
  const add = (item: T): void => {
    if (item.identity !== undefined && !byIdentity.has(item.identity)) {
      byIdentity.set(item.identity, item);
    }
    const same = byFingerprint.get(item.fingerprint);
    if (same === undefined) byFingerprint.set(item.fingerprint, [item]);
    else same.push(item);
  };
  for (const item of items) add(item);
  const find = (f: MatchableFinding): T | undefined => {
    if (f.identity !== undefined) {
      const hit = byIdentity.get(f.identity);
      if (hit !== undefined) return hit;
    }
    for (const candidate of byFingerprint.get(f.fingerprint) ?? []) {
      if (candidate.identity === undefined || f.identity === undefined) return candidate;
    }
    return undefined;
  };
  return { find, has: (f) => find(f) !== undefined, add };
}

// ------------------------------------------------------------------ the CI gate's keys

/**
 * Part of every match key's hash ({@link gateMatchKeys}); a different recipe
 * gets a new version, never a silently different key.
 */
const MATCH_KEY_VERSION = 1;

/** A finding the CI gate keys: identity's subject, with its stored content key. */
type GateKeySubject = IdentitySubject & { fingerprint: string; content_key?: string };

/** What the CI gate matches one finding to a baseline entry by, besides its identity and fingerprint. */
export interface GateKeys {
  /**
   * The finding's identity as the baseline knew it, when its file was
   * renamed since: the same recipe over the path the baseline recorded.
   * Absent when the file was not renamed, or the finding has no content key.
   */
  renamedIdentity?: string;
  /**
   * The baseline's `match_id` (`ci/baseline.ts`): the identity's recipe, made
   * tolerant of three changes that made the CI gate call a baselined finding
   * new (review 8, findings 4, 5 and 6):
   *
   *   - a dependency finding keyed WITHOUT its installed version — `(CVE,
   *     package, manifest path)`, like {@link resolutionKey}: a partial upgrade
   *     (lodash 4.17.15 → 4.17.19, fixing some CVEs) used to turn the CVEs it
   *     did not fix into new findings, and block the developer who improved
   *     security;
   *   - a gitleaks secret keyed the same way in history and in the working
   *     tree — `(rule, path, occurrence)`, the commit only in the message:
   *     an unrelated uncommitted edit to the file, a squash merge (a new
   *     commit) or a whitespace commit touching the line each made a
   *     baselined secret new. When the run read the secrets' values
   *     (`secretValue`, review 11 finding 2), the occurrence is the secret's
   *     place among the file's distinct values of that rule, in the order
   *     they were introduced — by commit, then line ({@link valueSlots}) —
   *     so every commit and pass that saw one value shares its key, and a
   *     secret added above a baselined one, in a later commit, takes a new
   *     occurrence instead of the baselined one's. Without values (a caller
   *     that read none): counted per pass (history, files) by line, a secret
   *     found twice on one line of history once — the 3.3.0 rule;
   *   - the path as the baseline recorded it, when the file was renamed
   *     since (`renamedFrom`, from `git diff -M`: `ci/renames.ts`).
   *
   * Absent when the finding has no content key (a row from before
   * identities) and is not a dependency finding.
   */
  matchKey?: string;
}

/**
 * {@link GateKeys} for every finding of `findings` (in input order) — the
 * whole set the gate judges, since occurrences are counted within it.
 */
export function gateMatchKeys(
  findings: readonly GateKeySubject[],
  opts: {
    renamedFrom?: ReadonlyMap<string, string>;
    /**
     * A gitleaks finding's secret as a per-run HMAC, or undefined when it
     * could not be read (`ci/secretValues.ts`). Absent: values are not
     * compared, and a slot is keyed whatever it holds (the pre-3.4 rule).
     */
    secretValue?: (finding: GateKeySubject) => string | undefined;
    /**
     * When a gitleaks finding's secret was introduced: its commit's time in
     * ms, `Infinity` for one no commit holds (the working tree), undefined
     * when not known (`ci/secretValues.ts#secretIntroducedAt`). Orders the
     * values of a file for their occurrences; without it, by line alone.
     */
    introducedAt?: (finding: GateKeySubject) => number | undefined;
  } = {},
): GateKeys[] {
  const renamed = opts.renamedFrom ?? new Map<string, string>();
  const out: GateKeys[] = findings.map(() => ({}));
  const byValue = opts.secretValue;

  // The identity as the baseline knew it: the stored recipe over the old path.
  const moved = findings.flatMap((finding, index) => {
    const path = locate(finding.file_path, undefined).key;
    const from = renamed.get(path);
    if (from === undefined || finding.content_key === undefined) return [];
    return [{ finding, index, tool: finding.tool.toLowerCase(), rule: finding.rule_id ?? '', path: from, contentKey: finding.content_key }];
  });
  for (const [index, identity] of identitiesOf(moved)) {
    const slot = out[index];
    if (slot !== undefined) slot.renamedIdentity = identity;
  }

  // The match key: grouped by (tool, rule, path, content). A secret whose
  // values were read is keyed by its value's slot (below); everything else
  // by occurrence counted per pass, one line of a secret's history once.
  const valued = new Map<string, Array<{ index: number; finding: GateKeySubject }>>();
  const groups = new Map<string, Array<{ index: number; finding: GateKeySubject; pass: string; head: string }>>();
  findings.forEach((finding, index) => {
    const content = matchContentKey(finding);
    if (content === null) return;
    const current = locate(finding.file_path, undefined).key;
    const path = renamed.get(current) ?? current;
    const head = JSON.stringify([MATCH_KEY_VERSION, finding.tool.toLowerCase(), finding.rule_id ?? '', path, content]);
    if (byValue !== undefined && isGitleaksSecret(finding)) {
      const members = valued.get(head);
      if (members === undefined) valued.set(head, [{ index, finding }]);
      else members.push({ index, finding });
      return;
    }
    const pass = isGitleaksSecret(finding) ? (isHistoryLocator(finding) ? 'history' : 'files') : '';
    const key = `${head}\n${pass}`;
    const members = groups.get(key);
    const member = { index, finding, pass, head };
    if (members === undefined) groups.set(key, [member]);
    else members.push(member);
  });
  // Each (head, occurrence) is one slot — the same secret in every pass that
  // saw it. A slot is keyed only when what its members hold is one value.
  const slots = new Map<string, Array<{ index: number; finding: GateKeySubject }>>();
  for (const members of groups.values()) {
    members.sort(
      (a, b) =>
        (a.finding.line_start ?? 0) - (b.finding.line_start ?? 0) ||
        (a.finding.line_end ?? 0) - (b.finding.line_end ?? 0) ||
        compareStrings(sha256(a.finding.snippet ?? ''), sha256(b.finding.snippet ?? '')) ||
        compareStrings(a.finding.fingerprint, b.finding.fingerprint) ||
        a.index - b.index,
    );
    let occurrence = -1;
    let lastLine: number | undefined;
    for (const m of members) {
      // A secret found on the same line by two commits (a whitespace commit
      // touching it) is one occurrence — without values, nothing says whether
      // it is one secret (with them, {@link valueSlots} keys secrets instead).
      const sameLine = m.pass === 'history' && m.finding.line_start !== undefined && m.finding.line_start === lastLine;
      if (!sameLine) occurrence += 1;
      lastLine = m.finding.line_start;
      const slotKey = `${m.head}\n${occurrence}`;
      const slot = slots.get(slotKey);
      if (slot === undefined) slots.set(slotKey, [m]);
      else slot.push(m);
    }
  }
  for (const [slotKey, members] of slots) {
    const matchKey = sha256(slotKey);
    for (const m of members) {
      const slot = out[m.index];
      if (slot !== undefined) slot.matchKey = matchKey;
    }
  }
  if (byValue !== undefined) {
    for (const [head, members] of valued) {
      for (const [index, occurrence] of valueSlots(members, byValue, opts.introducedAt)) {
        const slot = out[index];
        if (slot !== undefined) slot.matchKey = sha256(`${head}\n${occurrence}`);
      }
    }
  }
  return out;
}

/**
 * The occurrence of each gitleaks finding of one (rule, path) whose value is
 * known — finding index → occurrence (review 11, finding 2). One occurrence
 * per distinct VALUE, so every commit that touched a secret's line, the
 * working-tree copy and a move to another line all share the secret's key —
 * and so does another copy of the value in the same file, which is not new
 * (decided in review 12, finding 12: a move must pass, telling a copy from a
 * move would take tracking deletions, and a copy exposes nothing the baseline
 * did not accept; in another file it is new, the path being in the key).
 * The values are numbered in the order they were introduced: by the earliest
 * commit holding each (`introducedAt`; the working tree after every commit),
 * then line. Counted by line alone, a new secret added ABOVE a baselined one
 * took occurrence 0 — the baselined one's key — and passed the gate. A value
 * that cannot be read gets no occurrence: that finding matches by its exact
 * identity only. Ties (one commit, one line) are broken by the fingerprint,
 * which is the same in every run.
 */
function valueSlots(
  members: ReadonlyArray<{ index: number; finding: GateKeySubject }>,
  secretValue: (f: GateKeySubject) => string | undefined,
  introducedAt: ((f: GateKeySubject) => number | undefined) | undefined,
): Map<number, number> {
  const first = new Map<string, { at: number; line: number; end: number; fingerprint: string }>();
  const valueOf = new Map<number, string>();
  for (const { index, finding } of members) {
    const value = secretValue(finding);
    if (value === undefined) continue;
    valueOf.set(index, value);
    const at = introducedAt?.(finding) ?? (isHistoryLocator(finding) ? Number.MAX_SAFE_INTEGER : Number.POSITIVE_INFINITY);
    const here = { at, line: finding.line_start ?? 0, end: finding.line_end ?? 0, fingerprint: finding.fingerprint };
    const seen = first.get(value);
    if (seen === undefined || earlier(here, seen)) first.set(value, here);
  }
  const order = [...first.entries()].sort((a, b) => (earlier(a[1], b[1]) ? -1 : earlier(b[1], a[1]) ? 1 : 0));
  const occurrence = new Map(order.map(([value], i) => [value, i]));
  const out = new Map<number, number>();
  for (const [index, value] of valueOf) {
    const n = occurrence.get(value);
    if (n !== undefined) out.set(index, n);
  }
  return out;
}

/** Whether `a` was introduced before `b`: commit time, then line, then the fingerprint. */
function earlier(
  a: { at: number; line: number; end: number; fingerprint: string },
  b: { at: number; line: number; end: number; fingerprint: string },
): boolean {
  if (a.at !== b.at) return a.at < b.at;
  if (a.line !== b.line) return a.line < b.line;
  if (a.end !== b.end) return a.end < b.end;
  return a.fingerprint < b.fingerprint;
}

/** The content a match key hashes (see {@link GateKeys.matchKey}), or null when there is none to key on. */
function matchContentKey(f: GateKeySubject): string | null {
  const dependency = dependencyCoordinates(f);
  if (dependency !== null) return sha256(`dep\n${dependency.name.toLowerCase()}`);
  // The commit out: a secret is the same secret whichever commit or pass saw it.
  if (isGitleaksSecret(f)) return sha256(`secret\n${f.rule_id ?? ''}`);
  return f.content_key ?? null;
}

/** A gitleaks finding (history or files pass) — a credential by definition. */
function isGitleaksSecret(f: IdentitySubject): boolean {
  return f.tool.toLowerCase() === 'gitleaks';
}

// ------------------------------------------------------------------ internal

/**
 * The path as it enters the identity (`key`: relative, POSIX, no `./`) and as
 * it is handed to the reader (`readable`: relative to the project, or null
 * when it is not a path inside it — an image name, an absolute path
 * elsewhere).
 */
function locate(
  filePath: string | undefined,
  projectPath: string | undefined,
): { key: string; readable: string | null } {
  let path = filePath ?? '';
  if (path === '') return { key: '', readable: null };
  let insideProject = !isAbsolute(path);
  if (projectPath !== undefined && isAbsolute(path)) {
    const rel = relative(projectPath, path);
    if (rel !== '' && !isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`)) {
      path = rel;
      insideProject = true;
    }
  }
  const key = normalizePathPosix(path).replace(/^(\.\/)+/, '');
  return { key, readable: insideProject ? path.replace(/\\/g, '/') : null };
}

function contentSource(
  f: IdentitySubject,
  readable: string | null,
  linesOf: (readable: string) => string[] | null,
): string {
  const dependency = dependencyCoordinates(f);
  if (dependency !== null) return `dep\n${dependency.name}@${dependency.version}`;

  // Never the line, never its hash — see "Secrets" in the module comment.
  // Checked before anything reads the file, so a credential line is not even
  // loaded for this finding.
  if (isCredentialFinding(f)) {
    const locator = isHistoryLocator(f) && f.snippet !== undefined ? `\n${collapse(f.snippet)}` : '';
    return `secret\n${f.rule_id ?? ''}${locator}`;
  }

  if (isHistoryLocator(f) && f.snippet !== undefined) return `text\n${collapse(f.snippet)}`;

  if (readable !== null && f.line_start !== undefined) {
    const fileLines = linesOf(readable);
    const lines = fileLines === null ? null : sourceLines(fileLines, f.line_start, f.line_end);
    if (lines !== null) return `text\n${collapse(lines)}`;
  }

  if (f.snippet !== undefined && usableSnippet(f.snippet)) {
    return `text\n${collapse(snippetText(f.tool, f.snippet))}`;
  }
  return 'none';
}

/**
 * The source text inside a snippet. Bandit prefixes each line of its `code`
 * with the line number (`"2 data = pickle.loads(x)"`), gosec with the number
 * and a colon (`"15: \trows, _ := db.Query(q)"`); those numbers are exactly
 * what the identity must not depend on.
 */
const LINE_NUMBER_PREFIX: Readonly<Record<string, RegExp>> = { bandit: /^\d+ /, gosec: /^\d+: / };

function snippetText(tool: string, snippet: string): string {
  const prefix = LINE_NUMBER_PREFIX[tool.toLowerCase()];
  if (prefix === undefined) return snippet;
  return snippet
    .split(/\r\n|\r|\n/)
    .map((line) => line.replace(prefix, ''))
    .join('\n');
}

/**
 * Rule ids and subcategories that name what they flag as a credential. Each
 * word must stand alone (bounded by a non-letter), so `jsonwebtoken` or a
 * CSRF-token rule does not match; a bare `token` is not in the list for that
 * reason. Matching too much costs only precision (the content then says less
 * than the line would); matching too little puts a hash of a secret into a
 * committed file, so this leans wide.
 */
const CREDENTIAL_RULE =
  /(^|[^a-z])(secrets?|passwords?|passwd|pwd|credentials?|api[-_]?keys?|private[-_]?keys?|access[-_]?keys?|aws[-_]?keys?|hardcoded[-_ ]?(passwords?|secrets?|credentials?|keys?|tokens?))([^a-z]|$)/i;

/**
 * A finding whose flagged line holds a credential: every `subcategory:
 * 'secret'` finding (gitleaks, Trivy secrets), and a finding whose rule id or
 * subcategory names one — Bandit's B105–B107 (`hardcoded_password_*`),
 * gosec's G101 (`hardcoded_credentials`, set by its parser), the
 * shipped `hardcoded-aws-key` / `hardcoded-private-key` rules, the Semgrep
 * registry's `*.secrets.*` family.
 */
export function isCredentialFinding(f: Pick<IdentitySubject, 'subcategory' | 'rule_id'>): boolean {
  if ((f.subcategory ?? '').toLowerCase() === 'secret') return true;
  return CREDENTIAL_RULE.test(f.rule_id ?? '') || CREDENTIAL_RULE.test(f.subcategory ?? '');
}

/** A gitleaks finding whose snippet names the commit it was found in. */
function isHistoryLocator(f: IdentitySubject): boolean {
  return (
    f.tool.toLowerCase() === 'gitleaks' &&
    /;commit=[0-9a-f]{7,64}$/i.test(f.snippet ?? '')
  );
}

function usableSnippet(snippet: string): boolean {
  const text = collapse(snippet);
  return text !== '' && text.toLowerCase() !== REDACTED_SNIPPET;
}

/** Lines `start`..`end` (1-based, inclusive), or null when `start` is not in the file. */
function sourceLines(lines: readonly string[], start: number, end: number | undefined): string | null {
  if (!Number.isInteger(start) || start < 1) return null;
  if (start > lines.length) return null;
  const requestedEnd = end !== undefined && Number.isInteger(end) ? end : start;
  const last = Math.min(Math.max(requestedEnd, start), lines.length);
  return lines.slice(start - 1, last).join('\n');
}

function collapse(text: string): string {
  return text.replace(/\s+/g, ' ').trim();
}

function splitCoordinate(
  coordinate: string,
  allowBareName: boolean,
): { name: string; version: string } | null {
  const at = coordinate.lastIndexOf('@');
  if (at > 0) return { name: coordinate.slice(0, at), version: coordinate.slice(at + 1) };
  if (allowBareName && coordinate !== '' && at < 0) return { name: coordinate, version: '' };
  return null;
}

function realOrResolved(p: string): string {
  try {
    return realpathSync.native(resolve(p));
  } catch {
    return resolve(p);
  }
}

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function sha256(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}
