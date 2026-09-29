/**
 * What a comparison of two scans may call "resolved" — and "new".
 *
 * A finding of the older scan that the newer one does not report is resolved
 * only if the newer scan LOOKED — with the scanner that reports it. Counted
 * otherwise, the gap read as a fix: an orchestrated `security_scan_full`
 * run is compared as a whole (its parent row holds every child's findings
 * merged), and when a child measured nothing (Semgrep exit 7, Trivy not
 * installed) its type was absent from the parent and every earlier finding
 * of it read as resolved — in the dashboard's since_previous, `diff_scans`'s
 * default, `regression_alert` (where the false resolution cancelled a real
 * new high) and `set_baseline` (fix round 2). Nor is "the child ran" enough:
 * a Python project's sast child can be [semgrep failed, bandit ok] — coverage
 * partial, status completed — and every Semgrep finding still vanished (fix
 * round 3). So the question is asked per SCANNER:
 *
 *   - NOT RE-MEASURED: a finding of `from` whose scanner the newer scan did
 *     not measure (for the child that covers it) — it failed, was missing,
 *     or did not run at all. Never resolved, never unchanged.
 *   - NOT PREVIOUSLY MEASURED: a finding of `to` whose scanner the reference
 *     (a baseline, the previous run) NAMED and did not run ok — it failed, or
 *     was listed missing. Not "new": a partial baseline would otherwise raise
 *     a false regression alarm.
 *
 * The two are not mirrors (fix round 5). A reference that did not run a
 * scanner at all — not applicable then (no Python for Bandit, no
 * package.json for npm, no Dockerfile for Trivy's config pass) or not
 * requested (nuclei, security-code-scan's opt-in) — looked at everything it
 * had to, and what that scanner finds now is NEW: read as "not previously
 * measured", regression_alert stayed silent on Bandit's first high the day
 * Python was added. The newer side cannot make the same call — a scanner
 * that stopped running may simply be absent this time — so there a scanner
 * that did not run still leaves its findings not re-measured, never resolved.
 *
 * "Ran ok" is read from the scan's bookkeeping (`tools_run`, `missing_tools`)
 * through the explicit name table in `history/runNames.ts` — the names are
 * not the findings' tools (`npm` records npm-audit's findings,
 * `guardian-dast` the `dast` ones). For a finding's scanner:
 *
 *   - measured when some entry naming it ran ok, no entry naming it failed
 *     (a failed pass — `guardian-dast:unanswered`, `gitleaks-working-tree` —
 *     vetoes the whole scanner: its findings cannot be told apart by pass),
 *     and no `missing_tools` entry names it — unless that same name also ran
 *     ok, which is a run with a narrower gap inside it (bug_hunt's pack
 *     retry, gitleaks' size limits, a Semgrep partial parse) — and the
 *     finding is not in a file that run names as only partly parsed
 *     (`ToolRun.partially_parsed`: that file's findings are unmeasured);
 *   - UNMEASURED — a gap — when it is named, but a naming entry failed, or a
 *     `missing_tools` entry names it (outside the retry shape above), or no
 *     entry naming it ran ok;
 *   - NOT RUN when the bookkeeping never names a scanner the table knows —
 *     nuclei not requested, no image given: the scan did not look — or names
 *     it only in passes skipped with no gap recorded (`trivy` skipped for
 *     want of a Dockerfile: `computeCoverage`'s "nothing to scan"), and
 *     when one scan ran a pass that may have produced the finding and the
 *     other did not look at that pass's TARGET again: an image
 *     (`trivy-image`) and the project's files (`trivy-dockerfile`,
 *     `trivy-config`) are measured under the same key, but a Dockerfile
 *     pass never looked at the image, nor an image pass at the Dockerfile,
 *     nor a scan of image B at image A (`ToolRun.target`; see
 *     `targetNotRun`);
 *   - for a tool the table does not know at all, measured only by a scan
 *     with no gap anywhere (coverage `full`), never by a partial one;
 *   - a scan with no bookkeeping at all (the oldest rows) measured
 *     everything.
 *
 * An audit_executive row is judged by its sub-scans' own bookkeeping (its
 * own entries only say which sub-tool answered).
 */

import { join } from 'node:path';
import { indexFindings } from '../fingerprint/findingIdentity.js';
import { LLM_RULES_FILE } from '../runners/semgrepConfigs.js';
import { FIXPOINT_TIMEOUT_PACK_TYPE } from '../runners/semgrepReport.js';
import { pluginPacksDir, ruleIdsInFile } from '../runners/semgrepRuleIds.js';
import type { Storage } from '../storage/index.js';
import { computeCoverage } from '../tools/scanCoverage.js';
import type { Finding, PartialParse, ScanRecord, ToolRun } from '../types.js';
import { KNOWN_FINDING_KEYS, findingKey, keysOfRun, runNameEntry } from './runNames.js';
import { isOrchestratedFullScan, isScriptEraFullScan, scriptEraSlotOfFinding } from './scanRoles.js';

export interface ScanComparison {
  /** Whether `f`, a finding of `from`, was not measured again by `to` — a gap, or not run. */
  isNotRemeasured: (f: Finding) => boolean;
  /** Whether `f`, a finding of `to`, falls in a gap of `from` (a scanner it named and did not run ok). */
  isNotPreviouslyMeasured: (f: Finding) => boolean;
  /**
   * When `to` never ran `f`'s scanner at all (`f` a finding of `from`), the
   * name to report — the finding's tool (nuclei not requested), or the pass
   * that did not run again (`trivy-image`: no image given) — else null.
   */
  notRunByTo: (f: Finding) => string | null;
  /** The same for `from` and `f`, a finding of `to` — which makes `f` new, not unmeasured. */
  notRunByFrom: (f: Finding) => string | null;
  /** What `to` did not measure, gaps and scanners it did not run alike — see {@link notMeasured}. */
  notMeasuredByTo: string[];
  /** Of {@link notMeasuredByTo}, the gaps: what `to` named and did not run ok. */
  gapsByTo: string[];
  /** What `from` named and did not run ok — its gaps only. */
  notMeasuredByFrom: string[];
}

/** A comparison with nothing unmeasured on either side (no reference scan row to read). */
export const COMPLETE_COMPARISON: ScanComparison = {
  isNotRemeasured: () => false,
  isNotPreviouslyMeasured: () => false,
  notRunByTo: () => null,
  notRunByFrom: () => null,
  notMeasuredByTo: [],
  gapsByTo: [],
  notMeasuredByFrom: [],
};

interface ChildRef {
  type: string;
  row: ScanRecord | null;
}

/** The part of a scan's bookkeeping that answers for it (a slot's view, an audit's sub-scans'). */
export type Bookkeeping = Pick<ScanRecord, 'tools_run' | 'missing_tools'>;

/** How a scan's bookkeeping answers for one finding. */
type Verdict = 'measured' | 'unmeasured' | 'not_run';

/** An orchestrated run's children, as its parent row lists them. */
function childrenOf(storage: Storage, parent: ScanRecord): ChildRef[] {
  const listed = parent.meta?.['child_scans'];
  if (!Array.isArray(listed)) return [];
  const out: ChildRef[] = [];
  for (const entry of listed as unknown[]) {
    if (entry === null || typeof entry !== 'object') continue;
    const e = entry as { tool?: unknown; scan_id?: unknown };
    const row = typeof e.scan_id === 'string' ? storage.scans.getById(e.scan_id) : null;
    const type = row?.scan_type ?? (typeof e.tool === 'string' ? e.tool.replace(/^scan_/, '') : null);
    if (type !== null) out.push({ type, row });
  }
  return out;
}

/** A child that can speak for its type at all: present, completed. */
function usableChild(c: ChildRef): c is ChildRef & { row: ScanRecord } {
  return c.row !== null && c.row.status === 'completed';
}

/**
 * An audit_executive row's bookkeeping, as its sub-scans recorded it. The
 * row's own entries are one per sub-tool (`security_scan_full: ok`): that
 * the sub-tool answered, not that each of its scanners ran — a sub-scan
 * whose Semgrep failed still reports `ok`. Each ok entry is therefore
 * replaced by its sub-scan's own `tools_run` / `missing_tools`; an entry
 * without a readable sub-scan (a sub-tool that failed before it wrote one,
 * a pruned row) stays, and speaks through `runNames.ts`.
 */
function auditBookkeeping(storage: Storage, audit: ScanRecord): Bookkeeping {
  const ids = audit.meta?.['sub_scan_ids'];
  if (ids === null || typeof ids !== 'object' || Array.isArray(ids)) return audit;
  const byTool = ids as Record<string, unknown>;
  const tools_run: ToolRun[] = [];
  const missing_tools: string[] = [...audit.missing_tools];
  for (const entry of audit.tools_run) {
    const id = Object.hasOwn(byTool, entry.name) ? byTool[entry.name] : undefined;
    const sub = entry.status === 'ok' && typeof id === 'string' ? storage.scans.getById(id) : null;
    if (sub === null || (sub.tools_run.length === 0 && sub.missing_tools.length === 0)) {
      tools_run.push(entry);
      continue;
    }
    tools_run.push(...sub.tools_run);
    missing_tools.push(...sub.missing_tools);
  }
  return { tools_run, missing_tools };
}

function bookkeepingOf(storage: Storage, scan: ScanRecord): Bookkeeping {
  return scan.scan_type === 'audit' ? auditBookkeeping(storage, scan) : scan;
}

// ---------------------------------------------------------------------------
// Per-scanner "did this bookkeeping measure this key?"
// ---------------------------------------------------------------------------

function keyVerdict(book: Bookkeeping, key: string): Verdict {
  let named = false;
  let anyOk = false;
  let anyFailed = false;
  const okNames = new Set<string>();
  for (const run of book.tools_run) {
    const ok = run.status === 'ok';
    if (!(keysOfRun(run.name, ok)?.includes(key) ?? false)) continue;
    named = true;
    if (ok) {
      anyOk = true;
      okNames.add(run.name);
    } else if (run.status === 'failed') {
      anyFailed = true;
    }
  }
  let missing = false;
  for (const name of book.missing_tools) {
    if (!(keysOfRun(name, false)?.includes(key) ?? false)) continue;
    named = true;
    // Listed missing AND ok under the same name: the scanner ran, with a
    // narrower gap inside it (bug_hunt's pack retry, gitleaks' size limits).
    if (!okNames.has(name)) missing = true;
  }
  if (named) {
    if (anyFailed || missing) return 'unmeasured';
    // Named only by passes skipped with no gap recorded — nothing for them to
    // scan (no Dockerfile, no uncommitted files) — is the same as not named.
    return anyOk ? 'measured' : 'not_run';
  }
  if (KNOWN_FINDING_KEYS.has(key)) return 'not_run';
  // A tool no bookkeeping name is known to measure: only a scan with no gap
  // anywhere can speak for it — never a partial one.
  return computeCoverage(book.tools_run, book.missing_tools) === 'full' ? 'measured' : 'unmeasured';
}

function isEmptyBook(book: Bookkeeping): boolean {
  return book.tools_run.length === 0 && book.missing_tools.length === 0;
}

/** A finding's file as the partial-parse lists name it: `/`-separated. */
function fileOf(f: Pick<Finding, 'file_path'>): string | undefined {
  return f.file_path === undefined ? undefined : f.file_path.replace(/\\/g, '/');
}

/** Whether `run` ran ok and speaks for `key` — the one test every target and gap check below uses. */
function measuresKeyOk(run: ToolRun, key: string): boolean {
  return run.status === 'ok' && (keysOfRun(run.name, true)?.includes(key) ?? false);
}

/**
 * Whether a partial-parse entry is the plugin's LLM pack's own taint timeout
 * (`runners/semgrepReport.ts#withPluginPackFixpoint`). It is the PACK's gap:
 * a finding in that file is left unmeasured only when it is one of the
 * pack's own rules ({@link isPluginPackRule}). Read as the run's gap, a
 * registry finding fixed in such a file stayed open as "not re-measured".
 */
function isPluginPackGap(pp: PartialParse): boolean {
  return pp.type === FIXPOINT_TIMEOUT_PACK_TYPE;
}

let packRuleIds: ReadonlySet<string> | undefined;

/**
 * The rule ids the plugin's LLM pack declares (`configs/semgrep/llm.yml`),
 * as its findings are stored — the pack rule's own id (`localRuleIds.ts`).
 * Read once. A project-root rule carrying the same id is stored the same
 * way and is read as the pack's: that can only keep one of its findings
 * open, never close one.
 */
function pluginPackRuleIds(): ReadonlySet<string> {
  packRuleIds ??= new Set(ruleIdsInFile(join(pluginPacksDir(), LLM_RULES_FILE)));
  return packRuleIds;
}

function isPluginPackRule(ruleId: string | undefined): boolean {
  return ruleId !== undefined && pluginPackRuleIds().has(ruleId);
}

/**
 * The narrower gaps INSIDE an ok run that measures `key`: files it could
 * only partly parse (`ToolRun.partially_parsed`, the shared Semgrep judge's
 * `partial` verdict) and rules that did not load (`ToolRun.failed_rules`,
 * bug_hunt's broken-rule shape). The rest of that run measured — `ok` AND
 * missing, the retry shape `keyVerdict` reads as measured — but a finding in
 * one of those files, or of one of those rules, was not looked for. A file
 * of the plugin pack's own gap ({@link isPluginPackGap}) is a gap only for
 * the pack's rules: (file, pack rule) pairs.
 */
function narrowGapsOf(book: Bookkeeping, key: string): ScopeConstraint & { pairs: Map<string, ReadonlySet<string>> } {
  const files = new Set<string>();
  const rules = new Set<string>();
  const pairs = new Map<string, ReadonlySet<string>>();
  for (const run of book.tools_run) {
    if (!measuresKeyOk(run, key)) continue;
    for (const pp of run.partially_parsed ?? []) {
      if (isPluginPackGap(pp)) pairs.set(pp.file, pluginPackRuleIds());
      else files.add(pp.file);
    }
    for (const fr of run.failed_rules ?? []) rules.add(fr.rule_id);
  }
  for (const f of files) pairs.delete(f);
  return { files, rules, pairs };
}

/**
 * The run measuring `f`'s key that left `f` out — its file only partly
 * parsed (by the pack, for a pack rule's finding), or its rule not loaded —
 * with the label a reader is given, or null.
 */
function narrowGapOf(book: Bookkeeping, f: Finding): { run: ToolRun; label: string } | null {
  const key = findingKey(f);
  const file = fileOf(f);
  for (const run of book.tools_run) {
    if (!measuresKeyOk(run, key)) continue;
    const entries = file === undefined ? [] : (run.partially_parsed ?? []).filter((pp) => pp.file === file);
    if (entries.some((pp) => !isPluginPackGap(pp))) {
      return { run, label: `${run.name} (partly parsed: ${file})` };
    }
    if (entries.length > 0 && isPluginPackRule(f.rule_id)) {
      return { run, label: `${run.name} (LLM pack partly measured: ${file})` };
    }
    if (f.rule_id !== undefined && (run.failed_rules ?? []).some((fr) => fr.rule_id === f.rule_id)) {
      return { run, label: `${run.name} (rule not loaded: ${f.rule_id})` };
    }
  }
  return null;
}

/**
 * How `book` answers for `f`, its scanner's verdict narrowed to the finding:
 * `unmeasured` also when the run that measured the key could only partly
 * parse `f`'s file, or did not load `f`'s rule.
 */
function bookkeepingVerdict(book: Bookkeeping, f: Finding): Verdict {
  if (isEmptyBook(book)) return 'measured';
  const verdict = keyVerdict(book, findingKey(f));
  return verdict === 'measured' && narrowGapOf(book, f) !== null ? 'unmeasured' : verdict;
}

/** The runs and missing names of `book` that record a gap in `key`: failed, or missing without an ok run. */
function gapNamesFor(book: Bookkeeping, key: string): string[] {
  const okNames = new Set(book.tools_run.filter((r) => r.status === 'ok').map((r) => r.name));
  const names: string[] = [];
  const add = (name: string): void => {
    if (!names.includes(name)) names.push(name);
  };
  for (const run of book.tools_run) {
    if (run.status === 'failed' && (keysOfRun(run.name, false)?.includes(key) ?? false)) add(run.name);
  }
  for (const name of book.missing_tools) {
    if (!okNames.has(name) && (keysOfRun(name, false)?.includes(key) ?? false)) add(name);
  }
  return names;
}

/**
 * An ok pass of `holder` that runs only when it is asked for
 * (`runNames.ts` `onRequest`: `trivy-image` needs an image, nuclei must be
 * requested) and speaks for `key`, as its label — or null. A newer scan
 * that did not run such a pass at all did not look: the finding stays open.
 * A pass that runs whenever there is something for it (Bandit, when there
 * is Python) is not one: its absence says the target went away.
 */
function onRequestPassOf(holder: Bookkeeping, key: string): string | null {
  const run = holder.tools_run.find((r) => measuresKeyOk(r, key) && runNameEntry(r.name)?.onRequest === true);
  return run === undefined ? null : passLabel(run, targetOf(run));
}

/**
 * The open set's question (`openSet.ts`): does `asked`, a NEWER scan of the
 * same slot, leave `f` — a finding of the older scan `holder` describes —
 * still open? Returns the name of the gap, or null when `asked` re-measured
 * `f` (and did not find it: resolved) or did not run `f`'s scanner at all
 * with no gap recorded (not applicable: a Python-free project's Bandit).
 *
 * It CALLS the verdict every comparison uses — {@link answerFor}, through
 * `bookkeepingVerdict` and `targetNotRun` — so the open set and
 * `compareScansFor`'s "not re-measured" cannot drift apart. The one reading
 * it adds: a `not_run` of a pass that runs only on request (an image, nuclei)
 * is still a gap — the newer scan did not ask, so it did not look.
 *
 *   - a gap in `f`'s key (`semgrep` failed, or listed missing) → those names;
 *   - `f`'s file only partly parsed → `semgrep (partly parsed: wp/a.php)`;
 *   - `f`'s rule not loaded → `semgrep (rule not loaded: <rule id>)`;
 *   - a pass over another target, or one not requested this time →
 *     `trivy-image (registry/app:1)`, `nuclei`.
 */
export function openGapFor(holder: Bookkeeping, asked: Bookkeeping, f: Finding): string | null {
  const answer = answerFor(holder, asked, f);
  if (answer.verdict === 'measured') return null;
  if (answer.verdict === 'unmeasured') {
    const narrow = narrowGapOf(asked, f);
    if (narrow !== null) return narrow.label;
    const key = findingKey(f);
    const names = gapNamesFor(asked, key);
    return names.length > 0 ? names.join(', ') : key;
  }
  if (answer.byTarget) return answer.notRun;
  return onRequestPassOf(holder, findingKey(f));
}

/**
 * The findings a chain of newer scans left open, as a set of (file, rule)
 * pairs a finding must be in — the conjunction of every `some` scope
 * (below), kept in a form whose size does not grow with the chain:
 *
 *   - `all`: no narrow constraint yet — every finding of the key;
 *   - else a finding is admitted when its file is in `files` (any rule), its
 *     rule is in `rules` (any file), or the pair is in `pairs`.
 *
 * A constraint (files F, rules R: "in one of F, or of one of R") meets it
 * exactly: `files` becomes files ∩ F, `rules` rules ∩ R, and a file that
 * leaves `files` stays only with R's rules (a rule that leaves `rules`,
 * only in F's files) — as pairs. A file leaves `files` once and a rule
 * `rules` once, so the pairs ever made are bounded by the constraints' own
 * sizes, never by the chain's length: a partial parse AND a different rule
 * not loaded in each of 5000 scans closes after the third (review, M-4).
 *
 * Two bounds keep a step cheap however large each constraint is (round 3's
 * review, M-2: 2000 scans alternating two disjoint sets of W partly parsed
 * files and W rules not loaded cost W x W per step — 17.6 s at W = 200):
 *   - a constraint already met is skipped: meeting it again changes nothing
 *     (the set is inside it already), exactly;
 *   - a meet that would hold more than {@link MAX_ADMIT_PAIRS} pairs keeps
 *     the constraint itself instead (`F x * ∪ * x R`) — a superset of the
 *     exact answer, which lies inside every constraint met, so it can only
 *     carry MORE findings (flagged not re-measured), never drop one. Each step
 *     then costs O(|pairs| + |files| + |rules| + |F| + |R|), with pairs at most
 *     {@link MAX_ADMIT_PAIRS}.
 */
export type Admit =
  | { all: true }
  | {
      all: false;
      files: ReadonlySet<string>;
      rules: ReadonlySet<string>;
      pairs: ReadonlyMap<string, ReadonlySet<string>>;
    };

/**
 * What a chain of newer scans leaves open of a holder's findings under one
 * key: `never` as soon as one scan closes the key — the walk stops there —,
 * else the findings {@link Admit} names.
 */
export type ChainScope = { kind: 'never' } | { kind: 'open'; admit: Admit };

/**
 * One narrower gap of one scan: a finding in one of `files`, or of one of
 * `rules`, or one of `pairs` (a file the plugin's pack only partly measured,
 * with the pack's rules).
 */
export interface ScopeConstraint {
  files: ReadonlySet<string>;
  rules: ReadonlySet<string>;
  pairs?: ReadonlyMap<string, ReadonlySet<string>>;
}

const NO_PAIRS: ReadonlyMap<string, ReadonlySet<string>> = new Map();

const ADMIT_ALL: Admit = { all: true };
const NEVER_SCOPE: ChainScope = { kind: 'never' };

/** The most (file, rule) pairs an {@link Admit} holds before it widens to the constraint itself (sound: a superset). */
export const MAX_ADMIT_PAIRS = 10_000;

function onlyConstraint(c: ScopeConstraint): Admit {
  const pairs = new Map<string, ReadonlySet<string>>();
  for (const [f, rs] of c.pairs ?? NO_PAIRS) if (!c.files.has(f)) pairs.set(f, new Set(rs));
  return { all: false, files: new Set(c.files), rules: new Set(c.rules), pairs };
}

export function meetAdmit(s: Admit, c: ScopeConstraint): Admit {
  if (s.all) return onlyConstraint(c);
  const cPairs = c.pairs ?? NO_PAIRS;
  const files = new Set([...s.files].filter((f) => c.files.has(f)));
  const rules = new Set([...s.rules].filter((r) => c.rules.has(r)));
  // Before building any pair: how many could this meet make? Past the bound,
  // the constraint alone — a superset of the exact meet (see `Admit`).
  let bound = 0;
  for (const rs of s.pairs.values()) bound += rs.size;
  let filesLeaving = 0;
  for (const f of s.files) {
    if (c.files.has(f)) continue;
    filesLeaving += 1;
    bound += cPairs.get(f)?.size ?? 0;
  }
  let rulesLeaving = 0;
  for (const r of s.rules) if (!c.rules.has(r)) rulesLeaving += 1;
  let cPairCount = 0;
  if (rulesLeaving > 0) for (const rs of cPairs.values()) cPairCount += rs.size;
  bound += filesLeaving * c.rules.size + rulesLeaving * c.files.size + cPairCount;
  if (bound > MAX_ADMIT_PAIRS) return onlyConstraint(c);
  const pairs = new Map<string, Set<string>>();
  const add = (f: string, r: string): void => {
    if (files.has(f) || rules.has(r)) return;
    let set = pairs.get(f);
    if (set === undefined) {
      set = new Set();
      pairs.set(f, set);
    }
    set.add(r);
  };
  const inCPairs = (f: string, r: string): boolean => cPairs.get(f)?.has(r) ?? false;
  for (const [f, rs] of s.pairs) for (const r of rs) if (c.files.has(f) || c.rules.has(r) || inCPairs(f, r)) add(f, r);
  for (const f of s.files) {
    if (c.files.has(f)) continue;
    for (const r of c.rules) add(f, r);
    for (const r of cPairs.get(f) ?? []) add(f, r);
  }
  for (const r of s.rules) {
    if (c.rules.has(r)) continue;
    for (const f of c.files) add(f, r);
    for (const [f, rs] of cPairs) if (rs.has(r)) add(f, r);
  }
  return { all: false, files, rules, pairs };
}

function admitsNothing(s: Admit): boolean {
  return !s.all && s.files.size === 0 && s.rules.size === 0 && s.pairs.size === 0;
}

/** Whether a finding in `file` of `rule` is inside `scope`. */
export function scopeAdmits(scope: ChainScope, file: string | undefined, rule: string | undefined): boolean {
  if (scope.kind === 'never') return false;
  const a = scope.admit;
  if (a.all) return true;
  if (file !== undefined && a.files.has(file)) return true;
  if (rule !== undefined && a.rules.has(rule)) return true;
  return file !== undefined && rule !== undefined && (a.pairs.get(file)?.has(rule) ?? false);
}

/** The files and rules a finding admitted by `admit` can have — what the carry reads rows by. */
export function admitLookup(admit: Exclude<Admit, { all: true }>): { files: string[]; rules: string[] } {
  const files = new Set(admit.files);
  const rules = new Set(admit.rules);
  for (const [f, rs] of admit.pairs) {
    files.add(f);
    for (const r of rs) rules.add(r);
  }
  return { files: [...files], rules: [...rules] };
}

/**
 * What one scan of a chain says about one key, whoever holds the finding —
 * the holder-independent half of the per-pair verdict ({@link openGapFor}):
 *
 *   - no bookkeeping: it measured everything (closes the key for any holder);
 *   - `unmeasured`: leaves every such finding open;
 *   - `not_run`: closes the key, except for a holder whose pass runs only on
 *     request (it did not ask);
 *   - `measured`: closes the key — or narrows it to its partly parsed files
 *     and rules not loaded — for a holder whose every target it looked at
 *     again (`sameTarget`); leaves it open for any other.
 */
interface Covered {
  /** An ok pass over the project's files measures the key. */
  project: boolean;
  /** `pass\0ref` of every ok own-target pass (an image) that recorded its target. */
  images: Set<string>;
  /** Own-target passes that ran ok without recording a target: any image of that pass. */
  legacy: Set<string>;
  /** Every own-target pass that ran ok, whatever its target. */
  any: Set<string>;
  /** Its partly parsed files and rules not loaded, or null: none. */
  narrow: ScopeConstraint | null;
  /** `narrow`, spelled once: a constraint a fold has met already is skipped. */
  narrowSig: string;
}

/** A holder as the chain sees it for one key (the only part of it {@link openGapFor} reads). */
interface HolderClass {
  signature: string;
  /** It ran ok a pass that runs only on request and measures the key. */
  onRequest: boolean;
  /** The targets of its ok passes that measure the key, once each. */
  targets: PassTarget[];
}

interface ClassState {
  admit: Admit;
  /** The constraints met so far, by {@link Covered.narrowSig}. */
  met: Set<string>;
  closed: boolean;
  /** Positions reached in the class's driver lists (see `driverOf`). */
  a: number;
  b: number;
  snapshot: ChainScope | null;
}

interface KeyIndex {
  /** Chain scans indexed for this key. */
  len: number;
  firstEmpty: number;
  firstNotRun: number;
  at: Map<number, Covered>;
  measured: number[];
  project: number[];
  byImage: Map<string, number[]>;
  legacy: Map<string, number[]>;
  anyOf: Map<string, number[]>;
  classes: Map<string, ClassState>;
}

const NO_INDEXES: readonly number[] = [];

function pushTo(map: Map<string, number[]>, key: string, i: number): void {
  const list = map.get(key);
  if (list === undefined) map.set(key, [i]);
  else list.push(i);
}

function coversTarget(c: Covered, t: PassTarget): boolean {
  if (t.pass === PROJECT_FILES) return c.project;
  if (t.ref === undefined) return c.any.has(t.pass);
  return c.legacy.has(t.pass) || c.images.has(`${t.pass}\0${t.ref}`);
}

/**
 * The chain of newer scans the open set's carry-forward walks back past,
 * indexed per key so that a holder's scope is read in time linear in the
 * scans that could change it — never by re-folding the whole chain per
 * holder, which was quadratic whenever holders differed (fix round 3, I-1:
 * 2000 image scans each over its own image, 21 s).
 *
 * For one key a holder is its {@link HolderClass}; two holders of one class
 * get one scope, folded once and carried on as the chain grows. A scope is
 * `never` once the chain holds a scan with no bookkeeping, a `not_run` (for
 * a holder without an on-request pass), or a `measured` scan that looked at
 * every one of the holder's targets and has no narrower gap; else it is the
 * {@link Admit} of the narrower gaps of the `measured` scans that did look
 * at them all. Those scans are found through the class's rarest target —
 * the scans that looked at its image, else its image pass, else the
 * project's files — so a holder whose image no newer scan looked at costs
 * nothing, however long the chain. The carry-predicate property test holds
 * {@link scopeAdmits} over this equal to {@link openGapFor} against every
 * scan of the chain, for one holder and for a growing chain shared by many.
 */
export class ChainIndex {
  private readonly chain: Bookkeeping[] = [];
  private readonly byKey = new Map<string, KeyIndex>();

  push(book: Bookkeeping): void {
    this.chain.push(book);
  }

  get length(): number {
    return this.chain.length;
  }

  /** The chain's `i`-th scan, newest first. */
  bookAt(i: number): Bookkeeping | undefined {
    return this.chain[i];
  }

  /** `holder` for one key, as {@link scopeOfClass} takes it. */
  classOf(holder: Bookkeeping, key: string): HolderClass {
    const onRequest = onRequestPassOf(holder, key) !== null;
    const seen = new Map<string, PassTarget>();
    for (const run of holder.tools_run) {
      if (!measuresKeyOk(run, key)) continue;
      const t = targetOf(run);
      seen.set(`${t.pass}\0${t.ref ?? ''}\0${t.ref === undefined ? 'legacy' : 'ref'}`, t);
    }
    const targets = [...seen.values()];
    const signature = JSON.stringify([onRequest, [...seen.keys()].sort()]);
    return { signature, onRequest, targets };
  }

  /** {@link ChainScope} of `holder`'s findings under `key`, over the chain as it is now. */
  scope(holder: Bookkeeping, key: string): ChainScope {
    return this.scopeOfClass(this.classOf(holder, key), key);
  }

  scopeOfClass(cls: HolderClass, key: string): ChainScope {
    const idx = this.indexed(key);
    const L = this.chain.length;
    if (idx.firstEmpty < L || (!cls.onRequest && idx.firstNotRun < L)) return NEVER_SCOPE;
    let state = idx.classes.get(cls.signature);
    if (state === undefined) {
      state = { admit: ADMIT_ALL, met: new Set(), closed: false, a: 0, b: 0, snapshot: null };
      idx.classes.set(cls.signature, state);
    }
    this.advance(idx, cls, state, L);
    if (state.closed) return NEVER_SCOPE;
    if (state.snapshot === null) state.snapshot = { kind: 'open', admit: state.admit };
    return state.snapshot;
  }

  /** The class's driver: one or two ascending lists that hold every scan able to look at all its targets. */
  private driverOf(idx: KeyIndex, cls: HolderClass): [readonly number[], readonly number[]] {
    const image = cls.targets.find((t) => t.pass !== PROJECT_FILES && t.ref !== undefined);
    if (image !== undefined) {
      return [idx.byImage.get(`${image.pass}\0${image.ref ?? ''}`) ?? NO_INDEXES, idx.legacy.get(image.pass) ?? NO_INDEXES];
    }
    const legacyImage = cls.targets.find((t) => t.pass !== PROJECT_FILES);
    if (legacyImage !== undefined) return [idx.anyOf.get(legacyImage.pass) ?? NO_INDEXES, NO_INDEXES];
    if (cls.targets.length > 0) return [idx.project, NO_INDEXES];
    return [idx.measured, NO_INDEXES];
  }

  private advance(idx: KeyIndex, cls: HolderClass, state: ClassState, L: number): void {
    while (!state.closed) {
      const [listA, listB] = this.driverOf(idx, cls);
      const ia = listA[state.a];
      const ib = listB[state.b];
      const na = ia !== undefined && ia < L ? ia : undefined;
      const nb = ib !== undefined && ib < L ? ib : undefined;
      if (na === undefined && nb === undefined) return;
      const i = na === undefined ? (nb ?? 0) : nb === undefined ? na : Math.min(na, nb);
      if (na === i) state.a += 1;
      if (nb === i) state.b += 1;
      const c = idx.at.get(i);
      if (c === undefined || !cls.targets.every((t) => coversTarget(c, t))) continue;
      state.snapshot = null;
      if (c.narrow === null) {
        state.closed = true;
        return;
      }
      // Met already: the set lies inside it, meeting it again changes nothing.
      if (state.met.has(c.narrowSig)) continue;
      state.met.add(c.narrowSig);
      state.admit = meetAdmit(state.admit, c.narrow);
      if (admitsNothing(state.admit)) state.closed = true;
    }
  }

  /** The key's index, caught up with the chain. */
  private indexed(key: string): KeyIndex {
    let idx = this.byKey.get(key);
    if (idx === undefined) {
      idx = {
        len: 0,
        firstEmpty: Infinity,
        firstNotRun: Infinity,
        at: new Map(),
        measured: [],
        project: [],
        byImage: new Map(),
        legacy: new Map(),
        anyOf: new Map(),
        classes: new Map(),
      };
      this.byKey.set(key, idx);
    }
    for (; idx.len < this.chain.length; idx.len += 1) {
      const i = idx.len;
      const asked = this.chain[i];
      if (asked === undefined) break;
      if (isEmptyBook(asked)) {
        idx.firstEmpty = Math.min(idx.firstEmpty, i);
        continue;
      }
      const verdict = keyVerdict(asked, key);
      if (verdict === 'unmeasured') continue;
      if (verdict === 'not_run') {
        idx.firstNotRun = Math.min(idx.firstNotRun, i);
        continue;
      }
      const c: Covered = { project: false, images: new Set(), legacy: new Set(), any: new Set(), narrow: null, narrowSig: '' };
      for (const run of asked.tools_run) {
        if (!measuresKeyOk(run, key)) continue;
        const t = targetOf(run);
        if (t.pass === PROJECT_FILES) {
          c.project = true;
          continue;
        }
        c.any.add(t.pass);
        if (t.ref === undefined) c.legacy.add(t.pass);
        else c.images.add(`${t.pass}\0${t.ref}`);
      }
      const narrow = narrowGapsOf(asked, key);
      if (narrow.files.size > 0 || narrow.rules.size > 0 || narrow.pairs.size > 0) {
        c.narrow = narrow;
        // The pack's pairs are spelled by file: their rules are the pack's, always the same set.
        c.narrowSig = JSON.stringify([[...narrow.files].sort(), [...narrow.rules].sort(), [...narrow.pairs.keys()].sort()]);
      }
      idx.at.set(i, c);
      idx.measured.push(i);
      if (c.project) idx.project.push(i);
      for (const img of c.images) pushTo(idx.byImage, img, i);
      for (const pass of c.legacy) pushTo(idx.legacy, pass, i);
      for (const pass of c.any) pushTo(idx.anyOf, pass, i);
    }
    return idx;
  }
}

/** {@link ChainIndex} over a fixed chain, for one holder and key. */
export function chainScope(holder: Bookkeeping, chain: readonly Bookkeeping[], key: string): ChainScope {
  const index = new ChainIndex();
  for (const book of chain) index.push(book);
  return index.scope(holder, key);
}

/** A key no bookkeeping name measures — a finding tool the table does not know. */
export const UNKNOWN_FINDING_KEY = '\0unknown';

/**
 * Every key a finding of the scan `holder` describes could have: one of a
 * run that did not skip (a skipped run produced nothing), and
 * {@link UNKNOWN_FINDING_KEY} when a run's name is not in the table. A scan
 * with no bookkeeping at all could have produced anything.
 */
export function producedKeys(holder: Bookkeeping): string[] {
  const keys = new Set<string>();
  if (isEmptyBook(holder)) {
    for (const key of KNOWN_FINDING_KEYS) keys.add(key);
    keys.add(UNKNOWN_FINDING_KEY);
  }
  for (const run of holder.tools_run) {
    if (run.status === 'skipped') continue;
    const k = keysOfRun(run.name, run.status === 'ok');
    if (k === null) keys.add(UNKNOWN_FINDING_KEY);
    else for (const key of k) keys.add(key);
  }
  return [...keys];
}

/**
 * Whether any scan OLDER than the chain could still have a finding every
 * scan of it leaves open, whatever that scan ran: {@link ChainIndex}'s
 * scope for the widest holder the slot's history allows — every pass name
 * the slot's scans ever recorded (`names`), each ok, each over a target no
 * scan recorded — over every key it could produce. When even that holder
 * has nothing left open the carry-forward walk stops. `anyEmpty`: some scan
 * of the slot has no bookkeeping, and could have produced anything.
 */
export class StillCarry {
  private readonly classes: Array<{ key: string; cls: HolderClass }>;
  /** How much of the chain `check` has looked at for an empty book. */
  private seen = 0;
  private sawEmpty = false;

  constructor(
    private readonly index: ChainIndex,
    names: readonly string[],
    anyEmpty: boolean,
  ) {
    const widest: Bookkeeping = {
      tools_run: names.map((name) => ({ name, status: 'ok', target: '\0any image no scan recorded' })),
      missing_tools: [],
    };
    const keys = new Set(producedKeys(widest));
    if (anyEmpty) {
      for (const key of KNOWN_FINDING_KEYS) keys.add(key);
      keys.add(UNKNOWN_FINDING_KEY);
    }
    this.classes = [...keys].map((key) => ({ key, cls: index.classOf(widest, key) }));
  }

  check(): boolean {
    if (this.index.length === 0) return true;
    // A scan with no bookkeeping measured everything: nothing older is carried past it.
    for (; this.seen < this.index.length && !this.sawEmpty; this.seen += 1) {
      const book = this.index.bookAt(this.seen);
      if (book !== undefined && isEmptyBook(book)) this.sawEmpty = true;
    }
    if (this.sawEmpty) return false;
    return this.classes.some(({ key, cls }) => this.index.scopeOfClass(cls, key).kind !== 'never');
  }
}

/** Whether a gap name is a narrower gap inside a run that measured ({@link narrowGapNames}). */
function isNarrowGapName(name: string): boolean {
  return / \((partly parsed|rules not loaded|LLM pack partly measured): /.test(name);
}

/** How many files a run's narrower-gap name lists before "+N more" ({@link narrowGapNames}). */
const NARROW_GAP_FILES_NAMED = 5;

/**
 * `semgrep (partly parsed: a.php, b.js)` / `(rules not loaded: …)` for each
 * run with a narrower gap. The files are named once each and only the first
 * few, then counted (`+N more`): a loaded scan's taint fixpoint timeouts put
 * hundreds of files there (`runners/semgrepReport.ts`). Only a label — which
 * finding is not re-measured is decided from `partially_parsed` itself.
 */
function narrowGapNames(book: Bookkeeping): string[] {
  const names: string[] = [];
  const named = (files: readonly string[]): string => {
    const more = files.length - NARROW_GAP_FILES_NAMED;
    return [...files.slice(0, NARROW_GAP_FILES_NAMED), ...(more > 0 ? [`+${more} more`] : [])].join(', ');
  };
  for (const run of book.tools_run) {
    if (run.status !== 'ok') continue;
    const entries = run.partially_parsed ?? [];
    const parsed = [...new Set(entries.filter((pp) => !isPluginPackGap(pp)).map((pp) => pp.file))];
    // The plugin pack's own gap, named as the pack's: only its rules' findings there were left unmeasured.
    const byPack = [...new Set(entries.filter(isPluginPackGap).map((pp) => pp.file))].filter((f) => !parsed.includes(f));
    const failed = run.failed_rules ?? [];
    if (parsed.length > 0) names.push(`${run.name} (partly parsed: ${named(parsed)})`);
    if (byPack.length > 0) names.push(`${run.name} (LLM pack partly measured: ${named(byPack)})`);
    if (failed.length > 0) names.push(`${run.name} (rules not loaded: ${failed.map((fr) => fr.rule_id).join(', ')})`);
  }
  return names;
}

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

/**
 * The type of each finding of `scan`, in the terms of an orchestrated run's
 * children (sast / secrets / deps / iac), or null when it cannot be told.
 */
function typeResolver(storage: Storage, scan: ScanRecord): (f: Finding) => string | null {
  if (isOrchestratedFullScan(scan)) {
    const indexed = childrenOf(storage, scan)
      .filter((c): c is ChildRef & { row: ScanRecord } => c.row !== null)
      .map((c) => ({ type: c.type, index: indexFindings(storage.findings.listByScan(c.row.scan_id)) }));
    return (f) => indexed.find((c) => c.index.has(f))?.type ?? null;
  }
  if (isScriptEraFullScan(scan)) {
    return (f) => {
      const slot = scriptEraSlotOfFinding(f);
      // The script's Dockerfile pass is re-run today by scan_iac's
      // `trivy config` over the whole tree, the child an orchestrated run has.
      if (slot === 'containers') return 'iac';
      return slot === 'security_full' ? null : slot;
    };
  }
  return () => scan.scan_type;
}

/**
 * The bookkeeping that answers for findings like `f` in `scan` (`fType` is
 * `f`'s child type, in the terms of {@link typeResolver}, or null). For an
 * orchestrated run it is the child of that type's — null when that child is
 * missing or unfinished, which measured nothing — and, when the type cannot
 * be told, the run's merged bookkeeping.
 */
type BookFor = (fType: string | null) => Bookkeeping | null;

function booksOf(storage: Storage, scan: ScanRecord): BookFor {
  if (!isOrchestratedFullScan(scan)) {
    const book = bookkeepingOf(storage, scan);
    return () => book;
  }
  const children = childrenOf(storage, scan);
  return (fType) => {
    if (fType === null) return scan;
    const child = children.find((c) => c.type === fType);
    return child !== undefined && usableChild(child) ? child.row : null;
  };
}

/** Every pass without a target of its own looks at the project's files. */
const PROJECT_FILES = 'project files';

/**
 * What a pass looks at: its own target when it has one (`runNames.ts`:
 * `trivy-image` — an image, named by the pass, and which image by the run's
 * `target`, the reference it scanned), else the project's files. `ref` is
 * undefined for the project's files and for an image pass recorded before
 * the reference was (a legacy row).
 */
interface PassTarget {
  pass: string;
  ref?: string;
}

function targetOf(run: ToolRun): PassTarget {
  if (runNameEntry(run.name)?.ownTarget !== true) return { pass: PROJECT_FILES };
  if (run.target === undefined || run.target === '') return { pass: run.name };
  // A verification's target is the image AND the signer it was verified
  // against (`ToolRun.signer`): a pass for another signer did not ask the
  // question the older verdict answered.
  const signer = run.signer !== undefined ? `\0signer\0${run.signer}` : '';
  return { pass: run.name, ref: `${normalizeImageRef(run.target)}${signer}` };
}

/**
 * One image reference in the one spelling Docker resolves it to, so that
 * `nginx`, `nginx:latest` and `docker.io/library/nginx:latest` are one
 * target (fix round 1): the registry defaults to `docker.io`
 * (`index.docker.io` is the same registry), an official image on it gets
 * `library/`, and a reference with neither tag nor digest gets `:latest`.
 * The first path component is a registry only when it looks like a host
 * (a `.` or a `:` in it, or `localhost`) — Docker's own rule. Nothing else
 * is changed: `nginx:1.25` and `nginx@sha256:…` stay distinct targets.
 */
export function normalizeImageRef(ref: string): string {
  let name = ref.trim();
  let digest = '';
  const at = name.indexOf('@');
  if (at >= 0) {
    digest = name.slice(at);
    name = name.slice(0, at);
  }
  let tag = '';
  const colon = name.lastIndexOf(':');
  if (colon > name.lastIndexOf('/')) {
    tag = name.slice(colon);
    name = name.slice(0, colon);
  }
  const slash = name.indexOf('/');
  const first = slash >= 0 ? name.slice(0, slash) : '';
  const hasRegistry = slash >= 0 && (first.includes('.') || first.includes(':') || first === 'localhost');
  let registry = hasRegistry ? first : 'docker.io';
  let path = hasRegistry ? name.slice(slash + 1) : name;
  if (registry === 'index.docker.io' || registry === 'registry-1.docker.io') registry = 'docker.io';
  if (registry === 'docker.io' && !path.includes('/')) path = `library/${path}`;
  if (tag === '' && digest === '') tag = ':latest';
  return `${registry}/${path}${tag}${digest}`;
}

/**
 * The same target: the same pass, and — when BOTH runs recorded which image
 * — the same image. A legacy row that did not record it keeps the reading it
 * had before references were recorded (any run of the pass), so no stored
 * comparison changes; only two references that disagree tell images apart.
 */
function sameTarget(a: PassTarget, b: PassTarget): boolean {
  if (a.pass !== b.pass) return false;
  return a.ref === undefined || b.ref === undefined || a.ref === b.ref;
}

/** The name a pass that did not run again is reported under: `trivy-image (registry/app:1)`, as the run recorded it. */
function passLabel(run: ToolRun, target: PassTarget): string {
  if (target.ref === undefined) return run.name;
  const signer = run.signer !== undefined ? `, signer ${run.signer}` : '';
  return `${run.name} (${run.target ?? target.ref}${signer})`;
}

/**
 * A pass `holder` ran ok that may have produced `f` (it measures `f`'s key)
 * and whose TARGET `asked` did not look at — no pass of `asked` with that
 * target ran ok measuring the key — or null.
 *
 * `f` can share its key with passes that look elsewhere: an image's
 * misconfiguration and a Dockerfile's are both `trivy:config`, and the
 * finding does not say which pass produced it. So a finding is re-measured
 * only on every target that may have produced it, in BOTH directions: a
 * Dockerfile-only scan never looked at the image, and an image-only scan
 * never looked at the Dockerfile. The second direction was missing (Task
 * 24, probe H1): an image-only run resolved the Dockerfile's
 * misconfiguration, and in regression_alert that false resolution cancelled
 * a real new high. When the holder ran both passes the finding could be
 * either's, so only a scan that looked at both re-measures it. Two images
 * are two targets (follow-up X5): an image pass re-measures only the image
 * it scanned, so image B's scan never resolves image A's findings — reported
 * as `trivy-image (<image A>)`. A scan with no bookkeeping at all measured
 * everything, as everywhere else here.
 */
function targetNotRun(holder: Bookkeeping | null, asked: Bookkeeping, f: Finding): string | null {
  return holder === null ? null : targetNotRunForKey(holder, asked, findingKey(f));
}

/** {@link targetNotRun} for every finding under `key` — it depends on nothing else. */
function targetNotRunForKey(holder: Bookkeeping, asked: Bookkeeping, key: string): string | null {
  if (isEmptyBook(asked)) return null;
  for (const run of holder.tools_run) {
    if (!measuresKeyOk(run, key)) continue;
    const target = targetOf(run);
    if (!asked.tools_run.some((r) => measuresKeyOk(r, key) && sameTarget(targetOf(r), target))) return passLabel(run, target);
  }
  return null;
}

interface Answer {
  verdict: Verdict;
  /** For `not_run`: the name to report (the finding's tool, or the own-target pass). */
  notRun: string | null;
  /** `not_run` because `asked` did not look at the target of a pass that may have produced it. */
  byTarget: boolean;
}

/**
 * How `asked` answers for `f`, a finding of `holder` — `to` for a finding
 * of `from`, and the other way round — both already narrowed to `f`'s child.
 */
function answerFor(holder: Bookkeeping | null, asked: Bookkeeping | null, f: Finding): Answer {
  if (asked === null) return { verdict: 'unmeasured', notRun: null, byTarget: false };
  const verdict = bookkeepingVerdict(asked, f);
  if (verdict !== 'measured') return { verdict, notRun: verdict === 'not_run' ? f.tool : null, byTarget: false };
  const pass = targetNotRun(holder, asked, f);
  return pass === null ? { verdict, notRun: null, byTarget: false } : { verdict: 'not_run', notRun: pass, byTarget: true };
}

/**
 * Which of a scan's gaps {@link notMeasured} names: `any` — everything a
 * comparison against a NEWER scan treats as not re-measured, a scanner it
 * did not run included; `gaps` — only what it named and did not run ok,
 * which is all a REFERENCE (a baseline, the previous run) holds "not
 * previously measured".
 */
export type NotMeasuredScope = 'any' | 'gaps';

/**
 * What `scan` did not measure, for a caller to name — exactly the names
 * whose findings a comparison treats as unmeasured on the side `scope`
 * says, so a reader that promises "reported as not re-measured / not
 * previously measured" keeps the promise: the whole type of an orchestrated
 * run's missing, unfinished or blind child; the scan's own type when it
 * measured nothing at all; otherwise each bookkeeping name that failed or
 * is missing (`npm`, `guardian-dast:unanswered`, `pip-audit`), and — for
 * `any` — each one skipped with no gap recorded whose findings are then not
 * re-measured (`trivy` with no Dockerfile). A pass that was merely skipped
 * beside one that ran (no uncommitted files for gitleaks' working-tree pass)
 * is neither.
 */
export function notMeasured(storage: Storage, scan: ScanRecord, scope: NotMeasuredScope = 'any'): string[] {
  const out: string[] = [];
  const add = (x: string): void => {
    if (!out.includes(x)) out.push(x);
  };
  const gapsOf = (book: Bookkeeping, wholeType: string): void => {
    if (computeCoverage(book.tools_run, book.missing_tools) === 'none') {
      add(wholeType);
      return;
    }
    const names = [...book.tools_run.filter((t) => t.status !== 'ok').map((t) => t.name), ...book.missing_tools];
    for (const name of names) {
      if (scope === 'gaps') {
        if (isGap(book, name)) add(name);
        continue;
      }
      const keys = keysOfRun(name, false);
      if (keys === null || keys.length === 0 || keys.some((k) => keyVerdict(book, k) !== 'measured')) add(name);
    }
    // Files a run only partly parsed, rules it did not load: a gap on both sides (narrowGapOf).
    for (const name of narrowGapNames(book)) add(name);
  };
  if (!isOrchestratedFullScan(scan)) {
    gapsOf(bookkeepingOf(storage, scan), scan.scan_type);
    return out;
  }
  for (const child of childrenOf(storage, scan)) {
    if (!usableChild(child)) add(child.type);
    else gapsOf(child.row, child.type);
  }
  return out;
}

/**
 * A name the bookkeeping records as a gap: it failed, or is listed missing
 * without also having run ok (the retry shape, `keyVerdict`). Whatever it
 * speaks for then reads `unmeasured`, never `not_run`.
 */
function isGap(book: Bookkeeping, name: string): boolean {
  const as = (status: ToolRun['status']): boolean => book.tools_run.some((t) => t.name === name && t.status === status);
  return as('failed') || (book.missing_tools.includes(name) && !as('ok'));
}

export function compareScansFor(storage: Storage, from: ScanRecord, to: ScanRecord): ScanComparison {
  const typeOfFrom = typeResolver(storage, from);
  const typeOfTo = typeResolver(storage, to);
  const fromBooks = booksOf(storage, from);
  const toBooks = booksOf(storage, to);
  /** `to`'s answer for a finding of `from`. */
  const inTo = (f: Finding): Answer => {
    const t = typeOfFrom(f);
    return answerFor(fromBooks(t), toBooks(t), f);
  };
  /** `from`'s answer for a finding of `to`. */
  const inFrom = (f: Finding): Answer => {
    const t = typeOfTo(f);
    return answerFor(toBooks(t), fromBooks(t), f);
  };
  return {
    // Anything short of measured: the newer scan cannot resolve what it did
    // not look for, whether the scanner failed or did not run.
    isNotRemeasured: (f) => inTo(f).verdict !== 'measured',
    // Only a gap: a reference that did not run the scanner at all looked at
    // everything it had to, and the finding is new.
    isNotPreviouslyMeasured: (f) => inFrom(f).verdict === 'unmeasured',
    notRunByTo: (f) => inTo(f).notRun,
    notRunByFrom: (f) => inFrom(f).notRun,
    notMeasuredByTo: notMeasured(storage, to, 'any'),
    gapsByTo: notMeasured(storage, to, 'gaps'),
    notMeasuredByFrom: notMeasured(storage, from, 'gaps'),
  };
}

/** The part of a comparison every reader reports, with its caps. */
export interface ClassifiedDiff<T extends Finding> {
  new: T[];
  resolved: T[];
  unchanged: T[];
  notRemeasured: T[];
  notPreviouslyMeasured: T[];
  /** What `to` never ran, for `notRemeasured` findings: their tools (nuclei not requested) or passes (`trivy-image`). */
  notRunByTo: string[];
  /** What `from` never ran, for `new` findings that are new because of it (Bandit, the day Python was added). */
  notRunByFrom: string[];
}

/**
 * Classifies two scans' findings. Matching is by identity with the
 * fingerprint as the fallback (`indexFindings`); a finding present on both
 * sides is unchanged whatever the bookkeeping says.
 */
export function classifyDiff<T extends Finding>(
  check: ScanComparison,
  fromFindings: readonly T[],
  toFindings: readonly T[],
): ClassifiedDiff<T> {
  const fromIndex = indexFindings(fromFindings);
  const toIndex = indexFindings(toFindings);
  const out: ClassifiedDiff<T> = {
    new: [],
    resolved: [],
    unchanged: [],
    notRemeasured: [],
    notPreviouslyMeasured: [],
    notRunByTo: [],
    notRunByFrom: [],
  };
  const note = (list: string[], name: string | null): void => {
    if (name !== null && !list.includes(name)) list.push(name);
  };
  for (const f of toFindings) {
    if (fromIndex.has(f)) out.unchanged.push(f);
    else if (check.isNotPreviouslyMeasured(f)) out.notPreviouslyMeasured.push(f);
    else {
      out.new.push(f);
      note(out.notRunByFrom, check.notRunByFrom(f));
    }
  }
  for (const f of fromFindings) {
    if (toIndex.has(f)) continue;
    if (check.isNotRemeasured(f)) {
      out.notRemeasured.push(f);
      note(out.notRunByTo, check.notRunByTo(f));
    } else out.resolved.push(f);
  }
  return out;
}

/** What each side of a comparison did not measure, as a reader reports it. */
export interface MeasurementGaps {
  /** Everything the newer scan did not measure: its bookkeeping's gaps, then scanners it did not run. */
  byTo: string[];
  /** Of {@link byTo}, what the newer scan did not run (not requested, nothing to scan), rather than failed. */
  notRunByTo: string[];
  /** The reference's gaps: scanners it named and did not run ok. */
  byFrom: string[];
  /** Scanners the reference did not run at all, whose findings are therefore new. */
  notRunByFrom: string[];
}

export function measurementGaps(
  check: Pick<ScanComparison, 'notMeasuredByTo' | 'gapsByTo' | 'notMeasuredByFrom'>,
  d: Pick<ClassifiedDiff<Finding>, 'notRunByTo' | 'notRunByFrom'>,
): MeasurementGaps {
  const byTo = [...check.notMeasuredByTo, ...d.notRunByTo.filter((x) => !check.notMeasuredByTo.includes(x))];
  return {
    byTo,
    notRunByTo: byTo.filter((x) => !check.gapsByTo.includes(x)),
    byFrom: check.notMeasuredByFrom,
    notRunByFrom: d.notRunByFrom.filter((x) => !check.notMeasuredByFrom.includes(x)),
  };
}

/**
 * A human line for a response, or null when both scans measured everything
 * they ran. A scanner that failed is one to fix; one that did not run is not
 * — it was not requested, or had nothing to scan — so the two are worded
 * apart, and neither tells the reader to wait for a scanner that works.
 */
export function describeMeasurementGaps(from: ScanRecord, to: ScanRecord, gaps: MeasurementGaps): string | null {
  const parts: string[] = [];
  const failedByTo = gaps.byTo.filter((x) => !gaps.notRunByTo.includes(x));
  // A run that measured, with files it only partly parsed or rules that did
  // not load (`narrowGapNames`), neither failed nor is missing: said so.
  const narrowByTo = failedByTo.filter(isNarrowGapName);
  const brokenByTo = failedByTo.filter((x) => !isNarrowGapName(x));
  if (brokenByTo.length > 0) {
    parts.push(
      `Scan ${to.scan_id} did not measure ${brokenByTo.join(', ')} (it failed, or is not installed): ` +
        'earlier findings from it are reported as not re-measured, never as resolved — re-run once the scanner works.',
    );
  }
  if (narrowByTo.length > 0) {
    parts.push(
      `Scan ${to.scan_id} only partly measured ${narrowByTo.join(', ')}: earlier findings in those files, or of those ` +
        'rules, are reported as not re-measured, never as resolved — they are measured again once a run reads the ' +
        "whole file (Semgrep's parser cannot always, even on valid code) and loads the rule.",
    );
  }
  if (gaps.notRunByTo.length > 0) {
    parts.push(
      `Scan ${to.scan_id} did not run ${gaps.notRunByTo.join(', ')} (not requested, or nothing for it to scan): ` +
        'earlier findings from it are reported as not re-measured, never as resolved — run it again to re-measure them.',
    );
  }
  const narrowByFrom = gaps.byFrom.filter(isNarrowGapName);
  const brokenByFrom = gaps.byFrom.filter((x) => !isNarrowGapName(x));
  if (brokenByFrom.length > 0) {
    parts.push(
      `The reference scan ${from.scan_id} did not measure ${brokenByFrom.join(', ')} (it failed, or was not ` +
        'installed): findings from it are reported as not previously measured, never as new.',
    );
  }
  if (narrowByFrom.length > 0) {
    parts.push(
      `The reference scan ${from.scan_id} only partly measured ${narrowByFrom.join(', ')}: findings in those files, ` +
        'or of those rules, are reported as not previously measured, never as new.',
    );
  }
  if (gaps.notRunByFrom.length > 0) {
    parts.push(
      `The reference scan ${from.scan_id} did not run ${gaps.notRunByFrom.join(', ')} (not applicable, or not ` +
        'requested, then): findings from it are new.',
    );
  }
  return parts.length > 0 ? parts.join(' ') : null;
}
