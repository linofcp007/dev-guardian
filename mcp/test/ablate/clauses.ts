/**
 * Clause enumeration and removal for the ablation harness.
 *
 * ---- What a "clause" is here -------------------------------------------
 *
 * A Semgrep rule is a positive term plus a pile of qualifiers that narrow it:
 * `pattern-not`, `pattern-not-inside`, `pattern-not-regex`, `pattern-inside`,
 * `metavariable-regex`, `metavariable-type`, `metavariable-pattern`,
 * `metavariable-comparison` -- and, separately, the individual branches of a
 * `pattern-either`, which WIDEN rather than narrow. Ablation removes exactly
 * one of those at a time and re-measures. Everything in this file is pure:
 * text in, text out, no Semgrep, no filesystem.
 *
 * ---- Why clauses are named by BODY TEXT, never by line number -----------
 *
 * A previous hand-rolled ablation run over this repo's packs was thrown away
 * because someone edited a COMMENT in the pack while it ran. Every line below
 * the edit shifted, and since a block clause's first line is just
 * `- pattern-not-inside:` -- identical for all 86 of them in
 * `bugfix-java.yml` -- the single INERT verdict the run produced could not be
 * attributed to any clause. So identity here is:
 *
 *   rule id + clause kind + sha256 of the clause's own canonical JSON body
 *   (+ an occurrence ordinal, because `bugfix-java.yml` really does repeat
 *    `pattern-either: [$F, this.$F]` verbatim five times inside ONE rule)
 *
 * The structural path (`rules[3].patterns[2]`) is printed for orientation
 * only; nothing keys off it, and it is recomputed from a freshly parsed
 * document on every ablation.
 *
 * ---- Why removal goes through the YAML AST, not the source text ---------
 *
 * Splicing byte ranges out of the source means reconstructing where the `- `
 * marker and the trailing comments of a block clause begin and end, in a file
 * where clauses nest five deep. Deleting the node and re-serialising is the
 * same operation with none of that arithmetic. The cost is that
 * re-serialisation has to be trusted, so `harness.ts` does not trust it: it
 * scans the round-tripped-but-UNMODIFIED pack first and aborts unless it
 * produces exactly the same findings as the original file on disk.
 */

import { createHash } from 'node:crypto';
import { isMap, isNode, isScalar, isSeq, parseDocument } from 'yaml';

/** Keys whose pair is itself an ablatable clause. */
export const ABLATABLE_CLAUSE_KEYS = [
  'pattern-not',
  'pattern-not-inside',
  'pattern-not-regex',
  'pattern-inside',
  'metavariable-regex',
  'metavariable-type',
  'metavariable-pattern',
  'metavariable-comparison',
] as const;

export type ClauseKey = (typeof ABLATABLE_CLAUSE_KEYS)[number];
export type ClauseKind = ClauseKey | 'pattern-either-branch';

const ABLATABLE: ReadonlySet<string> = new Set<string>(ABLATABLE_CLAUSE_KEYS);

/**
 * Rule keys that carry prose or configuration rather than matching logic.
 * Not descended into, so a `metadata:` block that happens to contain a key
 * named `pattern-inside` can never be mistaken for a clause.
 */
const NON_MATCHING_KEYS: ReadonlySet<string> = new Set<string>([
  'id',
  'message',
  'severity',
  'languages',
  'metadata',
  'fix',
  'fix-regex',
  'paths',
  'options',
  'min-version',
  'max-version',
]);

/** A step in an address: a map key, or an index into a sequence. */
export type Step = string | number;
export type Address = readonly Step[];

export interface Clause {
  /** `- id:` of the rule this clause belongs to. */
  readonly ruleId: string;
  readonly kind: ClauseKind;
  /** Structural path, for orientation only. Identity is `hash`. */
  readonly path: string;
  /** Canonical one-line rendering of the clause's own YAML. */
  readonly body: string;
  /** First 12 hex of sha256(body). Stable across line moves. */
  readonly hash: string;
  /** 1-based ordinal among same-rule clauses with an identical body. */
  readonly occurrence: number;
  /** How many clauses in this rule share this body. 1 for most. */
  readonly occurrences: number;
  /** Opaque address used by {@link ablate}. */
  readonly address: Address;
}

export interface SkippedClause {
  readonly ruleId: string;
  readonly kind: ClauseKind;
  readonly path: string;
  readonly body: string;
  readonly reason: string;
}

export interface ClauseInventory {
  readonly clauses: readonly Clause[];
  readonly skipped: readonly SkippedClause[];
  /** Every `- id:` the pack declares, in source order. */
  readonly ruleIds: readonly string[];
}

export class AblationError extends Error {}

/** Human-readable name, used everywhere a clause is reported. */
export function clauseLabel(c: Clause): string {
  const ordinal = c.occurrences > 1 ? ` #${String(c.occurrence)}/${String(c.occurrences)}` : '';
  return `${c.kind}${ordinal} [${c.hash}] ${c.body}`;
}

function formatAddress(address: Address): string {
  let out = '';
  for (const step of address) {
    if (typeof step === 'number') out += `[${String(step)}]`;
    else out += out === '' ? step : `.${step}`;
  }
  return out;
}

/** Plain-JS view of a node, for canonical JSON rendering. */
function toPlain(node: unknown): unknown {
  if (isNode(node)) {
    const value: unknown = node.toJSON();
    return value;
  }
  return node;
}

function keyName(key: unknown): string | undefined {
  if (isScalar(key) && typeof key.value === 'string') return key.value;
  if (typeof key === 'string') return key;
  return undefined;
}

function sha(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex').slice(0, 12);
}

interface Draft {
  readonly ruleId: string;
  readonly kind: ClauseKind;
  readonly path: string;
  readonly body: string;
  readonly address: Address;
}

interface WalkState {
  ruleId: string;
  readonly drafts: Draft[];
  readonly skipped: SkippedClause[];
}

function emit(state: WalkState, kind: ClauseKind, address: Address, body: string): void {
  state.drafts.push({ ruleId: state.ruleId, kind, path: formatAddress(address), body, address });
}

function walk(node: unknown, address: Address, state: WalkState): void {
  if (isSeq(node)) {
    node.items.forEach((item, index) => {
      walk(item, [...address, index], state);
    });
    return;
  }
  if (!isMap(node)) return;

  for (const pair of node.items) {
    const key = keyName(pair.key);
    if (key === undefined || NON_MATCHING_KEYS.has(key)) continue;
    const child: unknown = pair.value;
    const childAddress: Address = [...address, key];

    if (key === 'pattern-either') {
      collectBranches(child, childAddress, state);
      continue;
    }
    if (ABLATABLE.has(key)) {
      emit(state, key as ClauseKey, childAddress, `${key}: ${JSON.stringify(toPlain(child))}`);
    }
    // Descend regardless: `pattern-not: { patterns: [...] }` hides a
    // `metavariable-comparison` two levels down, and deleting THAT is a
    // different experiment from deleting the `pattern-not` around it.
    walk(child, childAddress, state);
  }
}

function collectBranches(node: unknown, address: Address, state: WalkState): void {
  if (!isSeq(node)) return;
  const total = node.items.length;
  node.items.forEach((item, index) => {
    const itemAddress: Address = [...address, index];
    const body = JSON.stringify(toPlain(item));
    if (total < 2) {
      state.skipped.push({
        ruleId: state.ruleId,
        kind: 'pattern-either-branch',
        path: formatAddress(itemAddress),
        body,
        reason: 'sole branch of its pattern-either; removing it would empty the disjunction',
      });
    } else {
      emit(state, 'pattern-either-branch', itemAddress, body);
    }
    walk(item, itemAddress, state);
  });
}

/**
 * Enumerates every ablatable clause in a pack, in source order.
 *
 * Occurrence ordinals are assigned per (rule id, kind, body) so that the five
 * verbatim-identical `pattern-either` branches inside
 * `bugfix-java-null-safety-map-get-deref` stay individually nameable.
 */
export function enumerateClauses(source: string): ClauseInventory {
  const doc = parseDocument(source);
  const root: unknown = doc.contents;
  if (!isMap(root)) throw new AblationError('pack root is not a YAML mapping');
  const rules: unknown = root.get('rules', true);
  if (!isSeq(rules)) throw new AblationError('pack has no `rules:` sequence');

  const state: WalkState = { ruleId: '<unknown>', drafts: [], skipped: [] };
  const ruleIds: string[] = [];

  rules.items.forEach((rule, index) => {
    if (!isMap(rule)) return;
    const id: unknown = rule.get('id', false);
    state.ruleId = typeof id === 'string' ? id : `<rules[${String(index)}] has no id>`;
    ruleIds.push(state.ruleId);
    walk(rule, ['rules', index], state);
  });

  const counts = new Map<string, number>();
  for (const d of state.drafts) {
    const key = `${d.ruleId} ${d.kind} ${d.body}`;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  const seen = new Map<string, number>();
  const clauses: Clause[] = state.drafts.map((d) => {
    const key = `${d.ruleId} ${d.kind} ${d.body}`;
    const occurrence = (seen.get(key) ?? 0) + 1;
    seen.set(key, occurrence);
    return {
      ruleId: d.ruleId,
      kind: d.kind,
      path: d.path,
      body: d.body,
      hash: sha(d.body),
      occurrence,
      occurrences: counts.get(key) ?? 1,
      address: d.address,
    };
  });

  return { clauses, skipped: state.skipped, ruleIds };
}

function resolveNode(root: unknown, address: Address): unknown {
  let node: unknown = root;
  for (const step of address) {
    if (typeof step === 'number') {
      if (!isSeq(node)) return undefined;
      node = node.items[step];
    } else {
      if (!isMap(node)) return undefined;
      node = node.get(step, true);
    }
  }
  return node;
}

function detach(root: unknown, address: Address): void {
  const last = address[address.length - 1];
  if (last === undefined) throw new AblationError('cannot detach the document root');
  const where = formatAddress(address.slice(0, -1));
  const parent = resolveNode(root, address.slice(0, -1));
  if (typeof last === 'number') {
    if (!isSeq(parent)) throw new AblationError(`expected a sequence at ${where}`);
    parent.items.splice(last, 1);
    return;
  }
  if (!isMap(parent)) throw new AblationError(`expected a mapping at ${where}`);
  if (!parent.delete(last)) throw new AblationError(`no key ${last} at ${where}`);
}

/**
 * Removes containers the detach emptied. `- pattern-not: X` is a one-key map
 * inside a sequence item; deleting the key leaves `- {}`, which Semgrep
 * rejects, so the now-empty map has to go with it.
 */
function pruneEmptyAncestors(root: unknown, address: Address): void {
  for (let i = address.length - 1; i >= 1; i -= 1) {
    const ancestor = address.slice(0, i);
    const node = resolveNode(root, ancestor);
    if (isSeq(node)) {
      if (node.items.length > 0) return;
    } else if (isMap(node)) {
      if (node.items.length > 0) return;
    } else {
      return;
    }
    detach(root, ancestor);
  }
}

const RULE_ENTRY_POINTS = ['pattern', 'patterns', 'pattern-either', 'pattern-regex', 'mode'];

/**
 * Keys that MATCH something. Everything else in a `patterns:` group --
 * `pattern-not*`, `metavariable-*`, `focus-metavariable` -- only constrains
 * a match that some positive term produced.
 */
const POSITIVE_TERMS: ReadonlySet<string> = new Set<string>([
  'pattern',
  'patterns',
  'pattern-either',
  'pattern-regex',
  'pattern-inside',
]);

function hasPositiveTerm(seq: unknown): boolean {
  if (!isSeq(seq)) return false;
  return seq.items.some((item) => {
    if (!isMap(item)) return false;
    return item.items.some((pair) => {
      const key = keyName(pair.key);
      return key !== undefined && POSITIVE_TERMS.has(key);
    });
  });
}

/**
 * A `patterns:` group with nothing but conditions left in it is one of this
 * repo's five recorded ways for Semgrep to scan zero files while printing a
 * successful, empty result. The runtime `paths.scanned` gate in `semgrep.ts`
 * catches it, but it costs a scan and reports as an unexplained error; seeing
 * it here instead turns it into a named, up-front "this clause cannot be
 * removed on its own".
 */
function assertPositiveTermsSurvive(node: unknown, address: Address): void {
  if (isSeq(node)) {
    node.items.forEach((item, index) => {
      assertPositiveTermsSurvive(item, [...address, index]);
    });
    return;
  }
  if (!isMap(node)) return;
  for (const pair of node.items) {
    const key = keyName(pair.key);
    if (key === undefined) continue;
    const childAddress: Address = [...address, key];
    if (key === 'patterns' && !hasPositiveTerm(pair.value)) {
      throw new AblationError(
        `removing it would leave the patterns group at ${formatAddress(childAddress)} ` +
          `with only conditions and no positive term, which makes Semgrep scan nothing`,
      );
    }
    assertPositiveTermsSurvive(pair.value, childAddress);
  }
}

function assertNoEmptyCollections(node: unknown, address: Address): void {
  if (isSeq(node)) {
    if (node.items.length === 0) {
      throw new AblationError(`ablation left an empty sequence at ${formatAddress(address)}`);
    }
    node.items.forEach((item, index) => {
      assertNoEmptyCollections(item, [...address, index]);
    });
    return;
  }
  if (!isMap(node)) return;
  if (node.items.length === 0) {
    throw new AblationError(`ablation left an empty mapping at ${formatAddress(address)}`);
  }
  for (const pair of node.items) {
    const key = keyName(pair.key) ?? '?';
    assertNoEmptyCollections(pair.value, [...address, key]);
  }
}

function assertStillWellFormed(root: unknown): void {
  if (!isMap(root)) throw new AblationError('pack root is not a YAML mapping');
  const rules: unknown = root.get('rules', true);
  if (!isSeq(rules)) throw new AblationError('ablation removed the rules: sequence');
  for (const rule of rules.items) {
    if (!isMap(rule)) continue;
    const id: unknown = rule.get('id', false);
    const name = typeof id === 'string' ? id : '<unnamed rule>';
    if (!RULE_ENTRY_POINTS.some((k) => rule.has(k))) {
      throw new AblationError(`ablation left rule ${name} with no top-level pattern`);
    }
  }
  assertNoEmptyCollections(root, []);
  assertPositiveTermsSurvive(root, []);
}

/**
 * `lineWidth: 0` disables folding. Folded (`>-`) scalars re-wrap to the
 * serialiser's default width otherwise -- semantically identical, but it
 * makes a hand-inspected diff of the emitted config unreadable.
 */
const STRINGIFY = { lineWidth: 0 } as const;

/** The pack, parsed and re-serialised with nothing removed. The control. */
export function roundTrip(source: string): string {
  return parseDocument(source).toString(STRINGIFY);
}

/** The pack with exactly one clause removed. Throws {@link AblationError}. */
export function ablate(source: string, clause: Clause): string {
  return ablateAll(source, [clause]);
}

/** True when `outer` names an ancestor of (or the same node as) `inner`. */
export function containsAddress(outer: Address, inner: Address): boolean {
  if (outer.length > inner.length) return false;
  return outer.every((step, i) => step === inner[i]);
}

/**
 * Document order. Only the numeric steps matter -- removing a sequence item
 * shifts its later siblings, and nothing else -- but strings are ordered too
 * so the comparison is total and the sort is deterministic.
 */
function compareAddress(a: Address, b: Address): number {
  const shared = Math.min(a.length, b.length);
  for (let i = 0; i < shared; i += 1) {
    const x = a[i];
    const y = b[i];
    if (x === y) continue;
    if (typeof x === 'number' && typeof y === 'number') return x - y;
    return String(x) < String(y) ? -1 : 1;
  }
  return a.length - b.length;
}

/**
 * The pack with SEVERAL clauses removed at once.
 *
 * ---- Why this exists: the mutually-redundant pair ------------------------
 *
 * Single-clause ablation cannot see two clauses that exclude the same shape.
 * Each one alone is redundant with the other, so removing either changes
 * nothing and BOTH report DEAD -- while removing both together does change
 * the result. This repo has shipped that exact pair twice: `bugfix-go`'s
 * `type-assert-no-ok` carried two mutually redundant `pattern-not-inside`
 * clauses, and `err-discarded`'s `:=` branch was subsumed by its `=` branch.
 * Deleting either half is safe; deleting both is a regression, and a DEAD
 * verdict on its own does not tell you which situation you are in.
 *
 * ---- The two things that make it fiddly ---------------------------------
 *
 * Addresses are positions, and removing one node moves the others. Clauses
 * are therefore removed in DESCENDING document order: everything a removal
 * disturbs sits at an index at or after the divergence point, so every
 * address still to be processed -- all of them earlier -- stays valid.
 * Pruning happens per clause, immediately after its own detach, for the same
 * reason.
 *
 * And a pair where one clause CONTAINS the other is rejected rather than
 * measured: removing a `pattern-not` and the `metavariable-comparison` inside
 * it is just removing the `pattern-not`, which the single-clause pass already
 * did. It is not evidence of redundancy between two independent clauses.
 */
export function ablateAll(source: string, clauses: readonly Clause[]): string {
  if (clauses.length === 0) throw new AblationError('no clauses to ablate');
  for (const outer of clauses) {
    for (const inner of clauses) {
      if (outer !== inner && containsAddress(outer.address, inner.address)) {
        throw new AblationError(
          `${clauseLabel(outer)} encloses ${clauseLabel(inner)}; removing both is ` +
            `just removing the outer one, which the single-clause pass already measured`,
        );
      }
    }
  }
  const doc = parseDocument(source);
  const root: unknown = doc.contents;
  const descending = [...clauses].sort((x, y) => compareAddress(y.address, x.address));
  for (const clause of descending) {
    detach(root, clause.address);
    pruneEmptyAncestors(root, clause.address);
  }
  assertStillWellFormed(root);
  return doc.toString(STRINGIFY);
}
