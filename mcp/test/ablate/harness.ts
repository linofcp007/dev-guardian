/**
 * The three-axis ablation harness for `configs/semgrep/*.yml`.
 *
 * Ablation is: delete one clause, re-run the pack, see whether the result
 * moves. Six exclusion clauses that did nothing at all have shipped across
 * this repo's rule-pack series, and every one of them was written by someone
 * confident it was needed and found only by someone deleting it and watching
 * nothing change.
 *
 * ---- The three axes, and why there are three ----------------------------
 *
 * Each axis was added after a defect escaped the previous ones. All three run
 * on every clause.
 *
 *  1. LIVE. Removing the clause changes the result somewhere. A clause that
 *     changes nothing is dead weight and should be deleted from the pack,
 *     not kept "for symmetry".
 *
 *  2. KEEPS TRUE POSITIVES. Removing the clause must not REVEAL findings in
 *     `hits/` -- if it does, the clause was suppressing a fixture that exists
 *     precisely because it is a real bug. Added after four waves of
 *     false-positive closing silently ate true positives: `pattern-not-inside`
 *     excludes the whole node it matched, so a guard written for an `if` also
 *     suppressed the `else` arm, where the bug was.
 *
 *  3. NO ADDED NOISE ON REAL CODE. Scan a corpus nobody wrote as a fixture --
 *     for the JS/TS pack, this repo's own `mcp/src` -- and compare THE ABLATED
 *     RULE'S OWN findings before and after, on the files both scans finished.
 *     If removing the clause LOWERS that count, the clause was adding those
 *     findings to real code. This is the newest axis and it caught what the
 *     other two could not: a wave added a `RegExp#exec` branch to
 *     `unchecked-match` and forgot the `?.` exclusion its sibling branch had,
 *     taking that rule from 0 to 13 false positives on our own TypeScript.
 *     Axes 1 and 2 BOTH passed -- "the clause is live" and "it does not
 *     reduce true positives" are both true of a clause that only adds false
 *     positives.
 *
 *     Both scopings are load-bearing and both were bought with a defect. The
 *     axis originally subtracted whole-corpus totals, which cannot attribute
 *     anything -- 14 findings were once reported against clauses of
 *     `modify-during-iteration` and every one of them belonged to
 *     `empty-catch` -- and jitters by more than the deltas it reports. See
 *     `axis3.ts`, which holds the measurements and the reasoning.
 *
 * Axis 3 is a property of the invocation, not of the code: a pack gets a real
 * corpus if one exists in a language it matches (see `packs.ts`). Where none
 * does, axis 3 reports N/A rather than being quietly skipped. Where one exists
 * but is too noisy to resolve a clause's delta, the clause reads INCONCLUSIVE
 * -- also never a pass.
 *
 * ---- Axis 0, and the rules the other three axes cannot see ---------------
 *
 * The three axes above are properties of a CLAUSE, so a rule with no clauses
 * -- a bare `pattern:`, or a `patterns:` group of nothing but positive terms
 * -- has no verdict on any of them. It used to have no line in the report
 * either, which made `52/52 live` read as "the pack was checked" when a
 * quarter of the rules in this repo's packs had never been ablated because
 * there was nothing in them to ablate. Nothing was missing from the harness;
 * the count was lying about what it covered.
 *
 * Axis 0 is the one check every rule can have, clauses or not:
 *
 *  0. FIRES ON hits/. The rule produces at least one baseline finding in the
 *     fixture directory built to contain the bugs it is for. A rule that
 *     matches nothing is this repo's sixth recorded silent failure: the C#
 *     pack shipped `foreach ($T $X in $C)` where `foreach (var $X in $C)` was
 *     needed, and it found 0 of 5 real bugs with `paths.scanned` healthy,
 *     zero errors and every gate green. A rule ported by textual analogy
 *     finds nothing and nothing complains.
 *
 * It costs no extra Semgrep run -- the baseline fixture scan is already
 * there -- and it applies to every rule in the pack, not only the clauseless
 * ones. Where the fixture root has no `hits/` subdirectory at all it reports
 * N/A for the whole pack, on the same principle as axis 3: never a silent
 * skip.
 *
 * ---- The noise floor -----------------------------------------------------
 *
 * `paths.scanned` cannot see the thing that makes real-code counts move. It
 * counts files OPENED, not files finished, and semgrep-core's per-rule timeout
 * abandons rules on the slowest files without touching it. So the real corpus
 * is scanned TWICE at baseline -- once with the pack on disk, once with the
 * round-trip of it that every ablated variant descends from, which is the same
 * rules in different bytes. Any per-rule disagreement between those two is
 * measurement error by construction, it is printed as the pack's noise floor,
 * and no clause delta at or below its rule's floor is allowed to become a
 * verdict. Measured floor on every corpus here so far: 0.
 *
 * ---- Byte-identity of the pack ------------------------------------------
 *
 * The strongest available guarantee that the pack is unchanged after a run,
 * a crash or a Ctrl-C is that nothing ever writes to it. So nothing does: the
 * source is read ONCE into memory and hashed, ablated variants are serialised
 * to a temp directory, and Semgrep is pointed at those. The on-disk hash is
 * re-checked before every single ablation, which also catches the hazard that
 * discarded a previous run -- somebody editing the pack while it was going.
 */

import { cpSync, existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { writeFileSync } from 'node:fs';
import { AblationError, ablate, ablateAll, enumerateClauses, roundTrip } from './clauses.js';
import type { Clause, SkippedClause } from './clauses.js';
import { SemgrepFailure, findingsMissingFrom, sameFindings, scan, under } from './semgrep.js';
import type { Finding, ScanResult } from './semgrep.js';
import {
  axis3Verdict,
  comparable,
  comparableAll,
  noiseFloorByRule,
  noisyRules,
  scopeOf,
  worstFloor,
} from './axis3.js';
import type { Axis3Scope } from './axis3.js';

export interface RealCorpus {
  /** Short name printed in the report, e.g. `mcp/src`. */
  readonly label: string;
  /** Absolute path to a directory of code nobody wrote as a fixture. */
  readonly dir: string;
}

export interface PackSpec {
  readonly name: string;
  /** Absolute path to the pack under `configs/semgrep/`. */
  readonly config: string;
  /** Absolute path to the fixture root holding `hits/` and `misses/`. */
  readonly fixtures: string;
  /** Subdirectory of `fixtures` whose findings are true positives. */
  readonly hitsSubdir: string;
  /** Axis 3 corpus. Absent = axis 3 is N/A for this pack. */
  readonly realCode?: RealCorpus;
}

/**
 * `INCONCLUSIVE` is only ever produced by axis 3, and only when the corpus's
 * own measured noise floor swallows the delta. It is deliberately not a pass:
 * the run still exits non-zero, because "we could not tell" is a result the
 * reader has to see.
 */
export type Verdict = 'PASS' | 'FAIL' | 'N/A' | 'ERROR' | 'INCONCLUSIVE';

export interface ClauseVerdict {
  readonly clause: Clause;
  /** PASS = the clause is live. FAIL = DEAD, it changes nothing anywhere. */
  readonly live: Verdict;
  /** Corpora whose findings moved when the clause was removed. */
  readonly movedIn: readonly string[];
  /** Signed change in fixture finding count: ablated minus baseline. */
  readonly fixtureDelta: number;
  /** PASS = removing it revealed nothing in `hits/`. */
  readonly keepsTruePositives: Verdict;
  readonly revealedInHits: readonly Finding[];
  /**
   * PASS = removing it did not lower THIS RULE'S real-code count.
   * INCONCLUSIVE = it moved, but by no more than the rule's noise floor.
   */
  readonly noAddedNoise: Verdict;
  /**
   * Signed change in this rule's real-code count on the comparable files, or
   * null when axis 3 is N/A. Not the pack's total: a clause cannot move a
   * count that belongs to another rule, and the pack total is dominated by
   * timeout jitter in rules the clause has nothing to do with.
   */
  readonly realDelta: number | null;
  /** Real-code findings of this clause's own rule that the clause adds. */
  readonly addedByClause: readonly Finding[];
  /** This rule's measured noise floor; a delta must clear it to be a verdict. */
  readonly realFloor: number | null;
  /** Files some scan in this comparison did not finish, so both sides drop them. */
  readonly realExcludedFiles: number | null;
  readonly error: string | undefined;
  readonly seconds: number;
}

/**
 * Two clauses that ablate to the SAME pack. The commonest shape by far is a
 * `pattern-either` branch whose entire body is one clause:
 *
 *     - pattern-either:
 *         - pattern-inside: async function $F(...) { ... }
 *
 * Removing the branch and removing the `pattern-inside` inside it are the
 * same experiment -- deleting the inner pair empties the branch map, and
 * pruning then takes the branch with it. Running both costs a Semgrep pass
 * and produces two identical verdicts that look like independent evidence.
 */
export interface CollapsedClause {
  readonly clause: Clause;
  readonly sameAs: Clause;
}

/**
 * The second pass, over DEAD clauses only. Two clauses in the same rule that
 * exclude the same shape are each redundant with the other, so each one alone
 * reads DEAD -- and removing BOTH still changes the result. `MOVES` here means
 * the pair is mutually redundant: delete either half, never both.
 *
 * Restricted to same-rule pairs because rules are independent -- a clause in
 * one rule cannot mask a clause in another -- and to the DEAD set because
 * that is where the ambiguity lives, which keeps this a handful of extra
 * scans rather than a cross product.
 */
export interface PairVerdict {
  readonly ruleId: string;
  readonly a: Clause;
  readonly b: Clause;
  /** 'MOVES' = mutually redundant. 'INERT' = both really are dead weight. */
  readonly outcome: 'MOVES' | 'INERT' | 'ERROR';
  readonly fixtureDelta: number;
  readonly realDelta: number | null;
  readonly error: string | undefined;
}

/**
 * The per-RULE line of the report. Every rule in the pack gets one, including
 * every rule that has nothing to ablate -- that is the point of the type.
 *
 * `ablatedClauses === 0` is never a silence here: either `noClausesReason`
 * says why the rule has no clauses, or the clauses it has were filtered out
 * of this invocation, collapsed as duplicates, or skipped as load-bearing.
 */
export interface RuleVerdict {
  readonly ruleId: string;
  /** Ablatable clauses the pack declares in this rule. */
  readonly enumeratedClauses: number;
  /** Of those, the ones this run actually removed and measured. */
  readonly ablatedClauses: number;
  /** Set exactly when `enumeratedClauses === 0`: why there is nothing here. */
  readonly noClausesReason: string | undefined;
  /** Baseline findings this rule produced under `hits/`. */
  readonly hitsFindings: number;
  /** Axis 0. PASS = fires at least once in hits/. N/A = no hits corpus. */
  readonly firesOnHits: Verdict;
}

export interface PackReport {
  readonly pack: string;
  readonly configPath: string;
  readonly configSha256: string;
  readonly ruleCount: number;
  /** Rules that declare at least one ablatable clause. */
  readonly rulesWithClauses: number;
  readonly rules: readonly RuleVerdict[];
  readonly clauseCount: number;
  readonly skipped: readonly SkippedClause[];
  readonly collapsed: readonly CollapsedClause[];
  readonly fixtureCorpus: string;
  readonly realCorpus: string | null;
  readonly baselineFixtures: number;
  readonly baselineHits: number;
  /** Every baseline finding on the real corpus, comparable or not. */
  readonly baselineReal: number | null;
  /** Of those, the ones on files the baseline scans finished. */
  readonly baselineRealComparable: number | null;
  /** Files excluded from every axis-3 comparison in this run's baseline. */
  readonly realExcludedFiles: number | null;
  /**
   * The worst per-rule disagreement between two baseline scans of the SAME
   * rules over the same corpus. 0 means axis 3 can resolve a delta of 1.
   */
  readonly realNoiseFloor: number | null;
  /** The rules that disagreed, if any, worst first. Empty when the floor is 0. */
  readonly realNoisyRules: readonly { readonly ruleId: string; readonly drift: number }[];
  /** Aborts that named no file, so nothing could be excluded for them. */
  readonly realUnscopedAborts: number | null;
  readonly verdicts: readonly ClauseVerdict[];
  readonly pairs: readonly PairVerdict[];
  readonly seconds: number;
}

export interface RunOptions {
  readonly semgrepBin: string;
  /** Streamed so an interrupted run still leaves usable output. */
  readonly log: (line: string) => void;
  /** Optional substring filter over rule id, clause body, kind and hash. */
  readonly filter?: string | undefined;
  /** Registers a temp dir for the caller to clean up on exit or signal. */
  readonly registerTempDir?: ((dir: string) => void) | undefined;
}

export function sha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function matchesFilter(c: Clause, filter: string): boolean {
  const needle = filter.toLowerCase();
  return (
    c.ruleId.toLowerCase().includes(needle) ||
    c.kind.toLowerCase().includes(needle) ||
    c.body.toLowerCase().includes(needle) ||
    c.hash.toLowerCase().includes(needle)
  );
}

/** Reads the pack from disk and hashes it, without holding the file open. */
function readPack(config: string): { source: string; hash: string } {
  const source = readFileSync(config, 'utf8');
  return { source, hash: sha256(source) };
}

export function runPack(spec: PackSpec, options: RunOptions): PackReport {
  const started = Date.now();
  const { source, hash } = readPack(spec.config);
  const inventory = enumerateClauses(source);

  const work = mkdtempSync(join(tmpdir(), `guardian-ablate-${spec.name}-`));
  options.registerTempDir?.(work);

  // Semgrep's default ignore list skips any path with a `test/` segment, and
  // every fixture in this repo lives under `mcp/test/fixtures`. Pointed
  // straight at them Semgrep reports `paths.scanned: []`, which the scan gate
  // turns into an exception rather than a silent zero.
  const fixtures = join(work, 'fixtures');
  cpSync(spec.fixtures, fixtures, { recursive: true });

  const configPath = join(work, `${spec.name}.yml`);
  const write = (text: string): string => {
    writeFileSync(configPath, text, 'utf8');
    return configPath;
  };

  const scanFixtures = (cfg: string): readonly Finding[] =>
    scan({ bin: options.semgrepBin, config: cfg, target: fixtures, root: fixtures }).findings;
  const real = spec.realCode;
  const EMPTY_SCAN: ScanResult = {
    findings: [],
    scanned: 0,
    errors: [],
    abortedFiles: [],
    unscopedAborts: 0,
  };
  // The whole ScanResult, not just the findings: axis 3 needs `abortedFiles`
  // to know which files this scan may be compared on at all.
  const scanReal = (cfg: string): ScanResult =>
    real === undefined
      ? EMPTY_SCAN
      : scan({ bin: options.semgrepBin, config: cfg, target: real.dir, root: real.dir });

  // Axis 0 needs a `hits/` corpus the way axis 3 needs a real-code one, and
  // reports N/A on the same terms when there is none rather than passing
  // every rule by default. `routes.yml` is the pack that would land here.
  const hitsCorpus = existsSync(join(spec.fixtures, spec.hitsSubdir));

  const withClauses = inventory.rules.filter((r) => r.clauseCount > 0).length;
  options.log(`pack        ${spec.name}`);
  options.log(`config      ${spec.config}`);
  options.log(`sha256      ${hash}`);
  options.log(
    `rules       ${String(inventory.rules.length)}` +
      ` (${String(withClauses)} with ablatable clauses, ` +
      `${String(inventory.rules.length - withClauses)} with none)`,
  );
  options.log(`fixtures    ${spec.fixtures}`);
  options.log(`real code   ${real === undefined ? '(none -- axis 3 is N/A for this pack)' : real.label}`);

  // ---- Control: the pack as it sits on disk, then the same pack parsed and
  // re-serialised with nothing removed. Every ablated variant is produced by
  // the second code path, so if the two disagree the whole run is measuring
  // the serialiser rather than the rules, and there is no point continuing.
  const onDisk = scanFixtures(spec.config);
  const baselineFixtures = scanFixtures(write(roundTrip(source)));
  if (!sameFindings(onDisk, baselineFixtures)) {
    throw new Error(
      `round-trip control FAILED for ${spec.name}: re-serialising the pack with ` +
        `nothing removed changed the findings on the fixture corpus ` +
        `(${String(onDisk.length)} -> ${String(baselineFixtures.length)}). ` +
        `Every ablation would be measuring the YAML serialiser, not the rules.`,
    );
  }
  const baselineHits = under(baselineFixtures, spec.hitsSubdir);

  // ---- The real corpus gets the same control, and it doubles as the noise
  // floor. Two scans of the same rules over the same code: `spec.config` as it
  // sits on disk, and the round-trip in the temp dir that every ablated
  // variant descends from. They must agree per rule once the unfinished files
  // are out; whatever they do not agree about is the measurement error, and
  // no clause delta below it is allowed to become a verdict.
  //
  // Unlike the fixture control this does NOT abort on a disagreement. On a
  // large corpus a disagreement is expected to be timeouts, which is a
  // property of the machine rather than of the pack; aborting would make the
  // harness unusable on exactly the corpora it is most needed for. It is
  // measured, printed, and folded into the verdicts instead.
  const controlReal = scanReal(spec.config);
  const baselineRealScan = scanReal(configPath);
  const baselineScope = scopeOf([controlReal, baselineRealScan]);
  const baselineReal = baselineRealScan.findings;
  const floorByRule = noiseFloorByRule(
    controlReal.findings,
    baselineReal,
    inventory.ruleIds,
    baselineScope,
  );
  const packFloor = worstFloor(floorByRule);

  options.log(`baseline    ${String(baselineFixtures.length)} findings on fixtures ` +
    `(${String(baselineHits.length)} in ${spec.hitsSubdir}/)` +
    (real === undefined ? '' : `, ${String(baselineReal.length)} on ${real.label}`));
  options.log(`control     round-trip of the unmodified pack reproduces the on-disk result exactly`);
  if (real !== undefined) {
    const comparableBaseline = comparableAll(baselineReal, baselineScope).length;
    options.log(
      `real scope  ${String(comparableBaseline)}/${String(baselineReal.length)} baseline findings comparable; ` +
        `${String(baselineScope.excludedFiles)} file(s) excluded (a rule was abandoned on them for time or memory)`,
    );
    options.log(
      `noise floor ${String(packFloor)} -- two scans of the identical pack over ${real.label} ` +
        (packFloor === 0
          ? 'agreed on every rule'
          : `disagreed by up to ${String(packFloor)} finding(s) on one rule; ` +
            `any clause delta at or below its rule's floor reads INCONCLUSIVE`),
    );
    for (const n of noisyRules(floorByRule)) {
      options.log(`  NOISY   ${n.ruleId} -- control scans differ by ${String(n.drift)} finding(s)`);
    }
    if (baselineScope.unscopedAborts > 0) {
      options.log(
        `  WARNING ${String(baselineScope.unscopedAborts)} abort(s) named no file, so nothing could be ` +
          `excluded for them. Axis 3 on this run is weaker than its floor suggests.`,
      );
    }
  }

  // Axis 3 is now scoped BY RULE ID, so if a real-code finding's rule id stops
  // lining up with the pack's `- id:` values, every clause compares an empty
  // set against an empty set and the axis passes everything by construction --
  // the same silent all-clear the axis-0 guard below refuses on the fixture
  // corpus. It has to be asked separately because the corpora are different
  // and Semgrep derives `check_id` from the config PATH, which differs between
  // the on-disk pack and the temp-dir variants.
  if (
    real !== undefined &&
    baselineReal.length > 0 &&
    !baselineReal.some((f) => inventory.ruleIds.includes(f.ruleId))
  ) {
    throw new Error(
      `none of the ${String(baselineReal.length)} baseline findings on ${real.label} ` +
        `carry a rule id this pack declares (got e.g. \`${baselineReal[0]?.ruleId ?? ''}\`). ` +
        `Axis 3 would compare empty sets and pass every clause. Aborting.`,
    );
  }

  const selected = options.filter === undefined
    ? inventory.clauses
    : inventory.clauses.filter((c) => matchesFilter(c, options.filter ?? ''));

  // Pre-pass: build every ablated variant up front (pure, no Semgrep) and
  // collapse the ones that produce an identical pack. See `CollapsedClause`.
  const prepared: { readonly clause: Clause; readonly variant: string | undefined; readonly error: string | undefined }[] = [];
  const byVariant = new Map<string, Clause>();
  const collapsed: CollapsedClause[] = [];
  const skipped: SkippedClause[] = [...inventory.skipped];
  for (const clause of selected) {
    try {
      const variant = ablate(source, clause);
      const key = sha256(variant);
      const prior = byVariant.get(key);
      if (prior !== undefined) {
        collapsed.push({ clause, sameAs: prior });
        continue;
      }
      byVariant.set(key, clause);
      prepared.push({ clause, variant, error: undefined });
    } catch (err) {
      // An `AblationError` means the experiment is not expressible, not that
      // it failed: the clause is structurally load-bearing (its removal
      // leaves a group with no positive term, or a rule with no pattern at
      // all). That is a skip with a stated reason, listed in the report --
      // never a silent omission, and never an error count.
      if (err instanceof AblationError) {
        skipped.push({
          ruleId: clause.ruleId,
          kind: clause.kind,
          path: clause.path,
          body: clause.body,
          reason: err.message,
        });
        continue;
      }
      prepared.push({ clause, variant: undefined, error: err instanceof Error ? err.message : String(err) });
    }
  }

  options.log(`clauses     ${String(prepared.length)} to ablate` +
    (options.filter === undefined ? '' : ` (filtered from ${String(inventory.clauses.length)})`) +
    (collapsed.length === 0 ? '' : `, ${String(collapsed.length)} collapsed as duplicate ablations`) +
    (skipped.length === 0 ? '' : `, ${String(skipped.length)} not ablatable in isolation`));

  // ---- Axis 0, computed off the baseline scan that has already run.
  const ablatedPerRule = new Map<string, number>();
  for (const { clause } of prepared) {
    ablatedPerRule.set(clause.ruleId, (ablatedPerRule.get(clause.ruleId) ?? 0) + 1);
  }
  const hitsPerRule = new Map<string, number>();
  for (const f of baselineHits) hitsPerRule.set(f.ruleId, (hitsPerRule.get(f.ruleId) ?? 0) + 1);

  // A finding's rule id is the last dot-segment of Semgrep's `check_id`. If
  // that stops lining up with the pack's `- id:` values -- a rule id
  // containing a dot would do it -- every rule reads "fires on nothing" and
  // axis 0 becomes noise indistinguishable from the defect it hunts.
  if (baselineHits.length > 0 && !baselineHits.some((f) => inventory.ruleIds.includes(f.ruleId))) {
    throw new Error(
      `none of the ${String(baselineHits.length)} baseline findings in ${spec.hitsSubdir}/ ` +
        `carry a rule id this pack declares (got e.g. \`${baselineHits[0]?.ruleId ?? ''}\`). ` +
        `Axis 0 would report every rule as firing on nothing. Aborting.`,
    );
  }

  const ruleVerdicts: RuleVerdict[] = inventory.rules.map((r) => {
    const hits = hitsPerRule.get(r.ruleId) ?? 0;
    return {
      ruleId: r.ruleId,
      enumeratedClauses: r.clauseCount,
      ablatedClauses: ablatedPerRule.get(r.ruleId) ?? 0,
      noClausesReason: r.noClausesReason,
      hitsFindings: hits,
      firesOnHits: !hitsCorpus ? 'N/A' : hits > 0 ? 'PASS' : 'FAIL',
    };
  });
  const silent = ruleVerdicts.filter((r) => r.firesOnHits === 'FAIL');
  options.log(
    `axis 0      ` +
      (!hitsCorpus
        ? `N/A -- ${spec.hitsSubdir}/ does not exist under the fixture root, so ` +
          `"does this rule fire at all?" cannot be asked here`
        : `${String(ruleVerdicts.length - silent.length)}/${String(ruleVerdicts.length)} rules ` +
          `fire at least once in ${spec.hitsSubdir}/` +
          (silent.length === 0 ? '' : `, ${String(silent.length)} FIRE ON NOTHING`)),
  );
  for (const r of silent) {
    options.log(`  SILENT  ${spec.name} :: ${r.ruleId} -- 0 findings in ${spec.hitsSubdir}/`);
  }
  options.log('');

  const verdicts: ClauseVerdict[] = [];
  let index = 0;
  for (const { clause, variant, error: prepError } of prepared) {
    index += 1;
    const clauseStarted = Date.now();

    // Re-read and re-hash before every ablation. Cheap next to a Semgrep run,
    // and it catches the failure that discarded the previous ablation effort:
    // the pack being edited underneath a run in progress.
    const current = readPack(spec.config);
    if (current.hash !== hash) {
      throw new Error(
        `${spec.config} changed on disk mid-run (${hash} -> ${current.hash}). ` +
          `Every verdict after the edit would be measuring a different file. Aborting.`,
      );
    }

    let verdict: ClauseVerdict;
    try {
      if (variant === undefined) throw new AblationError(prepError ?? 'clause could not be removed');
      write(variant);
      const ablatedFixtures = scanFixtures(configPath);
      const ablatedReal = scanReal(configPath);

      // Both real-code comparisons -- axis 1's and axis 3's -- are made on the
      // ablated rule's own findings, over the files every scan in the
      // comparison finished. Axis 1 needs it as much as axis 3 does: a clause
      // of rule A cannot move rule B's findings, so an unscoped comparison
      // turns any timeout jitter anywhere in the pack into "this clause is
      // live". That is what made two runs of the same pack disagree on 6 of 12
      // clause verdicts.
      const scope: Axis3Scope = scopeOf([controlReal, baselineRealScan, ablatedReal]);
      const baseForRule = comparable(baselineReal, clause.ruleId, scope);
      const ablatedForRule = comparable(ablatedReal.findings, clause.ruleId, scope);

      const fixturesMoved = !sameFindings(baselineFixtures, ablatedFixtures);
      const realMoved = real !== undefined && !sameFindings(baseForRule, ablatedForRule);
      const movedIn: string[] = [];
      if (fixturesMoved) movedIn.push('fixtures');
      if (realMoved && real !== undefined) movedIn.push(real.label);

      const revealedInHits = findingsMissingFrom(
        under(ablatedFixtures, spec.hitsSubdir),
        baselineHits,
      );
      const addedByClause = real === undefined ? [] : findingsMissingFrom(baseForRule, ablatedForRule);
      const floor = floorByRule.get(clause.ruleId) ?? 0;

      verdict = {
        clause,
        live: movedIn.length > 0 ? 'PASS' : 'FAIL',
        movedIn,
        fixtureDelta: ablatedFixtures.length - baselineFixtures.length,
        keepsTruePositives: revealedInHits.length === 0 ? 'PASS' : 'FAIL',
        revealedInHits,
        noAddedNoise: real === undefined ? 'N/A' : axis3Verdict(addedByClause.length, floor),
        realDelta: real === undefined ? null : ablatedForRule.length - baseForRule.length,
        addedByClause,
        realFloor: real === undefined ? null : floor,
        realExcludedFiles: real === undefined ? null : scope.excludedFiles,
        error: undefined,
        seconds: (Date.now() - clauseStarted) / 1000,
      };
    } catch (err) {
      const message =
        err instanceof AblationError || err instanceof SemgrepFailure
          ? err.message
          : err instanceof Error
            ? err.message
            : String(err);
      verdict = {
        clause,
        live: 'ERROR',
        movedIn: [],
        fixtureDelta: 0,
        keepsTruePositives: 'ERROR',
        revealedInHits: [],
        noAddedNoise: 'ERROR',
        realDelta: null,
        addedByClause: [],
        realFloor: null,
        realExcludedFiles: null,
        error: message,
        seconds: (Date.now() - clauseStarted) / 1000,
      };
    }

    verdicts.push(verdict);
    options.log(progressLine(spec.name, index, prepared.length, verdict));
  }

  // ---- Second pass: the mutually-redundant pairs the first pass cannot see.
  const pairs: PairVerdict[] = [];
  const deadByRule = new Map<string, Clause[]>();
  for (const v of verdicts) {
    if (v.live !== 'FAIL') continue;
    const list = deadByRule.get(v.clause.ruleId);
    if (list) list.push(v.clause);
    else deadByRule.set(v.clause.ruleId, [v.clause]);
  }
  const pairCount = [...deadByRule.values()].reduce((n, cs) => n + (cs.length * (cs.length - 1)) / 2, 0);
  if (pairCount > 0) {
    options.log('');
    options.log(`pairs       ${String(pairCount)} same-rule DEAD pair(s) to re-ablate together`);
  }
  for (const [ruleId, dead] of deadByRule) {
    for (let i = 0; i < dead.length; i += 1) {
      for (let j = i + 1; j < dead.length; j += 1) {
        const a = dead[i];
        const b = dead[j];
        if (a === undefined || b === undefined) continue;
        let pair: PairVerdict;
        try {
          write(ablateAll(source, [a, b]));
          const ablatedFixtures = scanFixtures(configPath);
          const ablatedReal = scanReal(configPath);
          // Same scoping as the single-clause pass, and for the same reason:
          // both clauses belong to `ruleId`, so nothing outside it is evidence.
          const scope: Axis3Scope = scopeOf([controlReal, baselineRealScan, ablatedReal]);
          const baseForRule = comparable(baselineReal, ruleId, scope);
          const ablatedForRule = comparable(ablatedReal.findings, ruleId, scope);
          const moved =
            !sameFindings(baselineFixtures, ablatedFixtures) ||
            (real !== undefined && !sameFindings(baseForRule, ablatedForRule));
          pair = {
            ruleId,
            a,
            b,
            outcome: moved ? 'MOVES' : 'INERT',
            fixtureDelta: ablatedFixtures.length - baselineFixtures.length,
            realDelta: real === undefined ? null : ablatedForRule.length - baseForRule.length,
            error: undefined,
          };
        } catch (err) {
          pair = {
            ruleId,
            a,
            b,
            outcome: 'ERROR',
            fixtureDelta: 0,
            realDelta: null,
            error: err instanceof Error ? err.message : String(err),
          };
        }
        pairs.push(pair);
        options.log(
          `  pair  ${pair.outcome.padEnd(5, ' ')} ${ruleId} :: [${a.hash}] + [${b.hash}]` +
            (pair.error === undefined ? '' : ` -- ${pair.error.split('\n')[0] ?? ''}`),
        );
      }
    }
  }

  const after = readPack(spec.config);
  if (after.hash !== hash) {
    throw new Error(`${spec.config} is not byte-identical after the run (${hash} -> ${after.hash}).`);
  }

  return {
    pack: spec.name,
    configPath: spec.config,
    configSha256: hash,
    ruleCount: inventory.rules.length,
    rulesWithClauses: withClauses,
    rules: ruleVerdicts,
    clauseCount: prepared.length,
    skipped,
    collapsed,
    fixtureCorpus: spec.fixtures,
    realCorpus: real?.label ?? null,
    baselineFixtures: baselineFixtures.length,
    baselineHits: baselineHits.length,
    baselineReal: real === undefined ? null : baselineReal.length,
    baselineRealComparable:
      real === undefined ? null : comparableAll(baselineReal, baselineScope).length,
    realExcludedFiles: real === undefined ? null : baselineScope.excludedFiles,
    realNoiseFloor: real === undefined ? null : packFloor,
    realNoisyRules: real === undefined ? [] : noisyRules(floorByRule),
    realUnscopedAborts: real === undefined ? null : baselineScope.unscopedAborts,
    verdicts,
    pairs,
    seconds: (Date.now() - started) / 1000,
  };
}

/**
 * One self-describing line per clause, streamed as the run goes so that an
 * interrupted run still leaves usable evidence. It carries every field the
 * report needs to be attributable months later: the pack, the rule id, the
 * clause's content hash and its body, and a verdict for each of the three
 * axes. No line numbers anywhere -- that is the whole point.
 */
function progressLine(pack: string, index: number, total: number, v: ClauseVerdict): string {
  const counter = `[${String(index).padStart(String(total).length, ' ')}/${String(total)}]`;
  // The error's first line goes on the progress line, not only into the
  // final report: a run that is killed part-way (a supervisor timeout, a
  // Ctrl-C) never renders a report, and an `ERROR` with no reason attached
  // is indistinguishable from a harness bug when you read the log later.
  const flags =
    v.live === 'ERROR'
      ? `ERROR ${(v.error ?? 'unknown').split('\n')[0] ?? ''}`
      : [
          v.live === 'PASS' ? 'live' : 'DEAD',
          v.keepsTruePositives === 'PASS' ? 'keeps-tp' : 'SUPPRESSES-TP',
          v.noAddedNoise === 'N/A'
            ? 'real-n/a'
            : v.noAddedNoise === 'PASS'
              ? 'no-real-rise'
              : v.noAddedNoise === 'INCONCLUSIVE'
                ? 'REAL-UNDER-FLOOR'
                : 'RAISES-REAL',
        ].join(' ');
  return (
    `${counter} ${overallVerdict(v).padEnd(5, ' ')} ${flags.padEnd(36, ' ')} ` +
    `${pack} :: ${v.clause.ruleId} :: [${v.clause.hash}] ${short(v.clause.body, 80)}`
  );
}

/**
 * A rule is flagged when it fires on nothing in the corpus built to contain
 * the bugs it is for. Deliberately NOT flagged for having no clauses: having
 * nothing to ablate is a property of the rule, not a defect in it.
 */
export function ruleFlagged(r: RuleVerdict): boolean {
  return r.firesOnHits === 'FAIL';
}

/**
 * `NOISE` is its own outcome rather than a pass or a flag. The clause moved
 * the real-code count by no more than the corpus's own measured error, so the
 * honest report is that this run could not tell -- and the run still exits
 * non-zero, because a measurement that cannot resolve its own deltas needs
 * fixing (a quieter machine, a longer `--timeout`, a smaller corpus) before
 * its passes mean anything either.
 */
export function overallVerdict(v: ClauseVerdict): string {
  if (v.live === 'ERROR') return 'ERR';
  if (v.live === 'FAIL' || v.keepsTruePositives === 'FAIL' || v.noAddedNoise === 'FAIL') return 'FLAG';
  if (v.noAddedNoise === 'INCONCLUSIVE') return 'NOISE';
  return 'ok';
}

export function short(body: string, max = 96): string {
  const flat = body.replace(/\s+/g, ' ').trim();
  return flat.length <= max ? flat : `${flat.slice(0, max - 3)}...`;
}
