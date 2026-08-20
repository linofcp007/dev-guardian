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
 *     for the JS/TS pack, this repo's own `mcp/src` -- and compare before and
 *     after. If removing the clause LOWERS the count, the clause was adding
 *     those findings to real code. This is the newest axis and it caught what
 *     the other two could not: a wave added a `RegExp#exec` branch to
 *     `unchecked-match` and forgot the `?.` exclusion its sibling branch had,
 *     taking that rule from 0 to 13 false positives on our own TypeScript.
 *     Axes 1 and 2 BOTH passed -- "the clause is live" and "it does not
 *     reduce true positives" are both true of a clause that only adds false
 *     positives.
 *
 * Axis 3 is a property of the invocation, not of the code: a pack gets a real
 * corpus if one exists in a language it matches (see `packs.ts`). Where none
 * does, axis 3 reports N/A rather than being quietly skipped.
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

import { cpSync, mkdtempSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { writeFileSync } from 'node:fs';
import { AblationError, ablate, enumerateClauses, roundTrip } from './clauses.js';
import type { Clause, SkippedClause } from './clauses.js';
import { SemgrepFailure, findingsMissingFrom, sameFindings, scan, under } from './semgrep.js';
import type { Finding } from './semgrep.js';

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

export type Verdict = 'PASS' | 'FAIL' | 'N/A' | 'ERROR';

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
  /** PASS = removing it did not lower the real-code count. */
  readonly noAddedNoise: Verdict;
  /** Signed change in real-code count, or null when axis 3 is N/A. */
  readonly realDelta: number | null;
  /** Real-code findings the clause is responsible for adding. */
  readonly addedByClause: readonly Finding[];
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

export interface PackReport {
  readonly pack: string;
  readonly configPath: string;
  readonly configSha256: string;
  readonly ruleCount: number;
  readonly clauseCount: number;
  readonly skipped: readonly SkippedClause[];
  readonly collapsed: readonly CollapsedClause[];
  readonly fixtureCorpus: string;
  readonly realCorpus: string | null;
  readonly baselineFixtures: number;
  readonly baselineHits: number;
  readonly baselineReal: number | null;
  readonly verdicts: readonly ClauseVerdict[];
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
  const scanReal = (cfg: string): readonly Finding[] =>
    real === undefined
      ? []
      : scan({ bin: options.semgrepBin, config: cfg, target: real.dir, root: real.dir }).findings;

  options.log(`pack        ${spec.name}`);
  options.log(`config      ${spec.config}`);
  options.log(`sha256      ${hash}`);
  options.log(`rules       ${String(inventory.ruleIds.length)}`);
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
  const baselineReal = scanReal(configPath);

  options.log(`baseline    ${String(baselineFixtures.length)} findings on fixtures ` +
    `(${String(baselineHits.length)} in ${spec.hitsSubdir}/)` +
    (real === undefined ? '' : `, ${String(baselineReal.length)} on ${real.label}`));
  options.log(`control     round-trip of the unmodified pack reproduces the on-disk result exactly`);

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

      const fixturesMoved = !sameFindings(baselineFixtures, ablatedFixtures);
      const realMoved = real !== undefined && !sameFindings(baselineReal, ablatedReal);
      const movedIn: string[] = [];
      if (fixturesMoved) movedIn.push('fixtures');
      if (realMoved && real !== undefined) movedIn.push(real.label);

      const revealedInHits = findingsMissingFrom(
        under(ablatedFixtures, spec.hitsSubdir),
        baselineHits,
      );
      const addedByClause = real === undefined ? [] : findingsMissingFrom(baselineReal, ablatedReal);

      verdict = {
        clause,
        live: movedIn.length > 0 ? 'PASS' : 'FAIL',
        movedIn,
        fixtureDelta: ablatedFixtures.length - baselineFixtures.length,
        keepsTruePositives: revealedInHits.length === 0 ? 'PASS' : 'FAIL',
        revealedInHits,
        noAddedNoise: real === undefined ? 'N/A' : addedByClause.length === 0 ? 'PASS' : 'FAIL',
        realDelta: real === undefined ? null : ablatedReal.length - baselineReal.length,
        addedByClause,
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
        error: message,
        seconds: (Date.now() - clauseStarted) / 1000,
      };
    }

    verdicts.push(verdict);
    options.log(progressLine(spec.name, index, prepared.length, verdict));
  }

  const after = readPack(spec.config);
  if (after.hash !== hash) {
    throw new Error(`${spec.config} is not byte-identical after the run (${hash} -> ${after.hash}).`);
  }

  return {
    pack: spec.name,
    configPath: spec.config,
    configSha256: hash,
    ruleCount: inventory.ruleIds.length,
    clauseCount: prepared.length,
    skipped,
    collapsed,
    fixtureCorpus: spec.fixtures,
    realCorpus: real?.label ?? null,
    baselineFixtures: baselineFixtures.length,
    baselineHits: baselineHits.length,
    baselineReal: real === undefined ? null : baselineReal.length,
    verdicts,
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
          v.noAddedNoise === 'N/A' ? 'real-n/a' : v.noAddedNoise === 'PASS' ? 'no-real-rise' : 'RAISES-REAL',
        ].join(' ');
  return (
    `${counter} ${overallVerdict(v).padEnd(4, ' ')} ${flags.padEnd(32, ' ')} ` +
    `${pack} :: ${v.clause.ruleId} :: [${v.clause.hash}] ${short(v.clause.body, 80)}`
  );
}

export function overallVerdict(v: ClauseVerdict): string {
  if (v.live === 'ERROR') return 'ERR';
  if (v.live === 'FAIL' || v.keepsTruePositives === 'FAIL' || v.noAddedNoise === 'FAIL') return 'FLAG';
  return 'ok';
}

export function short(body: string, max = 96): string {
  const flat = body.replace(/\s+/g, ' ').trim();
  return flat.length <= max ? flat : `${flat.slice(0, max - 3)}...`;
}
