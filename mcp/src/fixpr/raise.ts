/**
 * `decideRaise` / `verifyWithRaises` — what `create_fix_pr` does when the
 * version it applied resolves its targets and brings an advisory of its own.
 *
 * `deps_update_plan` installs the MINIMUM version that clears the advisories
 * active on what is installed. An advisory that exists only on that minimum is
 * not among them, so the verification finds it as a new finding and refuses
 * the pull request — rightly: `verify.ts`, "a version bump that trades CVE-A
 * for CVE-B is not a fix". But the new finding names the version that clears
 * it (`lodash@4.18.0->4.18.1`), and until 3.11.0 the answer was `not_verified`
 * with two counts. Measured 2026-11-14 with the real Trivy: lodash 4.17.20 →
 * 4.18.0 → refused; from 4.18.0 the same command opened the pull request for
 * 4.18.1.
 *
 * **The decision is pure** (`decideRaise`): no git, no network, no scanner.
 * A target is raised only when the verification leaves NOTHING else to
 * explain — no target still present, and every new finding is a dependency
 * advisory, with one installable fixed version, on a package this group
 * upgraded, at the version it applied. One finding of any other kind and
 * nothing is raised: a higher version of package A says nothing about a new
 * finding in package B or in the source.
 *
 * **Never across a major.** A fixed version in the next major is a decision
 * for whoever maintains the project; the reason names the package, the
 * version and the advisory, and the group ends `not_verified` with them.
 *
 * **The cycle only knows when to stop** (`verifyWithRaises`): it is handed
 * "run one round of this group" and "plan again with these fixed versions"
 * as functions — `create_fix_pr` gives it `processGroup` and
 * `deps_update_plan`, a test gives it a script. At most `MAX_RAISES` raises;
 * every round is a fresh worktree of the base commit, never an install on top
 * of the last; the answer is always the LAST round's result, since an earlier
 * one describes a tree that no longer is the candidate.
 */

import { compareVersions, isCleanVersion, minCleanVersionAbove } from '../deps/versionCompare.js';
import { dependencyCoordinates } from '../fingerprint/findingIdentity.js';
import type { Finding } from '../types.js';
import { findingEcosystem, normalisePackageName } from './candidates.js';
import type { FixGroup, Raised, ScanVerdict, UpgradeStep } from './types.js';

/** Raises per group: the measured case and one more advisory in a chain. A user's decision (2026-11-15). */
export const MAX_RAISES = 2;

/** A new dependency finding of a failed verification, as the `not_verified` note names it. */
interface NewDependencyFinding {
  package_name: string;
  version: string;
  /** The finding's `rule_id` — a CVE or GHSA id. */
  advisory: string;
  /** As the scanner gave it; empty when the advisory has no fix. */
  fixed_version: string;
}

/** One package to plan again for: above which planned version, and why. */
interface Raise {
  package_name: string;
  /** The target of the step that was applied. */
  planned_version: string;
  /** The fixed versions of the new findings, as the scanner gave them. */
  fixed_versions: string[];
  /** The `rule_id`s of the new findings. */
  advisories: string[];
}

type RaiseDecision = { kind: 'raise'; raises: Raise[] } | { kind: 'stop'; reason: string; blocking: NewDependencyFinding[] };

/** What the cycle needs of one round: its result and — when it reached the scan differential — the verdict and the re-scan's findings. */
export interface Round<R> {
  result: R;
  /** Null when the round ended before the differential (refused, apply failed, the re-scan failed). */
  verdict: ScanVerdict | null;
  after: readonly Finding[];
}

interface StepTarget {
  step: UpgradeStep;
  key: string;
}

/** Every step of the group with the key its package is compared by (`candidates.ts#stepsFor`'s). */
function stepTargets(group: FixGroup): StepTarget[] {
  return group.candidates.flatMap((c) =>
    (c.steps ?? []).map((step) => ({ step, key: `${step.ecosystem}::${normalisePackageName(step.ecosystem, step.package_name)}` })),
  );
}

const sameVersion = (a: string, b: string): boolean =>
  a.trim() === b.trim() || (isCleanVersion(a) && isCleanVersion(b) && compareVersions(a.trim(), b.trim()) === 0);

/** The leading number of a clean version (`v2.3.1` → 2). */
function majorOf(version: string): number {
  return Number.parseInt(version.trim().replace(/^v/i, ''), 10);
}

/** The findings the verdict calls new, read from the re-scan by fingerprint. */
function newFindings(verdict: ScanVerdict, after: readonly Finding[]): Array<{ title: string; finding: Finding | undefined }> {
  const byFingerprint = new Map(after.map((f) => [f.fingerprint, f]));
  return verdict.new_findings.map((n) => ({ title: n.title, finding: byFingerprint.get(n.fingerprint) }));
}

/** `pkg@version->fixed`: the part after the arrow, or empty. */
function fixedVersionOf(f: Finding): string {
  const snippet = f.snippet ?? '';
  const arrow = snippet.indexOf('->');
  return arrow < 0 ? '' : snippet.slice(arrow + 2).trim();
}

function describe(f: Finding, coordinates: { name: string; version: string }): NewDependencyFinding {
  return { package_name: coordinates.name, version: coordinates.version, advisory: f.rule_id ?? f.title, fixed_version: fixedVersionOf(f) };
}

/** The new DEPENDENCY findings of a failed verification, for the note of a group that ends `not_verified`. */
function newDependencyFindings(verdict: ScanVerdict, after: readonly Finding[]): NewDependencyFinding[] {
  return newFindings(verdict, after).flatMap(({ finding }) => {
    const coordinates = finding === undefined ? null : dependencyCoordinates(finding);
    return finding === undefined || coordinates === null ? [] : [describe(finding, coordinates)];
  });
}

/**
 * Whether the new findings of a failed verification justify planning again
 * with a higher target — see the module comment. `after` is the re-scan the
 * verdict was judged on.
 */
export function decideRaise(opts: { group: FixGroup; verdict: ScanVerdict; after: readonly Finding[] }): RaiseDecision {
  const { group, verdict, after } = opts;
  const blocking = newDependencyFindings(verdict, after);
  const stop = (reason: string): RaiseDecision => ({ kind: 'stop', reason, blocking });

  if (verdict.still_present.length > 0) {
    return stop(`${verdict.still_present.length} target(s) are still present: a higher version is no answer to a fix that did not take`);
  }
  const fresh = newFindings(verdict, after);
  if (fresh.length === 0) return stop('the verification reported no new finding to raise a target for');

  const targets = stepTargets(group);
  const raises = new Map<string, Raise>();
  const reasons: string[] = [];
  for (const { title, finding } of fresh) {
    const coordinates = finding === undefined ? null : dependencyCoordinates(finding);
    if (finding === undefined || coordinates === null) {
      reasons.push(`a new finding is not a dependency advisory (${title})`);
      continue;
    }
    const advisory = finding.rule_id ?? finding.title;
    const at = `${coordinates.name}@${coordinates.version}`;
    const ecosystem = findingEcosystem(finding);
    const key = ecosystem === null ? null : `${ecosystem}::${normalisePackageName(ecosystem, coordinates.name)}`;
    const ofPackage = targets.filter((t) => t.key === key);
    if (ofPackage.length === 0) {
      reasons.push(`${advisory} is on ${at}, a package that is not one this fix upgraded`);
      continue;
    }
    const applied = ofPackage.find((t) => sameVersion(t.step.latest_version, coordinates.version));
    if (applied === undefined) {
      const planned = [...new Set(ofPackage.map((t) => t.step.latest_version))].join(', ');
      reasons.push(`${advisory} is on ${at}, which is not the version this fix applied (${planned})`);
      continue;
    }
    const planned = applied.step.latest_version;
    const fixed = fixedVersionOf(finding);
    if (fixed === '') {
      reasons.push(`${advisory} on ${at} has no fixed version`);
      continue;
    }
    // Read as the plan reads a stored advisory's: one clean version above what is installed, or nothing.
    const target = minCleanVersionAbove(planned, [fixed]);
    if (target === undefined) {
      reasons.push(`${advisory} on ${at} names no single version to install above it ('${fixed}')`);
      continue;
    }
    if (majorOf(target) > majorOf(planned)) {
      reasons.push(`${advisory} on ${at} is fixed in ${target}, a major above the ${planned} this fix planned for ${coordinates.name} — not raised`);
      continue;
    }
    const raise = raises.get(applied.key) ?? { package_name: applied.step.package_name, planned_version: planned, fixed_versions: [], advisories: [] };
    if (!raise.fixed_versions.includes(target)) raise.fixed_versions.push(target);
    if (!raise.advisories.includes(advisory)) raise.advisories.push(advisory);
    raises.set(applied.key, raise);
  }
  // One finding no higher version answers, and nothing is raised: the pull request could not open either way.
  if (reasons.length > 0) return stop(reasons.join('; '));
  return { kind: 'raise', raises: [...raises.values()] };
}

/** What was raised, as the result says it: from the first plan's version to the one `group` installs. */
function raisedIn(group: FixGroup, tried: ReadonlyMap<string, { package_name: string; planned_version: string; advisories: string[] }>): Raised[] {
  const targets = stepTargets(group);
  return [...tried.entries()].map(([key, t]) => ({
    package_name: t.package_name,
    planned_version: t.planned_version,
    applied_version: targets.find((s) => s.key === key)?.step.latest_version ?? t.planned_version,
    advisories: [...t.advisories],
  }));
}

/** `lodash 4.18.0 -> 4.18.1 (CVE-2026-2950)`, one per raised package. */
export function describeRaised(raised: readonly Raised[]): string {
  return raised.map((r) => `${r.package_name} ${r.planned_version} -> ${r.applied_version} (${r.advisories.join(', ')})`).join('; ');
}

/**
 * What a group's note adds once its rounds are over, from the cycle's answer.
 * A group that ends with new DEPENDENCY findings names each one — package,
 * version, advisory, and the version that clears it when one is known —
 * beside the counts it already gave, and says why its target was not raised
 * (the next major, the limit of raises, a plan that could not be made again):
 * until 3.11.0 the answer was two numbers. A raised round that ended before
 * its differential (`reachedDifferential: false`) says what it was raising.
 * Empty for everything else: a note is otherwise what it was.
 */
export function describeStop(cycle: { stopped: string | null; blocking: readonly NewDependencyFinding[] }, reachedDifferential: boolean): string {
  if (cycle.blocking.length > 0) {
    const named = cycle.blocking.map(
      (b) => `${b.package_name}@${b.version}: ${b.advisory}${b.fixed_version !== '' ? ` (fixed in ${b.fixed_version})` : ''}`,
    );
    return `. New: ${named.join('; ')}${cycle.stopped !== null ? `. Target not raised: ${cycle.stopped}` : ''}`;
  }
  return cycle.stopped !== null && !reachedDifferential ? ` (${cycle.stopped})` : '';
}

/**
 * Runs rounds of `group` until one verifies, one ends for a reason no higher
 * version answers, or `MAX_RAISES` raises were made. See the module comment.
 *
 * `runRound` is told what the round is trying (`trying`: empty for the first),
 * so that a round which verifies can say it where it reports — the pull
 * request body is written inside the round. `replan` is told every fixed
 * version learned so far, by package key, and must hand back the SAME group
 * (same `hash`: the same targets, so the same branch) with new steps.
 *
 * `raised` is non-empty only when the last round verified after a raise;
 * `stopped` says why no further raise was made, when one was considered or
 * under way; `blocking` names the new dependency findings left standing. A
 * round that throws (a cancelled request) is not run again.
 */
export async function verifyWithRaises<R>(opts: {
  group: FixGroup;
  runRound: (group: FixGroup, trying: readonly Raised[]) => Promise<Round<R>>;
  replan: (extra: ReadonlyMap<string, readonly string[]>) => Promise<FixGroup | { failed: string }>;
}): Promise<{ result: R; raised: Raised[]; stopped: string | null; blocking: NewDependencyFinding[]; rounds: number }> {
  let group = opts.group;
  let rounds = 0;
  let raises = 0;
  /** Package name (lowercased) → every fixed version a verification found for it. */
  const learned = new Map<string, string[]>();
  const tried = new Map<string, { package_name: string; planned_version: string; advisories: string[] }>();

  for (;;) {
    const trying = raises === 0 ? [] : raisedIn(group, tried);
    const round = await opts.runRound(group, trying);
    rounds += 1;
    const answer = (extra: { raised?: Raised[]; stopped?: string; blocking?: NewDependencyFinding[] }) => ({
      result: round.result,
      raised: extra.raised ?? [],
      stopped: extra.stopped ?? null,
      blocking: extra.blocking ?? [],
      rounds,
    });

    if (round.verdict === null) {
      // It never reached the differential: its own outcome says why. Only a raised round has more to say.
      return answer(raises === 0 ? {} : { stopped: `the round that raised ${describeRaised(trying)} ended before its verification` });
    }
    if (round.verdict.passed) return answer({ raised: trying });

    const blocking = newDependencyFindings(round.verdict, round.after);
    const decision = decideRaise({ group, verdict: round.verdict, after: round.after });
    if (decision.kind === 'stop') return answer({ stopped: decision.reason, blocking: decision.blocking });
    if (raises >= MAX_RAISES) {
      return answer({ stopped: `the limit of ${MAX_RAISES} raises per group was reached, and the version it reached has an advisory of its own`, blocking });
    }

    for (const raise of decision.raises) {
      // By the lowercased name, as `deps_update_plan` keys its advisories; a new array each time — the last
      // `replan` call may still hold the one before.
      const name = raise.package_name.toLowerCase();
      const known = learned.get(name) ?? [];
      learned.set(name, [...known, ...raise.fixed_versions.filter((v) => !known.includes(v))]);
    }
    const wanted = decision.raises.map((r) => `${r.package_name} above ${r.planned_version} (${r.advisories.join(', ')})`).join('; ');
    const next = await opts.replan(learned);
    if ('failed' in next) return answer({ stopped: `could not plan again to raise ${wanted}: ${next.failed}`, blocking });
    if (next.hash !== opts.group.hash) {
      return answer({ stopped: `planning again to raise ${wanted} gave a group that is not the same group (other targets): not applied`, blocking });
    }
    // Recorded against the FIRST plan's version: a second raise of the same package is still "planned X, applied Z".
    const keys = new Map(stepTargets(group).map((t) => [`${t.step.package_name}\n${t.step.latest_version}`, t.key]));
    for (const raise of decision.raises) {
      const key = keys.get(`${raise.package_name}\n${raise.planned_version}`);
      if (key === undefined) continue;
      const seen = tried.get(key) ?? { package_name: raise.package_name, planned_version: raise.planned_version, advisories: [] };
      for (const a of raise.advisories) if (!seen.advisories.includes(a)) seen.advisories.push(a);
      tried.set(key, seen);
    }
    raises += 1;
    group = next;
  }
}
