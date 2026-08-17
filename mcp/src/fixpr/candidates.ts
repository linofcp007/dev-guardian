/**
 * `buildGroups` / `selectGroups` — which findings are fixable at all, and how
 * they group into one candidate pull request per ecosystem or scanner.
 *
 * Pure: no git, no network, no scanner invocation. Everything downstream
 * (worktree, apply, verify, pr) trusts what this module decides, so the two
 * things it guarantees are absolute:
 *
 *   - A finding with `fix_available === false` is never a candidate, on
 *     either path (deps or semgrep). It is filtered out of `eligible` once,
 *     up front, before either branch runs — neither branch ever sees an
 *     unfixable finding, so no later change to one path can let it slip
 *     through the other.
 *   - `FixGroup.hash` is a function of the SET of fingerprints, not the
 *     order they arrived in. The branch name (a later task) is derived from
 *     it, and an unstable hash breaks the idempotency the design rests on
 *     (design doc §5).
 */

import { createHash } from 'node:crypto';
import { passes } from '../severity/filter.js';
import { SEVERITY_ORDER, type Finding, type Severity } from '../types.js';
import type { FixCandidate, FixGroup, FixSource, GroupSelection, UpgradeStep } from './types.js';

/** Findings from these tools carry dependency-upgrade fixes. */
const DEP_SCANNER_TOOLS: readonly string[] = ['trivy', 'npm-audit', 'wpscan'];

export function buildGroups(input: {
  findings: readonly Finding[];
  upgradeSteps: readonly UpgradeStep[];
  sources: readonly FixSource[];
  severityMin: Severity;
}): FixGroup[] {
  // Applied once, before either branch, so fix_available and severityMin
  // gate every candidate path identically — see the module comment.
  const eligible = input.findings.filter(
    (finding) => finding.fix_available && passes(finding.severity, input.severityMin),
  );

  const groups: FixGroup[] = [];
  if (input.sources.includes('deps')) {
    groups.push(...buildDepsGroups(eligible, input.upgradeSteps));
  }
  if (input.sources.includes('semgrep')) {
    const semgrepGroup = buildSemgrepGroup(eligible);
    if (semgrepGroup !== null) groups.push(semgrepGroup);
  }

  // Deterministic order: this feature is themed on idempotency end to end,
  // and an arbitrary Map-iteration order is one less thing to rely on.
  return groups.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
}

export function selectGroups(groups: readonly FixGroup[], maxPrs: number): GroupSelection {
  const ordered = [...groups].sort(
    (a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity],
  );
  const selected = ordered.slice(0, maxPrs);
  const excluded = ordered.slice(maxPrs);

  const deferred = excluded.map((group) => ({
    key: group.key,
    source: group.source,
    severity: group.severity,
    finding_count: countFingerprints(group),
  }));

  // deferred_reason is null iff deferred is empty — never inferred from
  // silence downstream (design doc §6: "no silent caps").
  const deferred_reason =
    deferred.length === 0
      ? null
      : `max_prs is ${maxPrs}; ${deferred.length} group(s) deferred: ` +
        deferred.map((group) => group.key).join(', ');

  return { selected, deferred, deferred_reason };
}

// --------------------------------------------------------------- deps

function buildDepsGroups(
  findings: readonly Finding[],
  upgradeSteps: readonly UpgradeStep[],
): FixGroup[] {
  // Keyed by ecosystem+package so two findings resolved by the same upgrade
  // (e.g. Trivy and npm-audit both flagging the same lodash CVE) collapse
  // into one candidate with one command, instead of the command being run
  // twice and the PR body listing it twice.
  const buckets = new Map<
    string,
    { step: UpgradeStep; fingerprints: string[]; severity: Severity }
  >();

  for (const finding of findings) {
    if (!DEP_SCANNER_TOOLS.includes(finding.tool)) continue;
    const step = upgradeSteps.find((candidate) => mentionsPackage(finding, candidate.package_name));
    if (step === undefined) continue;

    const bucketKey = `${step.ecosystem}::${step.package_name}`;
    const bucket = buckets.get(bucketKey);
    if (bucket === undefined) {
      buckets.set(bucketKey, { step, fingerprints: [finding.fingerprint], severity: finding.severity });
    } else {
      bucket.fingerprints.push(finding.fingerprint);
      if (SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[bucket.severity]) {
        bucket.severity = finding.severity;
      }
    }
  }

  const byEcosystem = new Map<string, FixCandidate[]>();
  for (const bucket of buckets.values()) {
    const candidate: FixCandidate = {
      source: 'deps',
      fingerprints: bucket.fingerprints,
      severity: bucket.severity,
      command: bucket.step.upgrade_command,
      label: `${bucket.step.package_name} ${bucket.step.installed_version} -> ${bucket.step.latest_version}`,
    };
    const list = byEcosystem.get(bucket.step.ecosystem);
    if (list === undefined) byEcosystem.set(bucket.step.ecosystem, [candidate]);
    else list.push(candidate);
  }

  return [...byEcosystem.entries()].map(([ecosystem, candidates]) =>
    makeGroup('deps', ecosystem, candidates),
  );
}

function mentionsPackage(finding: Finding, packageName: string): boolean {
  return (
    containsWholePackageName(finding.title, packageName) ||
    containsWholePackageName(finding.message ?? '', packageName)
  );
}

/**
 * Whether `packageName` appears in `text` as a whole token, not merely as a
 * substring. Plain `.includes()` treats "requests vulnerable" as mentioning
 * "request", "lodash.merge vulnerable" as mentioning "lodash", and
 * "axios-retry vulnerable" as mentioning "axios" — three different, real
 * packages, each of which would get the WRONG package's upgrade command
 * applied, not merely a missed pairing.
 *
 * A plain `\b` regex boundary does not fix this either: `-`, `.`, `@` and
 * `/` are all non-word characters, so `\b` sits on both sides of "axios"
 * inside "axios-retry" too. Instead this treats the characters that can
 * occur inside a real package identifier — across npm (including scoped
 * `@scope/pkg`), pip, composer, cargo, go, rubygems and dotnet names — as
 * NOT boundaries, and requires a true separator (whitespace, punctuation,
 * or the start/end of the string) on both sides of the match.
 */
function containsWholePackageName(text: string, packageName: string): boolean {
  if (packageName.length === 0) return false;
  let from = 0;
  for (;;) {
    const index = text.indexOf(packageName, from);
    if (index === -1) return false;
    const before = text[index - 1];
    const after = text[index + packageName.length];
    if (!isPackageNameChar(before) && !isPackageNameChar(after)) return true;
    from = index + 1;
  }
}

/**
 * Characters that continue a package-identifier token rather than ending
 * one: letters, digits, `_`, `-`, `.`, `@`, `/`. `undefined` — off the start
 * or end of the string — is never one of these, so it always counts as a
 * boundary.
 */
function isPackageNameChar(ch: string | undefined): boolean {
  return ch !== undefined && /[A-Za-z0-9_.@/-]/.test(ch);
}

// --------------------------------------------------------------- semgrep

function buildSemgrepGroup(findings: readonly Finding[]): FixGroup | null {
  // One --autofix pass handles every rule at once, so every qualifying
  // semgrep finding — whatever rule flagged it — becomes a candidate in the
  // same single group, never one group per rule.
  const candidates: FixCandidate[] = findings
    .filter((finding) => finding.tool === 'semgrep')
    .map((finding) => ({
      source: 'semgrep' as const,
      fingerprints: [finding.fingerprint],
      severity: finding.severity,
      command: null,
      // `||`, not `??`: an empty-string rule_id is exactly as unusable a
      // label as a missing one, and `??` would let '' straight through.
      label: finding.rule_id || finding.title,
    }));

  return candidates.length === 0 ? null : makeGroup('semgrep', 'semgrep', candidates);
}

// --------------------------------------------------------------- shared

function makeGroup(source: FixSource, key: string, candidates: FixCandidate[]): FixGroup {
  let severity: Severity = 'info';
  for (const candidate of candidates) {
    if (SEVERITY_ORDER[candidate.severity] > SEVERITY_ORDER[severity]) severity = candidate.severity;
  }

  // The hash covers the SET of fingerprints: sorted before hashing, so the
  // order candidates/findings arrived in never changes the digest.
  const fingerprints = candidates.flatMap((candidate) => candidate.fingerprints);
  const hash = createHash('sha256')
    .update([...fingerprints].sort().join('\n'))
    .digest('hex')
    .slice(0, 12);

  return { source, key, candidates, severity, hash };
}

function countFingerprints(group: FixGroup): number {
  return group.candidates.reduce((total, candidate) => total + candidate.fingerprints.length, 0);
}
