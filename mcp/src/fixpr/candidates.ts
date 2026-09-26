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
 *
 * A dependency finding is paired with an upgrade step by its STRUCTURED
 * package field (see `stepsFor`), never by words in its title or advisory
 * text — Task 11 item 3.
 */

import { createHash } from 'node:crypto';
import { dependencyCoordinates } from '../fingerprint/findingIdentity.js';
import { rankByExploitability } from '../intel/rank.js';
import type { CveIntelResult } from '../intel/types.js';
import { passes } from '../severity/filter.js';
import { SEVERITY_ORDER, type Finding, type Severity } from '../types.js';
import type { FixCandidate, FixGroup, FixSource, GroupSelection, UpgradeStep } from './types.js';

/** Findings from these tools carry dependency-upgrade fixes. */
export const DEP_SCANNER_TOOLS: readonly string[] = ['trivy', 'npm-audit', 'pip-audit', 'dotnet-list-package', 'wpscan'];

export function buildGroups(input: {
  findings: readonly Finding[];
  upgradeSteps: readonly UpgradeStep[];
  sources: readonly FixSource[];
  severityMin: Severity;
  /**
   * Whether the verification can re-scan this finding with the tool and rule
   * packs that produced it. One it cannot is never a candidate: a fix nobody
   * can prove is not applied. Default: every finding.
   */
  rescannable?: (finding: Finding) => boolean;
}): FixGroup[] {
  // Applied once, before either branch, so fix_available, severityMin and
  // rescannability gate every candidate path identically — see the module
  // comment.
  const rescannable = input.rescannable ?? ((): boolean => true);
  const eligible = input.findings.filter(
    (finding) => finding.fix_available && passes(finding.severity, input.severityMin) && rescannable(finding),
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

/**
 * The exploitability signal `create_fix_pr` orders fixes by (Task 24, item
 * 5): the CVE ids each finding is correlated with (`intel/rank.ts
 * #findingCveIds`) and their CISA KEV / FIRST EPSS intel
 * (`intel/enrich.ts#enrichCveIntel`). An id with no measured intel is no
 * signal — never "not exploited", never a boost.
 */
export interface Exploitability {
  cveIdsOf: (fingerprint: string) => readonly string[];
  intel: ReadonlyMap<string, CveIntelResult>;
}

/**
 * Severity first; within a severity band, KEV-listed first, then higher EPSS
 * (`rankByExploitability`), then the order `items` came in. The composition
 * order matters: `rankByExploitability` is a stable sort by exploitability
 * ALONE, so it runs first and the stable severity sort after it keeps
 * severity the primary key — the other way round, an exploited high would
 * displace every ordinary critical.
 */
function bySeverityThenExploitability<T extends { severity: Severity }>(
  items: readonly T[],
  fingerprintsOf: (item: T) => readonly string[],
  exploitability: Exploitability | undefined,
): T[] {
  const cveIdsOf = (item: T): string[] =>
    exploitability === undefined
      ? []
      : [...new Set(fingerprintsOf(item).flatMap((fp) => exploitability.cveIdsOf(fp)))];
  const ranked =
    exploitability === undefined ? [...items] : rankByExploitability(items, cveIdsOf, exploitability.intel);
  return ranked.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);
}

/**
 * `group` with its candidates in the order they are applied: severity, then
 * KEV, then EPSS. `applyGroup` applies them in order and stops at the first
 * that fails, so this decides which fixes are attempted first. The hash (a
 * function of the fingerprint SET) and so the branch name do not change.
 */
export function rankCandidates(group: FixGroup, exploitability: Exploitability): FixGroup {
  return {
    ...group,
    candidates: bySeverityThenExploitability(group.candidates, (c) => c.fingerprints, exploitability),
  };
}

export function selectGroups(
  groups: readonly FixGroup[],
  maxPrs: number,
  exploitability?: Exploitability,
): GroupSelection {
  // Severity first, then — given the signal — KEV and EPSS decide which of
  // equally severe groups the cap keeps.
  const ordered = bySeverityThenExploitability(
    groups,
    (group) => group.candidates.flatMap((candidate) => candidate.fingerprints),
    exploitability,
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
  // into one candidate with one set of steps, instead of the steps running
  // twice and the PR body listing them twice.
  const buckets = new Map<
    string,
    { steps: UpgradeStep[]; fingerprints: string[]; severity: Severity }
  >();

  for (const finding of findings) {
    if (!DEP_SCANNER_TOOLS.includes(finding.tool)) continue;
    const steps = stepsFor(finding, upgradeSteps);
    if (steps.length === 0) continue;
    const first = steps[0];
    if (first === undefined) continue;

    const bucketKey = `${first.ecosystem}::${normalisePackageName(first.ecosystem, first.package_name)}`;
    const bucket = buckets.get(bucketKey);
    if (bucket === undefined) {
      buckets.set(bucketKey, { steps, fingerprints: [finding.fingerprint], severity: finding.severity });
    } else {
      bucket.fingerprints.push(finding.fingerprint);
      if (SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[bucket.severity]) {
        bucket.severity = finding.severity;
      }
    }
  }

  const byEcosystem = new Map<string, FixCandidate[]>();
  for (const bucket of buckets.values()) {
    const first = bucket.steps[0];
    if (first === undefined) continue;
    const candidate: FixCandidate = {
      source: 'deps',
      fingerprints: bucket.fingerprints,
      severity: bucket.severity,
      command: first.upgrade_command,
      label: `${first.package_name} ${first.installed_version} -> ${first.latest_version}`,
      steps: bucket.steps,
    };
    const list = byEcosystem.get(first.ecosystem);
    if (list === undefined) byEcosystem.set(first.ecosystem, [candidate]);
    else list.push(candidate);
  }

  return [...byEcosystem.entries()].map(([ecosystem, candidates]) =>
    makeGroup('deps', ecosystem, candidates),
  );
}

/**
 * Every upgrade step for the package THIS finding is about — read from the
 * finding's structured package coordinates (`dependencyCoordinates`: the
 * `pkg@version` each dependency scanner writes), in the ecosystem the finding
 * belongs to. Never from its title or advisory text: those routinely name
 * OTHER packages ("…like `ms` or `once`…"), and a whole-word match on them
 * applied the wrong package's upgrade (Task 11 item 3).
 *
 * Every matching step, not the first: pip plans one step per pinned
 * requirements file, and the CVE is only gone when every pin moves.
 */
function stepsFor(finding: Finding, upgradeSteps: readonly UpgradeStep[]): UpgradeStep[] {
  const coordinates = dependencyCoordinates(finding);
  if (coordinates === null) return [];
  const ecosystem = findingEcosystem(finding);
  if (ecosystem === null) return [];
  const name = normalisePackageName(ecosystem, coordinates.name);
  return upgradeSteps.filter(
    (step) => step.ecosystem === ecosystem && normalisePackageName(ecosystem, step.package_name) === name,
  );
}

/** Scanners that are ecosystem-specific by construction. */
const TOOL_ECOSYSTEM: Readonly<Record<string, UpgradeStep['ecosystem']>> = {
  'npm-audit': 'npm',
  'pip-audit': 'pip',
  'dotnet-list-package': 'dotnet',
};

/**
 * The ecosystem a dependency finding belongs to: fixed by the tool for the
 * single-ecosystem auditors, and by the manifest or lockfile Trivy names as
 * the finding's file otherwise. Null when neither says — a WPScan component,
 * a container image — and such a finding is never paired: the same name can
 * be a different package in another ecosystem (`debug` on npm and PyPI).
 */
export function findingEcosystem(finding: Pick<Finding, 'tool' | 'file_path'>): UpgradeStep['ecosystem'] | null {
  const byTool = TOOL_ECOSYSTEM[finding.tool];
  if (byTool !== undefined) return byTool;
  if (finding.tool !== 'trivy') return null;
  const base = (finding.file_path ?? '').replace(/\\/g, '/').split('/').pop()?.toLowerCase() ?? '';
  if (['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'package.json', 'bun.lock'].includes(base)) {
    return 'npm';
  }
  if (/^requirements.*\.txt$/.test(base) || ['pipfile.lock', 'poetry.lock', 'pyproject.toml', 'uv.lock', 'setup.py'].includes(base)) {
    return 'pip';
  }
  if (base === 'composer.lock' || base === 'composer.json') return 'composer';
  if (base === 'cargo.lock' || base === 'cargo.toml') return 'cargo';
  if (base === 'go.mod' || base === 'go.sum') return 'go';
  if (base === 'gemfile.lock' || base === 'gemfile' || base.endsWith('.gemspec')) return 'rubygems';
  if (base === 'packages.lock.json' || base === 'packages.config' || /\.(csproj|fsproj|vbproj|deps\.json)$/.test(base)) {
    return 'dotnet';
  }
  return null;
}

/** Names as the ecosystem compares them: PEP 503 for pip (case-insensitive,
 *  runs of `-`, `_`, `.` equal), case-insensitive everywhere else. */
function normalisePackageName(ecosystem: UpgradeStep['ecosystem'], name: string): string {
  const lower = name.toLowerCase();
  return ecosystem === 'pip' ? lower.replace(/[-_.]+/g, '-') : lower;
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
      // The fix pass applies exactly this rule to exactly this file.
      ...(finding.rule_id ? { rule_id: finding.rule_id } : {}),
      ...(finding.file_path ? { file_path: finding.file_path } : {}),
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
