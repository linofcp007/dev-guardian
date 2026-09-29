/**
 * CISA's Stakeholder-Specific Vulnerability Categorization (SSVC) — the
 * deployer decision tree CISA publishes for prioritising remediation — and
 * how dev-guardian derives each of its four decision points from the data it
 * has. Pure: no storage, no network, no clock.
 *
 * ---- Source ---------------------------------------------------------------
 *
 * The decision table is Table 9 ("Table Representing Vulnerability
 * Prioritization") and Figure 1 of the CISA Stakeholder-Specific
 * Vulnerability Categorization Guide, November 2022:
 * https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf
 * cross-checked, row for row, against the same tree as CERT/CC publishes it,
 * `data/csv/cisa/cisa_coordinator_2_0_3.csv` in github.com/CERTCC/SSVC at
 * commit fa6a3a4cb3943d76e3f0057d84dc57b5fe3e064a. Both retrieved 2026-09-28;
 * they agree on all 36 rows. `test/unit/intel/ssvc.test.ts` holds the table
 * again in the guide's flat form and checks this module against it.
 *
 * Decision points and values (the guide's Tables 2-4 and 8):
 *   - Exploitation: none | poc (public proof of concept) | active
 *   - Automatable: no | yes (steps 1-4 of the kill chain can be automated)
 *   - Technical Impact: partial | total
 *   - Mission & Well-being: low | medium | high (Mission Prevalence x Public
 *     Well-Being Impact, the guide's Table 8)
 * Decisions: Track, Track*, Attend, Act (the guide's Table 1).
 *
 * ---- What dev-guardian measures, and what it approximates -------------------
 *
 * The guide has no "unknown" value: "CISA identifies the value that is the
 * most reasonable assumption based on prior events". dev-guardian takes the
 * MORE SEVERE value instead whenever it has no data, and marks that decision
 * point `assumed: true` with the reason — a decision resting on an
 * assumption must never read as one resting on data.
 *
 *   - Exploitation. `active` from a CISA KEV listing (KEV is a list of CVEs
 *     exploited in the wild — the guide's own definition of active). `poc` is
 *     APPROXIMATED from FIRST EPSS: dev-guardian stores no exploit-reference
 *     feed, and EPSS models exploitation activity with published exploit
 *     code (Exploit-DB, Metasploit, GitHub) among its inputs, so a score of at least
 *     {@link EPSS_POC_THRESHOLD} stands in for "a public PoC exists". Below
 *     it — or with no EPSS score — it is `poc` too, but ASSUMED: a low EPSS
 *     is not proof that no PoC exists, and dev-guardian has no exploit feed
 *     that could show it (review of the 3.0 additions, M1), so `none` is
 *     never produced. A CVE with no intel at all (offline, a failed fetch)
 *     is assumed `active`. The threshold is dev-guardian's choice, not
 *     CISA's or FIRST's.
 *   - Automatable. From exposure, the one barrier the attack surface can
 *     show: `yes` when validate_finding's dependency provider finds the
 *     package imported by a file an HTTP route reaches. Nothing dev-guardian
 *     measures shows the barrier that makes it `no` (authentication, no
 *     network path, exploit mitigations), and "no route reaches it" is
 *     absence of evidence — so every other case is `yes`, assumed.
 *   - Technical Impact. APPROXIMATED from the finding's severity: critical
 *     and high are `total`, the rest `partial`. A high-severity
 *     denial-of-service is really `partial` (the guide says so), so this
 *     errs towards `total` — the safe direction.
 *   - Mission & Well-being. The caller's (`prioritize_findings`'
 *     `mission_wellbeing`); `medium` when not given, and marked assumed.
 */

import type { CveIntelResult } from './types.js';
import type { DependencyAssessment } from '../validate/dependencyProvider.js';
import type { Severity } from '../types.js';

export type Exploitation = 'none' | 'poc' | 'active';
export type Automatable = 'no' | 'yes';
export type TechnicalImpact = 'partial' | 'total';
export type MissionWellbeing = 'low' | 'medium' | 'high';

export const SSVC_DECISIONS = ['Act', 'Attend', 'Track*', 'Track'] as const;
export type SsvcDecision = (typeof SSVC_DECISIONS)[number];

export const MISSION_WELLBEING_VALUES = ['low', 'medium', 'high'] as const satisfies readonly MissionWellbeing[];

/** EPSS at or above this reads as "a public PoC exists" — see the module comment. */
export const EPSS_POC_THRESHOLD = 0.1;

/** The Mission & Well-being value used when the caller gives none. */
export const DEFAULT_MISSION_WELLBEING: MissionWellbeing = 'medium';

/** One decision point's value, whether it was assumed, and what it rests on. */
export interface SsvcPoint<V extends string> {
  value: V;
  assumed: boolean;
  basis: string;
}

export interface SsvcPoints {
  exploitation: SsvcPoint<Exploitation>;
  automatable: SsvcPoint<Automatable>;
  technical_impact: SsvcPoint<TechnicalImpact>;
  mission_wellbeing: SsvcPoint<MissionWellbeing>;
}

export interface SsvcAssessment extends SsvcPoints {
  decision: SsvcDecision;
  /** The decision points that were assumed, in the tree's order. */
  assumed: (keyof SsvcPoints)[];
}

type Leaves = Record<MissionWellbeing, SsvcDecision>;

/**
 * CISA's tree, Exploitation → Automatable → Technical Impact → Mission &
 * Well-being. Nested so the compiler holds it to all 36 leaves.
 */
const TREE: Record<Exploitation, Record<Automatable, Record<TechnicalImpact, Leaves>>> = {
  none: {
    no: {
      partial: { low: 'Track', medium: 'Track', high: 'Track' },
      total: { low: 'Track', medium: 'Track', high: 'Track*' },
    },
    yes: {
      partial: { low: 'Track', medium: 'Track', high: 'Attend' },
      total: { low: 'Track', medium: 'Track', high: 'Attend' },
    },
  },
  poc: {
    no: {
      partial: { low: 'Track', medium: 'Track', high: 'Track*' },
      total: { low: 'Track', medium: 'Track*', high: 'Attend' },
    },
    yes: {
      partial: { low: 'Track', medium: 'Track', high: 'Attend' },
      total: { low: 'Track', medium: 'Track*', high: 'Attend' },
    },
  },
  active: {
    no: {
      partial: { low: 'Track', medium: 'Track', high: 'Attend' },
      total: { low: 'Track', medium: 'Attend', high: 'Act' },
    },
    yes: {
      partial: { low: 'Attend', medium: 'Attend', high: 'Act' },
      total: { low: 'Attend', medium: 'Act', high: 'Act' },
    },
  },
};

export function ssvcDecision(values: {
  exploitation: Exploitation;
  automatable: Automatable;
  technical_impact: TechnicalImpact;
  mission_wellbeing: MissionWellbeing;
}): SsvcDecision {
  return TREE[values.exploitation][values.automatable][values.technical_impact][values.mission_wellbeing];
}

export function assessSsvc(points: SsvcPoints): SsvcAssessment {
  const order: (keyof SsvcPoints)[] = ['exploitation', 'automatable', 'technical_impact', 'mission_wellbeing'];
  return {
    decision: ssvcDecision({
      exploitation: points.exploitation.value,
      automatable: points.automatable.value,
      technical_impact: points.technical_impact.value,
      mission_wellbeing: points.mission_wellbeing.value,
    }),
    ...points,
    assumed: order.filter((key) => points[key].assumed),
  };
}

/**
 * Exploitation over every CVE a finding is correlated with: the worst any of
 * them shows, and an unmeasured one counts as the worst (see the module
 * comment).
 */
export function exploitationPoint(
  cveIds: readonly string[],
  intel: ReadonlyMap<string, CveIntelResult>,
): SsvcPoint<Exploitation> {
  const kev: string[] = [];
  const unmeasured: string[] = [];
  const unscored: string[] = [];
  let maxEpss: { id: string; score: number } | null = null;
  for (const id of cveIds) {
    const entry = intel.get(id);
    if (entry === undefined || entry.status !== 'ok') {
      unmeasured.push(id);
      continue;
    }
    if (entry.kev) kev.push(id);
    if (entry.epss_score === undefined) unscored.push(id);
    else if (maxEpss === null || entry.epss_score > maxEpss.score) maxEpss = { id, score: entry.epss_score };
  }

  if (kev.length > 0) {
    return { value: 'active', assumed: false, basis: `CISA KEV lists ${kev.join(', ')} as exploited in the wild` };
  }
  if (unmeasured.length > 0) {
    return {
      value: 'active',
      assumed: true,
      basis:
        `no KEV/EPSS intel for ${unmeasured.join(', ')} (offline, or the fetch failed): assumed the ` +
        'most severe value',
    };
  }
  if (maxEpss !== null && maxEpss.score >= EPSS_POC_THRESHOLD) {
    return {
      value: 'poc',
      assumed: false,
      basis:
        `approximated: not KEV-listed, FIRST EPSS ${maxEpss.score.toFixed(3)} for ${maxEpss.id} is at ` +
        `least ${EPSS_POC_THRESHOLD}, read as a public proof of concept`,
    };
  }
  if (unscored.length > 0) {
    return {
      value: 'poc',
      assumed: true,
      basis:
        `not KEV-listed, but FIRST has no EPSS score for ${unscored.join(', ')}: a public proof of ` +
        'concept cannot be ruled out, so assumed poc',
    };
  }
  // Never `none` (review of the 3.0 additions, M1): a low EPSS score is not
  // evidence that no public proof of concept exists, and dev-guardian has
  // nothing else to tell — so the more severe of what KEV leaves open.
  return {
    value: 'poc',
    assumed: true,
    basis:
      `not KEV-listed, and FIRST EPSS is below ${EPSS_POC_THRESHOLD}` +
      (maxEpss === null ? '' : ` (highest ${maxEpss.score.toFixed(3)})`) +
      ', but dev-guardian has no exploit or proof-of-concept feed to show that none exists: assumed poc',
  };
}

/**
 * Automatable from exposure. `dependency` is null when there was nothing to
 * assess against; `whyNone` then says why (no snapshot, not a package).
 */
export function automatablePoint(
  dependency: DependencyAssessment | null,
  whyNone: string | null,
  /** Set when the surface snapshot maps another tree than the finding's scan (review M8). */
  staleSnapshot: string | null = null,
): SsvcPoint<Automatable> {
  if (dependency?.verdict === 'reachable') {
    const exposure = dependency.evidence[0]?.detail ?? 'a file an HTTP route reaches imports the package';
    if (staleSnapshot !== null) {
      return {
        value: 'yes',
        assumed: true,
        basis: `${exposure} — but ${staleSnapshot}, so it is not data about this tree: assumed the most severe value`,
      };
    }
    return { value: 'yes', assumed: false, basis: `exposed: ${exposure} — no barrier dev-guardian can see` };
  }
  // For `unknown`, the provider's own first gap says why — "no import
  // found" and "the snapshot never recorded imports" are different facts.
  const why =
    dependency === null
      ? (whyNone ?? 'no reachability data')
      : dependency.verdict === 'imported'
        ? 'the package is imported, but no route was shown to reach an importing file — not evidence of a barrier'
        : (dependency.coverage_gaps[0] ?? 'no import of the package was found — absence of evidence, not a barrier');
  return { value: 'yes', assumed: true, basis: `${why}: assumed the most severe value` };
}

export function technicalImpactPoint(severity: Severity): SsvcPoint<TechnicalImpact> {
  const total = severity === 'critical' || severity === 'high';
  return {
    value: total ? 'total' : 'partial',
    assumed: false,
    basis:
      `approximated from severity=${severity} (critical/high → total, otherwise partial; a ` +
      'high-severity denial of service is really partial)',
  };
}

export function missionWellbeingPoint(value: MissionWellbeing | undefined): SsvcPoint<MissionWellbeing> {
  if (value !== undefined) {
    return { value, assumed: false, basis: 'given as mission_wellbeing' };
  }
  return {
    value: DEFAULT_MISSION_WELLBEING,
    assumed: true,
    basis: `default ${DEFAULT_MISSION_WELLBEING} — pass mission_wellbeing (low/medium/high) for this system`,
  };
}
