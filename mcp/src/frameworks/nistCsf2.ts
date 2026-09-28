/**
 * NIST Cybersecurity Framework 2.0 — the function and category ids, and
 * dev-guardian's own mapping from OWASP Top 10:2025 categories onto them.
 *
 * ---- Source of the ids --------------------------------------------------
 *
 * NIST's Cybersecurity and Privacy Reference Tool export of the framework,
 * https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/csf_2_0_0/export/json?element=all
 * (document `CSF_2_0_0`, "NIST Cybersecurity Framework Version 2.0", which
 * points at https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf),
 * retrieved 2026-09-28. Titles and subcategory texts are copied from it.
 * That export lists 34 categories: the 22 of CSF 2.0 below, and twelve CSF
 * 1.1 categories 2.0 withdrew (each carries a `WR-` withdrawal record —
 * ID.BE, ID.GV, ID.RM, ID.SC, PR.AC, PR.IP, PR.MA, PR.PT, DE.DP, RS.RP,
 * RS.IM, RC.IM). None of those is cited here.
 *
 * ---- The OWASP → CSF mapping is OURS ------------------------------------
 *
 * NIST publishes no mapping from the OWASP Top 10 to CSF 2.0, and neither
 * does OWASP. {@link OWASP_TO_CSF} is dev-guardian's reading of which CSF
 * outcomes a scan for each weakness class gives evidence about, and every
 * document that renders it says so. Two rules shape it:
 *   - every category lands in ID.RA-01 ("Vulnerabilities in assets are
 *     identified, validated, and recorded"): a scanner that ran and looked
 *     for the class is exactly that outcome, whatever it found;
 *   - GOVERN (except GV.SC for supply chain), RESPOND and RECOVER are
 *     organisational processes no code scan can evidence, and are never
 *     mapped — an evidence pack lists them as not assessable rather than
 *     implying a scan speaks for them.
 */

import type { Owasp2025Id } from './owaspTop10_2025.js';

export const CSF_FUNCTIONS = [
  { id: 'GV', title: 'GOVERN' },
  { id: 'ID', title: 'IDENTIFY' },
  { id: 'PR', title: 'PROTECT' },
  { id: 'DE', title: 'DETECT' },
  { id: 'RS', title: 'RESPOND' },
  { id: 'RC', title: 'RECOVER' },
] as const;
export type CsfFunctionId = (typeof CSF_FUNCTIONS)[number]['id'];

export const CSF_CATEGORIES = [
  { id: 'GV.OC', function: 'GV', title: 'Organizational Context' },
  { id: 'GV.RM', function: 'GV', title: 'Risk Management Strategy' },
  { id: 'GV.RR', function: 'GV', title: 'Roles, Responsibilities, and Authorities' },
  { id: 'GV.PO', function: 'GV', title: 'Policy' },
  { id: 'GV.OV', function: 'GV', title: 'Oversight' },
  { id: 'GV.SC', function: 'GV', title: 'Cybersecurity Supply Chain Risk Management' },
  { id: 'ID.AM', function: 'ID', title: 'Asset Management' },
  { id: 'ID.RA', function: 'ID', title: 'Risk Assessment' },
  { id: 'ID.IM', function: 'ID', title: 'Improvement' },
  { id: 'PR.AA', function: 'PR', title: 'Identity Management, Authentication, and Access Control' },
  { id: 'PR.AT', function: 'PR', title: 'Awareness and Training' },
  { id: 'PR.DS', function: 'PR', title: 'Data Security' },
  { id: 'PR.PS', function: 'PR', title: 'Platform Security' },
  { id: 'PR.IR', function: 'PR', title: 'Technology Infrastructure Resilience' },
  { id: 'DE.CM', function: 'DE', title: 'Continuous Monitoring' },
  { id: 'DE.AE', function: 'DE', title: 'Adverse Event Analysis' },
  { id: 'RS.MA', function: 'RS', title: 'Incident Management' },
  { id: 'RS.AN', function: 'RS', title: 'Incident Analysis' },
  { id: 'RS.CO', function: 'RS', title: 'Incident Response Reporting and Communication' },
  { id: 'RS.MI', function: 'RS', title: 'Incident Mitigation' },
  { id: 'RC.RP', function: 'RC', title: 'Incident Recovery Plan Execution' },
  { id: 'RC.CO', function: 'RC', title: 'Incident Recovery Communication' },
] as const satisfies ReadonlyArray<{ id: string; function: CsfFunctionId; title: string }>;
export type CsfCategoryId = (typeof CSF_CATEGORIES)[number]['id'];

/** The text of every CSF 2.0 subcategory {@link OWASP_TO_CSF} cites, verbatim from NIST. */
export const CSF_SUBCATEGORY_TEXT: Readonly<Record<string, string>> = {
  'GV.SC-07':
    'The risks posed by a supplier, their products and services, and other third parties are understood, ' +
    'recorded, prioritized, assessed, responded to, and monitored over the course of the relationship',
  'ID.RA-01': 'Vulnerabilities in assets are identified, validated, and recorded',
  'PR.AA-01': 'Identities and credentials for authorized users, services, and hardware are managed by the organization',
  'PR.AA-03': 'Users, services, and hardware are authenticated',
  'PR.AA-05':
    'Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and ' +
    'reviewed, and incorporate the principles of least privilege and separation of duties',
  'PR.DS-01': 'The confidentiality, integrity, and availability of data-at-rest are protected',
  'PR.DS-02': 'The confidentiality, integrity, and availability of data-in-transit are protected',
  'PR.DS-10': 'The confidentiality, integrity, and availability of data-in-use are protected',
  'PR.PS-01': 'Configuration management practices are established and applied',
  'PR.PS-02': 'Software is maintained, replaced, and removed commensurate with risk',
  'PR.PS-04': 'Log records are generated and made available for continuous monitoring',
  'PR.PS-06':
    'Secure software development practices are integrated, and their performance is monitored throughout ' +
    'the software development life cycle',
  'PR.IR-03': 'Mechanisms are implemented to achieve resilience requirements in normal and adverse situations',
  'DE.CM-09':
    'Computing hardware and software, runtime environments, and their data are monitored to find potentially ' +
    'adverse events',
};

export interface CsfReference {
  category: CsfCategoryId;
  /** The subcategories of `category` the weakness class bears on. */
  subcategories: readonly string[];
}

const RISK_ASSESSMENT: CsfReference = { category: 'ID.RA', subcategories: ['ID.RA-01'] };

/** dev-guardian's own mapping — see the module comment. Not NIST's, not OWASP's. */
export const OWASP_TO_CSF: Readonly<Record<Owasp2025Id, readonly CsfReference[]>> = {
  'A01:2025': [RISK_ASSESSMENT, { category: 'PR.AA', subcategories: ['PR.AA-05'] }, { category: 'PR.DS', subcategories: ['PR.DS-01'] }],
  'A02:2025': [RISK_ASSESSMENT, { category: 'PR.PS', subcategories: ['PR.PS-01'] }],
  // ID.RA-09 ("the authenticity and integrity of hardware and software are
  // assessed prior to acquisition and use") is not cited for A03 or A08:
  // nothing here verifies a signature or a provenance attestation yet. Part
  // E's `cosign verify` in scan_containers may evidence it once integrated.
  'A03:2025': [RISK_ASSESSMENT, { category: 'GV.SC', subcategories: ['GV.SC-07'] }, { category: 'PR.PS', subcategories: ['PR.PS-02'] }],
  'A04:2025': [RISK_ASSESSMENT, { category: 'PR.DS', subcategories: ['PR.DS-01', 'PR.DS-02'] }],
  'A05:2025': [RISK_ASSESSMENT, { category: 'PR.PS', subcategories: ['PR.PS-06'] }, { category: 'PR.DS', subcategories: ['PR.DS-10'] }],
  'A06:2025': [RISK_ASSESSMENT, { category: 'PR.PS', subcategories: ['PR.PS-06'] }],
  'A07:2025': [RISK_ASSESSMENT, { category: 'PR.AA', subcategories: ['PR.AA-01', 'PR.AA-03'] }],
  'A08:2025': [RISK_ASSESSMENT, { category: 'PR.DS', subcategories: ['PR.DS-01'] }],
  'A09:2025': [RISK_ASSESSMENT, { category: 'PR.PS', subcategories: ['PR.PS-04'] }, { category: 'DE.CM', subcategories: ['DE.CM-09'] }],
  'A10:2025': [RISK_ASSESSMENT, { category: 'PR.IR', subcategories: ['PR.IR-03'] }, { category: 'PR.PS', subcategories: ['PR.PS-06'] }],
};

/** The CSF categories one OWASP category bears on, in {@link OWASP_TO_CSF}'s order. */
export function csfCategoriesOfOwasp(id: Owasp2025Id): CsfCategoryId[] {
  return OWASP_TO_CSF[id].map((r) => r.category);
}

/** The OWASP categories {@link OWASP_TO_CSF} files under one CSF category, and the subcategories it cites there. */
export function owaspForCsfCategory(category: CsfCategoryId): Array<{ owasp: Owasp2025Id; subcategories: readonly string[] }> {
  const out: Array<{ owasp: Owasp2025Id; subcategories: readonly string[] }> = [];
  for (const [owasp, refs] of Object.entries(OWASP_TO_CSF) as Array<[Owasp2025Id, readonly CsfReference[]]>) {
    for (const r of refs) if (r.category === category) out.push({ owasp, subcategories: r.subcategories });
  }
  return out;
}
