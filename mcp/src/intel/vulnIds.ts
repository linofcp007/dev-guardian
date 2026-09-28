/**
 * A finding's OWN vulnerability ids — the only ids that tie it to a
 * vulnerability anywhere in dev-guardian: KEV/EPSS weighting
 * (`prioritize_findings`, `create_fix_pr`), the SSVC decision, VEX
 * suppressions (`suppress_finding`) and VEX statements (`export_vex`).
 *
 * Own ids are two things, and nothing else:
 *   - the finding's rule id, when it is an advisory id — a dependency
 *     scanner's rule id IS its advisory (`CVE-…`, `GHSA-…`, `PYSEC-…`,
 *     `SNYK-…`); npm audit v2's rule id can be the advisory URL, whose GHSA
 *     id is taken out of it;
 *   - the aliases its scanner recorded for that advisory
 *     (`Finding.vuln_aliases`: Trivy's `VendorIDs`, pip-audit's OSV
 *     `aliases`, npm audit's GHSA and CVE ids, WPScan's other CVEs).
 *
 * NEVER an id the title or description mentions. Reading those tied a
 * finding to every CVE its text named — measured on real scanner output:
 * CVE-2026-4800's lodash description mentions CVE-2021-23337 ("an
 * incomplete fix for …") and inherited its EPSS score; a PyYAML advisory
 * (PYSEC-2021-142 = CVE-2020-14343) mentions CVE-2020-1747, and a VEX
 * suppression of it was published against CVE-2020-1747. A mention is
 * context for a reader, not an identity.
 */

import { dependencyCoordinates } from '../fingerprint/findingIdentity.js';
import type { Finding } from '../types.js';

/** Advisory schemes recognised on any finding: a rule id of one of these IS a vulnerability id. */
const KNOWN_SCHEME =
  /^(CVE-\d{4}-\d+|GHSA(-[0-9a-z]{4}){3}|PYSEC-\d{4}-\d+|GO-\d{4}-\d+|RUSTSEC-\d{4}-\d+|OSV-\d{4}-\d+|GSD-\d{4}-\d+|MAL-\d{4}-\d+|DSA-\d+(-\d+)?|DLA-\d+(-\d+)?|RHSA-\d{4}:\d+|USN-\d+(-\d+)?|ALAS2?-\d{4}-\d+)$/i;

/**
 * The shape of an advisory id of any other scheme (`SNYK-JS-LODASH-567746`,
 * `NSWG-ECO-17`): accepted only where the scanner says it is one — a
 * dependency finding's rule id, or a recorded alias. On a SAST or
 * misconfiguration finding the same shape is a rule name (`AVD-DS-0002`).
 */
const ADVISORY_SHAPED = /^[A-Z][A-Z0-9]*-[A-Za-z0-9][A-Za-z0-9._:-]*$/;

const GITHUB_ADVISORY_URL = /^https?:\/\/github\.com\/advisories\/(GHSA(-[0-9a-z]{4}){3})\/?$/i;

type VulnIdSubject = Pick<Finding, 'tool' | 'rule_id' | 'subcategory' | 'snippet' | 'line_start' | 'vuln_aliases'>;

/** The GHSA id of a GitHub advisory URL, or null for any other text. */
export function advisoryIdFromUrl(url: string): string | null {
  const match = GITHUB_ADVISORY_URL.exec(url.trim());
  return match?.[1] === undefined ? null : canonical(match[1]);
}

/** Ids compare case-insensitively (`GHSA-35JH-…` is `GHSA-35jh-…`). */
export function vulnIdKey(id: string): string {
  return id.trim().toUpperCase();
}

export function sameVulnIds(a: string, b: string): boolean {
  return vulnIdKey(a) === vulnIdKey(b);
}

export function isCveId(id: string): boolean {
  return /^CVE-\d{4}-\d+$/i.test(id.trim());
}

/**
 * The finding's own vulnerability ids, rule id first, each once, in the
 * canonical spelling (CVE upper case, a GHSA id's suffix lower case).
 */
export function findingVulnIds(finding: VulnIdSubject): string[] {
  const ids: string[] = [];
  const seen = new Set<string>();
  const add = (id: string | null): void => {
    if (id === null || seen.has(vulnIdKey(id))) return;
    seen.add(vulnIdKey(id));
    ids.push(id);
  };
  if (finding.rule_id !== undefined) {
    add(ownIdOf(finding.rule_id, dependencyCoordinates(finding) !== null));
  }
  for (const alias of finding.vuln_aliases ?? []) add(ownIdOf(alias, true));
  return ids;
}

/** `id` as a canonical vulnerability id, or null when it is not one. */
function ownIdOf(raw: string, advisoryContext: boolean): string | null {
  const text = raw.trim();
  const fromUrl = advisoryIdFromUrl(text);
  if (fromUrl !== null) return fromUrl;
  if (KNOWN_SCHEME.test(text)) return canonical(text);
  if (advisoryContext && ADVISORY_SHAPED.test(text)) return text;
  return null;
}

function canonical(id: string): string {
  if (/^GHSA-/i.test(id)) return `GHSA-${id.slice(5).toLowerCase()}`;
  return id.toUpperCase();
}
