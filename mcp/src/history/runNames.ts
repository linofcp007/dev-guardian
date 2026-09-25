/**
 * The names a scan's bookkeeping uses — `tools_run[].name` and
 * `missing_tools[]` — and which findings each one speaks for.
 *
 * `history/runCompare.ts` asks, per finding, "did the scanner that reports
 * this run ok?", and the two vocabularies do not line up:
 *
 *   - deps_audit records its native auditors by COMMAND (`npm`,
 *     `pip-audit`) while npm's findings say `npm-audit`;
 *   - scan_dast records its engine as `guardian-dast`, and the engine's
 *     partial-run markers as `guardian-dast:unanswered` and
 *     `guardian-dast:wall-clock`, while its findings say `dast`;
 *   - every Trivy finding says `trivy`, whichever pass produced it
 *     (`trivy`, `trivy-image`, `trivy-config`, `trivy-dockerfile`);
 *   - scan_secrets' two gitleaks passes are `gitleaks` and
 *     `gitleaks-working-tree`; the WordPress passes are `semgrep-wp` and
 *     `phpcs-wpcs`, listed missing as `semgrep` and `phpcs`;
 *   - scan_sast lists the absent .NET SDK as `dotnet-sdk`, not the
 *     `security-code-scan` analyser it runs;
 *   - audit_executive records one entry per SUB-TOOL (`deps_audit`,
 *     `security_scan_full`, …), each standing for several scanners.
 *
 * Round 3 guessed with a naming rule (a `base-variant` name also speaks for
 * `base`) and fell back to the scan's overall coverage for every name the
 * rule missed — so a failed `npm` beside an ok Trivy (coverage `partial`)
 * resolved every npm-audit finding, and a failed `guardian-dast` beside an
 * ok nuclei resolved every engine finding. This table replaces the guess.
 * It is exhaustive by test: `test/unit/history/runNames.test.ts` reads
 * every finding `tool` and every bookkeeping name out of `src/` and fails
 * on one this table does not place, on a name written through an
 * expression the test has not been taught to read, and on an entry here
 * that no scan writes any more.
 */

import type { Finding } from '../types.js';

/** Trivy's dependency / image pass: CVEs, licenses, secrets. */
export const TRIVY_FS = 'trivy:fs';
/** Trivy's config pass: misconfigurations (IaC, Dockerfile). */
export const TRIVY_CONFIG = 'trivy:config';
/** scan_skill's OSV lookup has a bookkeeping entry of its own (`osv.dev`). */
export const SKILL_OSV = 'guardian-scanskill:osv';

const SKILL_TOOL = 'guardian-scanskill';
const SKILL_OSV_RULE = 'osv-vulnerable-dependency';

/**
 * The key a finding is measured under: its `tool`, split where one tool
 * name covers passes that are recorded — and can fail — separately.
 */
export function findingKey(
  f: Pick<Finding, 'tool'> & Partial<Pick<Finding, 'rule_id' | 'category' | 'subcategory'>>,
): string {
  if (f.tool === 'trivy') {
    return f.category === 'license' || f.subcategory === 'cve' || f.subcategory === 'secret' ? TRIVY_FS : TRIVY_CONFIG;
  }
  if (f.tool === SKILL_TOOL && f.rule_id === SKILL_OSV_RULE) return SKILL_OSV;
  return f.tool;
}

export interface RunName {
  /**
   * The finding keys ({@link findingKey}) this entry speaks for. Empty: it
   * reports no findings (evidence only, or metadata).
   */
  measures: readonly string[];
  /**
   * What it speaks for when it did NOT run ok, when that is more: `trivy`
   * skipped or failed means Trivy itself is absent, so no pass of it ran.
   */
  whenNotOk?: readonly string[];
  /**
   * It looks at a target no other pass looks at — `trivy-image`, a container
   * image — under keys other passes also measure: a misconfiguration is
   * `trivy:config` whether the image or the Dockerfile produced it, and the
   * finding does not say which. So a finding of the older scan, where this
   * pass ran ok, is re-measured only by a newer scan that ran this same pass
   * ok again: a Dockerfile-only run never looked at the image.
   */
  ownTarget?: true;
}

const scanner = (...measures: string[]): RunName => ({ measures });

/** Every name a scan in this codebase writes to `tools_run` or `missing_tools`. */
export const RUN_NAMES = {
  // SAST — scan_sast, bug_hunt, review_pr, map_attack_surface, security_scan_full.
  semgrep: scanner('semgrep'),
  'semgrep-wp': scanner('semgrep'),
  bandit: scanner('bandit'),
  'security-code-scan': scanner('security-code-scan'),
  // scan_sast's missing_tools entry when the SDK that runs security-code-scan is absent.
  'dotnet-sdk': scanner('security-code-scan'),

  // Secrets — scan_secrets, scan_wordpress, review_pr (runners/gitleaksScan.ts).
  gitleaks: scanner('gitleaks'),
  'gitleaks-working-tree': scanner('gitleaks'),

  // Trivy, by pass.
  trivy: { measures: [TRIVY_FS], whenNotOk: [TRIVY_FS, TRIVY_CONFIG] },
  // `trivy image --scanners vuln,secret,misconfig`: CVEs and secrets, and
  // the image's own misconfigurations.
  'trivy-image': { measures: [TRIVY_FS, TRIVY_CONFIG], ownTarget: true },
  'trivy-config': scanner(TRIVY_CONFIG),
  'trivy-dockerfile': scanner(TRIVY_CONFIG),

  // deps_audit's native auditors, recorded by command.
  npm: scanner('npm-audit'),
  'pip-audit': scanner(), // captured as evidence only: no findings

  // quality_check. Its read of `.guardian/budgets.yml` measures the quality
  // budgets against jscpd's and radon's own reports, so either one not
  // running ok leaves the budget findings unmeasured too.
  eslint: scanner('eslint'),
  ruff: scanner('ruff'),
  radon: { measures: ['radon'], whenNotOk: ['radon', 'budgets'] },
  jscpd: { measures: ['jscpd'], whenNotOk: ['jscpd', 'budgets'] },
  staticcheck: scanner('staticcheck'),
  budgets: scanner('budgets'),

  // scan_containers, beside its Trivy passes: the Dockerfile linter and the
  // compose-file hardening checks.
  hadolint: scanner('hadolint'),
  'docker-compose': scanner('docker-compose'),

  // scan_wordpress's PHPCS pass, and its missing_tools name.
  'phpcs-wpcs': scanner('phpcs'),
  phpcs: scanner('phpcs'),

  // scan_dast: the own engine, its partial-run markers, and nuclei.
  'guardian-dast': scanner('dast'),
  'guardian-dast:unanswered': scanner('dast'),
  'guardian-dast:wall-clock': scanner('dast'),
  nuclei: scanner('nuclei'),

  // WordPress.
  wpscan: scanner('wpscan'),
  wp_plugin_check: scanner(), // a findings-less lookup
  'wp-cli': scanner(), // wp_audit, wp_cron_audit: report through meta
  'http-probe': scanner(), // wp_rest_audit: reports through meta

  // .NET. `scan_dotnet_secrets` and `dotnet_target_framework_check` are
  // also audit_executive's entries for those sub-tools.
  scan_dotnet_secrets: scanner('scan_dotnet_secrets'),
  dotnet_efcore_audit: scanner('dotnet_efcore_audit'),
  dotnet_target_framework_check: scanner(),

  // compliance_check.
  'policy-docs': scanner(),

  // scan_skill.
  'guardian-scanskill:patterns': scanner(SKILL_TOOL),
  'guardian-scanskill:yara': scanner(SKILL_TOOL),
  'guardian-scanskill:taint': scanner(SKILL_TOOL),
  'osv.dev': scanner(SKILL_OSV),

  // audit_executive: one entry per sub-tool. `runCompare.ts` reads the
  // sub-scan's own bookkeeping instead whenever the row still exists; these
  // speak for a sub-tool that failed before it wrote one.
  security_scan_full: scanner('semgrep', 'bandit', 'security-code-scan', 'gitleaks', TRIVY_FS, TRIVY_CONFIG),
  quality_check: scanner('eslint', 'ruff', 'radon', 'jscpd', 'staticcheck', 'budgets'),
  deps_audit: scanner(TRIVY_FS, 'npm-audit'),
  compliance_check: scanner(TRIVY_FS),
  scan_wordpress: scanner('semgrep', 'gitleaks', TRIVY_FS, 'phpcs'),

  // security_scan_full: its own entry for a child that threw, answered an
  // error, or is not registered — the child wrote no bookkeeping of its own.
  // (An audit reads these through the security_scan_full sub-scan.)
  scan_sast: scanner('semgrep', 'bandit', 'security-code-scan'),
  scan_secrets: scanner('gitleaks'),
  scan_deps: scanner(TRIVY_FS),
  scan_iac: scanner(TRIVY_CONFIG),

  // generate_sbom: the producer of an SBOM row, which holds no findings.
  syft: scanner(),
} as const satisfies Record<string, RunName>;

const BY_NAME: ReadonlyMap<string, RunName> = new Map(Object.entries(RUN_NAMES));

/**
 * The entry for a bookkeeping name, or null when this table does not know
 * it. A `base:suffix` name that is not listed is a pass of `base` and speaks
 * for what `base` does — a failed one then vetoes `base`'s findings.
 */
export function runNameEntry(name: string): RunName | null {
  const listed = BY_NAME.get(name);
  if (listed !== undefined) return listed;
  const colon = name.indexOf(':');
  return colon > 0 ? (BY_NAME.get(name.slice(0, colon)) ?? null) : null;
}

/** The finding keys `name` speaks for, given whether it ran ok; null when the name is unknown. */
export function keysOfRun(name: string, ok: boolean): readonly string[] | null {
  const entry = runNameEntry(name);
  if (entry === null) return null;
  return ok ? entry.measures : (entry.whenNotOk ?? entry.measures);
}

/**
 * Every finding key some bookkeeping name speaks for. A finding whose key is
 * here, read against a scan whose bookkeeping never names it, was not
 * looked for: that scan did not run its scanner.
 */
export const KNOWN_FINDING_KEYS: ReadonlySet<string> = new Set(
  [...BY_NAME.values()].flatMap((e) => [...e.measures, ...(e.whenNotOk ?? [])]),
);
