/**
 * Which scans describe a project's CURRENT state — the one classification
 * every "open findings" / "latest scan" reader shares.
 *
 * One database holds scans from many projects and of many types, and "the
 * latest completed scan" used to mean the latest of ANY type in ANY project.
 * Measured consequences: `generate_sbom` after a SAST scan made
 * `guardian://findings/open` and `risk_score` report zero (an SBOM row has no
 * findings, and it was the newest row); and whenever another project scanned
 * later, its findings answered for this one.
 *
 * The rule instead: a project's open findings are the union, over every
 * `'state'` type below, of the newest usable scan of that type for that
 * project (see `history/openSet.ts`). A `'never'` type does not describe the
 * project's findings, so it can never shadow one that does:
 *
 *   - `sbom`, `detect_stack`, `init`, `observability` — artefacts and setup,
 *     no findings at all;
 *   - `audit` — `audit_executive`'s roll-up re-files the findings of the
 *     scans it ran, which are already counted under their own types;
 *   - `skill_audit` — the target is a third-party skill, not this project;
 *   - `agent_audit` — the target is the AI-agent workspace config (MCP
 *     servers, permissions, hooks), not the project's code;
 *   - `review_pr` — scoped to a diff: its silence about a file says nothing
 *     about that file;
 *   - `wp_audit`, `wp_cron_audit`, `wp_rest_audit`, `dotnet_target_framework`
 *     — report through `meta`, never through findings.
 *
 * Independently of type, a scan whose `meta.scope` is set (diff or partial
 * runs) is never a state scan — see {@link isScopedScan}.
 */

import type { Finding, ScanRecord, ScanType, ToolRun } from '../types.js';

export type ScanTypeRole = 'state' | 'never';

/**
 * THE classification. `satisfies Record<ScanType, …>` makes it exhaustive at
 * compile time: a new scan type that is not placed here does not build.
 */
export const SCAN_TYPE_ROLE = {
  // Two shapes — see isOrchestratedFullScan below. An orchestrated row's
  // children (sast/secrets/deps/iac) are the sources, never the row itself;
  // a script-era row is split across sast/secrets/deps/containers, so rows
  // written before child scans existed do not vanish from the open set.
  security_full: 'state',
  sast: 'state',
  secrets: 'state',
  deps: 'state',
  deps_audit: 'state',
  containers: 'state',
  iac: 'state',
  bugs: 'state',
  quality: 'state',
  dast: 'state',
  compliance: 'state',
  perf: 'state',
  wordpress: 'state',
  wp_vuln_check: 'state',
  wp_vuln_check_source: 'state',
  dotnet_secrets: 'state',
  dotnet_efcore_audit: 'state',

  sbom: 'never',
  detect_stack: 'never',
  init: 'never',
  observability: 'never',
  audit: 'never',
  skill_audit: 'never',
  agent_audit: 'never',
  review_pr: 'never',
  wp_audit: 'never',
  wp_cron_audit: 'never',
  wp_rest_audit: 'never',
  dotnet_target_framework: 'never',
} as const satisfies Record<ScanType, ScanTypeRole>;

/** Every `'state'` type, in the declaration order above. */
export const STATE_SCAN_TYPES: readonly ScanType[] = (
  Object.keys(SCAN_TYPE_ROLE) as ScanType[]
).filter((t) => SCAN_TYPE_ROLE[t] === 'state');

export function isStateScanType(type: string): type is ScanType {
  return (STATE_SCAN_TYPES as readonly string[]).includes(type);
}

/**
 * `security_full` rows come in two shapes, and the open set treats them
 * differently:
 *
 *   - **Orchestrated** (Task 9 onwards): the tool runs `scan_sast`,
 *     `scan_secrets`, `scan_deps` and `scan_iac` as real child scans of
 *     their own types (`meta.parent_scan_id`), and the parent row keeps
 *     their findings merged, plus `meta.child_scans`. The children ARE the
 *     measurement; the parent is a copy. The parent is therefore never an
 *     open-set source — its children supersede and are superseded like any
 *     other scan of their type, and nothing is counted twice.
 *   - **Script-era** (2.0.x, `scripts/scan/full-security-scan.sh`): one row
 *     holding everything, with bookkeeping named after scanners. It ran
 *     `semgrep --config=auto` (+ Bandit), `gitleaks detect` (history only),
 *     `trivy fs --scanners vuln,license` and `trivy config Dockerfile` — for
 *     each slot a SUBSET of what the dedicated tool runs today (scan_sast adds
 *     the project's rules, base.yml, registered packs, p/csharp; scan_secrets
 *     adds uncommitted files; scan_containers adds the image). Its findings
 *     are routed to the slot of the tool that re-evaluates them
 *     ({@link scriptEraSlotOfFinding}); see `history/openSet.ts` for why such a
 *     row never supersedes a dedicated scan.
 */
export function isOrchestratedFullScan(scan: Pick<ScanRecord, 'scan_type' | 'meta'>): boolean {
  return scan.scan_type === 'security_full' && Array.isArray(scan.meta?.['child_scans']);
}

export function isScriptEraFullScan(scan: Pick<ScanRecord, 'scan_type' | 'meta'>): boolean {
  return scan.scan_type === 'security_full' && !isOrchestratedFullScan(scan);
}

/**
 * The slot each script-era `ToolRun` / `missing_tools` entry speaks for.
 * `trivy` is the `trivy fs` dependency pass; `trivy-dockerfile` is the
 * `trivy config Dockerfile` pass — exactly what `scan_containers` re-runs
 * under the same name.
 */
export const SCRIPT_ERA_RUN_SLOTS: Readonly<Record<string, ScanType>> = {
  semgrep: 'sast',
  bandit: 'sast',
  gitleaks: 'secrets',
  trivy: 'deps',
  'trivy-dockerfile': 'containers',
};

/**
 * The slot of a finding a script-era row holds. Every Trivy finding carries
 * tool `trivy`, so a Trivy finding is routed by what it is: a CVE or a
 * license came from the dependency pass (`scan_deps` re-evaluates it); a
 * misconfiguration came from the Dockerfile pass (`scan_containers`
 * re-evaluates it — `scan_deps` never does, so routing it by tool name let a
 * newer `scan_deps` drop it). An unknown tool stays in the residual
 * `security_full` slot, so nothing such a row holds is ever dropped.
 */
export function scriptEraSlotOfFinding(f: Pick<Finding, 'tool' | 'category' | 'subcategory'>): OpenSetSlot {
  switch (f.tool) {
    case 'semgrep':
    case 'bandit':
      return 'sast';
    case 'gitleaks':
      return 'secrets';
    case 'trivy':
      if (f.category === 'license' || f.subcategory === 'cve') return 'deps';
      if (f.subcategory === 'secret') return 'secrets';
      return 'containers';
    default:
      return 'security_full';
  }
}

/**
 * An open-set slot: one per `'state'` type. Each is fed by scans of its own
 * type, plus — for the slots a script-era security_full routes to — that
 * row's matching part. The `security_full` slot holds only a script-era
 * row's unroutable remainder.
 */
export type OpenSetSlot = ScanType;

/** Scan types whose rows can feed `slot`. */
export function sourceTypesOf(slot: OpenSetSlot): ScanType[] {
  if (slot === 'security_full') return ['security_full'];
  const coveredByFull = Object.values(SCRIPT_ERA_RUN_SLOTS).includes(slot);
  return coveredByFull ? [slot, 'security_full'] : [slot];
}

/** The slot one of a script-era row's `tools_run` / `missing_tools` names belongs to. */
function runSlotOf(tool: string): OpenSetSlot {
  return SCRIPT_ERA_RUN_SLOTS[tool] ?? 'security_full';
}

/** Whether `finding`, read from `scan`, belongs to `slot`. */
export function findingInSlot(
  scan: Pick<ScanRecord, 'scan_type'>,
  finding: Pick<Finding, 'tool' | 'category' | 'subcategory'>,
  slot: OpenSetSlot,
): boolean {
  if (scan.scan_type !== 'security_full') return scan.scan_type === slot;
  return scriptEraSlotOfFinding(finding) === slot;
}

/**
 * The part of `scan`'s bookkeeping that speaks for `slot` — the whole of it
 * for a single-purpose scan, the slot's own tools for a security_full one.
 * Coverage is judged on this: a security_full run whose gitleaks was missing
 * measured nothing about secrets, even though its semgrep half is complete.
 */
export function slotView(
  scan: Pick<ScanRecord, 'scan_type' | 'tools_run' | 'missing_tools'>,
  slot: OpenSetSlot,
): { tools_run: ToolRun[]; missing_tools: string[] } {
  if (scan.scan_type !== 'security_full') {
    return { tools_run: scan.tools_run, missing_tools: scan.missing_tools };
  }
  return {
    tools_run: scan.tools_run.filter((t) => runSlotOf(t.name) === slot),
    missing_tools: scan.missing_tools.filter((t) => runSlotOf(t) === slot),
  };
}

/**
 * A scan that looked at part of the project only. Its findings are real, but
 * its silence about everything outside its scope is not evidence, so it must
 * never supersede a full scan of the same type.
 *
 *   - `meta.scope` set — the marker diff/partial runs carry;
 *   - a `wp_vuln_check` row carrying `meta.slug` — `wp_plugin_check` files
 *     its single-plugin lookup under that type, with no findings.
 */
export function isScopedScan(scan: Pick<ScanRecord, 'scan_type' | 'meta'>): boolean {
  const meta = scan.meta;
  if (meta === undefined) return false;
  if (meta['scope'] !== undefined && meta['scope'] !== null) return true;
  return scan.scan_type === 'wp_vuln_check' && meta['slug'] !== undefined;
}
