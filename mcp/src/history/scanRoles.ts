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
  // Covers sast + secrets + deps through SECURITY_FULL_TOOL_TYPES below, so a
  // newer scan_sast supersedes its semgrep findings but not its gitleaks
  // ones. Rows written before child scans existed must not vanish from the
  // open set, and do not: they still source every slot nothing newer covers.
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
  dotnet_secrets: 'state',
  dotnet_efcore_audit: 'state',

  sbom: 'never',
  detect_stack: 'never',
  init: 'never',
  observability: 'never',
  audit: 'never',
  skill_audit: 'never',
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
 * `security_full` runs several scanners; each one's findings and its
 * `tools_run` / `missing_tools` entries belong to the type the dedicated
 * tool for that scanner writes. Keyed by tool name — the `tool` of a
 * finding and the `name` of a `ToolRun` (the Dockerfile pass records its run
 * as `trivy-dockerfile` while its findings carry `trivy`).
 *
 * A tool missing from this map stays in the `security_full` slot itself, so
 * nothing a security_full row holds is ever dropped from the open set.
 */
export const SECURITY_FULL_TOOL_TYPES: Readonly<Record<string, ScanType>> = {
  semgrep: 'sast',
  bandit: 'sast',
  gitleaks: 'secrets',
  trivy: 'deps',
  'trivy-dockerfile': 'deps',
};

/**
 * An open-set slot: one per `'state'` type. Everything but `security_full`
 * is fed by scans of its own type, plus — for the types in
 * {@link SECURITY_FULL_TOOL_TYPES} — the matching part of `security_full`
 * scans. The `security_full` slot holds only what that map does not route.
 */
export type OpenSetSlot = ScanType;

/** Scan types whose rows can feed `slot`. */
export function sourceTypesOf(slot: OpenSetSlot): ScanType[] {
  if (slot === 'security_full') return ['security_full'];
  const coveredByFull = Object.values(SECURITY_FULL_TOOL_TYPES).includes(slot);
  return coveredByFull ? [slot, 'security_full'] : [slot];
}

/** The slot one of a security_full row's tools belongs to. */
function fullSlotOf(tool: string): OpenSetSlot {
  return SECURITY_FULL_TOOL_TYPES[tool] ?? 'security_full';
}

/** Whether `finding`, read from `scan`, belongs to `slot`. */
export function findingInSlot(scan: Pick<ScanRecord, 'scan_type'>, finding: Pick<Finding, 'tool'>, slot: OpenSetSlot): boolean {
  if (scan.scan_type !== 'security_full') return scan.scan_type === slot;
  return fullSlotOf(finding.tool) === slot;
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
    tools_run: scan.tools_run.filter((t) => fullSlotOf(t.name) === slot),
    missing_tools: scan.missing_tools.filter((t) => fullSlotOf(t) === slot),
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
