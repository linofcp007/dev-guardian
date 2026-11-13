// @ts-nocheck -- Phase 4 scaffold (dev-spec-driven): the failing tests come first; the implementation replaces these bodies.
/**
 * The selftest's core controls: what is run, on which canary, and what has to
 * come back.
 *
 * One control per rule pack of `configs/semgrep/` — a pack is tested alone, so
 * that its verdict depends on nothing but itself —, the secret scan
 * (gitleaks), the dependency audit and the IaC scan (Trivy), and four checks
 * of the guardrail hooks. Every other installed scanner is listed by the
 * selftest as `no_canary`: installed, not verified.
 *
 * The rule each pack's canary must fire is FIXED here, chosen by measurement
 * with the pinned Semgrep: a rule of ours, which changes only when we change
 * it. The dependency and IaC canaries accept any finding on their file (a
 * vulnerability of that package, any check on that Dockerfile): an advisory
 * id or a check id is the scanner's to rename.
 *
 * {@link controlsProblems} is what holds the registry to the packs: a pack
 * added to `configs/semgrep/` with no control, no canary or a rule that is
 * not in it fails the suite by name.
 */

import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { ruleIdsInFile } from '../runners/semgrepRuleIds.js';
import { CANARY_SUFFIX } from './canaries.js';
import { SECRET_CANARY } from './hookChecks.js';

/** The scanners that have a control: every other catalogued one is `no_canary` when installed. */
export type ScannerName = 'semgrep' | 'gitleaks' | 'trivy';
export const SCANNERS_WITH_CONTROLS: readonly ScannerName[] = ['semgrep', 'gitleaks', 'trivy'];

/** The id of the selftest's own Semgrep rule, which matches the marker every Semgrep canary carries. */
export const PROBE_RULE_ID = 'dev-guardian-selftest-probe';

export type ControlKind = 'semgrep-pack' | 'gitleaks' | 'trivy-deps' | 'trivy-iac' | 'hook';

export interface Control {
  /** `semgrep:<pack>`, `gitleaks`, `trivy:deps`, `trivy:iac`, `hooks:<check>`. */
  id: string;
  kind: ControlKind;
  /** The scanner's name in the catalogue, or `hooks`. */
  scanner: ScannerName | 'hooks';
  /** The seeded file, relative to the temporary project, with forward slashes; `null` for a hook check that needs none. */
  canary: string | null;
  /** What has to be reported on the canary: a rule's id, a package's name, `*` for anything, or the hook's answer. */
  expect: string;
  /** `semgrep-pack`: the pack's file name in `configs/semgrep/`. */
  pack?: string;
  timeoutMs: number;
}

/** One pack over a dozen small files: seconds. The ceiling is for a machine under load. */
const PACK_TIMEOUT_MS = 180_000;
/** Trivy may fetch its database on a first run. */
const SCANNER_TIMEOUT_MS = 300_000;
const HOOK_TIMEOUT_MS = 20_000;

/** Each pack's canary, and the rule of that pack it must fire (measured — see `configs/selftest/README.md`). */
const PACK_CANARIES: Readonly<Record<string, readonly [canary: string, rule: string]>> = {
  // @@PACK_CANARIES@@
};

const packControls: Control[] = Object.entries(PACK_CANARIES).map(([pack, [canary, rule]]) => ({
  id: `semgrep:${pack.replace(/\.ya?ml$/, '')}`,
  kind: 'semgrep-pack',
  scanner: 'semgrep',
  canary,
  expect: rule,
  pack,
  timeoutMs: PACK_TIMEOUT_MS,
}));

export const CORE_CONTROLS: readonly Control[] = [];

export interface ControlsCheck {
  /** `configs/semgrep/`. */
  packsDir: string;
  /** `configs/selftest/`. */
  canariesDir: string;
  controls?: readonly Control[];
}

/**
 * What is wrong between the registry, the packs and the shipped canaries —
 * empty when nothing is: every pack file has exactly one control; every
 * control's pack exists and holds the rule the control expects; every canary
 * a control names is shipped; no two controls share an id.
 */
export function controlsProblems(check: ControlsCheck): string[] {
  throw new Error('selftest: not implemented');
}
