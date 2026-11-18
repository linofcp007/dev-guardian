/**
 * The selftest's core controls: what is run, on which canary, and what has to
 * come back.
 *
 * One control per rule pack of `configs/semgrep/` — a pack is tested alone, so
 * that its verdict depends on nothing but itself —, the secret scan
 * (gitleaks), the dependency audit and the IaC scan (Trivy), and five checks
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
import { SELFTEST_SCANNERS, type SelftestScanner } from './store.js';

/** The scanners that have a control: every other catalogued one is `no_canary` when installed. */
export type ScannerName = SelftestScanner;
export const SCANNERS_WITH_CONTROLS: readonly ScannerName[] = SELFTEST_SCANNERS;

/** The id of the selftest's own Semgrep rule, which matches the marker every Semgrep canary carries. */
export const PROBE_RULE_ID = 'dev-guardian-selftest-probe';

type ControlKind = 'semgrep-pack' | 'gitleaks' | 'trivy-deps' | 'trivy-iac' | 'hook';

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
  'base.yml': ['base/canary.js', 'js-insecure-randomness'],
  'bugfix-cs.yml': ['bugfix-cs/Canary.cs', 'bugfix-cs-race-condition-static-random'],
  'bugfix-go.yml': ['bugfix-go/canary.go', 'bugfix-go-off-by-one-loop-lte-len'],
  'bugfix-java.yml': ['bugfix-java/Canary.java', 'bugfix-java-race-condition-static-dateformat'],
  'bugfix-js.yml': ['bugfix-js/canary.js', 'bugfix-js-edge-case-parseint-without-radix'],
  'bugfix-php.yml': ['bugfix-php/canary.php', 'bugfix-php-null-safety-loose-null-compare'],
  'bugfix-py.yml': ['bugfix-py/canary.py', 'bugfix-py-off-by-one-range-len-plus-one'],
  'bugfix-rs.yml': ['bugfix-rs/canary.rs', 'bugfix-rs-race-condition-blocking-sleep-in-async'],
  'client-trust.yml': ['client-trust/canary.js', 'client-public-env-secret'],
  'llm.yml': ['llm/canary.py', 'llm-torch-load-weights-only-false'],
  'mobile.yml': ['mobile/res/xml/network_security_config.xml', 'mobile-android-nsc-cleartext'],
  'rgpd.yml': ['rgpd/canary.js', 'rgpd-pii-in-log-js'],
  'routes.yml': ['routes/server.js', 'guardian-route-express'],
  'web-js.yml': ['web-js/canary.js', 'web-js-sql-template'],
  'wordpress.yml': ['wordpress/canary.php', 'wordpress-esc-sql-unquoted'],
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

export const CORE_CONTROLS: readonly Control[] = [
  ...packControls,
  { id: 'gitleaks', kind: 'gitleaks', scanner: 'gitleaks', canary: SECRET_CANARY, expect: '*', timeoutMs: SCANNER_TIMEOUT_MS },
  { id: 'trivy:deps', kind: 'trivy-deps', scanner: 'trivy', canary: 'deps/package-lock.json', expect: 'minimist', timeoutMs: SCANNER_TIMEOUT_MS },
  { id: 'trivy:iac', kind: 'trivy-iac', scanner: 'trivy', canary: 'iac/Dockerfile.selftest', expect: '*', timeoutMs: SCANNER_TIMEOUT_MS },
  { id: 'hooks:bash-block', kind: 'hook', scanner: 'hooks', canary: null, expect: 'deny', timeoutMs: HOOK_TIMEOUT_MS },
  { id: 'hooks:powershell-block', kind: 'hook', scanner: 'hooks', canary: null, expect: 'deny', timeoutMs: HOOK_TIMEOUT_MS },
  { id: 'hooks:settings-guard', kind: 'hook', scanner: 'hooks', canary: null, expect: 'deny', timeoutMs: HOOK_TIMEOUT_MS },
  { id: 'hooks:secret-warning', kind: 'hook', scanner: 'hooks', canary: SECRET_CANARY, expect: 'secret-warning', timeoutMs: HOOK_TIMEOUT_MS },
  { id: 'hooks:install-vet', kind: 'hook', scanner: 'hooks', canary: null, expect: 'deny', timeoutMs: HOOK_TIMEOUT_MS },
];

interface ControlsCheck {
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
  const controls = check.controls ?? CORE_CONTROLS;
  const problems: string[] = [];
  const ids = new Set<string>();
  for (const c of controls) {
    if (ids.has(c.id)) problems.push(`two controls are named ${c.id}`);
    ids.add(c.id);
  }
  let packs: string[];
  try {
    packs = readdirSync(check.packsDir).filter((name) => /\.ya?ml$/.test(name)).sort();
  } catch {
    return [...problems, `the rule packs' directory could not be read: ${check.packsDir}`];
  }
  const packControlsOf = (pack: string): Control[] => controls.filter((c) => c.kind === 'semgrep-pack' && c.pack === pack);
  for (const pack of packs) {
    const n = packControlsOf(pack).length;
    if (n === 0) problems.push(`${pack} has no selftest control: add its canary to configs/selftest/ and its entry to selftest/controls.ts`);
    else if (n > 1) problems.push(`${pack} has ${n} selftest controls`);
  }
  for (const c of controls) {
    if (c.kind === 'semgrep-pack') {
      const pack = c.pack ?? '';
      if (!packs.includes(pack)) {
        problems.push(`${c.id} names the pack ${pack}, which is not in ${check.packsDir}`);
        continue;
      }
      if (!ruleIdsInFile(join(check.packsDir, pack)).includes(c.expect)) {
        problems.push(`${c.id} expects the rule ${c.expect}, which ${pack} does not hold`);
      }
    }
    // The secret canary's file is a template too; every seeded file is shipped under its name plus the suffix.
    if (c.canary !== null && !existsSync(join(check.canariesDir, 'project', ...`${c.canary}${CANARY_SUFFIX}`.split('/')))) {
      problems.push(`${c.id}'s canary is not shipped: configs/selftest/project/${c.canary}${CANARY_SUFFIX}`);
    }
  }
  return problems;
}
