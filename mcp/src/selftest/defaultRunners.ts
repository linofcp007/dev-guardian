/**
 * The selftest's real runners: every process a selftest starts.
 *
 * The hook checks go through {@link runDispatcher}. The scanner runners are
 * the scan tools' own — written in the next step; until then they say so
 * instead of pretending to have run.
 */

import { runDispatcher } from './hookRunner.js';
import type { ScanOutcome, ScannerProbe, SelftestRunners } from './run.js';

const notYet = (what: string): never => {
  throw new Error(`selftest: ${what} is not implemented`);
};

export function defaultRunners(): SelftestRunners {
  return {
    probe: async (): Promise<ScannerProbe> => notYet('the version probe'),
    semgrep: async (): Promise<ScanOutcome> => notYet('the Semgrep runner'),
    gitleaks: async (): Promise<ScanOutcome> => notYet('the gitleaks runner'),
    trivy: async (): Promise<ScanOutcome> => notYet('the Trivy runner'),
    hook: runDispatcher,
    installedTools: async (): Promise<string[]> => notYet('the list of installed scanners'),
  };
}
