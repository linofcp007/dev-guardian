/**
 * A scanned repository's own configuration for the scanners it is scanned
 * with — honoured when it is the project's call to make (its accepted
 * risks, its rule selection), but never in silence (round 4, item 3).
 *
 * A file a scanner reads on its own from the project decides part of what
 * the scan reports. Where it is legitimate — `.trivyignore`, a root
 * `.bandit`, `.hadolint.yaml`, `.github/actionlint.yaml`, `zizmor.yml`,
 * `.gitleaks.toml` / `.gitleaksignore` — the run that read it names it in
 * `tools_run[].honoured_config` and its reason. Where it is not (a
 * `trivy.yaml` that can point Trivy at another server, a `.syft.yaml`, a
 * `.bandit` below the root), the helpers that spawn the scanner keep it out
 * (`trivyRun.ts`, `syftRun.ts`, scan_sast's `--ini`).
 */

import { lstatSync } from 'node:fs';
import { join } from 'node:path';
import type { ToolRun } from '../types.js';

/** Which of `candidates` (project-relative, `/`-separated) are regular files in the project. */
export function presentProjectFiles(projectPath: string, candidates: readonly string[]): string[] {
  return candidates.filter((rel) => {
    try {
      return lstatSync(join(projectPath, ...rel.split('/'))).isFile();
    } catch {
      return false;
    }
  });
}

/**
 * `run` naming the project files it honoured and what they decide: a note on
 * its reason, the files in `honoured_config`. Unchanged when there are none.
 */
export function withProjectConfig(run: ToolRun, files: readonly string[], decides: string): ToolRun {
  if (files.length === 0) return run;
  const note = `honoured the project's ${files.join(', ')} (${decides})`;
  return {
    ...run,
    reason: run.reason !== undefined && run.reason.length > 0 ? `${run.reason}; ${note}` : note,
    honoured_config: [...new Set([...(run.honoured_config ?? []), ...files])],
  };
}
