/**
 * Every Syft spawn in this codebase — one helper, so that no SBOM can be
 * steered by the configuration of the repository it describes, and Syft never
 * phones home. The same rule as `runners/trivyRun.ts`.
 *
 * ---- The defect ------------------------------------------------------------
 *
 * `generate_sbom` ran `syft <project>` with the project as its working
 * directory and no `-c`, so Syft read the project's own `.syft.yaml` (or
 * `.syft/config.yaml`) — its debug log says `config: .syft.yaml`. Measured on
 * Syft 1.51.1: a committed `select-catalogers: ['-javascript']` took a
 * project pinning lodash 4.17.15 from 2 library components to 0, and the
 * same file can turn on Syft's network lookups (`java.use-network`,
 * `golang.search-remote-licenses`). And every run asked
 * `toolbox-data.anchore.io` whether a newer Syft exists
 * (`check-for-app-update`, on by default).
 *
 * ---- What this does --------------------------------------------------------
 *
 *   - Syft runs in `workDir` — a report directory this scan created, never
 *     the project — and is handed its target and output as explicit paths.
 *   - It is always given `-c <an empty file this helper writes>`: with `-c`,
 *     Syft reads that file and no other (measured: the project's
 *     `.syft.yaml` above is ignored even with the project as working
 *     directory).
 *   - `SYFT_CHECK_FOR_APP_UPDATE=false` in every run's environment.
 *   - The root `.guardian/`'s generated output (`platform/guardianOutput.ts`)
 *     is left out, `--exclude ./<path>` each: measured on Syft 1.55.0
 *     (2026-10-25), a `package-lock.json` under `.guardian/reports/` became
 *     components of the project's SBOM, and `./.guardian/reports` left it
 *     out while `lib/.guardian/reports/` and the root `.guardian/` itself
 *     were still read; a pattern without `./` is refused on a directory
 *     scan. An earlier `sbom.cdx.json` there was not re-read — the
 *     sbom-cataloger is off on a directory scan — but nothing there is the
 *     project's.
 *
 * `test/unit/runners/syftRun.test.ts` fails when any spawn in `src/` names
 * Syft outside this file.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT_OUTPUT_PATHS } from '../platform/guardianOutput.js';
import { runProcess, type ProcessRunResult } from './processRunner.js';

/** The empty configuration file written into the working directory. */
export const NEUTRAL_SYFT_CONFIG = 'syft-neutral-config.yaml';

const NEUTRAL_CONFIG_TEXT =
  '# Written by dev-guardian: an empty Syft configuration, passed as -c so that the\n' +
  "# scanned repository's own .syft.yaml is never read.\n";

/** Syft's update check (toolbox-data.anchore.io), off. */
export const SYFT_NO_PHONE_HOME_ENV: Readonly<Record<string, string>> = {
  SYFT_CHECK_FOR_APP_UPDATE: 'false',
};

interface SyftInvocation {
  /** The directory (or image reference) the SBOM describes. */
  target: string;
  /** Syft's output format (`cyclonedx-json`, `spdx-json`). */
  format: string;
  /** Where Syft writes the document. */
  outFile: string;
  /** Where Syft runs and the empty config is written: a directory this scan created, never the project. */
  workDir: string;
  env?: NodeJS.ProcessEnv;
  signal?: AbortSignal;
  onLog?: (line: string) => void;
  timeoutMs?: number;
}

/** The argv of one run — pure, for the tests. */
export function syftArgv(inv: Pick<SyftInvocation, 'target' | 'format' | 'outFile'>, configPath: string): string[] {
  // Relative to the scanned directory, where Syft anchors a `./` pattern (module comment).
  const excludes = ROOT_OUTPUT_PATHS.flatMap((p) => ['--exclude', `./${p}`]);
  return [inv.target, '-o', `${inv.format}=${inv.outFile}`, '--quiet', '-c', configPath, ...excludes];
}

/** Run Syft — see the module comment. A config that cannot be written is a failed run, never one without it. */
export async function runSyft(inv: SyftInvocation): Promise<ProcessRunResult> {
  const configPath = join(inv.workDir, NEUTRAL_SYFT_CONFIG);
  try {
    mkdirSync(inv.workDir, { recursive: true });
    writeFileSync(configPath, NEUTRAL_CONFIG_TEXT, 'utf8');
  } catch (e) {
    const why = e instanceof Error ? e.message : String(e);
    return {
      outcome: 'failed',
      exitCode: null,
      stdout: '',
      stderr: `could not write the neutral Syft configuration ${configPath}: ${why}`,
      truncated: false,
    };
  }
  return runProcess({
    command: 'syft',
    args: syftArgv(inv, configPath),
    cwd: inv.workDir,
    // Merged over the server's own environment by the runner.
    env: { ...(inv.env ?? {}), ...SYFT_NO_PHONE_HOME_ENV },
    ...(inv.signal !== undefined ? { signal: inv.signal } : {}),
    ...(inv.onLog !== undefined ? { onLog: inv.onLog } : {}),
    ...(inv.timeoutMs !== undefined ? { timeoutMs: inv.timeoutMs } : {}),
  });
}
