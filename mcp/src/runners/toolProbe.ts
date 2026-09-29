/**
 * Toolchain probing in TypeScript — no bash involved.
 *
 * `check_toolchain` used to shell out to `scripts/scan/check-tools.sh`, which
 * probed 11 tools while the catalogue lists 17: nuclei, phpcs, wp-cli,
 * wpscan, jscpd, lighthouse and the three .NET entries were ALWAYS reported
 * missing (a machine with .NET SDK 10.0.401 was told to install it). And the
 * script's own parsing broke the tool outright on a real Windows machine:
 * `bandit --version` prints its interpreter path first, `syft version`
 * prints several `…Version:` lines, and the script pasted both raw into a
 * JSON string — `check_toolchain` failed with "output not JSON".
 *
 * Here every catalogue entry names its own binary and version command
 * (`installCatalog.ts`), each is run through `runProcess` (argv, no shell),
 * and the version is read by one tolerant parser.
 */

import { resolveBinary } from '../platform/pkgManagerDetect.js';
import { compareSemver } from '../platform/semverCompare.js';
import { runProcess } from './processRunner.js';

export interface VersionProbe {
  /** Executable, resolved on PATH by the runner. */
  command: string;
  args: string[];
  /**
   * How to read the output. `semver` (default): the version line, else the
   * first version-shaped token. `dotnet-sdks`: the highest SDK that
   * `dotnet --list-sdks` lists — `dotnet --version` would report the SDK a
   * `global.json` pins, and exits non-zero when that one is missing.
   */
  parse?: 'semver' | 'dotnet-sdks';
  /**
   * Variables set over the server's environment for the probe — Semgrep's
   * version check off (`semgrepRun.ts#SEMGREP_NO_VERSION_CHECK_ENV`):
   * `semgrep --version` asks Semgrep's servers for a newer release too.
   */
  env?: Readonly<Record<string, string>>;
}

export interface ProbeResult {
  /** True when the command ran and exited 0 (and, for SDKs, listed one). */
  installed: boolean;
  /** Parsed version, or '' when none could be read. */
  version: string;
  /**
   * Why a binary that exists could not be probed (non-zero exit, timeout).
   * Absent when the binary is simply not there.
   */
  error?: string;
}

/** Per-probe ceiling. A version command answers in well under a second; a
 *  loaded machine can stretch Python-based ones (semgrep, bandit) to several. */
export const PROBE_TIMEOUT_MS = 30_000;

/**
 * Read a version out of a tool's `--version` output.
 *
 *   1. A line that IS a version line (`Version: 0.69.3` — trivy, syft; syft
 *      also prints `GoVersion:` and `SchemaVersion:`, which this skips).
 *   2. Otherwise the first version-shaped token not glued to a word:
 *      `ruff 0.16.6`, `k6.exe v2.2.0 (… go1.26.5 …)` → 2.2.0 not 1.26.5,
 *      `…\Scripts\bandit 1.9.4` then `python version = 3.14.7` → 1.9.4.
 *
 * Returns `major.minor[.patch]` without a leading `v` or any suffix.
 */
export function extractVersion(text: string): string | null {
  const line = /^\s*Version:\s*v?(\d+\.\d+(?:\.\d+)?)/im.exec(text);
  if (line?.[1] !== undefined) return line[1];
  const token = /(?<![\w.])v?(\d+\.\d+(?:\.\d+)?)/.exec(text);
  return token?.[1] ?? null;
}

/** Highest SDK in `dotnet --list-sdks` output (`10.0.401 [C:\…\sdk]` per line). */
export function highestDotnetSdk(text: string): string | null {
  let best: string | null = null;
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*(\d+\.\d+\.\d+)/.exec(line);
    const v = m?.[1];
    if (v === undefined) continue;
    if (best === null || (compareSemver(v, best) ?? 0) > 0) best = v;
  }
  return best;
}

export async function runVersionProbe(probe: VersionProbe, cwd: string): Promise<ProbeResult> {
  const r = await runProcess({
    command: probe.command,
    args: probe.args,
    cwd,
    // Merged over the server's own environment (runProcess extends it).
    ...(probe.env !== undefined ? { env: { ...probe.env } } : {}),
    timeoutMs: PROBE_TIMEOUT_MS,
    stdoutCapBytes: 256 * 1024,
  });
  if (r.outcome === 'timed_out') {
    return { installed: false, version: '', error: `version probe timed out after ${PROBE_TIMEOUT_MS / 1000} s` };
  }
  if (r.outcome !== 'completed') {
    // A failure is either "not there" or "there but broken", and the exit
    // code cannot tell them apart on Windows: execa resolves the command
    // through cross-spawn, which runs an UNRESOLVED command via `cmd.exe /c`
    // — so a missing tool comes back as exit 1 with a localised "is not
    // recognized" message, not as a spawn error. The PATH lookup decides:
    // nothing found means not installed, and says nothing more.
    const onPath = await resolveBinary(probe.command);
    if (!onPath) return { installed: false, version: '' };
    const why = firstLine(r.stderr) ?? firstLine(r.stdout) ?? r.outcome;
    let error = `found at ${onPath}, but \`${[probe.command, ...probe.args].join(' ')}\` exited ${r.exitCode ?? '(no exit code)'}: ${why}`;
    // Measured on a Windows host: `syft` and `pre-commit` on PATH were
    // extensionless `#!/usr/bin/env bash` shims — visible to Git Bash and to
    // `where`, not executable by any Windows process, so the server's own
    // direct invocations of both failed while the old bash probe said
    // "installed".
    if (process.platform === 'win32' && !/\.(exe|cmd|bat|com)$/i.test(onPath)) {
      error +=
        ' — the first match has no .exe/.cmd/.bat extension; if it is a bash shim it runs only ' +
        'inside bash and cannot be started by this server: put the real executable on PATH';
    }
    return { installed: false, version: '', error };
  }
  const text = `${r.stdout}\n${r.stderr}`;
  if (probe.parse === 'dotnet-sdks') {
    const sdk = highestDotnetSdk(r.stdout);
    return sdk === null
      ? { installed: false, version: '', error: 'dotnet is present but lists no SDK (runtime only)' }
      : { installed: true, version: sdk };
  }
  return { installed: true, version: extractVersion(text) ?? (firstLine(text) ?? '').slice(0, 80) };
}

function firstLine(text: string): string | undefined {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .find((l) => l.length > 0);
}
