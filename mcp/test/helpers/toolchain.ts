/**
 * "Is this binary installed?", answered once at collection time so `it.skipIf`
 * can report a skip as a skip — and answered the way the SERVER answers it.
 *
 * `install_toolchain` puts Trivy, gitleaks, Syft and cosign in the per-user
 * tools directory (`~/.local/bin`, `%USERPROFILE%\.local\bin`) and leaves PATH
 * alone; the server appends that directory to its own PATH before every
 * lookup (`src/platform/userBin.ts`). This probe used to run `where` /
 * `which` without that step, so on a machine the product itself had set up
 * every test of a real Trivy or gitleaks was skipped, in silence, for a
 * scanner the product runs — and two `create_fix_pr` tests stayed red behind
 * the skip for as long as nobody put that directory on PATH by hand. The
 * probe now takes the same step: appended, never prepended, so a binary on
 * the user's own PATH is still the one that runs.
 *
 * ---- Why this is shared, and why the timeout is what it is ----------------
 *
 * Six test files had their own byte-identical copy of this, each with
 * `timeout: 2_000`. A `where`/`which` lookup takes single-digit milliseconds,
 * so two seconds looks like generous headroom — until the machine is busy,
 * at which point spawning ANY process can take longer than that. Reproduced
 * on a full-suite run with other work on the box: the probe timed out,
 * `SEMGREP_INSTALLED` came back `false` with Semgrep sitting on PATH the
 * whole time, and `projectRulesFixture`'s `GUARDIAN_REQUIRE_SEMGREP=1` gate
 * failed with "semgrep is not on PATH".
 *
 * That is the worst possible way for this to break. The whole point of the
 * skip discipline (see `rulePackFixture.test.ts`'s header) is that "the
 * scanner is missing" and "the scanner ran and disagreed" must never be
 * confusable — and a probe that reports a busy machine as a missing toolchain
 * makes them confusable in the one place built to keep them apart.
 *
 * 30 seconds bounds a genuinely wedged process and nothing else: no answer
 * this probe legitimately produces is anywhere near it, so it can never again
 * be the thing that decides whether a suite runs.
 */
import { execa } from 'execa';
import { detectOs } from '../../src/platform/osDetect.js';
import { ensureUserBinOnPath } from '../../src/platform/userBin.js';
import { highestDotnetSdk } from '../../src/runners/toolProbe.js';

export const PROBE_TIMEOUT_MS = 30_000;

/** Resolves `true` when `bin` is on PATH or in the per-user tools directory
 *  of `home` (the user's own, by default), which this call appends to the
 *  process's PATH as the server does. Never throws — a probe that fails to
 *  run reports "not installed", which is the safe direction: the caller
 *  skips, and `GUARDIAN_REQUIRE_SEMGREP=1` turns that skip into a hard
 *  failure for anyone who needs to know. */
export async function isInstalled(bin: string, home?: string): Promise<boolean> {
  try {
    ensureUserBinOnPath(process.env, home);
    const r = await execa(detectOs() === 'win32' ? 'where' : 'which', [bin], {
      reject: false,
      timeout: PROBE_TIMEOUT_MS,
    });
    return r.exitCode === 0;
  } catch {
    return false;
  }
}

/**
 * Resolves `true` when a .NET SDK is installed — not merely the `dotnet`
 * host. A machine with only the runtime has `dotnet` on PATH, and there
 * `dotnet new` and `dotnet restore` fail ("No .NET SDKs were found"), so an
 * e2e gated on the binary alone fails instead of skipping. Read the way
 * `check_toolchain` reads it: the highest SDK `dotnet --list-sdks` lists.
 */
export async function isDotnetSdkInstalled(): Promise<boolean> {
  if (!(await isInstalled('dotnet'))) return false;
  try {
    const r = await execa('dotnet', ['--list-sdks'], { reject: false, timeout: PROBE_TIMEOUT_MS });
    return r.exitCode === 0 && highestDotnetSdk(String(r.stdout)) !== null;
  } catch {
    return false;
  }
}
