/**
 * "Is this binary on PATH?", answered once at collection time so `it.skipIf`
 * can report a skip as a skip.
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

/** Resolves `true` when `bin` is on PATH. Never throws — a probe that fails
 *  to run reports "not installed", which is the safe direction: the caller
 *  skips, and `GUARDIAN_REQUIRE_SEMGREP=1` turns that skip into a hard
 *  failure for anyone who needs to know. */
export const PROBE_TIMEOUT_MS = 30_000;

export async function isInstalled(bin: string): Promise<boolean> {
  try {
    const r = await execa(detectOs() === 'win32' ? 'where' : 'which', [bin], {
      reject: false,
      timeout: PROBE_TIMEOUT_MS,
    });
    return r.exitCode === 0;
  } catch {
    return false;
  }
}
