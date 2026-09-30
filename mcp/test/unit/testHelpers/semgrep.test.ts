/**
 * `test/helpers/semgrep.ts` — the bound every synchronous Semgrep spawn in the
 * suite relies on. Exercised against a stand-in command (`node`), never real
 * Semgrep: the property under test is that a command which never finishes
 * FAILS at the bound, and no real Semgrep can be made to hang on purpose.
 */

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';
import {
  SemgrepTimeoutError,
  runSemgrep,
  semgrepAvailable,
  semgrepStdout,
} from '../../helpers/semgrep.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);
afterEach(() => {
  vi.unstubAllEnvs();
});

/** A stand-in "semgrep": answers --version at once, never finishes anything else. */
function fakeSemgrep(): string {
  const dir = makeTempDir('guardian-fake-semgrep-');
  const script = join(dir, 'fake-semgrep.mjs');
  writeFileSync(
    script,
    [
      "if (process.argv.includes('--version')) { process.stdout.write('0.0.0-fake\\n'); process.exit(0); }",
      "if (process.argv.includes('--fail')) { process.stderr.write('boom\\n'); process.exit(2); }",
      "if (process.argv.includes('--echo')) { process.stdout.write('{\"results\":[]}'); process.exit(0); }",
      "if (process.argv.includes('--errors')) { process.stdout.write('{\"results\":[],\"errors\":[{\"type\":\"Timeout\",\"message\":\"rule r timed out on f.py\"}]}'); process.exit(2); }",
      'setInterval(() => {}, 1 << 30);',
    ].join('\n'),
  );
  return script;
}

function useFake(): void {
  vi.stubEnv('GUARDIAN_TEST_SEMGREP_CMD', JSON.stringify([process.execPath, fakeSemgrep()]));
}

describe('runSemgrep — a hung semgrep fails at the bound, never hangs the worker', () => {
  it('throws SemgrepTimeoutError, naming the command, once the bound passes', () => {
    useFake();
    const t0 = Date.now();
    let caught: unknown;
    try {
      runSemgrep(['--config', 'x.yml', '--json', '.'], { timeoutMs: 1_500 });
    } catch (e) {
      caught = e;
    }
    const elapsed = Date.now() - t0;
    expect(caught).toBeInstanceOf(SemgrepTimeoutError);
    expect(String(caught)).toMatch(/did not finish within 1\.5 s and was killed/);
    expect(String(caught)).toContain('--config x.yml --json .');
    expect(elapsed).toBeGreaterThanOrEqual(1_400);
    expect(elapsed).toBeLessThan(8_000);
  });

  it('GUARDIAN_TEST_SEMGREP_TIMEOUT_MS sets the default bound', () => {
    useFake();
    vi.stubEnv('GUARDIAN_TEST_SEMGREP_TIMEOUT_MS', '1000');
    expect(() => runSemgrep(['--scan'])).toThrow(SemgrepTimeoutError);
  });

  it('semgrepStdout throws the same timeout instead of returning', () => {
    useFake();
    expect(() => semgrepStdout(['--scan'], { timeoutMs: 1_000 })).toThrow(SemgrepTimeoutError);
  });
});

describe('runSemgrep — ordinary runs', () => {
  it('returns stdout, stderr and the exit status of a run that finishes', () => {
    useFake();
    expect(runSemgrep(['--echo'])).toEqual({ status: 0, stdout: '{"results":[]}', stderr: '' });
    expect(runSemgrep(['--fail'])).toMatchObject({ status: 2, stderr: 'boom\n' });
  });

  it('semgrepStdout keeps execFileSync semantics: a non-zero exit throws with the stderr tail', () => {
    useFake();
    expect(semgrepStdout(['--echo'])).toBe('{"results":[]}');
    expect(() => semgrepStdout(['--fail'])).toThrow(/semgrep exited 2: semgrep --fail\nboom/);
  });

  // Under --quiet --json the report's `errors` are the only place Semgrep
  // says why it exited 2; the failure message used to drop them.
  it("semgrepStdout's failure names the report's errors", () => {
    useFake();
    expect(() => semgrepStdout(['--errors'])).toThrow(/report errors \(1\): .*rule r timed out on f\.py/);
  });

  it('semgrepAvailable is false for a command that does not exist, true for one that answers', () => {
    vi.stubEnv('GUARDIAN_TEST_SEMGREP_CMD', JSON.stringify(['guardian-no-such-semgrep-binary']));
    expect(semgrepAvailable()).toBe(false);
    useFake();
    expect(semgrepAvailable()).toBe(true);
  });

  // Review 3.0, R7: "on PATH but failing" read as absent, so the rule-pack
  // files SKIPPED on a broken Semgrep and a single-pack run went green.
  it('semgrepAvailable THROWS for a command that is there but fails --version: broken is not absent', () => {
    const dir = makeTempDir('guardian-broken-semgrep-');
    const script = join(dir, 'broken-semgrep.mjs');
    writeFileSync(script, "process.stderr.write('ModuleNotFoundError: no module named semgrep\\n'); process.exit(1);\n");
    vi.stubEnv('GUARDIAN_TEST_SEMGREP_CMD', JSON.stringify([process.execPath, script]));
    expect(() => semgrepAvailable()).toThrow(/on PATH but `semgrep --version` exited 1[\s\S]*ModuleNotFoundError/);
  });
});
