import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execPath } from 'node:process';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { runProcess } from '../../../src/runners/processRunner.js';

/**
 * `extendEnv` is the half of the environment-scrubbing contract that is easy
 * to get wrong invisibly: execa MERGES `env` over `process.env` by default, so
 * a caller that passes a carefully allowlisted `env` and forgets
 * `extendEnv: false` hands the child every parent variable anyway. Nothing
 * about that failure is observable from the option object — only from what the
 * child actually receives.
 *
 * So these spawn a real Node child (the same portable-shell trick
 * `shellRunner.test.ts` uses — no bash required) and read the environment back
 * out of its stdout. A mock of `runProcess` could not prove this: the whole
 * question is what execa does with the options, not what it is handed.
 */
function writeEnvPrinter(): { path: string; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), 'processrunner-'));
  const path = join(dir, 'printenv.js');
  // JSON of the child's own environment, so the test reads exactly what the
  // child sees rather than a shell's rendering of it.
  writeFileSync(path, 'process.stdout.write(JSON.stringify(process.env));');
  return { path, dir };
}

const PARENT_ONLY = 'GUARDIAN_PROCESSRUNNER_PARENT_SECRET';

async function childEnv(options: {
  env?: NodeJS.ProcessEnv;
  extendEnv?: boolean;
}): Promise<Record<string, string>> {
  const { path, dir } = writeEnvPrinter();
  const result = await runProcess({
    command: execPath,
    args: [path],
    cwd: dir,
    ...options,
  });
  expect(result.outcome).toBe('completed');
  return JSON.parse(result.stdout) as Record<string, string>;
}

describe('runProcess environment handling', () => {
  beforeEach(() => {
    process.env[PARENT_ONLY] = 'inherited-value';
  });

  afterEach(() => {
    delete process.env[PARENT_ONLY];
  });

  it('inherits the parent environment by default', async () => {
    // The baseline the scrub has to overcome, and the behaviour every other
    // caller in this repo (semgrep, trivy, gitleaks, git) still relies on.
    const env = await childEnv({});
    expect(env[PARENT_ONLY]).toBe('inherited-value');
  });

  it('still inherits when env is passed WITHOUT extendEnv: false', async () => {
    // The trap, pinned: an allowlist alone scrubs nothing. If this ever starts
    // returning undefined, execa's default changed and `extendEnv: false` at
    // the call sites is no longer what is doing the work.
    const env = await childEnv({ env: { GUARDIAN_EXPLICIT: 'yes' } });
    expect(env['GUARDIAN_EXPLICIT']).toBe('yes');
    expect(env[PARENT_ONLY]).toBe('inherited-value');
  });

  it('replaces the environment when extendEnv is false', async () => {
    // THE assertion: the parent-only variable must be gone from the child.
    const env = await childEnv({ env: { GUARDIAN_EXPLICIT: 'yes' }, extendEnv: false });
    expect(env['GUARDIAN_EXPLICIT']).toBe('yes');
    expect(env[PARENT_ONLY]).toBeUndefined();
  });
});
