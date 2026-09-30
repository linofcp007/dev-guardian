/**
 * The CLI reads and writes files inside the repository it gates — a CI
 * checkout, which a pull request controls: `.guardian/ci.json` (the
 * argv-only refusals), `.guardian/baseline.json` (read by `scan`, written by
 * `baseline update`) and `.guardian/hooks-allowlist.json` (`check`). Each
 * was `existsSync` + `readFileSync` / `writeFileSync`: measured on 3.0.0,
 * `baseline update` over a dangling `baseline.json` link created the link's
 * target outside the project, and a FIFO at any of the three blocked the CLI
 * until the CI job's own timeout.
 *
 * Every run here strips the scanners from PATH, so nothing reaches a real
 * scanner and each run takes about two seconds.
 */
import { spawnSync, type SpawnSyncReturns } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { spawnSyncCapped, testTimeoutAbove } from '../helpers/spawnCap.js';
import { CAN_SYMLINK, POSIX } from '../helpers/fsCapabilities.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const here = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(here, '..', '..', '..', 'cli', 'dev-guardian.mjs');
/** A hang-breaker, far above the ~2 s these runs take: reaching it is the failure. */
const TIMEOUT_MS = 45_000;
// Above the cap, so a hung child is reported by the cap — naming it — and
// not by vitest's 10 s default failing the test after the fact (R7-I1).
vi.setConfig({ testTimeout: testTimeoutAbove(TIMEOUT_MS) });

function cli(args: string[], cwd?: string): SpawnSyncReturns<string> {
  return spawnSyncCapped(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    cwd,
    timeout: TIMEOUT_MS,
    env: {
      ...process.env,
      PATH: dirname(process.execPath),
      GUARDIAN_DATA_DIR: makeTempDir('cli-hostile-data-'),
      GUARDIAN_OFFLINE: '1',
    },
  });
}

function project(): string {
  const p = makeTempDir('cli-hostile-proj-');
  mkdirSync(join(p, '.guardian'));
  writeFileSync(join(p, 'a.txt'), 'x\n');
  return p;
}

describe('dev-guardian CLI — hostile repository files', () => {
  it.skipIf(!CAN_SYMLINK)(
    'baseline update never creates the target of a dangling .guardian/baseline.json link',
    () => {
      const p = project();
      const outside = makeTempDir('cli-hostile-outside-');
      symlinkSync(join(outside, 'planted.json'), join(p, '.guardian', 'baseline.json'), 'file');

      const r = cli(['baseline', 'update', '--project', p]);

      expect(r.error).toBeUndefined();
      expect(readdirSync(outside)).toEqual([]);
      expect(r.status).toBe(3);
      expect(r.stderr).toMatch(/baseline/i);
    },
    TIMEOUT_MS + 5_000,
  );

  it.skipIf(!CAN_SYMLINK)(
    'scan refuses a baseline that is a link to a file outside the project, rather than reading it',
    () => {
      const p = project();
      const outside = makeTempDir('cli-hostile-outside-');
      writeFileSync(join(outside, 'baseline.json'), JSON.stringify({ version: 1, entries: [] }));
      symlinkSync(join(outside, 'baseline.json'), join(p, '.guardian', 'baseline.json'), 'file');

      const r = cli(['scan', '--project', p]);

      expect(r.error).toBeUndefined();
      expect(r.status).toBe(3);
      expect(r.stderr).toMatch(/baseline\.json.*outside the project/i);
    },
    TIMEOUT_MS + 5_000,
  );

  it.skipIf(!POSIX)(
    'scan answers at once when .guardian/ci.json is a FIFO (POSIX)',
    () => {
      const p = project();
      expect(spawnSync('mkfifo', [join(p, '.guardian', 'ci.json')]).status).toBe(0);
      const r = cli(['scan', '--project', p, '--start-command', 'node', 'server.js']);
      expect(r.error).toBeUndefined();
      expect(r.status).toBe(3);
      expect(r.stderr).toMatch(/--base-url/);
    },
    TIMEOUT_MS + 5_000,
  );

  it.skipIf(!POSIX)(
    'scan answers at once when .guardian/baseline.json is a FIFO (POSIX)',
    () => {
      const p = project();
      expect(spawnSync('mkfifo', [join(p, '.guardian', 'baseline.json')]).status).toBe(0);
      const r = cli(['scan', '--project', p]);
      expect(r.error).toBeUndefined();
      expect(r.status).toBe(3);
      expect(r.stderr).toMatch(/baseline\.json.*not a regular file/i);
    },
    TIMEOUT_MS + 5_000,
  );

  it.skipIf(!POSIX)(
    'check answers at once when .guardian/hooks-allowlist.json is a FIFO (POSIX)',
    () => {
      const p = project();
      expect(spawnSync('mkfifo', [join(p, '.guardian', 'hooks-allowlist.json')]).status).toBe(0);
      writeFileSync(join(p, 'f.js'), 'const a = 1;\n');
      const r = cli(['check', '--file', join(p, 'f.js')], p);
      expect(r.error).toBeUndefined();
      expect(r.status).toBe(0);
    },
    TIMEOUT_MS + 5_000,
  );

  it('ci-init still refuses a ci.json that declares attest (the bounded read changed nothing there)', () => {
    const p = project();
    writeFileSync(join(p, '.guardian', 'ci.json'), JSON.stringify({ attest: true }));
    const r = cli(['ci-init', 'github', '--project', p]);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/attest/);
    expect(existsSync(join(p, '.github'))).toBe(false);
  });
});
