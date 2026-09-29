/**
 * vitest `globalSetup`: removes the temp directories a test's cleanup could
 * not — see `LEFTOVERS_FILE` in `test/helpers/tempDir.ts`. Once before the
 * run (what an earlier run left listed) and once after it (what this run
 * left, now that the processes that held it have exited). Runs in the main
 * process, never in a worker.
 *
 * It also gives the run its own dev-guardian data directory
 * (`GUARDIAN_DATA_DIR`: the per-user database fallbacks and the registry of
 * databases dev-guardian created — `storage/userData.ts`), under the OS temp
 * directory, before any worker starts (workers, and every process a test
 * spawns, inherit it), and removes it after the run. Earlier runs shared one
 * fixed `dev-guardian-test-data` directory that nothing ever removed; any
 * left behind is removed here too.
 */

import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { removeLeftovers, rmDirOrDefer } from '../helpers/tempDir.js';

export default function setup(): () => void {
  removeLeftovers();
  rmDirOrDefer(join(tmpdir(), 'dev-guardian-test-data'));
  const dataDir = mkdtempSync(join(tmpdir(), 'dev-guardian-test-data-'));
  process.env['GUARDIAN_DATA_DIR'] = dataDir;
  return () => {
    rmDirOrDefer(dataDir);
    removeLeftovers();
  };
}
