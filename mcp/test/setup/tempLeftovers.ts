/**
 * vitest `globalSetup`: removes the temp directories a test's cleanup could
 * not — see `LEFTOVERS_FILE` in `test/helpers/tempDir.ts`. Once before the
 * run (what an earlier run left listed) and once after it (what this run
 * left, now that the processes that held it have exited). Runs in the main
 * process, never in a worker.
 */

import { removeLeftovers } from '../helpers/tempDir.js';

export default function setup(): () => void {
  removeLeftovers();
  return () => removeLeftovers();
}
