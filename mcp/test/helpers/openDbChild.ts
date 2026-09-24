/**
 * Child-process entry point for the concurrent-open test
 * (`test/integration/storageConcurrency.test.ts`): open (and so migrate) the
 * project database exactly as the server does, then close it.
 *
 *   node --import <tsx> openDbChild.ts <projectPath> <startAtEpochMs>
 *
 * Every child sleeps until the same wall-clock instant before opening, so the
 * opens really overlap instead of being serialised by process start-up time.
 * Exit 0 on success; exit 1 with the error on stderr otherwise.
 */

import { openDatabase } from '../../src/storage/db.js';

const [projectPath, startAtRaw] = process.argv.slice(2);
if (projectPath === undefined || startAtRaw === undefined) {
  process.stderr.write('usage: openDbChild.ts <projectPath> <startAtEpochMs>\n');
  process.exit(2);
}

const wait = Number(startAtRaw) - Date.now();
setTimeout(
  () => {
    try {
      const { db } = openDatabase({ projectPath });
      db.close();
      process.exit(0);
    } catch (error) {
      process.stderr.write(`${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`);
      process.exit(1);
    }
  },
  Math.max(0, wait),
);
