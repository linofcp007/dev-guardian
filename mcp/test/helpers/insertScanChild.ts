/**
 * Child-process entry point for the chunked-insert test
 * (`test/unit/storage/findingsBulkInsert.test.ts`): opens `dbPath` with the
 * server's own busy timeout, prints `ready`, and on the first line of stdin
 * inserts one scan row — the write another process's `scans.insert` makes —
 * then prints `ok <startedAtMs> <doneAtMs>` or `fail <startedAtMs> <doneAtMs>
 * <message>` and exits.
 *
 *   node --import <tsx> insertScanChild.ts <dbPath>
 */

import { GuardianDatabase } from '../../src/storage/db.js';

const [dbPath] = process.argv.slice(2);
if (dbPath === undefined) {
  process.stderr.write('usage: insertScanChild.ts <dbPath>\n');
  process.exit(2);
}

const db = new GuardianDatabase(dbPath);
process.stdout.write('ready\n');
process.stdin.once('data', () => {
  const started = Date.now();
  try {
    db.prepare(
      `INSERT INTO scans (id, scan_type, project_path, tree_hash, started_at, status)
       VALUES ('other-process', 'secrets', '/other', 'h', ?, 'running')`,
    ).run(new Date().toISOString());
    process.stdout.write(`ok ${started} ${Date.now()}\n`);
  } catch (error) {
    process.stdout.write(`fail ${started} ${Date.now()} ${error instanceof Error ? error.message : String(error)}\n`);
  }
  db.close();
  process.exit(0);
});
