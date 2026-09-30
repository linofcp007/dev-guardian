/**
 * Registers an existing test database as this user's WITHOUT migrating it —
 * what `db adopt --yes` leaves behind, minus the migrations it runs — so a
 * test can hold a registered database at an older schema (the upgrade a
 * later build's migrations make, with several servers starting at once).
 * Writes the id into `schema_meta` and the entry into the per-user registry
 * (the test run's own `GUARDIAN_DATA_DIR`).
 */

import { createRequire } from 'node:module';
import { canonicalPath } from '../../src/platform/projectPath.js';
import { newDbId, registerDbId } from '../../src/storage/dbRegistry.js';

const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite') as typeof import('node:sqlite');

export function registerInPlace(dbPath: string, projectPath: string): string {
  const id = newDbId();
  registerDbId({
    db_id: id,
    db_path: canonicalPath(dbPath),
    project_path: canonicalPath(projectPath),
    created_at: new Date().toISOString(),
  });
  const raw = new DatabaseSync(dbPath);
  try {
    raw.prepare(`INSERT INTO schema_meta (key, value) VALUES ('db_id', ?)`).run(id);
  } finally {
    raw.close();
  }
  return id;
}
