/**
 * Forward-only SQL migration runner.
 *
 * Migrations live next to this file as `NNN_name.sql`. The current schema
 * version is stored in `schema_meta.version`. On startup we apply every
 * migration whose number is greater than the recorded version, in numeric
 * order, each wrapped in a transaction.
 *
 * Migrations are SQL only (no JS hooks): keep the surface area small and the
 * audit trail trivial — what you read in the .sql file is what runs.
 */

import type { DB } from '../db.js';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Where the `NNN_name.sql` files live at runtime. Resolved by probing, because
 * the path differs across the three ways this module runs:
 *   - tsc output / tsx tests → this module sits beside the .sql files;
 *   - esbuild bundle (dist/server.js) → `import.meta.url` collapses to `dist/`,
 *     so the assets are one level down in `dist/storage/migrations/` (where
 *     `scripts/copy-assets.mjs` mirrors them).
 */
function resolveMigrationsDir(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [here, join(here, 'storage', 'migrations'), join(here, 'migrations')];
  for (const dir of candidates) {
    try {
      if (existsSync(dir) && readdirSync(dir).some((f) => /^\d+_.+\.sql$/.test(f))) return dir;
    } catch {
      /* unreadable candidate — try the next one */
    }
  }
  return here;
}

const MIGRATIONS_DIR = resolveMigrationsDir();

interface Migration {
  version: number;
  name: string;
  filePath: string;
}

export function runMigrations(db: DB): void {
  ensureSchemaMetaTable(db);
  const current = getCurrentVersion(db);
  const pending = listMigrations().filter((m) => m.version > current);

  for (const migration of pending) {
    applyMigration(db, migration);
  }
}

function ensureSchemaMetaTable(db: DB): void {
  // schema_meta is also created by 001_initial.sql, but we need it to exist
  // BEFORE we read the current version on a brand-new DB.
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_meta (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )
  `);
}

function getCurrentVersion(db: DB): number {
  const row = db
    .prepare<[], { value: string }>("SELECT value FROM schema_meta WHERE key = 'version'")
    .get();
  if (!row) return 0;
  const n = Number.parseInt(row.value, 10);
  return Number.isFinite(n) ? n : 0;
}

function setVersion(db: DB, version: number): void {
  db.prepare(
    `INSERT INTO schema_meta(key, value) VALUES('version', ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
  ).run(String(version));
}

function listMigrations(): Migration[] {
  const files = readdirSync(MIGRATIONS_DIR).filter((f) => /^\d+_.+\.sql$/.test(f));
  return files
    .map((f) => {
      const match = /^(\d+)_(.+)\.sql$/.exec(f);
      if (!match) throw new Error(`Unreachable: regex matched once but not twice for '${f}'`);
      const versionPart = match[1];
      const namePart = match[2];
      if (versionPart === undefined || namePart === undefined) {
        throw new Error(`Unreachable: capture groups undefined for '${f}'`);
      }
      return {
        version: Number.parseInt(versionPart, 10),
        name: namePart,
        filePath: join(MIGRATIONS_DIR, f),
      };
    })
    .sort((a, b) => a.version - b.version);
}

function applyMigration(db: DB, migration: Migration): void {
  const sql = readFileSync(migration.filePath, 'utf8');
  const tx = db.transaction(() => {
    db.exec(sql);
    setVersion(db, migration.version);
  });
  tx();
}
