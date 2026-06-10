import { describe, expect, it } from 'vitest';
import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';

describe('migrations runner', () => {
  it('applies initial schema on a brand-new DB', () => {
    const db = new Database(':memory:');
    runMigrations(db);

    const tables = db
      .prepare(
        `SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`,
      )
      .all() as { name: string }[];
    const names = tables.map((t) => t.name);

    for (const expected of [
      'baselines',
      'cves',
      'findings',
      'runtime_meta',
      'scans',
      'schema_meta',
      'stack_snapshots',
      'suppressions',
      'tree_cache',
    ]) {
      expect(names).toContain(expected);
    }
  });

  it('records the current schema version', () => {
    const db = new Database(':memory:');
    runMigrations(db);
    const row = db
      .prepare(`SELECT value FROM schema_meta WHERE key = 'version'`)
      .get() as { value: string } | undefined;
    expect(row?.value).toBe('1');
  });

  it('is idempotent (running twice does not throw and version stays the same)', () => {
    const db = new Database(':memory:');
    runMigrations(db);
    expect(() => runMigrations(db)).not.toThrow();
    const row = db
      .prepare(`SELECT value FROM schema_meta WHERE key = 'version'`)
      .get() as { value: string };
    expect(row.value).toBe('1');
  });
});
