import { readFileSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { listMigrations, runMigrations } from '../../../src/storage/migrations/runner.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';
import { MCP_ROOT } from '../../helpers/tsxNode.js';

afterAll(cleanupTempDirs);

describe('listMigrations', () => {
  it('lists the shipped migrations in version order with unique numbers', () => {
    const versions = listMigrations().map((m) => m.version);
    expect(versions).toEqual([...versions].sort((a, b) => a - b));
    expect(new Set(versions).size).toBe(versions.length);
  });

  it('refuses two files with the same number instead of silently skipping one', () => {
    const dir = makeTempDir('guardian-migrations-');
    writeFileSync(join(dir, '001_first.sql'), 'SELECT 1;');
    writeFileSync(join(dir, '002_mine.sql'), 'SELECT 1;');
    writeFileSync(join(dir, '002_theirs.sql'), 'SELECT 1;');
    expect(() => listMigrations(dir)).toThrow(/Duplicate migration number 2: '(mine|theirs)' and '(mine|theirs)'/);
  });
});

describe('the committed dist/', () => {
  // Claude Code runs mcp/dist directly (the repo IS the distribution), and the
  // runner reads the .sql files from dist/storage/migrations at runtime. A
  // migration missing there is a schema the shipped server never applies —
  // while every test run against src/ passes. scripts/copy-assets.mjs once
  // copied nothing at all from any checkout whose path contained a '.'.
  it('ships every migration in src/, byte for byte', () => {
    const distDir = join(MCP_ROOT, 'dist', 'storage', 'migrations');
    for (const m of listMigrations()) {
      const shipped = join(distDir, basename(m.filePath));
      expect(readFileSync(shipped, 'utf8'), shipped).toBe(readFileSync(m.filePath, 'utf8'));
    }
  });
});

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
      'finding_validations',
      'findings',
      'runtime_meta',
      'scan_cves',
      'scans',
      'schema_meta',
      'stack_snapshots',
      'suppressions',
      'surface_snapshots',
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
    expect(row?.value).toBe('5');
  });

  it('is idempotent (running twice does not throw and version stays the same)', () => {
    const db = new Database(':memory:');
    runMigrations(db);
    expect(() => runMigrations(db)).not.toThrow();
    const row = db
      .prepare(`SELECT value FROM schema_meta WHERE key = 'version'`)
      .get() as { value: string };
    expect(row.value).toBe('5');
  });
});
