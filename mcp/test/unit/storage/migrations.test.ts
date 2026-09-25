import { readFileSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { listMigrations, runMigrations } from '../../../src/storage/migrations/runner.js';
import { Storage } from '../../../src/storage/index.js';
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

// The version `runMigrations` leaves a DB at once every shipped migration has
// applied — i.e. the highest version number on disk. Computed rather than
// hardcoded: a hardcoded literal here is exactly the kind of thing a NEW
// migration silently breaks (four assertions below used to read '7' and
// broke the moment migration 009 shipped), and in a numbering scheme where a
// concurrent branch's reserved number is renumbered at merge time (see
// `migrations/runner.ts`'s own numbering-convention doc), a literal would go
// stale again at that very merge.
const LATEST_VERSION = String(listMigrations().at(-1)?.version ?? 0);

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
    expect(row?.value).toBe(LATEST_VERSION);
  });

  it('is idempotent (running twice does not throw and version stays the same)', () => {
    const db = new Database(':memory:');
    runMigrations(db);
    expect(() => runMigrations(db)).not.toThrow();
    const row = db
      .prepare(`SELECT value FROM schema_meta WHERE key = 'version'`)
      .get() as { value: string };
    expect(row.value).toBe(LATEST_VERSION);
  });

  it('upgrades a version-5 database in place, leaving its rows readable and uncached (006)', () => {
    // A 2.0.0-era database: schema 1–5 applied, one completed scan and one
    // surface snapshot. After 006 both rows are still there, with a NULL
    // cache key — history, never a cache hit.
    const db = new Database(':memory:');
    for (const m of listMigrations().filter((x) => x.version <= 5)) {
      db.exec(readFileSync(m.filePath, 'utf8'));
    }
    db.exec(`INSERT INTO schema_meta(key, value) VALUES('version', '5')`);
    db.exec(
      `INSERT INTO scans (id, scan_type, project_path, tree_hash, started_at, finished_at, status)
       VALUES ('old', 'deps', '/p', 'h', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:01.000Z', 'completed')`,
    );
    db.exec(
      `INSERT INTO surface_snapshots (project_path, captured_at, tree_hash, json)
       VALUES ('/p', '2026-01-01T00:00:00.000Z', 'h', '{}')`,
    );

    runMigrations(db);

    const version = db
      .prepare(`SELECT value FROM schema_meta WHERE key = 'version'`)
      .get() as { value: string };
    expect(version.value).toBe(LATEST_VERSION);
    const scan = db.prepare(`SELECT id, cache_key FROM scans`).get() as {
      id: string;
      cache_key: string | null;
    };
    expect(scan).toEqual({ id: 'old', cache_key: null });
    const snap = db.prepare(`SELECT cache_key FROM surface_snapshots`).get() as {
      cache_key: string | null;
    };
    expect(snap.cache_key).toBeNull();
  });

  it('upgrades a version-6 database in place: old findings and suppressions keep working by fingerprint (007)', () => {
    // A database as 2.0.x left it: a completed scan, one finding and a
    // suppression naming it by fingerprint — the only key 2.0.x had.
    const db = new Database(':memory:');
    for (const m of listMigrations().filter((x) => x.version <= 6)) {
      db.exec(readFileSync(m.filePath, 'utf8'));
    }
    db.exec(`INSERT INTO schema_meta(key, value) VALUES('version', '6')`);
    db.exec(
      `INSERT INTO scans (id, scan_type, project_path, tree_hash, started_at, finished_at, status)
       VALUES ('old', 'sast', '/p', 'h', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:01.000Z', 'completed')`,
    );
    db.exec(
      `INSERT INTO findings (fingerprint, scan_id, tool, severity, category, title, file_path, line_start)
       VALUES ('fp-old', 'old', 'semgrep', 'high', 'security', 't', 'a.js', 3),
              ('fp-open', 'old', 'semgrep', 'high', 'security', 't', 'b.js', 3)`,
    );
    db.exec(
      `INSERT INTO suppressions (finding_fingerprint, reason, created_at)
       VALUES ('fp-old', 'reviewed', '2026-01-01T00:00:00.000Z')`,
    );

    runMigrations(db);

    const version = db.prepare(`SELECT value FROM schema_meta WHERE key = 'version'`).get() as { value: string };
    expect(version.value).toBe(LATEST_VERSION);
    const rows = db.prepare(`SELECT fingerprint, identity, content_key FROM findings ORDER BY fingerprint`).all();
    expect(rows).toEqual([
      { fingerprint: 'fp-old', identity: null, content_key: null },
      { fingerprint: 'fp-open', identity: null, content_key: null },
    ]);
    const suppression = db.prepare(`SELECT finding_identity FROM suppressions`).get() as {
      finding_identity: string | null;
    };
    expect(suppression.finding_identity).toBeNull();

    // Still suppressed, by fingerprint: NULL identities never match each other.
    const storage = new Storage(db);
    expect(storage.findings.listOpen().map((f) => f.fingerprint)).toEqual(['fp-open']);
    expect(storage.suppressions.isSuppressed('fp-old')).toBe(true);
    expect(storage.suppressions.isSuppressed('fp-open')).toBe(false);

    const indexes = db
      .prepare(`SELECT name FROM sqlite_master WHERE type = 'index' AND name IN ('idx_findings_identity', 'idx_suppressions_identity') ORDER BY name`)
      .all();
    expect(indexes).toEqual([{ name: 'idx_findings_identity' }, { name: 'idx_suppressions_identity' }]);
  });
});
