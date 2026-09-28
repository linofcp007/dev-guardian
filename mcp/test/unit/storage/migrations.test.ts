import { readFileSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { openSetForProject } from '../../../src/history/openSet.js';
import { listMigrations, runMigrations } from '../../../src/storage/migrations/runner.js';
import { Storage } from '../../../src/storage/index.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';
import { MCP_ROOT } from '../../helpers/tsxNode.js';

afterAll(cleanupTempDirs);

/** The version the newest shipped migration brings a database to. */
const LATEST = String(Math.max(...listMigrations().map((m) => m.version)));

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
    expect(row?.value).toBe(LATEST);
  });

  it('is idempotent (running twice does not throw and version stays the same)', () => {
    const db = new Database(':memory:');
    runMigrations(db);
    expect(() => runMigrations(db)).not.toThrow();
    const row = db
      .prepare(`SELECT value FROM schema_meta WHERE key = 'version'`)
      .get() as { value: string };
    expect(row.value).toBe(LATEST);
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
    expect(version.value).toBe(LATEST);
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
    expect(version.value).toBe(LATEST);
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

  it('upgrades a version-7 database in place: every baseline learns its project and scan type (008)', () => {
    // Baselines had no project column, so `guardian://baseline`, `diff_scans
    // from:'baseline'` and `regression_alert` read one global row — another
    // project's, whenever it had set one more recently.
    const db = new Database(':memory:');
    for (const m of listMigrations().filter((x) => x.version <= 7)) {
      db.exec(readFileSync(m.filePath, 'utf8'));
    }
    db.exec(`INSERT INTO schema_meta(key, value) VALUES('version', '7')`);
    db.exec(
      `INSERT INTO scans (id, scan_type, project_path, tree_hash, started_at, finished_at, status)
       VALUES ('a1', 'sast', '/a', 'h', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:01.000Z', 'completed'),
              ('b1', 'secrets', '/b', 'h', '2026-01-02T00:00:00.000Z', '2026-01-02T00:00:01.000Z', 'completed')`,
    );
    db.exec(
      `INSERT INTO baselines (scan_id, set_at, note)
       VALUES ('a1', '2026-01-01T00:00:02.000Z', 'mine'), ('b1', '2026-01-02T00:00:02.000Z', 'theirs')`,
    );

    runMigrations(db);

    const rows = db.prepare(`SELECT scan_id, project_path, scan_type FROM baselines ORDER BY id`).all();
    expect(rows).toEqual([
      { scan_id: 'a1', project_path: '/a', scan_type: 'sast' },
      { scan_id: 'b1', project_path: '/b', scan_type: 'secrets' },
    ]);
    const storage = new Storage(db);
    expect(storage.baselines.getActiveForProject('/a')).toEqual(
      expect.objectContaining({ scan_id: 'a1', project_path: '/a', scan_type: 'sast', note: 'mine' }),
    );

    // An older build sharing this file still inserts without the new
    // columns; its row must not be invisible to the project it belongs to.
    db.exec(`INSERT INTO baselines (scan_id, set_at) VALUES ('a1', '2026-01-03T00:00:00.000Z')`);
    expect(storage.baselines.getActiveForProject('/a')?.set_at).toBe('2026-01-03T00:00:00.000Z');
    expect(storage.baselines.getActiveForProject('/b')?.scan_id).toBe('b1');
  });

  it('upgrades a version-10 database in place: every suppression learns its project (011)', () => {
    // A pre-011 database: suppressions had no project_path, so a suppression
    // matched a same-fingerprint/identity finding in ANY project sharing the
    // database — reproduced in findingsRepo.test.ts's "suppressions are per
    // project at match time" block. Backfilled here from the newest scan
    // reporting the suppressed fingerprint/identity; a suppression whose
    // target is in no stored scan (fp-unknown below) has nothing to
    // backfill from and stays NULL — "matches every project", the same
    // global behaviour it had before this migration, not "matches nothing".
    const db = new Database(':memory:');
    for (const m of listMigrations().filter((x) => x.version <= 10)) {
      db.exec(readFileSync(m.filePath, 'utf8'));
    }
    db.exec(`INSERT INTO schema_meta(key, value) VALUES('version', '10')`);
    db.exec(
      `INSERT INTO scans (id, scan_type, project_path, tree_hash, started_at, finished_at, status)
       VALUES ('a1', 'sast', '/a', 'h', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:01.000Z', 'completed')`,
    );
    db.exec(
      `INSERT INTO findings (fingerprint, scan_id, tool, severity, category, title, file_path, line_start, identity)
       VALUES ('fp-a', 'a1', 'semgrep', 'high', 'security', 't', 'a.js', 3, 'id-a')`,
    );
    db.exec(
      `INSERT INTO suppressions (finding_fingerprint, finding_identity, reason, created_at)
       VALUES ('fp-a', 'id-a', 'reviewed', '2026-01-01T00:00:02.000Z'),
              ('fp-unknown', NULL, 'dangling — no scan ever reported this fingerprint', '2026-01-01T00:00:03.000Z')`,
    );

    runMigrations(db);

    const version = db.prepare(`SELECT value FROM schema_meta WHERE key = 'version'`).get() as { value: string };
    expect(version.value).toBe(LATEST);
    const rows = db
      .prepare(`SELECT finding_fingerprint, project_path FROM suppressions ORDER BY finding_fingerprint`)
      .all();
    expect(rows).toEqual([
      { finding_fingerprint: 'fp-a', project_path: '/a' },
      { finding_fingerprint: 'fp-unknown', project_path: null },
    ]);

    // And the backfilled row now actually scopes the match: a same
    // fingerprint reported by a DIFFERENT project is not suppressed there.
    db.exec(
      `INSERT INTO scans (id, scan_type, project_path, tree_hash, started_at, finished_at, status)
       VALUES ('b1', 'sast', '/b', 'h', '2026-01-02T00:00:00.000Z', '2026-01-02T00:00:01.000Z', 'completed')`,
    );
    db.exec(
      `INSERT INTO findings (fingerprint, scan_id, tool, severity, category, title, file_path, line_start)
       VALUES ('fp-a', 'b1', 'semgrep', 'high', 'security', 't', 'a.js', 3)`,
    );
    const storage = new Storage(db);
    expect(storage.findings.listOpenForProject('/a')).toEqual([]);
    expect(storage.findings.listOpenForProject('/b').map((f) => f.fingerprint)).toEqual(['fp-a']);
  });

  // Coordinator fix round 2: the first cut of 011's backfill picked "the
  // newest scan reporting the fingerprint", with no `status = 'completed'`
  // filter and no exclusion of `create_fix_pr`'s disposable worktrees
  // (`%guardian-fixpr-wt-%`, `findingsRepo.ts`'s own `WORKTREE_PATH_EXCLUSION`).
  // Fingerprints are project-relative, so a single `create_fix_pr` call —
  // which re-runs `scan_sast` inside such a worktree to verify a fix —
  // produced a newer scan of the SAME fingerprint in a directory that no
  // longer exists by the time the migration runs. Reproduced by the
  // reviewer with a newer scan in a fixpr worktree AND in a second, real
  // project (`/main-clone`).
  it('backfills from the real project, excluding a create_fix_pr worktree scan (011)', () => {
    const db = new Database(':memory:');
    for (const m of listMigrations().filter((x) => x.version <= 10)) {
      db.exec(readFileSync(m.filePath, 'utf8'));
    }
    db.exec(`INSERT INTO schema_meta(key, value) VALUES('version', '10')`);
    db.exec(
      `INSERT INTO scans (id, scan_type, project_path, tree_hash, started_at, finished_at, status)
       VALUES ('main1', 'sast', '/main', 'h', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:01.000Z', 'completed')`,
    );
    db.exec(
      `INSERT INTO findings (fingerprint, scan_id, tool, severity, category, title, file_path, line_start, identity)
       VALUES ('fp-a', 'main1', 'semgrep', 'high', 'security', 't', 'a.js', 3, 'id-a')`,
    );
    db.exec(
      `INSERT INTO suppressions (finding_fingerprint, finding_identity, reason, created_at)
       VALUES ('fp-a', 'id-a', 'reviewed in /main', '2026-01-01T00:00:02.000Z')`,
    );
    // create_fix_pr's own verification re-scan: newer, same fingerprint,
    // inside a disposable worktree that is gone by the time this runs.
    db.exec(
      `INSERT INTO scans (id, scan_type, project_path, tree_hash, started_at, finished_at, status)
       VALUES ('wt1', 'sast', '/tmp/guardian-fixpr-wt-Ab12', 'h', '2026-01-02T00:00:00.000Z', '2026-01-02T00:00:01.000Z', 'completed')`,
    );
    db.exec(
      `INSERT INTO findings (fingerprint, scan_id, tool, severity, category, title, file_path, line_start, identity)
       VALUES ('fp-a', 'wt1', 'semgrep', 'high', 'security', 't', 'a.js', 3, 'id-a')`,
    );

    runMigrations(db);

    // The ONLY real candidate is /main — the worktree is excluded outright,
    // not merely outranked by recency — so this is unambiguous.
    const row = db.prepare(`SELECT project_path FROM suppressions WHERE finding_fingerprint = 'fp-a'`).get() as {
      project_path: string | null;
    };
    expect(row.project_path).toBe('/main');

    const storage = new Storage(db);
    expect(storage.findings.listOpenForProject('/main')).toEqual([]);
    expect(openSetForProject(storage, '/main').findings).toEqual([]);
  });

  it('leaves project_path NULL (ambiguous) when a genuinely different real project also reports the fingerprint (011)', () => {
    const db = new Database(':memory:');
    for (const m of listMigrations().filter((x) => x.version <= 10)) {
      db.exec(readFileSync(m.filePath, 'utf8'));
    }
    db.exec(`INSERT INTO schema_meta(key, value) VALUES('version', '10')`);
    db.exec(
      `INSERT INTO scans (id, scan_type, project_path, tree_hash, started_at, finished_at, status)
       VALUES ('main1', 'sast', '/main', 'h', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:01.000Z', 'completed')`,
    );
    db.exec(
      `INSERT INTO findings (fingerprint, scan_id, tool, severity, category, title, file_path, line_start, identity)
       VALUES ('fp-a', 'main1', 'semgrep', 'high', 'security', 't', 'a.js', 3, 'id-a')`,
    );
    db.exec(
      `INSERT INTO suppressions (finding_fingerprint, finding_identity, reason, created_at)
       VALUES ('fp-a', 'id-a', 'reviewed in /main', '2026-01-01T00:00:02.000Z')`,
    );
    // create_fix_pr's disposable worktree — excluded, same as above.
    db.exec(
      `INSERT INTO scans (id, scan_type, project_path, tree_hash, started_at, finished_at, status)
       VALUES ('wt1', 'sast', '/tmp/guardian-fixpr-wt-Ab12', 'h', '2026-01-02T00:00:00.000Z', '2026-01-02T00:00:01.000Z', 'completed')`,
    );
    db.exec(
      `INSERT INTO findings (fingerprint, scan_id, tool, severity, category, title, file_path, line_start, identity)
       VALUES ('fp-a', 'wt1', 'semgrep', 'high', 'security', 't', 'a.js', 3, 'id-a')`,
    );
    // A second, genuinely different, real project — a clone of /main that
    // happens to share the same relative paths and so the same fingerprint.
    db.exec(
      `INSERT INTO scans (id, scan_type, project_path, tree_hash, started_at, finished_at, status)
       VALUES ('clone1', 'sast', '/main-clone', 'h', '2026-01-03T00:00:00.000Z', '2026-01-03T00:00:01.000Z', 'completed')`,
    );
    db.exec(
      `INSERT INTO findings (fingerprint, scan_id, tool, severity, category, title, file_path, line_start, identity)
       VALUES ('fp-a', 'clone1', 'semgrep', 'high', 'security', 't', 'a.js', 3, 'id-a')`,
    );

    runMigrations(db);

    // Two DIFFERENT real projects now report this fingerprint/identity —
    // genuinely ambiguous, so the row is left NULL rather than guessing.
    const row = db.prepare(`SELECT project_path FROM suppressions WHERE finding_fingerprint = 'fp-a'`).get() as {
      project_path: string | null;
    };
    expect(row.project_path).toBeNull();

    // NULL is "matches every project" (the pre-011 global behaviour), so the
    // suppression still hides the finding in /main via both readers —
    // safe, even though the attribution itself could not be resolved.
    const storage = new Storage(db);
    expect(storage.findings.listOpenForProject('/main')).toEqual([]);
    expect(openSetForProject(storage, '/main').findings).toEqual([]);
  });

  it('excludes a non-completed scan from the backfill candidates (011)', () => {
    const db = new Database(':memory:');
    for (const m of listMigrations().filter((x) => x.version <= 10)) {
      db.exec(readFileSync(m.filePath, 'utf8'));
    }
    db.exec(`INSERT INTO schema_meta(key, value) VALUES('version', '10')`);
    db.exec(
      `INSERT INTO scans (id, scan_type, project_path, tree_hash, started_at, finished_at, status)
       VALUES ('main1', 'sast', '/main', 'h', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:01.000Z', 'completed')`,
    );
    db.exec(
      `INSERT INTO findings (fingerprint, scan_id, tool, severity, category, title, file_path, line_start, identity)
       VALUES ('fp-a', 'main1', 'semgrep', 'high', 'security', 't', 'a.js', 3, 'id-a')`,
    );
    db.exec(
      `INSERT INTO suppressions (finding_fingerprint, finding_identity, reason, created_at)
       VALUES ('fp-a', 'id-a', 'reviewed in /main', '2026-01-01T00:00:02.000Z')`,
    );
    // A newer scan of a SECOND project that never finished — must not count
    // as a candidate, ambiguous or otherwise.
    db.exec(
      `INSERT INTO scans (id, scan_type, project_path, tree_hash, started_at, finished_at, status)
       VALUES ('failed1', 'sast', '/other', 'h', '2026-01-02T00:00:00.000Z', NULL, 'failed')`,
    );
    db.exec(
      `INSERT INTO findings (fingerprint, scan_id, tool, severity, category, title, file_path, line_start, identity)
       VALUES ('fp-a', 'failed1', 'semgrep', 'high', 'security', 't', 'a.js', 3, 'id-a')`,
    );

    runMigrations(db);

    const row = db.prepare(`SELECT project_path FROM suppressions WHERE finding_fingerprint = 'fp-a'`).get() as {
      project_path: string | null;
    };
    expect(row.project_path).toBe('/main');
  });

  it('upgrades a version-11 database in place: audit_mcp_tools gets its pin table, old rows untouched (012)', () => {
    const db = new Database(':memory:');
    for (const m of listMigrations().filter((x) => x.version <= 11)) {
      db.exec(readFileSync(m.filePath, 'utf8'));
    }
    db.exec(`INSERT INTO schema_meta(key, value) VALUES('version', '11')`);
    db.exec(
      `INSERT INTO agent_config_hashes (project_path, entry_key, hash, updated_at)
       VALUES ('/p', '.mcp.json::x', 'h', '2026-01-01T00:00:00.000Z')`,
    );

    runMigrations(db);

    const columns = (db.prepare(`PRAGMA table_info(mcp_tool_pins)`).all() as { name: string }[]).map((c) => c.name);
    expect(columns).toEqual(expect.arrayContaining(['project_path', 'server_key', 'tool_name', 'hash', 'updated_at']));
    const storage = new Storage(db);
    expect(storage.agentAudit.getHashes('/p').get('.mcp.json::x')).toBe('h');
    expect(storage.mcpToolPins.getServerPins('/p', '.mcp.json::x')).toEqual(new Map());
    const version = db.prepare(`SELECT value FROM schema_meta WHERE key = 'version'`).get() as { value: string };
    expect(version.value).toBe(LATEST);
  });
});
