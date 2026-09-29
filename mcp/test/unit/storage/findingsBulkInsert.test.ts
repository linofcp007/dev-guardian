/**
 * `bulkInsert` wrote a scan's findings in ONE transaction: 30,000 findings on
 * a 300 MB database held the write lock for 8.8 s, and another process's
 * `scans.insert` failed with `database is locked` after its 5 s busy timeout.
 * It now writes FINDINGS_INSERT_CHUNK rows per transaction, with a pause
 * longer than SQLite's busy-handler poll between them, while the scan row is
 * still `running` — which no reader shows (see `historyComparisons.test.ts`
 * for the readers that take a scan id).
 */

import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { GuardianDatabase } from '../../../src/storage/db.js';
import { FINDINGS_INSERT_CHUNK, type InsertFindingInput } from '../../../src/storage/findingsRepo.js';
import { Storage } from '../../../src/storage/index.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';
import { MCP_ROOT, TSX_NODE_ARGS } from '../../helpers/tsxNode.js';

afterAll(cleanupTempDirs);

function rows(scanId: string, n: number): InsertFindingInput[] {
  return Array.from({ length: n }, (_, i) => ({
    scan_id: scanId,
    fingerprint: `fp-${i}`,
    tool: 'semgrep',
    rule_id: `rule-${i % 13}`,
    severity: 'high',
    category: 'security',
    title: `finding ${i}`,
    file_path: `src/f${i % 50}.ts`,
    line_start: i,
    fix_available: false,
    fix_applied: false,
  }));
}

function fileDb(): { db: GuardianDatabase; path: string; storage: Storage } {
  const path = join(makeTempDir('guardian-bulk-'), 'guardian.db');
  const db = new GuardianDatabase(path);
  db.exec('PRAGMA journal_mode = WAL');
  runMigrations(db);
  return { db, path, storage: new Storage(db) };
}

describe('bulkInsert writes in chunks', () => {
  it(`commits ${FINDINGS_INSERT_CHUNK} rows per transaction, every row once`, () => {
    const { db, storage } = fileDb();
    storage.scans.insert({ scan_id: 's1', scan_type: 'sast', project_path: '/p', tree_hash: 'h' });
    const commits: number[] = [];

    const n = 2 * FINDINGS_INSERT_CHUNK + 500;
    const inserted = storage.findings.bulkInsert(rows('s1', n), { gapMs: 0, afterChunk: (so) => commits.push(so) });

    expect(inserted).toBe(n);
    expect(commits).toEqual([FINDINGS_INSERT_CHUNK, 2 * FINDINGS_INSERT_CHUNK, n]);
    expect(storage.findings.listByScan('s1')).toHaveLength(n);
    db.close();
  });

  it('holds no write lock between chunks: another connection writes there at once', () => {
    const { db, path, storage } = fileDb();
    storage.scans.insert({ scan_id: 's1', scan_type: 'sast', project_path: '/p', tree_hash: 'h' });
    const other = new GuardianDatabase(path);
    other.exec('PRAGMA busy_timeout = 0');
    let wrote = 0;
    storage.findings.bulkInsert(rows('s1', 3 * 100), {
      chunkSize: 100,
      gapMs: 0,
      afterChunk: () => {
        other.prepare(
          `INSERT INTO scans (id, scan_type, project_path, tree_hash, started_at, status)
           VALUES (?, 'secrets', '/q', 'h', '2026-01-01T00:00:00.000Z', 'running')`,
        ).run(`between-${wrote}`);
        wrote += 1;
      },
    });
    expect(wrote).toBe(3);
    other.close();
    db.close();
  });

  it('a scan of up to one chunk is one transaction and pays no pause', () => {
    const { db, storage } = fileDb();
    storage.scans.insert({ scan_id: 's1', scan_type: 'sast', project_path: '/p', tree_hash: 'h' });
    const commits: number[] = [];
    const t0 = Date.now();
    storage.findings.bulkInsert(rows('s1', 50), { gapMs: 5000, afterChunk: (so) => commits.push(so) });
    expect(Date.now() - t0).toBeLessThan(4000);
    expect(commits).toEqual([50]);
    db.close();
  });

  it("another PROCESS's scans.insert gets in while a large insert is still running", async () => {
    // What the review measured: a second process (another MCP server, the
    // CLI) waiting on the write lock behind one scan's findings. With one
    // transaction it waited for the whole insert — past its busy timeout on
    // a large database. The default pause lets it in between two chunks.
    const { db, path, storage } = fileDb();
    storage.scans.insert({ scan_id: 's1', scan_type: 'sast', project_path: '/p', tree_hash: 'h' });

    const child = spawn(process.execPath, [...TSX_NODE_ARGS, join(MCP_ROOT, 'test', 'helpers', 'insertScanChild.ts'), path], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let out = '';
    child.stdout.on('data', (d: Buffer) => {
      out += d.toString();
    });
    const exited = new Promise<void>((resolve) => child.on('exit', () => resolve()));
    await new Promise<void>((resolve, reject) => {
      const timer = setInterval(() => {
        if (out.includes('ready')) {
          clearInterval(timer);
          resolve();
        }
      }, 20);
      child.on('exit', () => {
        clearInterval(timer);
        reject(new Error(`child exited before ready: ${out}`));
      });
    });

    let signalled = false;
    storage.findings.bulkInsert(rows('s1', 30 * 200), {
      chunkSize: 200,
      afterChunk: () => {
        if (signalled) return;
        signalled = true;
        child.stdin.write('go\n');
      },
    });
    const insertEnded = Date.now();
    await exited;

    const [verdict, , doneAt] = (out.split('\n').find((l) => l.startsWith('ok') || l.startsWith('fail')) ?? '').split(' ');
    expect(verdict, out).toBe('ok');
    expect(Number(doneAt)).toBeLessThan(insertEnded);
    db.close();
  }, 60_000);
});
