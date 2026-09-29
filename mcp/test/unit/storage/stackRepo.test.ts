/**
 * `stack_snapshots` grew with every `detect_stack` run and had no index on
 * `project_path`, while every reader since Task 24 asks for ONE project's
 * newest row (`getLatestForProject`) — a full scan of an ever-growing table
 * of JSON blobs. It is now kept to the newest {@link STACK_SNAPSHOTS_KEPT}
 * per project, as `surface_snapshots` already was, and indexed by project.
 */

import { describe, expect, it } from 'vitest';
import { GuardianDatabase } from '../../../src/storage/db.js';
import { Storage } from '../../../src/storage/index.js';
import { pruneStackSnapshots } from '../../../src/storage/maintenance.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { STACK_SNAPSHOTS_KEPT } from '../../../src/storage/stackRepo.js';
import type { StackSnapshot } from '../../../src/types.js';

function fresh(): { db: GuardianDatabase; storage: Storage } {
  const db = new GuardianDatabase(':memory:');
  runMigrations(db);
  return { db, storage: new Storage(db) };
}

function snapshot(language: string): StackSnapshot {
  return { languages: [language], frameworks: [] } as unknown as StackSnapshot;
}

function countFor(db: GuardianDatabase, project: string): number {
  return db.prepare<[string], { n: number }>('SELECT COUNT(*) AS n FROM stack_snapshots WHERE project_path = ?').get(project)?.n ?? -1;
}

describe('stack_snapshots retention', () => {
  it(`keeps the newest ${STACK_SNAPSHOTS_KEPT} per project on insert, and the newest is still served`, () => {
    const { db, storage } = fresh();
    for (let i = 0; i < 15; i++) storage.stack.insert({ project_path: '/p1', snapshot: snapshot(`lang${i}`) });
    for (let i = 0; i < 3; i++) storage.stack.insert({ project_path: '/p2', snapshot: snapshot(`other${i}`) });

    expect(countFor(db, '/p1')).toBe(STACK_SNAPSHOTS_KEPT);
    expect(countFor(db, '/p2')).toBe(3);
    expect(storage.stack.getLatestForProject('/p1')?.snapshot.languages).toEqual(['lang14']);
  });

  it('prunes a backlog written before retention existed, in bounded batches', () => {
    const { db } = fresh();
    const insert = db.prepare<[string, string]>(
      `INSERT INTO stack_snapshots (project_path, captured_at, json) VALUES (?, ?, '{}')`,
    );
    for (let i = 0; i < 40; i++) insert.run('/p1', new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString());
    for (let i = 0; i < 5; i++) insert.run('/p2', new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString());

    expect(pruneStackSnapshots(db, 20)).toEqual({ deleted: 20, remaining: 10 });
    expect(pruneStackSnapshots(db, 20)).toEqual({ deleted: 10, remaining: 0 });
    expect(countFor(db, '/p1')).toBe(STACK_SNAPSHOTS_KEPT);
    expect(countFor(db, '/p2')).toBe(5);
    const newest = db
      .prepare<[], { captured_at: string }>(`SELECT MIN(captured_at) AS captured_at FROM stack_snapshots WHERE project_path = '/p1'`)
      .get();
    expect(newest?.captured_at).toBe(new Date(Date.UTC(2026, 0, 1, 0, 0, 30)).toISOString());
  });

  it('a project lookup uses an index on project_path', () => {
    const { db } = fresh();
    const plan = db
      .prepare<[], { detail: string }>(
        `EXPLAIN QUERY PLAN SELECT * FROM stack_snapshots WHERE project_path = '/p' ORDER BY captured_at DESC, id DESC LIMIT 1`,
      )
      .all()
      .map((r) => r.detail)
      .join('\n');
    expect(plan).toMatch(/USING INDEX idx_stack_project/);
  });
});
