/**
 * Several processes opening the same fresh `.guardian/guardian.db` at once.
 *
 * This is the real deployment shape, not a stress test: the plugin's MCP
 * server, a project-level MCP server and the CLI all open the same file, and
 * on a first run they do it within the same second. Before the busy timeout
 * and the locked migration runner, 15 of 20 fresh opens failed with
 * `database is locked` (4 processes, 5 rounds). With the in-lock version
 * re-read removed from the runner, the upgrade case below fails with
 * `duplicate column name: owner_pid` — a second process re-running 004.
 */

import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { GuardianDatabase } from '../../src/storage/db.js';
import { lookupDbId } from '../../src/storage/dbRegistry.js';
import { listMigrations } from '../../src/storage/migrations/runner.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { MCP_ROOT, TSX_NODE_ARGS } from '../helpers/tsxNode.js';

afterAll(cleanupTempDirs);

const CHILD = join(MCP_ROOT, 'test', 'helpers', 'openDbChild.ts');
const PROCESSES = 4;
const ROUNDS = 5;

interface ChildOutcome {
  code: number | null;
  stderr: string;
}

function openInChild(projectPath: string, startAt: number): Promise<ChildOutcome> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [...TSX_NODE_ARGS, CHILD, projectPath, String(startAt)], {
      cwd: MCP_ROOT,
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    let stderr = '';
    child.stderr.on('data', (d: Buffer) => {
      stderr += d.toString();
    });
    child.on('exit', (code) => resolve({ code, stderr }));
  });
}

/**
 * A project database as 2.0.0 left it: WAL mode, schema version 3. Several
 * servers starting against it after an update all race to apply the newer
 * migrations — the race the in-lock version re-read exists for. (A FRESH file
 * barely exercises it: switching the file to WAL serialises the openers
 * before they reach the migrations.)
 */
function databaseAt2_0_0(project: string): void {
  // In the project's own repository, untracked: adopted (and registered) as
  // an earlier version's database by whichever opener gets there first — the
  // other three find the id registered, or adopt it too; none falls back.
  const init = spawnSync('git', ['init', '-q'], { cwd: project, encoding: 'utf8' });
  if (init.status !== 0) throw new Error(`git init: ${init.stderr}`);
  mkdirSync(join(project, '.guardian'));
  const db = new GuardianDatabase(join(project, '.guardian', 'guardian.db'));
  db.pragma('journal_mode = WAL');
  for (const m of listMigrations()) {
    if (m.version > 3) break;
    db.exec(readFileSync(m.filePath, 'utf8'));
  }
  db.exec("INSERT INTO schema_meta (key, value) VALUES ('version', '3')");
  db.close();
}

describe.each([
  ['a fresh project database', (_project: string): void => {}],
  ['a 2.0.0 project database being upgraded', databaseAt2_0_0],
])('concurrent opens of %s', (_label, prepare) => {
  it(`${PROCESSES} processes x ${ROUNDS} rounds: every open succeeds and the schema is applied once`, async () => {
    const latest = Math.max(...listMigrations().map((m) => m.version));
    const failures: string[] = [];

    for (let round = 0; round < ROUNDS; round++) {
      const project = makeTempDir('guardian-concurrent-');
      prepare(project);
      // Far enough ahead that every child has finished starting up.
      const startAt = Date.now() + 3000;
      const outcomes = await Promise.all(
        Array.from({ length: PROCESSES }, () => openInChild(project, startAt)),
      );
      outcomes.forEach((o, i) => {
        if (o.code !== 0) failures.push(`round ${round} child ${i}: exit ${o.code}: ${o.stderr.trim()}`);
      });

      const db = new GuardianDatabase(join(project, '.guardian', 'guardian.db'));
      const version = db
        .prepare<[], { value: string }>("SELECT value FROM schema_meta WHERE key = 'version'")
        .get();
      expect(version?.value).toBe(String(latest));
      // Every opener used the project's database, and it ended up with ONE
      // id that is registered (the creators' race registers before writing).
      const id = db.prepare<[], { value: string }>("SELECT value FROM schema_meta WHERE key = 'db_id'").get()?.value;
      expect(id).toMatch(/^[0-9a-f]{32}$/);
      expect(lookupDbId(id ?? '')).not.toBeNull();
      db.close();
    }

    expect(failures).toEqual([]);
  }, 120_000);
});
