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
import { mkdirSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { GuardianDatabase } from '../../src/storage/db.js';
import { lookupDbId, registryDir } from '../../src/storage/dbRegistry.js';
import { canonicalPath } from '../../src/platform/projectPath.js';
import { listMigrations } from '../../src/storage/migrations/runner.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { registerInPlace } from '../helpers/registerInPlace.js';
import { MCP_ROOT, TSX_NODE_ARGS } from '../helpers/tsxNode.js';

afterAll(cleanupTempDirs);

const CHILD = join(MCP_ROOT, 'test', 'helpers', 'openDbChild.ts');
const PROCESSES = 4;
const ROUNDS = 5;

interface ChildOutcome {
  code: number | null;
  stderr: string;
  /** When the open began and ended (epoch ms), and how late the child reached the shared instant; null if it did not say. */
  timing: { late: number; start: number; end: number } | null;
}

/**
 * Starts `PROCESSES` children that open `projectPath`, and — once every one
 * has said `ready` — tells them all the same instant to open at, 200 ms
 * ahead (see `openDbChild.ts` for why a handshake and not a fixed lead).
 */
function openInChildren(projectPath: string): Promise<ChildOutcome[]> {
  const now = (): number => performance.timeOrigin + performance.now();
  const children = Array.from({ length: PROCESSES }, () =>
    spawn(process.execPath, [...TSX_NODE_ARGS, CHILD, projectPath], {
      cwd: MCP_ROOT,
      stdio: ['pipe', 'pipe', 'pipe'],
    }),
  );
  let ready = 0;
  const outcomes = children.map(
    (child) =>
      new Promise<ChildOutcome>((resolve) => {
        let stdout = '';
        let stderr = '';
        let saidReady = false;
        child.stdout.on('data', (d: Buffer) => {
          stdout += d.toString();
          if (!saidReady && /^ready$/m.test(stdout)) {
            saidReady = true;
            ready += 1;
            if (ready === PROCESSES) {
              const startAt = now() + 200;
              for (const c of children) c.stdin.end(`go ${String(startAt)}\n`);
            }
          }
        });
        child.stderr.on('data', (d: Buffer) => {
          stderr += d.toString();
        });
        // 'close', not 'exit': at 'exit' the output streams may still hold
        // data, and a failing child's stack trace was lost that way.
        child.on('close', (code) => {
          let timing: ChildOutcome['timing'] = null;
          const json = stdout.split(/\r?\n/).find((l) => l.startsWith('{'));
          try {
            timing = json === undefined ? null : (JSON.parse(json) as ChildOutcome['timing']);
          } catch {
            /* reported through the assertions */
          }
          resolve({ code, stderr, timing });
        });
      }),
  );
  // A child that dies before `ready` would leave the others waiting for ever.
  for (const child of children) {
    child.on('close', () => {
      if (ready < PROCESSES) for (const c of children) c.stdin.end();
    });
  }
  return Promise.all(outcomes);
}

/**
 * The most opens in progress at one instant. Below 2, the round opened the
 * database one process at a time and tested no concurrency at all — which a
 * slow start-up (a child reaching `startAt` after another had finished)
 * produced silently before the children reported their timing.
 */
function maxOverlap(intervals: ReadonlyArray<{ start: number; end: number }>): number {
  const events = intervals.flatMap((i) => [
    { t: i.start, d: 1 },
    { t: i.end, d: -1 },
  ]);
  // Ends before starts at the same instant: touching is not overlapping.
  events.sort((a, b) => a.t - b.t || a.d - b.d);
  let open = 0;
  let most = 0;
  for (const e of events) {
    open += e.d;
    most = Math.max(most, open);
  }
  return most;
}

/**
 * A project database as 2.0.0 left it: WAL mode, schema version 3. Several
 * servers starting against it after an update all race to apply the newer
 * migrations — the race the in-lock version re-read exists for. (A FRESH file
 * barely exercises it: switching the file to WAL serialises the openers
 * before they reach the migrations.)
 */
function databaseAt2_0_0(project: string): void {
  // In the project's own repository, untracked, and registered as this
  // user's (`db adopt --yes` — nothing is adopted automatically since round
  // 6) but not yet migrated: the upgrade a later build's migrations make.
  const init = spawnSync('git', ['init', '-q'], { cwd: project, encoding: 'utf8' });
  if (init.status !== 0) throw new Error(`git init: ${init.stderr}`);
  mkdirSync(join(project, '.guardian'));
  const dbPath = join(project, '.guardian', 'guardian.db');
  const db = new GuardianDatabase(dbPath);
  db.pragma('journal_mode = WAL');
  for (const m of listMigrations()) {
    if (m.version > 3) break;
    db.exec(readFileSync(m.filePath, 'utf8'));
  }
  db.exec("INSERT INTO schema_meta (key, value) VALUES ('version', '3')");
  db.close();
  registerInPlace(dbPath, project);
}

/** The ids whose registry entry names `dbPath`. */
function registeredFor(dbPath: string): string[] {
  const target = canonicalPath(dbPath);
  return readdirSync(registryDir())
    .filter((name) => name.endsWith('.json'))
    .filter((name) => {
      const entry = JSON.parse(readFileSync(join(registryDir(), name), 'utf8')) as { db_path?: unknown };
      return entry.db_path === target;
    })
    .map((name) => name.slice(0, -'.json'.length));
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
      const outcomes = await openInChildren(project);
      outcomes.forEach((o, i) => {
        if (o.code !== 0) failures.push(`round ${round} child ${i}: exit ${o.code}: ${o.stderr.trim()}`);
      });
      // The opens really overlapped: every child reported when it opened and
      // at least two were in progress at once. Without this the round could
      // pass with no concurrency at all. (How late each child woke is in the
      // message, not asserted: under a loaded machine a spin can be
      // descheduled for tens of ms, which costs nothing while opens take
      // hundreds — overlap is the property, lateness only a way to lose it.)
      const timings = outcomes.map((o) => o.timing).filter((t) => t !== null);
      expect(timings, `round ${round}: a child did not report its timing — ${JSON.stringify(outcomes)}`).toHaveLength(PROCESSES);
      expect(maxOverlap(timings), `round ${round}: the opens did not overlap: ${JSON.stringify(timings)}`).toBeGreaterThanOrEqual(2);

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
      // And ONE registry entry names this database: every opener that lost
      // the race removed the id it had registered (round 5: four concurrent
      // adopters left three orphans).
      expect(registeredFor(join(project, '.guardian', 'guardian.db'))).toEqual([id]);
    }

    expect(failures).toEqual([]);
  }, 120_000);
});
