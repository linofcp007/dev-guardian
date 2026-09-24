/**
 * Several processes opening the same fresh `.guardian/guardian.db` at once.
 *
 * This is the real deployment shape, not a stress test: the plugin's MCP
 * server, a project-level MCP server and the CLI all open the same file, and
 * on a first run they do it within the same second. Before the busy timeout
 * and the locked migration runner, 14 of 20 such opens failed with
 * `database is locked` (4 processes, 5 rounds).
 */

import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { GuardianDatabase } from '../../src/storage/db.js';
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

describe('concurrent opens of a fresh project database', () => {
  it(`${PROCESSES} processes x ${ROUNDS} rounds: every open succeeds and the schema is applied once`, async () => {
    const latest = Math.max(...listMigrations().map((m) => m.version));
    const failures: string[] = [];

    for (let round = 0; round < ROUNDS; round++) {
      const project = makeTempDir('guardian-concurrent-');
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
      db.close();
    }

    expect(failures).toEqual([]);
  }, 120_000);
});
