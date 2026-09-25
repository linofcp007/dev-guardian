/**
 * `prepareTestEnvironment` — the same dependency install in the fix's tree
 * and in the base-commit tree its failing test run is compared against, so
 * the test differential compares like with like (Task 11 item 1).
 *
 * The comparison run used to happen in the user's own project, which has its
 * `node_modules` — while the fix's worktree, a fresh checkout, had none for
 * a Semgrep group. `npm test` failed in the worktree for want of
 * dependencies, passed in the project, and the fix was blamed. Both trees are
 * now fresh checkouts of committed HEAD, prepared identically:
 *
 *   - only for an npm-run test command (`cargo test`, `go test` fetch their
 *     own dependencies; pytest uses whatever interpreter it finds either way);
 *   - only `npm ci --ignore-scripts`, and only with a lockfile: `npm ci`
 *     writes nothing but `node_modules`, where `npm install` would create a
 *     lockfile that a pull request would then carry;
 *   - only when `node_modules` is git-ignored in that tree, so the install
 *     can never end up in the commit.
 *
 * Anything else prepares nothing — in both trees alike.
 */

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { runProcess } from '../runners/processRunner.js';
import type { DerivedTestCommand } from './testCommand.js';

/** How long one dependency install may take. */
const INSTALL_TIMEOUT_MS = 15 * 60_000;

export type TestEnvironment =
  | { ok: true; /** The command run, or null when nothing needed preparing. */ command: string | null }
  | { ok: false; command: string; reason: string };

export async function prepareTestEnvironment(opts: {
  treePath: string;
  derived: DerivedTestCommand | null;
  /** Injected so tests can supply a fake. Defaults to the real runProcess. */
  run?: typeof runProcess;
}): Promise<TestEnvironment> {
  const { treePath, derived } = opts;
  if (derived === null || derived.command !== 'npm') return { ok: true, command: null };
  const hasLock = existsSync(join(treePath, 'package-lock.json')) || existsSync(join(treePath, 'npm-shrinkwrap.json'));
  if (!hasLock) return { ok: true, command: null };
  const run = opts.run ?? runProcess;

  const ignored = await run({ command: 'git', args: ['-C', treePath, 'check-ignore', '-q', 'node_modules'], cwd: treePath });
  if (ignored.outcome !== 'completed') return { ok: true, command: null };

  const command = 'npm ci --ignore-scripts';
  const result = await run({ command: 'npm', args: ['ci', '--ignore-scripts'], cwd: treePath, timeoutMs: INSTALL_TIMEOUT_MS });
  if (result.outcome !== 'completed') {
    const line = result.stderr.split(/\r?\n/).map((l) => l.trim()).find((l) => l.length > 0);
    return { ok: false, command, reason: `${command} ${result.outcome}${line !== undefined ? `: ${line}` : ''}` };
  }
  return { ok: true, command };
}
