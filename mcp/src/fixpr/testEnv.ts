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
 *     can never end up in the commit — asked as `node_modules/`, a
 *     directory: the commonest `.gitignore` line is the directory pattern
 *     `node_modules/`, which `git check-ignore node_modules` does not match
 *     while nothing is there yet. Asked that way, no `npm ci` ran in either
 *     tree, the suite failed in both for want of its dependencies, and the
 *     fix's pull request said the tests were "already failing".
 *
 * Anything else prepares nothing — in both trees alike — and a tree whose
 * dependencies are needed but were not installed is `unprepared`, with the
 * reason: a failing run there says nothing about the fix, so the test
 * differential calls it unattributed, never already failing (`verify.ts`).
 */

import { PROJECT_FILE_MAX_BYTES, presentInProject, readProjectJson } from '../platform/projectFs.js';
import { runProcess } from '../runners/processRunner.js';
import { GIT_COMMAND } from '../platform/gitSafety.js';
import type { DerivedTestCommand } from './testCommand.js';
import { packageManagerEnv } from './testCommandEnv.js';

/** How long one dependency install may take. */
const INSTALL_TIMEOUT_MS = 15 * 60_000;

type TestEnvironment =
  | {
      ok: true;
      /** The command run, or null when nothing needed preparing. */
      command: string | null;
      /** Why the tree's dependencies were needed but not installed. Absent: nothing is missing. */
      unprepared?: string;
    }
  | { ok: false; command: string; reason: string };

/** The `package.json` fields whose packages `npm ci` would install. */
const DEPENDENCY_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies'];

/** Whether the tree's `package.json` declares a package to install — true when it cannot be read. */
function declaresDependencies(treePath: string): boolean {
  const pkg = readProjectJson(treePath, 'package.json', PROJECT_FILE_MAX_BYTES);
  if (typeof pkg !== 'object' || pkg === null || Array.isArray(pkg)) return true;
  return DEPENDENCY_FIELDS.some((field) => {
    const value = (pkg as Record<string, unknown>)[field];
    return typeof value === 'object' && value !== null && Object.keys(value).length > 0;
  });
}

export async function prepareTestEnvironment(opts: {
  treePath: string;
  derived: DerivedTestCommand | null;
  /** Injected so tests can supply a fake. Defaults to the real runProcess. */
  run?: typeof runProcess;
}): Promise<TestEnvironment> {
  const { treePath, derived } = opts;
  if (derived === null || derived.command !== 'npm') return { ok: true, command: null };
  const hasLock = presentInProject(treePath, 'package-lock.json') || presentInProject(treePath, 'npm-shrinkwrap.json');
  if (!hasLock) {
    return declaresDependencies(treePath)
      ? {
          ok: true,
          command: null,
          unprepared:
            'package.json declares dependencies but the tree has no lockfile, so none were installed ' +
            '(npm install would write a lockfile into the pull request)',
        }
      : { ok: true, command: null };
  }
  const run = opts.run ?? runProcess;

  const ignored = await run({ command: GIT_COMMAND, args: ['-C', treePath, 'check-ignore', '-q', 'node_modules/'], cwd: treePath });
  if (ignored.outcome !== 'completed') {
    return {
      ok: true,
      command: null,
      unprepared: 'node_modules/ is not git-ignored, so its dependencies were not installed (they would be committed)',
    };
  }

  const command = 'npm ci --ignore-scripts';
  // A fetch: the package-manager environment, never this server's
  // (`testCommandEnv.ts#packageManagerEnv`). `--ignore-scripts` stops a
  // lifecycle script, not where the fetch goes or which token it carries —
  // that is why the tree's own `.npmrc` is set aside before this runs.
  const result = await run({
    command: 'npm',
    args: ['ci', '--ignore-scripts'],
    cwd: treePath,
    env: packageManagerEnv(),
    extendEnv: false,
    timeoutMs: INSTALL_TIMEOUT_MS,
  });
  if (result.outcome !== 'completed') {
    const line = result.stderr.split(/\r?\n/).map((l) => l.trim()).find((l) => l.length > 0);
    return { ok: false, command, reason: `${command} ${result.outcome}${line !== undefined ? `: ${line}` : ''}` };
  }
  return { ok: true, command };
}
