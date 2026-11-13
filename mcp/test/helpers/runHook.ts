/**
 * Running `hooks/guardian-hook.mjs` the way Claude Code does: a REAL
 * SUBPROCESS fed the JSON payload on stdin. It is the only way to exercise the
 * dispatcher's own routing and its filesystem-facing configuration, which the
 * pure detectors' tests cannot see.
 *
 * Moved here from `test/e2e/hooksDispatcher.test.ts`, unchanged, so that a
 * second e2e file (`knownLimitsHook.test.ts`) launches the hook the same way
 * instead of from a copy that could drift.
 */

import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSyncCapped } from './spawnCap.js';

const here = dirname(fileURLToPath(import.meta.url));
// mcp/test/helpers -> mcp/test -> mcp -> repo root
const REPO_ROOT = resolve(here, '..', '..', '..');

/** The dispatcher every hook entry of `hooks/hooks.json` runs. */
export const HOOK = resolve(REPO_ROOT, 'hooks', 'guardian-hook.mjs');

/** Hang-breaker only; nothing asserts by reaching it — every case is a
 *  fast, dependency-free regex pass with no real scanner involved. */
export const HOOK_TIMEOUT_MS = 15_000;

export interface HookResult {
  status: number | null;
  stdout: unknown;
  stderr: string;
}

export function runHook(
  payload: Record<string, unknown>,
  opts: { cwd: string; env?: Record<string, string>; homeDir?: string; projectDir?: string; hook?: string } = {
    cwd: process.cwd(),
  },
): HookResult {
  const home = opts.homeDir ?? opts.cwd;
  const r = spawnSyncCapped(process.execPath, [opts.hook ?? HOOK], {
    cwd: opts.cwd,
    input: JSON.stringify(payload),
    encoding: 'utf8',
    timeout: HOOK_TIMEOUT_MS,
    env: {
      ...process.env,
      // Isolates the user-level config lookup (~/.config/dev-guardian/…)
      // from whatever the machine actually running this suite has.
      HOME: home,
      USERPROFILE: home,
      CLAUDE_CONFIG_DIR: '',
      GUARDIAN_HOOKS_BASH_BLOCK: '',
      GUARDIAN_HOOKS: '',
      // Claude Code sets it for every hook: the project the session opened.
      // `''` leaves it unset, and the hook finds the root from the cwd.
      CLAUDE_PROJECT_DIR: opts.projectDir ?? opts.cwd,
      ...opts.env,
    },
  });
  let stdout: unknown = undefined;
  const trimmed = (r.stdout ?? '').trim();
  if (trimmed) {
    try {
      stdout = JSON.parse(trimmed);
    } catch {
      stdout = trimmed;
    }
  }
  return { status: r.status, stdout, stderr: r.stderr ?? '' };
}
