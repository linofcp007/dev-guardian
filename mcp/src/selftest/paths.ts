/**
 * Where this install keeps what a selftest needs, and the line a user runs.
 *
 * Every path comes from the resolver the rest of the plugin uses for it — the
 * rule packs' directory, the `configs/` directory, the per-user data
 * directory, the version — so the selftest tests the packs a scan loads and
 * the dispatcher Claude Code starts, never a second idea of where they are.
 * The plugin's root is the parent of `configs/`.
 *
 * `health_status` imports this to print the command: it holds path
 * arithmetic and those resolvers, and starts nothing.
 */

import { dirname, join } from 'node:path';
import { userDataDir } from '../hooks/userDataDir.js';
import { resolveConfigsDir } from '../platform/configsDir.js';
import { resolveVersion } from '../platform/version.js';
import { pluginPacksDir } from '../runners/semgrepRuleIds.js';

/** Where this install keeps what a selftest needs. */
export interface InstallPaths {
  /** `configs/semgrep/`. */
  packsDir: string;
  /** `configs/selftest/`. */
  canariesDir: string;
  /** `hooks/guardian-hook.mjs`. */
  dispatcherPath: string;
  /** The CLI, for the command line a user is given. */
  cliPath: string;
  /** dev-guardian's per-user data directory. */
  dataDir: string;
  pluginVersion: string;
}

export function installPaths(): InstallPaths {
  const configs = resolveConfigsDir();
  const root = dirname(configs);
  return {
    packsDir: pluginPacksDir(),
    canariesDir: join(configs, 'selftest'),
    dispatcherPath: join(root, 'hooks', 'guardian-hook.mjs'),
    cliPath: join(root, 'cli', 'dev-guardian.mjs'),
    dataDir: userDataDir(),
    pluginVersion: resolveVersion(),
  };
}

/** The line a user runs: `node "<plugin root>/cli/dev-guardian.mjs" selftest`. */
export function selftestCommand(cliPath: string): string {
  return `node "${cliPath.split('\\').join('/')}" selftest`;
}
