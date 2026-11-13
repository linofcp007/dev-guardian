// @ts-nocheck -- Phase 4 scaffold (dev-spec-driven): the failing tests come first; the implementation replaces these bodies.
/**
 * Where this install keeps what a selftest needs, and the line a user runs (scaffold).
 */

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
  throw new Error('selftest: not implemented');
}

/** The line a user runs: `node "<plugin root>/cli/dev-guardian.mjs" selftest`. */
export function selftestCommand(cliPath: string): string {
  throw new Error('selftest: not implemented');
}
