/**
 * The environment of the package-manager processes `create_fix_pr` runs
 * through OTHER tools: `deps_update_plan` (`npm outdated`, `composer
 * outdated`, `cargo outdated`, `go list`, `bundle outdated`, `dotnet
 * restore`) in its planning worktree, and `deps_audit` (`npm audit`,
 * `pip-audit`, `dotnet restore`) when it re-scans a fix.
 *
 * Those tools run the same way whoever calls them, and a user's own
 * `deps_audit` keeps its environment. Only while `create_fix_pr` runs them
 * does `packageManagerEnvOptions()` return `{ env, extendEnv: false }` —
 * `packageManagerEnv` (`fixpr/testCommandEnv.ts`) — which each such call site spreads into its
 * process options. An `AsyncLocalStorage`, not a parameter threaded through
 * every tool's handler: the setting follows the call and nothing else, so a
 * tool another client runs at the same moment is unaffected.
 */

import { AsyncLocalStorage } from 'node:async_hooks';

const store = new AsyncLocalStorage<NodeJS.ProcessEnv>();

/** Runs `fn` with `env` as the environment of every package-manager process it starts. */
export function withPackageManagerEnv<T>(env: NodeJS.ProcessEnv, fn: () => Promise<T>): Promise<T> {
  return store.run(env, fn);
}

/** `{ env, extendEnv: false }` inside {@link withPackageManagerEnv}, else nothing. */
export function packageManagerEnvOptions(): { env: NodeJS.ProcessEnv; extendEnv: false } | Record<string, never> {
  const env = store.getStore();
  return env === undefined ? {} : { env, extendEnv: false };
}
