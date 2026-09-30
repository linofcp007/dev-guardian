/**
 * dev-guardian's per-user data directory, resolved — the one copy. The
 * storage module that owns the directory (`storage/userData.ts`) re-exports
 * it, and the hooks' registry guard (`hooks/dataRegistry.ts`) calls it; they
 * used to hold two copies that could drift.
 *
 * It lives here, not in `storage/`, because the hooks and the CLI's `check`
 * load `mcp/dist/hooks/` without the storage layer: `cli/dev-guardian.mjs`
 * must run `--help` and `check` with `dist/storage/` absent
 * (`test/e2e/cliLazyStorage.test.ts`), and a hook module that cannot load
 * fails open. Node built-ins only.
 */

import { homedir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';

/** Where the data directory comes from; each defaults to this process's. */
export interface DataDirContext {
  env?: Readonly<Record<string, string | undefined>>;
  platform?: NodeJS.Platform;
  /** The home directory. Default: `os.homedir()`, which throws when there is none. */
  home?: string;
}

/**
 * dev-guardian's per-user data directory: `GUARDIAN_DATA_DIR` when set;
 * otherwise `%LOCALAPPDATA%\dev-guardian` on Windows and
 * `$XDG_DATA_HOME/dev-guardian` (only an absolute XDG_DATA_HOME counts, as
 * the XDG spec says) or `~/.local/share/dev-guardian` elsewhere. Read at call
 * time. Pure path arithmetic, no I/O.
 */
export function userDataDir(ctx: DataDirContext = {}): string {
  const env = ctx.env ?? process.env;
  const override = env['GUARDIAN_DATA_DIR']?.trim();
  if (override !== undefined && override !== '') return resolve(override);
  // Only when needed: an override or an absolute LOCALAPPDATA / XDG_DATA_HOME needs no home.
  const home = (): string => ctx.home ?? homedir();
  if ((ctx.platform ?? process.platform) === 'win32') {
    const local = env['LOCALAPPDATA']?.trim();
    return join(local !== undefined && isAbsolute(local) ? local : join(home(), 'AppData', 'Local'), 'dev-guardian');
  }
  const xdg = env['XDG_DATA_HOME']?.trim();
  return join(xdg !== undefined && isAbsolute(xdg) ? xdg : join(home(), '.local', 'share'), 'dev-guardian');
}
