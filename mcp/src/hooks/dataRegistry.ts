/**
 * dev-guardian's registry of the project databases it trusts —
 * `<user data dir>/registry/<db_id>.json` — as the hooks guard it (review 3.0
 * wave 2, round 2). `dev-guardian db adopt --yes` writes an entry there, which
 * is the user's decision: a hostile repository can ship a database that hides
 * its findings. The shell guard denies that command when it is written
 * directly, but it is a speed bump, not a wall; this is the stronger defence —
 * the directory itself, refused to an assistant's Write / Edit and to the shell
 * writes the shell guard can see, the way the hook configuration is.
 *
 * {@link userDataDir} mirrors the storage module's own (`storage/userData.ts`),
 * which owns the directory and is not a dependency here: the hooks load only
 * the pre-compiled files in `mcp/dist/hooks/`. Node built-ins and
 * `guardedPath.ts` only.
 */

import { readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, join, parse, relative, resolve } from 'node:path';
import { walkLinksUnder } from './configFile.js';
import { fileIdentity, guardedPath, hardLinkedTo } from './guardedPath.js';

/** Where the data directory comes from; each defaults to this process's. */
export interface DataDirContext {
  env?: Readonly<Record<string, string | undefined>>;
  platform?: NodeJS.Platform;
  home?: string;
}

function safeHome(): string {
  try {
    return homedir();
  } catch {
    return '';
  }
}

/**
 * dev-guardian's per-user data directory: `GUARDIAN_DATA_DIR` when set;
 * otherwise `%LOCALAPPDATA%\dev-guardian` on Windows and
 * `$XDG_DATA_HOME/dev-guardian` (an absolute one only) or
 * `~/.local/share/dev-guardian` elsewhere. Pure path arithmetic.
 */
export function userDataDir(ctx: DataDirContext = {}): string {
  const env = ctx.env ?? process.env;
  const override = env['GUARDIAN_DATA_DIR']?.trim();
  if (override !== undefined && override !== '') return resolve(override);
  const home = ctx.home ?? safeHome();
  if ((ctx.platform ?? process.platform) === 'win32') {
    const local = env['LOCALAPPDATA']?.trim();
    return join(local !== undefined && isAbsolute(local) ? local : join(home, 'AppData', 'Local'), 'dev-guardian');
  }
  const xdg = env['XDG_DATA_HOME']?.trim();
  return join(xdg !== undefined && isAbsolute(xdg) ? xdg : join(home, '.local', 'share'), 'dev-guardian');
}

/** The registry directory: `<user data dir>/registry`. */
export function registryDir(ctx: DataDirContext = {}): string {
  return join(userDataDir(ctx), 'registry');
}

/** `path` is `dir` or lies below it (case-insensitively where the platform's paths are). */
function atOrBelow(dir: string, path: string): boolean {
  const rel = relative(dir, path);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

/** The most registry entries compared for a hard link: far more than one user's databases. */
const MAX_ENTRIES = 1024;

/** The files directly in `dir`, when no link on the way to it leads to a network or device path. */
function filesIn(dir: string): string[] {
  try {
    const root = parse(dir).root;
    if (root === '' || !walkLinksUnder(root, dir).ok) return [];
    return readdirSync(dir)
      .slice(0, MAX_ENTRIES)
      .map((name) => join(dir, name));
  } catch {
    return [];
  }
}

/**
 * Whether a write of `abs` (absolute, as written) reaches the registry: the
 * registry itself or a path below it, as the filesystem opens it — an NTFS
 * stream suffix, trailing dots, an 8.3 name or a link on the way resolved
 * ({@link guardedPath}) — or, when `abs` is a file with more than one link, a
 * HARD link to one of its entries, which no path comparison sees.
 */
export function writesRegistry(abs: string, ctx: DataDirContext = {}): boolean {
  const opts = ctx.platform === undefined ? {} : { platform: ctx.platform };
  const registry = guardedPath(resolve(registryDir(ctx)), opts);
  const target = guardedPath(resolve(abs), opts);
  if (atOrBelow(registry, target)) return true;
  const id = fileIdentity(target);
  if (id === undefined || id.nlink < 2n) return false;
  return hardLinkedTo(target, filesIn(registry)) !== undefined;
}
