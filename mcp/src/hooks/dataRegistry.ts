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
 * {@link userDataDir} is the one resolution of the directory
 * (`hooks/userDataDir.ts`), which the storage module that owns it
 * re-exports; the two used to be separate copies. Node built-ins and sibling
 * hook modules only: the hooks and the CLI's `check` load `mcp/dist/hooks/`
 * without the storage layer or `node_modules`
 * (`test/unit/hooks/hooksDistImports.test.ts` holds that).
 */

import { readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, join, parse, relative, resolve } from 'node:path';
import { walkLinksUnder } from './configFile.js';
import { fileIdentity, guardedPath, hardLinkedTo } from './guardedPath.js';
import { userDataDir as resolveUserDataDir, type DataDirContext } from './userDataDir.js';

export type { DataDirContext };

function safeHome(): string {
  try {
    return homedir();
  } catch {
    return '';
  }
}

/**
 * dev-guardian's per-user data directory, as `hooks/userDataDir.ts` resolves
 * it for the storage module too — except that a missing home is `''` here
 * rather than a throw: a hook never fails for it.
 */
export function userDataDir(ctx: DataDirContext = {}): string {
  return resolveUserDataDir({ ...ctx, home: ctx.home ?? safeHome() });
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
