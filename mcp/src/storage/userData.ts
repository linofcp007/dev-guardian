/**
 * dev-guardian's per-user data directory, and the checks that keep what is
 * in it private: the per-project fallback databases (`db.ts`) and the
 * registry of databases this user's dev-guardian created (`dbRegistry.ts`).
 *
 * Every directory is created 0700 and, on POSIX, checked BEFORE anything is
 * created inside it: owned by this user, a real directory (the data
 * directory itself may be a link — the user chose it — nothing under it
 * may), and narrowed to 0700 when it is wider. Windows keeps
 * `%LOCALAPPDATA%` per-user by its ACL and has no uid to compare.
 */

import { chmodSync, lstatSync, mkdirSync, statSync, type Stats } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { GuardianDbError } from './dbError.js';

/**
 * dev-guardian's per-user data directory: `GUARDIAN_DATA_DIR` when set;
 * otherwise `%LOCALAPPDATA%\dev-guardian` on Windows and
 * `$XDG_DATA_HOME/dev-guardian` (only an absolute XDG_DATA_HOME counts, as
 * the XDG spec says) or `~/.local/share/dev-guardian` elsewhere. Read at call
 * time. Pure path arithmetic, no I/O.
 */
export function userDataDir(): string {
  const override = process.env['GUARDIAN_DATA_DIR']?.trim();
  if (override !== undefined && override !== '') return resolve(override);
  if (process.platform === 'win32') {
    const local = process.env['LOCALAPPDATA']?.trim();
    return join(local !== undefined && isAbsolute(local) ? local : join(homedir(), 'AppData', 'Local'), 'dev-guardian');
  }
  const xdg = process.env['XDG_DATA_HOME']?.trim();
  return join(xdg !== undefined && isAbsolute(xdg) ? xdg : join(homedir(), '.local', 'share'), 'dev-guardian');
}

/** A {@link GuardianDbError} for a per-user location this user does not own. */
export function notPrivate(path: string, why: string): GuardianDbError {
  return new GuardianDbError(
    'untrusted',
    path,
    `'${path}' ${why}, so dev-guardian will not keep its per-user data there. Remove it, or set ` +
      'GUARDIAN_DATA_DIR to a directory only you can write, and restart.',
  );
}

function currentUid(): number | undefined {
  return typeof process.getuid === 'function' ? process.getuid() : undefined;
}

/** Throws unless `st` is a directory of this user's; narrows it to 0700. */
function assertPrivateDir(path: string, st: Stats): void {
  if (st.isSymbolicLink()) throw notPrivate(path, 'is a symbolic link');
  if (!st.isDirectory()) throw notPrivate(path, 'is not a directory');
  if (process.platform === 'win32') return;
  const uid = currentUid();
  if (uid !== undefined && st.uid !== uid) throw notPrivate(path, `belongs to uid ${st.uid}, not to this user (${uid})`);
  if ((st.mode & 0o077) !== 0) chmodSync(path, 0o700);
}

function statOrNull(path: string, follow: boolean): Stats | null {
  try {
    return follow ? statSync(path) : lstatSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }
}

/**
 * The data directory, created 0700 when it does not exist, and checked —
 * before anything is created in it — when it does. Returns its path.
 */
export function ensurePrivateDataDir(): string {
  const dir = userDataDir();
  const existing = statOrNull(dir, true);
  if (existing === null) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    assertPrivateDir(dir, statSync(dir));
  } else {
    assertPrivateDir(dir, existing);
  }
  return dir;
}

/**
 * `name` directly under the (checked) data directory, created 0700 when it
 * does not exist and checked when it does — never a link.
 */
export function ensurePrivateSubdir(name: string): string {
  const parent = ensurePrivateDataDir();
  const dir = join(parent, name);
  const existing = statOrNull(dir, false);
  if (existing === null) {
    try {
      mkdirSync(dir, { mode: 0o700 });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
    }
  }
  assertPrivateDir(dir, lstatSync(dir));
  return dir;
}

/** On POSIX, an existing file here must be a regular file of this user's (never a link). */
export function assertOwnedRegularFileIfPresent(path: string): void {
  const st = statOrNull(path, false);
  if (st === null) return;
  if (!st.isFile()) throw notPrivate(path, st.isSymbolicLink() ? 'is a symbolic link' : 'is not a regular file');
  if (process.platform === 'win32') return;
  const uid = currentUid();
  if (uid !== undefined && st.uid !== uid) throw notPrivate(path, `belongs to uid ${st.uid}, not to this user (${uid})`);
}
