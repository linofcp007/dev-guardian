/**
 * The databases this user's dev-guardian created or the user registered —
 * the registry that makes a project's `.guardian/guardian.db` trusted.
 *
 * Every database dev-guardian CREATES gets a random 128-bit `db_id` in its
 * `schema_meta`, registered here first; `dev-guardian db adopt --yes`
 * registers an existing one the user vouches for. On open, a project
 * database whose `db_id` is registered for its path is this user's own
 * (`db.ts#openDatabase`); one with no id (from before 3.0.1), or an id this
 * user never registered, came from somewhere else — a clone, an archive, a
 * submodule — or has not been registered yet, and is FOREIGN.
 *
 * The registry is a directory, `<userDataDir()>/registry/`, holding one file
 * per id, `<db_id>.json` — `{ db_id, db_path, project_path, created_at }`.
 * One file per id, written to a temporary name and renamed into place, so
 * two processes registering at once never lose each other's entry the way a
 * shared file rewritten by both would. The directory is created 0700 and
 * checked for ownership (`userData.ts`); an entry must be a regular file of
 * this user's, never a link, and must name its own id. The `db_path` it
 * records binds the id to one location: an id is trusted only for the
 * database at the canonical path it was registered for (`db.ts`). The id
 * travels with the file — a Docker `COPY . .`, a package, an archive of the
 * project carry `.guardian/guardian.db` — so without that binding it was a
 * bearer token, trusted wherever a copy landed. A repository its owner moved
 * is foreign at its new path, and the warning names where it was registered.
 *
 * An id is 32 lower-case hex characters. One read from a database is
 * checked against that before it names a file — it is the database's word,
 * and a database can be anyone's.
 */

import { randomBytes } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readdirSync,
  readSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { canonicalPath } from '../platform/projectPath.js';
import { assertOwnedRegularFileIfPresent, dataDirFailure, ensurePrivateSubdir, userDataDir } from './userData.js';

export const DB_ID_SHAPE = /^[0-9a-f]{32}$/;

/** The `schema_meta` key a database's id is stored under. */
export const DB_ID_KEY = 'db_id';

export interface RegistryEntry {
  db_id: string;
  db_path: string;
  project_path: string;
  created_at: string;
}

/** A fresh random id. */
export function newDbId(): string {
  return randomBytes(16).toString('hex');
}

/** `<userDataDir()>/registry` — path arithmetic only. */
export function registryDir(): string {
  return join(userDataDir(), 'registry');
}

/**
 * The entry registered for `id`, or null: not registered, not an id, or an
 * entry that is not a regular file of this user's naming that id. Never
 * throws for a missing registry.
 */
export function lookupDbId(id: string): RegistryEntry | null {
  if (!DB_ID_SHAPE.test(id)) return null;
  const path = join(registryDir(), `${id}.json`);
  try {
    assertOwnedRegularFileIfPresent(path);
  } catch {
    return null;
  }
  let text: string;
  try {
    text = readBounded(path, 4096);
  } catch {
    return null;
  }
  try {
    const parsed = JSON.parse(text) as Partial<RegistryEntry>;
    if (parsed.db_id !== id) return null;
    return {
      db_id: id,
      db_path: typeof parsed.db_path === 'string' ? parsed.db_path : '',
      project_path: typeof parsed.project_path === 'string' ? parsed.project_path : '',
      created_at: typeof parsed.created_at === 'string' ? parsed.created_at : '',
    };
  } catch {
    return null;
  }
}

/**
 * The entry registered for the database at `canonicalDbPath` (a
 * `canonicalPath`), found by reading the registry — or null. For when the
 * database itself cannot be read to learn its id: a corrupt file that is the
 * user's own is kept for them, one that is not is foreign (`db.ts`), and the
 * SessionStart hook says when a project's database is not registered. Never
 * throws: a registry that cannot be read registers nothing.
 */
export function findEntryForDbPath(canonicalDbPath: string): RegistryEntry | null {
  let names: string[];
  try {
    names = readdirSync(registryDir());
  } catch {
    return null;
  }
  for (const name of names) {
    const id = name.endsWith('.json') ? name.slice(0, -'.json'.length) : '';
    if (!DB_ID_SHAPE.test(id)) continue;
    const entry = lookupDbId(id);
    if (entry !== null && entry.db_path === canonicalDbPath) return entry;
  }
  return null;
}

/**
 * Whether the regular file at `dbPath` (a project's `.guardian/guardian.db`)
 * is registered as this user's, WITHOUT opening it — for the SessionStart
 * hook, which reads no project database: `none` when no regular file is
 * there, `unknown` when the registry exists but cannot be listed.
 * `unregistered` includes a registry that does not exist yet (an upgrade
 * from 3.0.0 has none). Never throws.
 */
export function databaseRegistration(dbPath: string): 'registered' | 'unregistered' | 'none' | 'unknown' {
  try {
    if (!lstatSync(dbPath).isFile()) return 'none';
  } catch {
    return 'none';
  }
  let canonical: string;
  try {
    canonical = canonicalPath(dbPath);
  } catch {
    return 'unknown';
  }
  try {
    readdirSync(registryDir());
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'ENOENT' ? 'unregistered' : 'unknown';
  }
  return findEntryForDbPath(canonical) !== null ? 'registered' : 'unregistered';
}

/**
 * Registers `entry` (temporary file, then rename). Every failure — the data
 * directory or the registry not private, not creatable, not writable — is a
 * `GuardianDbError` of kind `data-dir` (`userData.ts`).
 */
export function registerDbId(entry: RegistryEntry): void {
  if (!DB_ID_SHAPE.test(entry.db_id)) throw new Error(`not a database id: ${entry.db_id}`);
  const dir = ensurePrivateSubdir('registry');
  const target = join(dir, `${entry.db_id}.json`);
  const temp = `${target}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
  try {
    writeFileSync(temp, `${JSON.stringify(entry, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  } catch (error) {
    throw dataDirFailure(dir, 'written', error);
  }
  try {
    renameSync(temp, target);
  } catch (error) {
    rmSync(temp, { force: true });
    throw dataDirFailure(dir, 'written', error);
  }
}

/** Removes `id`'s entry, best effort: an id minted and never written to a database. */
export function forgetDbId(id: string): void {
  if (!DB_ID_SHAPE.test(id)) return;
  try {
    rmSync(join(registryDir(), `${id}.json`), { force: true });
  } catch {
    /* an orphan entry names a path and nothing else */
  }
}

/** At most `max` bytes of a regular file, judged by the descriptor it opened. */
function readBounded(path: string, max: number): string {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > max) throw new Error('not a registry entry');
    const buf = Buffer.alloc(st.size);
    let got = 0;
    while (got < st.size) {
      const n = readSync(fd, buf, got, st.size - got, got);
      if (n === 0) break;
      got += n;
    }
    return buf.subarray(0, got).toString('utf8');
  } finally {
    closeSync(fd);
  }
}
