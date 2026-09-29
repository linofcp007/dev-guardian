/**
 * The databases this user's dev-guardian created — the registry that makes a
 * project's `.guardian/guardian.db` trusted.
 *
 * Every database dev-guardian CREATES gets a random 128-bit `db_id` in its
 * `schema_meta`, registered here first. On open, a project database whose
 * `db_id` is registered is this user's own (`db.ts#openDatabase`); one with
 * no id, or an id this user never registered, came from somewhere else — a
 * clone, an archive, a submodule — and is FOREIGN, unless a legacy database
 * passes the one-time adoption (`dbProvenance.ts`).
 *
 * The registry is a directory, `<userDataDir()>/registry/`, holding one file
 * per id, `<db_id>.json` — `{ db_id, db_path, project_path, created_at }`.
 * One file per id, written to a temporary name and renamed into place, so
 * two processes registering at once never lose each other's entry the way a
 * shared file rewritten by both would. The directory is created 0700 and
 * checked for ownership (`userData.ts`); an entry must be a regular file of
 * this user's, never a link, and must name its own id. The paths it records
 * are informational: a repository moved or copied by its owner keeps its
 * database trusted (its history, keyed by the old path, simply does not
 * match the new one).
 *
 * An id is 32 lower-case hex characters. One read from a database is
 * checked against that before it names a file — it is the database's word,
 * and a database can be anyone's.
 */

import { randomBytes } from 'node:crypto';
import { closeSync, constants, fstatSync, openSync, readSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { assertOwnedRegularFileIfPresent, ensurePrivateSubdir, userDataDir } from './userData.js';

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
 * Registers `entry` (temporary file, then rename). Throws what the file
 * system throws, and a `GuardianDbError` when the data directory is not
 * private (`userData.ts`).
 */
export function registerDbId(entry: RegistryEntry): void {
  if (!DB_ID_SHAPE.test(entry.db_id)) throw new Error(`not a database id: ${entry.db_id}`);
  const dir = ensurePrivateSubdir('registry');
  const target = join(dir, `${entry.db_id}.json`);
  const temp = `${target}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
  writeFileSync(temp, `${JSON.stringify(entry, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  try {
    renameSync(temp, target);
  } catch (error) {
    rmSync(temp, { force: true });
    throw error;
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
