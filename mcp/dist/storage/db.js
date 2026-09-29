/**
 * SQLite connection management for the dev-guardian MCP server.
 *
 * Backed by Node's built-in `node:sqlite` (`DatabaseSync`) — no native module,
 * so the server runs from a self-contained bundle with **zero** runtime
 * `node_modules`. A thin adapter (`GuardianDatabase` / `GuardianStatement`)
 * preserves the small, better-sqlite3-shaped surface the repos rely on:
 * `prepare<P, R>()`, `run()/get()/all()`, `exec()`, `pragma()` and a
 * nesting-aware `transaction()`. This stays the only module that knows the
 * engine is node:sqlite; swapping it again only touches files in this folder.
 *
 * The DB lives at `<project_root>/.guardian/guardian.db`. It is REFUSED, and
 * the per-user fallback used instead with a warning the caller includes in
 * tool responses (`health_status`'s `storage_warning`, every scan's
 * `warnings`), when:
 *   - the location is not writable (read-only mounts, missing permissions, a
 *     database left behind by a `sudo` or Docker run). Writability is PROBED
 *     — a file is created in `.guardian/` and the database takes a real
 *     write — not asked of `accessSync`, which on Windows ignores ACLs;
 *   - git tracks it (`dbTrust.ts`): a committed database is the committer's
 *     schema, and SQL inside it runs on every write the server makes;
 *   - it holds a schema object, or a table or index definition, that the
 *     migrations never create (`schemaCheck.ts#untrustedObjects`) — a
 *     trigger that deletes every finding as it is inserted was reproduced.
 *
 * The fallback is `<user data dir>/<sha1(project_root)>/guardian.db`
 * ({@link userDataDir}: `%LOCALAPPDATA%\dev-guardian` on Windows,
 * `$XDG_DATA_HOME/dev-guardian` or `~/.local/share/dev-guardian` elsewhere,
 * `GUARDIAN_DATA_DIR` when set). It used to be `os.tmpdir()/dev-guardian/…`:
 * a predictable path in a directory every user can write, which another user
 * could create first and fill, and which nothing checked the owner of. Its
 * directories are created 0700 and, on POSIX, must belong to this user.
 *
 * Every connection opens with `trusted_schema = OFF` (no function the schema
 * names runs unless SQLite marks it innocuous), `cell_size_check = ON`
 * (malformed pages are caught as corruption rather than read) and no memory
 * map (a file read through `mmap` bypasses those checks). A file SQLite
 * cannot read at all is one {@link GuardianDbError} naming it and saying to
 * move it aside — the server prints it without a stack trace.
 *
 * The connection opens in WAL mode with foreign keys on; the resolver uses
 * `:memory:` when the caller asks for it, which the unit tests rely on.
 */
import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, existsSync, lstatSync, mkdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { gitTracksDatabase } from './dbTrust.js';
import { listMigrations, runMigrations } from './migrations/runner.js';
import { missingIndexSql, missingObjects, readSchema, recordsNewerMigrations, untrustedObjects, } from './schemaCheck.js';
let sqliteModule;
function loadSqlite() {
    sqliteModule ??= createRequire(import.meta.url)('node:sqlite');
    return sqliteModule;
}
/** What the server prints, and exits 1 with, when `node:sqlite` is unavailable. */
export const NODE_SQLITE_REQUIRED = 'dev-guardian requires Node.js >= 22.13 (node:sqlite)';
/**
 * Whether this Node can load `node:sqlite` without flags — Node >= 22.13
 * (22.5-22.12 have it only behind `--experimental-sqlite`, which this project
 * never requires). Entry points check it before touching storage.
 */
export function nodeSqliteAvailable() {
    try {
        loadSqlite();
        return true;
    }
    catch {
        return false;
    }
}
/**
 * How long every connection waits for another connection's lock before
 * failing with `database is locked`. SQLite's own default is 0 — fail at
 * once — and several processes share one database file in real use (the
 * plugin's MCP server, a project-level one, the CLI): with 0, 15 of 20
 * fresh-database opens by 4 concurrent processes failed, and a write lock
 * held by one server made the next one's startup exit 1.
 */
export const BUSY_TIMEOUT_MS = 5000;
/**
 * Prepared-statement wrapper over `node:sqlite`'s `StatementSync`.
 *
 * Methods are declared as methods (not arrow properties) on purpose: that keeps
 * their parameter types bivariant, so a `GuardianStatement<unknown[]>` returned
 * by an un-generic `prepare()` stays assignable to a typed
 * `GuardianStatement<[string, ...]>` field — exactly how better-sqlite3's
 * `Statement` behaved.
 */
export class GuardianStatement {
    stmt;
    constructor(stmt) {
        this.stmt = stmt;
    }
    run(...params) {
        const info = this.stmt.run(...params);
        return { changes: Number(info.changes), lastInsertRowid: info.lastInsertRowid };
    }
    get(...params) {
        return this.stmt.get(...params);
    }
    all(...params) {
        return this.stmt.all(...params);
    }
}
/**
 * Minimal database handle over `node:sqlite`, exposing exactly what the storage
 * repos use. Construct from a path (or `':memory:'`) — tests build these
 * directly; the server goes through {@link openDatabase}.
 */
export class GuardianDatabase {
    raw;
    txDepth = 0;
    /**
     * The path passed to the constructor (or `':memory:'`). Mirrors
     * better-sqlite3's `db.name`, which `healthStatus` reads to stat the DB file.
     */
    name;
    constructor(source) {
        if (typeof source === 'string') {
            this.raw = new (loadSqlite().DatabaseSync)(source);
            this.name = source;
        }
        else {
            this.raw = source;
            this.name = '';
        }
        // First statement on every connection, before anything that can take a
        // lock (switching a fresh file to WAL does). A PRAGMA rather than the
        // constructor's `timeout` option, which only exists from Node 22.16 —
        // on 22.13 an unknown option is silently ignored.
        this.raw.exec(`PRAGMA busy_timeout = ${BUSY_TIMEOUT_MS}`);
    }
    prepare(source) {
        return new GuardianStatement(this.raw.prepare(source));
    }
    /** Run one or more statements for their side effects (DDL, PRAGMA, BEGIN…). */
    exec(sql) {
        this.raw.exec(sql);
    }
    /** better-sqlite3-style PRAGMA setter. Any returned row is intentionally ignored. */
    pragma(source) {
        this.raw.exec(`PRAGMA ${source}`);
    }
    /**
     * Wraps `fn` in a transaction and returns a callable, mirroring
     * better-sqlite3's `db.transaction(fn)`. Nesting-aware: the outermost call
     * uses BEGIN IMMEDIATE/COMMIT/ROLLBACK, inner calls use SAVEPOINTs — so the
     * repos' `tx(args)` semantics carry over unchanged.
     *
     * `BEGIN IMMEDIATE`, not a deferred `BEGIN`: a deferred transaction takes
     * the write lock only at its first write, and if another connection wrote
     * in between, that upgrade fails with SQLITE_BUSY without ever consulting
     * the busy timeout. Taking the lock up front is what lets the timeout work.
     *
     * On failure, the ORIGINAL error is what the caller sees. SQLite rolls the
     * whole transaction back by itself on some errors (`RAISE(ROLLBACK)`, a full
     * disk, I/O errors); an unconditional `ROLLBACK` then throws
     * `cannot rollback - no transaction is active`, which replaced the error
     * that explained what went wrong and skipped the depth reset, leaving every
     * later "transaction" on this connection a deferred SAVEPOINT.
     */
    transaction(fn) {
        return (...args) => {
            const depth = this.txDepth;
            const top = depth === 0;
            this.raw.exec(top ? 'BEGIN IMMEDIATE' : `SAVEPOINT sp_${depth}`);
            this.txDepth = depth + 1;
            try {
                const result = fn(...args);
                this.raw.exec(top ? 'COMMIT' : `RELEASE sp_${depth}`);
                return result;
            }
            catch (error) {
                this.rollbackAfterFailure(top, depth);
                throw error;
            }
            finally {
                this.txDepth = depth;
            }
        };
    }
    /** Best-effort undo for {@link transaction}; never throws over the caller's error. */
    rollbackAfterFailure(top, depth) {
        if (this.inTransaction() === false)
            return; // SQLite already rolled it back
        try {
            if (top) {
                this.raw.exec('ROLLBACK');
            }
            else {
                this.raw.exec(`ROLLBACK TO sp_${depth}`);
                this.raw.exec(`RELEASE sp_${depth}`);
            }
        }
        catch {
            // The error that made us roll back is the one worth reporting.
        }
    }
    /**
     * `DatabaseSync#isTransaction` exists from Node 22.16 / 24.0. On 22.13–22.15
     * it reads `undefined` at runtime (whatever the type declarations say), and
     * the answer is "unknown": the rollback is then attempted and its own
     * failure swallowed.
     */
    inTransaction() {
        const flag = this.raw.isTransaction;
        return typeof flag === 'boolean' ? flag : undefined;
    }
    close() {
        this.raw.close();
    }
}
/**
 * A database file dev-guardian cannot use, said in one line that names the
 * file and what to do about it — what the server prints (and exits 1 with)
 * instead of a stack trace from deep inside `new Storage()` or SQLite.
 *
 *   - `schema`: the migrations ran and an object the code needs is still
 *     missing (see `schemaCheck.ts#missingObjects`);
 *   - `corrupt`: SQLite cannot read the file (SQLITE_CORRUPT, SQLITE_NOTADB);
 *   - `untrusted`: the file holds objects the migrations never create, or its
 *     location is not private to this user — see {@link openDatabase}.
 */
export class GuardianDbError extends Error {
    kind;
    dbPath;
    constructor(kind, dbPath, message) {
        super(message);
        this.kind = kind;
        this.dbPath = dbPath;
        this.name = 'GuardianDbError';
    }
}
let referenceSchema;
/**
 * The schema the shipped migrations build on an empty database, read once
 * per process. Every database, whatever its age, holds a subset of it —
 * migrations only ever add — so it is both what a database may hold and
 * what it must hold once migrated.
 */
export function expectedSchema() {
    if (referenceSchema !== undefined)
        return referenceSchema;
    const db = new GuardianDatabase(':memory:');
    try {
        runMigrations(db);
        referenceSchema = readSchema(db);
    }
    finally {
        db.close();
    }
    return referenceSchema;
}
/** Throws a {@link GuardianDbError} naming what the migrated `db` still lacks. */
function assertSchemaComplete(db, dbPath) {
    const missing = missingObjects(db, expectedSchema());
    if (missing.length === 0)
        return;
    const shown = missing.slice(0, 8).join(', ') + (missing.length > 8 ? `, and ${missing.length - 8} more` : '');
    throw new GuardianDbError('schema', dbPath, `the database '${dbPath}' is missing ${shown} after its migrations ran — ` +
        'it was changed outside dev-guardian, or copied from an incomplete file. ' +
        'Move it aside (rename it) and restart: a new database is created in its place, ' +
        'and the old file stays readable for recovery.');
}
/**
 * Recreates, from the reference, every index the migrated `db` lacks on a
 * table it has: a 3.0 development database that ran 005's first cut never
 * got three of them, and 005 is recorded as applied. An index changes speed,
 * never an answer, so it is repaired rather than refused.
 */
function recreateMissingIndexes(db) {
    const statements = missingIndexSql(db, expectedSchema());
    if (statements.length === 0)
        return;
    db.transaction(() => {
        for (const sql of statements)
            db.exec(sql);
    })();
}
/**
 * Refuses `db` when its schema holds anything the migrations never create —
 * see `schemaCheck.ts#untrustedObjects`. Runs BEFORE the migrations, which
 * write to the very tables a trigger would sit on.
 */
function assertTrustedSchema(db, dbPath) {
    // A later build migrated it (a downgrade): what its additive migrations can
    // create, and cannot hide a row with, is accepted (`schemaCheck.ts`).
    const newerBuild = recordsNewerMigrations(db, latestMigration());
    const found = untrustedObjects(db, expectedSchema(), { newerBuild });
    if (found.length === 0)
        return;
    const shown = found.slice(0, 5).join('; ') + (found.length > 5 ? `; and ${found.length - 5} more` : '');
    throw new GuardianDbError('untrusted', dbPath, `'${dbPath}' holds schema objects dev-guardian's migrations never create (${shown}). ` +
        'SQL stored in a database runs on every write the server makes — a trigger, or a constraint an ' +
        'INSERT OR IGNORE obeys, can hide findings from every reader — so it is not used' +
        (newerBuild
            ? '. It records migrations from a newer dev-guardian than this one: an object of that kind is refused ' +
                'from any build, and the newer dev-guardian reads this database'
            : ''));
}
let latestKnownMigration;
/** The highest migration number this build ships. */
function latestMigration() {
    latestKnownMigration ??= Math.max(0, ...listMigrations().map((m) => m.version));
    return latestKnownMigration;
}
/**
 * Pragmas, the trust check, migrations and the completeness check: what makes
 * a handle usable. A file SQLite cannot read at all becomes one
 * {@link GuardianDbError} of kind `corrupt`.
 */
function prepareForUse(db, dbPath) {
    try {
        applyPragmas(db);
        assertTrustedSchema(db, dbPath);
        runMigrations(db);
        recreateMissingIndexes(db);
        assertSchemaComplete(db, dbPath);
    }
    catch (error) {
        throw asCorruptionError(error, dbPath);
    }
}
/** SQLITE_CORRUPT (11) or SQLITE_NOTADB (26) as a {@link GuardianDbError}; anything else unchanged. */
function asCorruptionError(error, dbPath) {
    const code = sqliteErrorCode(error);
    if (code !== 11 && code !== 26)
        return error;
    const detail = error instanceof Error ? error.message : String(error);
    return new GuardianDbError('corrupt', dbPath, `the database '${dbPath}' cannot be read (${detail}). Move it aside (rename it, for example to ` +
        'guardian.db.corrupt) and restart: a new, empty database is created in its place, and the old file ' +
        'stays available for recovery.');
}
/**
 * Open (and migrate) a guardian database. Idempotent — calling twice on the
 * same path returns two independent connections to the same file.
 */
export function openDatabase(options) {
    if (options.inMemory)
        return openInMemory();
    const projectPath = resolve(options.projectPath);
    const preferredPath = join(projectPath, '.guardian', 'guardian.db');
    const existingOnly = options.existingOnly === true;
    let refusal;
    if (!isDirectory(projectPath)) {
        // Caller's responsibility to have a real project dir; if it doesn't
        // exist, we can't write there.
        refusal = `Project path '${projectPath}' is not writable (it is not an existing directory)`;
    }
    else if (!existingOnly || existsSync(preferredPath)) {
        const verdict = existsSync(preferredPath) ? gitTracksDatabase(projectPath) : null;
        if (verdict?.state === 'tracked') {
            refusal =
                `'${preferredPath}' is tracked by git (${verdict.detail}). A committed database is not trusted: ` +
                    'SQL stored in it — a trigger, a constraint — runs on every write the server makes and can hide ' +
                    'findings from every reader. Stop tracking it (git rm --cached .guardian/guardian.db); one that ' +
                    'came with a clone is best deleted';
        }
        else if (verdict?.state === 'unknown') {
            refusal =
                `could not confirm that '${preferredPath}' is not tracked by git (${verdict.detail}); ` +
                    'a committed database is not trusted, so it is not used until git can answer';
        }
        else {
            const note = verdict?.plausibleOnly === true
                ? `could not ask git whether '${preferredPath}' is tracked (${verdict.detail}), so it is used; ` +
                    'install git, or make it answer, to have that confirmed.'
                : undefined;
            try {
                return { db: openWritable(preferredPath), path: preferredPath, ...(note !== undefined ? { warning: note } : {}) };
            }
            catch (error) {
                if (error instanceof GuardianDbError && error.kind === 'untrusted') {
                    refusal = error.message;
                }
                else if (isNotWritableError(error)) {
                    const reason = error instanceof Error ? error.message : String(error);
                    refusal = `Project path '${projectPath}' is not writable (${reason})`;
                }
                else {
                    throw error;
                }
            }
        }
    }
    const chosenPath = resolveFallbackDbPath(projectPath);
    if (existingOnly && !existsSync(chosenPath)) {
        return { ...openInMemory(), ...(refusal !== undefined ? { warning: `${refusal}.` } : {}) };
    }
    ensurePrivateFallbackDir(dirname(chosenPath));
    const db = openFallback(chosenPath);
    if (refusal === undefined)
        return { db, path: chosenPath };
    return {
        db,
        path: chosenPath,
        warning: `${refusal}; dev-guardian DB persisted to '${chosenPath}' instead. ` +
            `Scans will not be visible alongside the project.`,
    };
}
function openInMemory() {
    const db = new GuardianDatabase(':memory:');
    applyPragmas(db);
    runMigrations(db);
    return { db, path: ':memory:' };
}
/**
 * Opens (and migrates) `dbPath` only if it can really be written: creates
 * its directory, creates and removes a probe file there, then makes the
 * database take a write. Throws otherwise — see {@link isNotWritableError}
 * for the failures that mean "use the fallback".
 */
function openWritable(dbPath) {
    const dir = dirname(dbPath);
    ensureDir(dir);
    probeDirectoryWritable(dir);
    const db = new GuardianDatabase(dbPath);
    try {
        prepareForUse(db, dbPath);
        probeDatabaseWritable(db);
        return db;
    }
    catch (error) {
        closeQuietly(db);
        throw error;
    }
}
/** Opens `dbPath` and makes it usable ({@link prepareForUse}); closes it again on failure. */
function openPrepared(dbPath) {
    const db = new GuardianDatabase(dbPath);
    try {
        prepareForUse(db, dbPath);
        return db;
    }
    catch (error) {
        closeQuietly(db);
        throw error;
    }
}
/**
 * The per-user fallback: checked for ownership (POSIX) before it is opened,
 * and refused outright — there is nowhere further to fall back to — when it
 * is not ours or holds objects the migrations never create.
 */
function openFallback(dbPath) {
    assertOwnedRegularFileIfPresent(dbPath);
    try {
        return openPrepared(dbPath);
    }
    catch (error) {
        if (error instanceof GuardianDbError && error.kind === 'untrusted') {
            throw new GuardianDbError('untrusted', dbPath, `${error.message}. It is dev-guardian's per-user database for this project: move it aside and restart.`);
        }
        throw error;
    }
}
function closeQuietly(db) {
    try {
        db.close();
    }
    catch {
        /* the open failure is the one worth reporting */
    }
}
function probeDirectoryWritable(dir) {
    const probe = join(dir, `.write-probe-${process.pid}-${randomBytes(4).toString('hex')}`);
    writeFileSync(probe, '', { flag: 'wx' });
    try {
        rmSync(probe, { force: true });
    }
    catch {
        /* a probe we could create but not delete is harmless; .guardian/ is git-ignored */
    }
}
/**
 * A read-only database FILE opens without complaint and serves every read —
 * SQLite quietly opens it read-only — so only a write reveals it. An UPDATE
 * that matches nothing still has to begin a write transaction, which is
 * where SQLite answers SQLITE_READONLY, before and regardless of any lock.
 *
 * The busy timeout is dropped to 0 for the probe: SQLITE_BUSY means another
 * process is writing this same file right now — proof enough that it is
 * writable, and no reason to stall startup for 5 s.
 */
function probeDatabaseWritable(db) {
    db.exec('PRAGMA busy_timeout = 0');
    try {
        db.exec('UPDATE schema_meta SET value = value WHERE 0');
    }
    catch (error) {
        if (!isBusyError(error))
            throw error;
    }
    finally {
        db.exec(`PRAGMA busy_timeout = ${BUSY_TIMEOUT_MS}`);
    }
}
/**
 * Failures that mean "this location cannot be written by us": the OS
 * refusing (EACCES/EPERM, or EROFS on a read-only mount) or SQLite refusing
 * (SQLITE_READONLY = 8, SQLITE_CANTOPEN = 14 — what an ACL-denied directory
 * produces on Windows). Anything else is a real error and propagates.
 */
function isNotWritableError(error) {
    if (error instanceof Error && 'code' in error) {
        const code = error.code;
        if (code === 'EACCES' || code === 'EPERM' || code === 'EROFS')
            return true;
    }
    const sqlite = sqliteErrorCode(error);
    return sqlite === 8 || sqlite === 14;
}
/**
 * dev-guardian's per-user data directory: `GUARDIAN_DATA_DIR` when set;
 * otherwise `%LOCALAPPDATA%\dev-guardian` on Windows and
 * `$XDG_DATA_HOME/dev-guardian` (only an absolute XDG_DATA_HOME counts, as
 * the XDG spec says) or `~/.local/share/dev-guardian` elsewhere. Read at call
 * time. Pure path arithmetic, no I/O.
 */
export function userDataDir() {
    const override = process.env['GUARDIAN_DATA_DIR']?.trim();
    if (override !== undefined && override !== '')
        return resolve(override);
    if (process.platform === 'win32') {
        const local = process.env['LOCALAPPDATA']?.trim();
        return join(local !== undefined && isAbsolute(local) ? local : join(homedir(), 'AppData', 'Local'), 'dev-guardian');
    }
    const xdg = process.env['XDG_DATA_HOME']?.trim();
    return join(xdg !== undefined && isAbsolute(xdg) ? xdg : join(homedir(), '.local', 'share'), 'dev-guardian');
}
/**
 * Where {@link openDatabase} redirects a project's database when
 * `<projectPath>/.guardian/guardian.db` is not writable or not trusted:
 * `<userDataDir()>/<sha1(project)>/guardian.db`, keyed by {@link shortHash}
 * of the RESOLVED project path — mirrors `openDatabase`'s own internal
 * `resolve()` exactly, so a caller that passes a relative path still lands
 * on the same file `openDatabase` itself would open for it. Pure path
 * arithmetic, no I/O.
 *
 * It was `os.tmpdir()/dev-guardian/<sha1(project)>/guardian.db` — a path
 * anyone could compute, in a directory anyone can write, opened by the CLI
 * whenever it existed. A database there from before this change is not
 * carried over: that location is exactly what could not be trusted.
 */
export function resolveFallbackDbPath(projectPath) {
    return join(userDataDir(), shortHash(resolve(projectPath)), 'guardian.db');
}
/** A {@link GuardianDbError} for a fallback location this user does not own. */
function notPrivate(path, why) {
    return new GuardianDbError('untrusted', path, `'${path}' ${why}, so dev-guardian will not keep its per-user database there. Remove it, or set ` +
        'GUARDIAN_DATA_DIR to a directory only you can write, and restart.');
}
/**
 * Creates the fallback's directories 0700 and, on POSIX, makes sure the data
 * directory and the project's directory in it belong to this user and are
 * not a symbolic link (the data directory itself may be one: the user chose
 * it). A directory another user could read is narrowed to 0700. Windows keeps
 * `%LOCALAPPDATA%` per-user by its ACL, and has no uid to compare.
 */
function ensurePrivateFallbackDir(dir) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    if (process.platform === 'win32')
        return;
    const uid = typeof process.getuid === 'function' ? process.getuid() : undefined;
    const checks = [
        [userDataDir(), true],
        [dir, false],
    ];
    for (const [path, followLink] of checks) {
        const st = followLink ? statSync(path) : lstatSync(path);
        if (st.isSymbolicLink())
            throw notPrivate(path, 'is a symbolic link');
        if (!st.isDirectory())
            throw notPrivate(path, 'is not a directory');
        if (uid !== undefined && st.uid !== uid)
            throw notPrivate(path, `belongs to uid ${st.uid}, not to this user (${uid})`);
        if ((st.mode & 0o077) !== 0)
            chmodSync(path, 0o700);
    }
}
/** On POSIX, an existing fallback file must be a regular file of this user's. */
function assertOwnedRegularFileIfPresent(path) {
    if (process.platform === 'win32')
        return;
    let st;
    try {
        st = lstatSync(path);
    }
    catch {
        return; // created by the open, 0600 under a 0700 directory
    }
    if (!st.isFile())
        throw notPrivate(path, st.isSymbolicLink() ? 'is a symbolic link' : 'is not a regular file');
    const uid = typeof process.getuid === 'function' ? process.getuid() : undefined;
    if (uid !== undefined && st.uid !== uid)
        throw notPrivate(path, `belongs to uid ${st.uid}, not to this user (${uid})`);
}
/**
 * Open a database at an EXACT, already-known path — no writability probe, no
 * primary/fallback decision, and (unlike {@link openDatabase}'s own
 * non-memory branch) no directory creation: the caller has already
 * established, by checking the filesystem itself, that `path` exists and is
 * the one to read.
 *
 * Exists for `status`/`dashboard`'s own read-only detection: once it has
 * found a database sitting at the FALLBACK location (see
 * `resolveFallbackDbPath`) rather than the primary one, re-running
 * `openDatabase`'s own writability probe would be pointless at best (the
 * answer is already known from the filesystem) and WRONG at worst — if the
 * project directory happens to be writable again by the time `status` runs
 * (permissions fixed, a different mount, …), `openDatabase({ projectPath })`
 * would pick the PRIMARY path instead (writable wins), silently ignoring the
 * very fallback database this function was called to read and, worse,
 * creating a fresh EMPTY primary file in its place. Opening the exact path
 * already located sidesteps that re-derivation entirely.
 *
 * Still applies the same pragmas and runs migrations `openDatabase` would
 * have, so a database that predates a later migration is brought current
 * before use — this is a genuine open, not a bypass of either.
 */
export function openDatabaseAtPath(path) {
    return openPrepared(path);
}
function applyPragmas(db) {
    // First, before anything reads the schema: a function the file's schema
    // names (in a view, a trigger, a default, an index expression) runs only if
    // SQLite marks it innocuous.
    db.pragma('trusted_schema = OFF');
    // A page whose cell sizes do not add up is reported as corruption instead
    // of being read — a crafted file is the case that matters.
    db.pragma('cell_size_check = ON');
    // No memory map: reads through mmap skip the page checks above, and a file
    // another process truncates under a mapping faults the whole process. It
    // was 64 MB; the page cache serves the same reads.
    db.pragma('mmap_size = 0');
    // WAL gives concurrent readers + one writer without the classic SQLITE_BUSY
    // storm. Required because the server reads from resources while tools write.
    retryWhileBusy(() => db.pragma('journal_mode = WAL'));
    db.pragma('foreign_keys = ON');
    // Synchronous=NORMAL is the documented WAL pairing for durability vs. speed.
    db.pragma('synchronous = NORMAL');
}
/**
 * Runs `op`, retrying on SQLITE_BUSY until {@link BUSY_TIMEOUT_MS} has passed.
 *
 * For the few statements the busy timeout does not cover. SQLite skips the
 * busy handler when waiting could deadlock — two connections that both hold
 * a read lock and both want to upgrade it, which is exactly what several
 * processes switching one fresh file to WAL at the same moment do. Measured:
 * with the busy timeout alone, 7 of 20 concurrent fresh opens still failed
 * `database is locked` on `journal_mode = WAL`. Retrying after the statement
 * has released its read lock breaks the tie.
 */
function retryWhileBusy(op) {
    const deadline = Date.now() + BUSY_TIMEOUT_MS;
    for (;;) {
        try {
            op();
            return;
        }
        catch (error) {
            if (!isBusyError(error) || Date.now() >= deadline)
                throw error;
            sleepSync(20 + Math.floor(Math.random() * 30));
        }
    }
}
/** SQLITE_BUSY (5) or SQLITE_LOCKED (6), including their extended codes. */
function isBusyError(error) {
    const primary = sqliteErrorCode(error);
    return primary === 5 || primary === 6;
}
/** The primary SQLite result code of a `node:sqlite` error, if it is one. */
function sqliteErrorCode(error) {
    if (typeof error !== 'object' || error === null || !('errcode' in error))
        return undefined;
    const code = error.errcode;
    // Extended result codes carry the primary code in their low byte.
    return typeof code === 'number' ? code & 0xff : undefined;
}
/** Blocks this thread for `ms` without spinning. */
export function sleepSync(ms) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}
function ensureDir(dir) {
    if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
    }
}
function isDirectory(path) {
    try {
        return statSync(path).isDirectory();
    }
    catch {
        return false;
    }
}
function shortHash(input) {
    return createHash('sha1').update(input).digest('hex').slice(0, 16);
}
//# sourceMappingURL=db.js.map