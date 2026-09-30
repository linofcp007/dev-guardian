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
 * The DB lives at `<project_root>/.guardian/guardian.db`, and is used only
 * when it is THIS user's (`dbProvenance.ts`, `dbRegistry.ts`): one this
 * build creates gets a random `db_id`, registered in the per-user registry
 * before it is written; an existing one is trusted only when its id is
 * registered for the very path it is opened at. Nothing else is trusted
 * automatically — a database from before 3.1.0, a copy of a registered one,
 * another user's — until the user registers it with `dev-guardian db adopt
 * --yes` ({@link registerProjectDatabase}), after seeing what it holds. It is
 * REFUSED otherwise, and the per-user fallback used instead, with a warning
 * the caller includes in tool responses (`health_status`'s
 * `storage_warning`, every scan's `warnings`) saying why, what to do, and
 * where the history now goes. Refused, too, when:
 *   - the location is not writable (read-only mounts, missing permissions, a
 *     database left behind by a `sudo` or Docker run). Writability is PROBED
 *     — a file is created in `.guardian/` and the database takes a real
 *     write — not asked of `accessSync`, which on Windows ignores ACLs;
 *   - git tracks it (any case) or `.guardian` is a submodule, or `.guardian`
 *     or the database is a link, whoever made it;
 *   - it holds a schema object, or a table or index definition, that the
 *     migrations never create (`schemaCheck.ts#untrustedObjects`) — a
 *     trigger that deletes every finding as it is inserted was reproduced.
 * A refused project database is never written to: it is read through a
 * read-only connection to learn its id, and left exactly as it was.
 *
 * The fallback is `<user data dir>/<sha1(project_root)>/guardian.db`
 * ({@link userDataDir}: `%LOCALAPPDATA%\dev-guardian` on Windows,
 * `$XDG_DATA_HOME/dev-guardian` or `~/.local/share/dev-guardian` elsewhere,
 * `GUARDIAN_DATA_DIR` when set). It used to be `os.tmpdir()/dev-guardian/…`:
 * a predictable path in a directory every user can write, which another user
 * could create first and fill, and which nothing checked the owner of. Its
 * directories are created 0700 and, on POSIX, must belong to this user —
 * checked before anything is created inside them (`userData.ts`).
 *
 * Every connection opens with `trusted_schema = OFF` (no function the schema
 * names runs unless SQLite marks it innocuous), `cell_size_check = ON`
 * (malformed pages are caught as corruption rather than read) and no memory
 * map (a file read through `mmap` bypasses those checks). A file SQLite
 * cannot read never stops the server: one that is not the user's registered
 * database is foreign (the fallback), the user's own gives way to an
 * in-memory database for the session, with a warning naming it and saying
 * to move it aside.
 *
 * The connection opens in WAL mode with foreign keys on; the resolver uses
 * `:memory:` when the caller asks for it, which the unit tests rely on.
 */
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { presentInProject } from '../platform/projectFs.js';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { storedPathTarget } from '../platform/pathSpelling.js';
import { canonicalPath } from '../platform/projectPath.js';
import { resolveScriptsDir } from '../platform/scriptsDir.js';
import { GuardianDbError, reasonOf } from './dbError.js';
import { gitIndexAt, gitProblem, locationProblem, probeDatabase, PROJECT_KEYED_TABLES, summarizeDatabase, } from './dbProvenance.js';
import { DB_ID_KEY, findEntryForDbPath, forgetDbId, lookupDbId, newDbId, registerDbId, } from './dbRegistry.js';
import { listMigrations, runMigrations } from './migrations/runner.js';
import { assertOwnedRegularFileIfPresent, ensurePrivateSubdir, isDataDirError, userDataDir } from './userData.js';
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
export { GuardianDbError } from './dbError.js';
export { userDataDir } from './userData.js';
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
function prepareForUse(db, dbPath, afterPragmas) {
    try {
        applyPragmas(db);
        afterPragmas?.(db);
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
    // The reason alone: `openDatabase` says what to do (MOVE_ASIDE).
    return new GuardianDbError('corrupt', dbPath, `the database '${dbPath}' cannot be read (${detail})`, detail);
}
/**
 * Open (and migrate) a guardian database. Idempotent — calling twice on the
 * same path returns two independent connections to the same file.
 *
 * Never throws for a database it cannot use (round 6: an unreadable or
 * corrupt one used to stop the server): a foreign or unreadable project
 * database gives way to the per-user fallback, and the user's OWN database
 * that cannot be read — or a fallback that cannot — to an in-memory one for
 * the session, each with a warning naming the file and what to do.
 */
export function openDatabase(options) {
    if (options.inMemory)
        return openInMemory();
    const projectPath = resolve(options.projectPath);
    const preferredPath = join(projectPath, '.guardian', 'guardian.db');
    const existingOnly = options.existingOnly === true;
    let refusal;
    // How the warning ends: where the history goes meanwhile.
    let keptIn = (at) => `. Meanwhile this project's scans are kept in '${at}' (not merged back later).`;
    const keptInFallback = (at) => `; history is kept in '${at}'.`;
    if (!isDirectory(projectPath)) {
        // Caller's responsibility to have a real project dir; if it doesn't
        // exist, we can't write there.
        refusal = `Project path '${projectPath}' is not writable (it is not an existing directory)`;
    }
    else if (!existingOnly || presentInProject(projectPath, preferredPath)) {
        const verdict = judgeProjectDatabase(projectPath, preferredPath);
        if (verdict.kind === 'own-unreadable') {
            return inMemoryInstead(preferredPath, `the database '${preferredPath}' cannot be read (${verdict.detail}).${MOVE_ASIDE}`);
        }
        if (verdict.kind === 'foreign') {
            refusal = foreignReason(projectPath, preferredPath, verdict.foreign);
            if (verdict.foreign.kind === 'file-system')
                keptIn = keptInFallback;
        }
        else if (!(existingOnly && verdict.kind === 'create')) {
            try {
                return openProjectDatabase(projectPath, preferredPath, verdict);
            }
            catch (error) {
                const unfit = fileSystemProblem(error);
                if (isDataDirError(error)) {
                    // Creating needs the registry. Without it the project's database is
                    // not used — never trusted unregistered — and neither is a fallback
                    // in the same unusable directory.
                    return unpersisted(error.message);
                }
                if (error instanceof GuardianDbError && error.kind === 'untrusted') {
                    refusal =
                        `${error.message}. The file is left as it is; ` +
                            'delete it or move it aside to have dev-guardian start a new one there';
                }
                else if (error instanceof GuardianDbError) {
                    // The user's own database, unreadable or incomplete: never an exit.
                    return inMemoryInstead(preferredPath, `${error.message}${error.kind === 'corrupt' ? `.${MOVE_ASIDE}` : ''}`);
                }
                else if (unfit !== null) {
                    // Round 7: a NEW project on a mapped network drive exited with
                    // "disk I/O error" on its first start (3.0.0 did too): WAL needs
                    // shared memory a network file system does not give. Later starts
                    // find the file it left and fall back the same way (the probe).
                    refusal = `'${preferredPath}' is not used: ${unfit}`;
                    keptIn = keptInFallback;
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
    let db;
    try {
        ensurePrivateSubdir(shortHash(projectPath));
        db = openFallback(chosenPath);
    }
    catch (error) {
        if (isDataDirError(error))
            return unpersisted(error.message, refusal);
        if (error instanceof GuardianDbError) {
            return inMemoryInstead(chosenPath, (refusal !== undefined ? `${refusal}. ` : '') +
                `${error.message}. It is dev-guardian's per-user database for this project: move it aside and restart.`);
        }
        throw error;
    }
    if (refusal === undefined)
        return { db, path: chosenPath };
    return { db, path: chosenPath, warning: `${refusal}${keptIn(chosenPath)}` };
}
const MOVE_ASIDE = ' Move it aside (rename it, for example to guardian.db.corrupt) and restart: a new, empty database is created ' +
    'in its place, and the old file stays available for recovery';
/** An in-memory database for the session instead of `unusable`, with `why` and that history will not persist. */
function inMemoryInstead(unusable, why) {
    return {
        ...openInMemory(),
        unusable,
        warning: `${why}. This session runs on an in-memory database: history will not persist until then.`,
    };
}
/**
 * The session's database when the per-user data directory cannot be used
 * (`userData.ts` — `reason` is the failure, a `data-dir` error's message):
 * an in-memory one, with a warning every tool surfaces. Never an exit — a
 * container user with no home (`HOME=/`) made the server exit 1 where 3.0.0
 * had opened the project's database — and never the project's database
 * trusted unregistered, which would undo the provenance check.
 */
function unpersisted(reason, refusal) {
    return {
        ...openInMemory(),
        warning: (refusal !== undefined ? `${refusal}. ` : '') +
            "dev-guardian's per-user data directory cannot be used, so neither the project's database nor a " +
            `per-user fallback is, and history will not persist: ${reason}; set GUARDIAN_DATA_DIR to a writable ` +
            'directory. This session runs on an in-memory database.',
    };
}
/**
 * Whether `.guardian/guardian.db` is this user's — see the module comment and
 * `dbProvenance.ts`. Where it lives and whether git tracks it are asked
 * BEFORE its bytes are read (a tracked or linked file is foreign whatever it
 * holds); then its id, through a read-only connection. A file that cannot be
 * read is the user's own when a registry entry names its path — kept for
 * them, in memory meanwhile — and foreign otherwise.
 */
function judgeProjectDatabase(projectPath, dbPath) {
    const location = locationProblem(projectPath, dbPath);
    if (location !== null)
        return { kind: 'foreign', foreign: { kind: 'location', why: location } };
    if (!existsSync(dbPath))
        return { kind: 'create' };
    const index = gitIndexAt(projectPath);
    const fromGit = gitProblem(index);
    if (fromGit !== null) {
        return { kind: 'foreign', foreign: { kind: 'tracked', why: fromGit, tracked: index.tracked.length > 0 } };
    }
    let probe;
    try {
        probe = probeDatabase(dbPath);
    }
    catch (error) {
        const unfit = fileSystemProblem(error);
        if (unfit !== null)
            return { kind: 'foreign', foreign: { kind: 'file-system', why: unfit } };
        const detail = reasonOf(error);
        return findEntryForDbPath(safeCanonical(dbPath)) !== null
            ? { kind: 'own-unreadable', detail }
            : { kind: 'foreign', foreign: { kind: 'unreadable', detail } };
    }
    // Nothing in it yet: another process is creating it this very moment (or
    // the file is empty). Either way it holds nothing to trust or distrust.
    if (probe.empty)
        return { kind: 'create' };
    // A registered id is trusted only WHERE it was registered. The id travels
    // with the file — a Docker `COPY . .`, a package, an archive of the
    // project all carry `.guardian/guardian.db` — so on its own it is a bearer
    // token: a copy anywhere would read as this user's.
    const entry = probe.dbId !== null ? lookupDbId(probe.dbId) : null;
    if (entry !== null && probe.dbId !== null && entry.db_path === safeCanonical(dbPath)) {
        return { kind: 'trusted', dbId: probe.dbId };
    }
    if (entry !== null)
        return { kind: 'foreign', foreign: { kind: 'registered-elsewhere', at: entry.db_path } };
    if (probe.dbId !== null)
        return { kind: 'foreign', foreign: { kind: 'unregistered-id' } };
    return { kind: 'foreign', foreign: { kind: 'legacy' } };
}
/**
 * The warning for a foreign database: short, what it is, and what to do.
 * For a database from before 3.1.0 this is the upgrade path.
 */
function foreignReason(projectPath, dbPath, foreign) {
    const adopt = adoptCommand(projectPath);
    const yourself = 'yourself, in a terminal (an assistant must not run it for you: it decides whose data dev-guardian trusts)';
    switch (foreign.kind) {
        case 'legacy':
            return (`This project's database '${dbPath}' was created before dev-guardian 3.1.0 and is not trusted ` +
                `automatically. If it is yours, run \`${adopt} --yes\` once, ${yourself}; without --yes it shows what ` +
                'the database holds first');
        case 'unregistered-id':
            return (`'${dbPath}' carries a dev-guardian id this user never registered — another user's or another machine's ` +
                `database — and is not trusted. If it is yours, review it with \`${adopt}\` and register it with --yes, ` +
                `${yourself}; otherwise delete it`);
        case 'registered-elsewhere':
            return (`'${dbPath}' was registered at '${foreign.at}', not here: it is a copy (a moved or copied repository, or ` +
                'one shipped with its .guardian — a Docker COPY, a package, an archive) and is not trusted here. If it is ' +
                `yours, review it with \`${adopt}\` and register it here with --yes, ${yourself}`);
        case 'tracked':
            return (`'${dbPath}' is not used: ${foreign.why}. ` +
                (foreign.tracked
                    ? 'One that came with the repository is not yours: delete it, and dev-guardian starts a new one there. ' +
                        'One you committed yourself: stop tracking it (git rm --cached .guardian/guardian.db)'
                    : 'Remove the submodule, and dev-guardian starts a database of its own there'));
        case 'location':
            return `'${dbPath}' is not used: ${foreign.why}. The file is left as it is`;
        case 'unreadable':
            return (`'${dbPath}' cannot be read (${foreign.detail}) and is not a database this user registered: it is left as ` +
                'it is. Delete it or move it aside, and dev-guardian starts a new one there');
        case 'file-system':
            return `'${dbPath}' is not used: ${foreign.why}`;
    }
}
/** The CLI command that inspects, and with `--yes` registers, `projectPath`'s database. */
export function adoptCommand(projectPath) {
    const cli = join(dirname(resolveScriptsDir()), 'cli', 'dev-guardian.mjs');
    return `node "${cli}" db adopt --project "${projectPath}"`;
}
/**
 * Everything a person needs to decide whether `.guardian/guardian.db` is
 * theirs, read without changing it. The stored paths are resolved on disk
 * (links followed) to say where each leads — the command is the user's, on
 * their own machine — except network, device and process-relative ones,
 * which are never looked at (`platform/pathSpelling.ts#isUnresolvablePath`).
 */
export function inspectProjectDatabase(projectPath) {
    const project = resolve(projectPath);
    const dbPath = join(project, '.guardian', 'guardian.db');
    const canonicalProject = safeCanonical(project);
    const report = {
        db_path: dbPath,
        canonical_project: canonicalProject,
        exists: presentInProject(project, dbPath),
        status: 'none',
        why: null,
        blockers: [],
        warnings: [],
        contents: null,
        paths: [],
        rehome: { paths: 0, rows: 0 },
    };
    if (!report.exists)
        return report;
    const verdict = judgeProjectDatabase(project, dbPath);
    report.status = verdict.kind === 'trusted' ? 'trusted' : verdict.kind === 'create' ? 'none' : 'foreign';
    if (verdict.kind === 'foreign')
        report.why = shortReason(verdict.foreign);
    if (verdict.kind === 'own-unreadable')
        report.why = `it cannot be read (${verdict.detail})`;
    const location = locationProblem(project, dbPath);
    if (location !== null)
        report.blockers.push(location);
    const fromGit = gitProblem(gitIndexAt(project));
    if (fromGit !== null)
        report.blockers.push(fromGit);
    if (location !== null)
        return report;
    try {
        const schema = schemaProblem(dbPath);
        if (schema !== null)
            report.blockers.push(schema);
        report.contents = summarizeDatabase(dbPath);
    }
    catch (error) {
        report.blockers.push(fileSystemProblem(error) ?? `it cannot be read (${reasonOf(error)})`);
        return report;
    }
    const contents = report.contents;
    if (contents.null_scoped_suppressions > 0) {
        report.warnings.push(`${contents.null_scoped_suppressions} suppression(s) have no project: they apply to EVERY project, and hide ` +
            'the findings they match everywhere');
    }
    if (contents.future_dated.scans > 0) {
        const why = `${contents.future_dated.scans} scan(s) are dated in the future (the furthest: ` +
            `${contents.future_dated.latest ?? 'unknown'}): a clock that was wrong where they ran, or rows written to ` +
            'outrank your own scans. dev-guardian will not register a database that holds any';
        report.warnings.push(why);
        report.blockers.push(why);
    }
    report.paths = contents.paths.map((p) => ({ ...p, target: storedPathTarget(p.project_path, canonicalProject) }));
    const moving = report.paths.filter((p) => p.target === 'this-project');
    report.rehome = { paths: moving.length, rows: moving.reduce((n, p) => n + p.rows, 0) };
    return report;
}
/** The one-line status of a foreign database, for `db adopt`'s report. */
function shortReason(foreign) {
    switch (foreign.kind) {
        case 'legacy':
            return 'created before dev-guardian 3.1.0 (it carries no id): not used until you register it';
        case 'unregistered-id':
            return 'it carries an id this user never registered (another user or another machine): not used';
        case 'registered-elsewhere':
            return `it was registered at '${foreign.at}', not here (a copy): not used here`;
        case 'tracked':
        case 'location':
            return `${foreign.why}: not used`;
        case 'unreadable':
            return `it cannot be read (${foreign.detail})`;
        case 'file-system':
            return `${foreign.why}: not used`;
    }
}
/** What the schema check refuses in `dbPath`, read through a read-only connection; null when nothing. */
function schemaProblem(dbPath) {
    const db = new GuardianDatabase(new (loadSqlite().DatabaseSync)(dbPath, { readOnly: true }));
    try {
        db.pragma('trusted_schema = OFF');
        const newerBuild = recordsNewerMigrations(db, latestMigration());
        const found = untrustedObjects(db, expectedSchema(), { newerBuild });
        if (found.length === 0)
            return null;
        return `its schema holds what dev-guardian's migrations never create (${found.slice(0, 5).join('; ')}${found.length > 5 ? '; …' : ''})`;
    }
    catch (error) {
        throw asCorruptionError(error, dbPath);
    }
    finally {
        closeQuietly(db);
    }
}
/**
 * `dev-guardian db adopt --yes`: registers `projectPath`'s database as this
 * user's, after the person saw {@link inspectProjectDatabase}'s report — the
 * ONLY way an existing database comes to be trusted (`dbProvenance.ts`). A
 * blocker refuses it, with no override. Migrates it (as the server would)
 * and writes a freshly registered id. With `rehome`, also moves the rows
 * filed under another path that leads to this project to its canonical path
 * ({@link rehomeProjectRows}) — on a database registered already, too.
 */
export function registerProjectDatabase(projectPath, opts = {}) {
    const report = inspectProjectDatabase(projectPath);
    if (!report.exists)
        throw new Error(`there is no database at '${report.db_path}'`);
    if (report.blockers.length > 0) {
        throw new Error(`'${report.db_path}' cannot be registered: ${report.blockers.join('; ')}`);
    }
    const dbPath = report.db_path;
    const already = report.status === 'trusted';
    if (!already)
        ensurePrivateSubdir('registry');
    const db = openWritable(dbPath);
    try {
        const dbId = already
            ? (probeDatabase(dbPath).dbId ?? '')
            : claimDbId(db, (mine) => ({
                db_id: mine,
                db_path: safeCanonical(dbPath),
                project_path: report.canonical_project,
                created_at: new Date().toISOString(),
            }));
        const result = { db_path: dbPath, db_id: dbId, already };
        if (opts.rehome === true) {
            const moving = report.paths.filter((p) => p.target === 'this-project').map((p) => p.project_path);
            result.rehomed = { paths: moving.length, ...rehomeProjectRows(db, report.canonical_project, moving) };
        }
        return result;
    }
    finally {
        closeQuietly(db);
    }
}
/**
 * Rewrites every row filed under one of `from` — paths that lead to this
 * project (`storedPathTarget` === `this-project`) — to `canonical`, in every
 * project-keyed table, in one transaction. Rows are never moved to another
 * project: `from` holds only paths that resolve to this one. A row whose key
 * already exists under `canonical` (a pin, a validation, a config hash) is
 * left where it is: the canonical one, the newer, wins.
 */
function rehomeProjectRows(db, canonical, from) {
    if (from.length === 0)
        return { moved: 0, kept: 0 };
    return db.transaction(() => {
        let moved = 0;
        let kept = 0;
        for (const table of PROJECT_KEYED_TABLES) {
            for (const path of from) {
                moved += db
                    .prepare(`UPDATE OR IGNORE "${table}" SET project_path = ? WHERE project_path = ?`)
                    .run(canonical, path).changes;
                kept +=
                    db.prepare(`SELECT COUNT(*) AS n FROM "${table}" WHERE project_path = ?`).get(path)?.n ?? 0;
            }
        }
        return { moved, kept };
    })();
}
/**
 * Opens the project's database on the verdict's terms: a new one gets its id
 * registered and written before anything else; a registered one is opened.
 */
function openProjectDatabase(projectPath, dbPath, verdict) {
    if (verdict.kind === 'trusted')
        return { db: openWritable(dbPath), path: dbPath };
    const entryFor = (id) => ({
        db_id: id,
        db_path: safeCanonical(dbPath),
        project_path: safeCanonical(projectPath),
        created_at: new Date().toISOString(),
    });
    // Creating registers an id: the registry must be usable BEFORE anything is
    // created in the project. Registered BEFORE the database is written, so a
    // process that reads the id from the file always finds it registered;
    // written before the migrations, so no other process sees tables with no id.
    ensurePrivateSubdir('registry');
    return { db: openWritable(dbPath, (raw) => claimDbId(raw, entryFor)), path: dbPath };
}
/**
 * Writes a freshly registered id into `schema_meta` and returns the id the
 * database ends up with. Under the write lock: an id another process wrote
 * first, registered for THIS database, wins (it registered it before
 * writing) and ours is forgotten — so of several processes creating or
 * adopting one database at once, exactly one registry entry is left; any
 * other id (none, a legacy database's unregistered one, one registered for
 * another location) is replaced by ours.
 */
function claimDbId(db, entryFor) {
    const mine = newDbId();
    const entry = entryFor(mine);
    registerDbId(entry);
    let kept = mine;
    try {
        kept = db.transaction(() => {
            db.exec('CREATE TABLE IF NOT EXISTS schema_meta (\n  key   TEXT PRIMARY KEY,\n  value TEXT NOT NULL\n)');
            const current = db
                .prepare('SELECT value FROM schema_meta WHERE key = ?')
                .get(DB_ID_KEY)?.value;
            if (typeof current === 'string' && current !== mine && lookupDbId(current)?.db_path === entry.db_path) {
                return current;
            }
            db.prepare('INSERT INTO schema_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(DB_ID_KEY, mine);
            return mine;
        })();
    }
    catch (error) {
        forgetDbId(mine);
        throw error;
    }
    if (kept !== mine)
        forgetDbId(mine);
    return kept;
}
function safeCanonical(path) {
    try {
        return canonicalPath(path);
    }
    catch {
        return resolve(path);
    }
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
 * for the failures that mean "use the fallback". `afterPragmas` runs on the
 * connection before the schema is judged and migrated.
 */
function openWritable(dbPath, afterPragmas) {
    const dir = dirname(dbPath);
    ensureDir(dir);
    probeDirectoryWritable(dir);
    const db = new GuardianDatabase(dbPath);
    try {
        prepareForUse(db, dbPath, afterPragmas);
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
 * Why SQLite cannot use the project's database where it lies — null when
 * `error` is not that. SQLITE_IOERR (any extended code: the shared-memory
 * ones a network file system gives WAL among them) and SQLITE_CANTOPEN from
 * SQLite itself, after the directory took a probe file: on a mapped network
 * drive (SMB) a new project's first start failed with "disk I/O error" and
 * the server exited. Said so the user knows why, and where history goes.
 */
function fileSystemProblem(error) {
    const code = sqliteErrorCode(error);
    if (code !== 10 && code !== 14)
        return null;
    return (`the project's .guardian is on a file system SQLite's WAL can't use (network drive?) — SQLite said ` +
        `"${reasonOf(error)}"${code === 14 ? ', which a directory that is not writable also causes' : ''}`);
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