/**
 * A database file dev-guardian cannot use, said in one line that names the
 * file and what to do about it — what the server prints (and exits 1 with)
 * instead of a stack trace from deep inside `new Storage()` or SQLite.
 *
 *   - `schema`: the migrations ran and an object the code needs is still
 *     missing (see `schemaCheck.ts#missingObjects`);
 *   - `corrupt`: SQLite cannot read the file (SQLITE_CORRUPT, SQLITE_NOTADB);
 *   - `untrusted`: the file holds objects the migrations never create — see
 *     `db.ts#openDatabase`;
 *   - `data-dir`: the per-user data directory, or the registry or a fallback
 *     directory in it, cannot be created, written, or is not private to this
 *     user (`userData.ts`). The message is the reason alone. Never fatal:
 *     `db.ts#openDatabase` runs the session on an in-memory database and
 *     says history will not persist.
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
//# sourceMappingURL=dbError.js.map