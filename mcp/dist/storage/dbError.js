/**
 * A database file dev-guardian cannot use, said in one line that names the
 * file — never a stack trace from deep inside SQLite. `db.ts#openDatabase`
 * never lets one stop the server: it answers each with the per-user
 * fallback or an in-memory database, and a warning.
 *
 *   - `schema`: the migrations ran and an object the code needs is still
 *     missing (see `schemaCheck.ts#missingObjects`);
 *   - `corrupt`: SQLite cannot read the file (SQLITE_CORRUPT, SQLITE_NOTADB);
 *     the message is the reason alone;
 *   - `untrusted`: the file holds objects the migrations never create — see
 *     `db.ts#openDatabase`;
 *   - `data-dir`: the per-user data directory, or the registry or a fallback
 *     directory in it, cannot be created, written, or is not private to this
 *     user (`userData.ts`). The message is the reason alone.
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