/**
 * A database file dev-guardian cannot use, said in one line that names the
 * file — never a stack trace from deep inside SQLite. `db.ts#openDatabase`
 * never lets one stop the server: it answers each with the per-user
 * fallback or an in-memory database, and a warning.
 *
 *   - `schema`: the migrations ran and an object the code needs is still
 *     missing (see `schemaCheck.ts#missingObjects`);
 *   - `corrupt`: SQLite cannot read the file (SQLITE_CORRUPT, SQLITE_NOTADB);
 *     the message names the file, and {@link GuardianDbError.reason} holds
 *     SQLite's own words, for a caller that names the file itself (a message
 *     built from the message read "cannot be read (the database '…' cannot
 *     be read (…))");
 *   - `untrusted`: the file holds objects the migrations never create — see
 *     `db.ts#openDatabase`;
 *   - `data-dir`: the per-user data directory, or the registry or a fallback
 *     directory in it, cannot be created, written, or is not private to this
 *     user (`userData.ts`). The message is the reason alone.
 */
export class GuardianDbError extends Error {
    kind;
    dbPath;
    reason;
    constructor(kind, dbPath, message, 
    /** The underlying reason alone (SQLite's words), when the message wraps one. */
    reason) {
        super(message);
        this.kind = kind;
        this.dbPath = dbPath;
        this.reason = reason;
        this.name = 'GuardianDbError';
    }
}
/** Why `error` happened, in its own words: a {@link GuardianDbError}'s reason, else its message. */
export function reasonOf(error) {
    if (error instanceof GuardianDbError)
        return error.reason ?? error.message;
    return error instanceof Error ? error.message : String(error);
}
//# sourceMappingURL=dbError.js.map