/**
 * A database file dev-guardian cannot use, said in one line that names the
 * file and what to do about it — what the server prints (and exits 1 with)
 * instead of a stack trace from deep inside `new Storage()` or SQLite.
 *
 *   - `schema`: the migrations ran and an object the code needs is still
 *     missing (see `schemaCheck.ts#missingObjects`);
 *   - `corrupt`: SQLite cannot read the file (SQLITE_CORRUPT, SQLITE_NOTADB);
 *   - `untrusted`: the file holds objects the migrations never create, or its
 *     location is not private to this user — see `db.ts#openDatabase`.
 */
export class GuardianDbError extends Error {
  constructor(
    readonly kind: 'schema' | 'corrupt' | 'untrusted',
    readonly dbPath: string,
    message: string,
  ) {
    super(message);
    this.name = 'GuardianDbError';
  }
}
