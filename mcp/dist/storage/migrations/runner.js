/**
 * Forward-only SQL migration runner.
 *
 * Migrations live next to this file as `NNN_name.sql`. The current schema
 * version is stored in `schema_meta.version`. On startup we apply every
 * migration whose number is greater than the recorded version, in numeric
 * order, each in its own transaction.
 *
 * Migrations are SQL only (no JS hooks): keep the surface area small and the
 * audit trail trivial — what you read in the .sql file is what runs. The one
 * data step SQL cannot express runs after them, in `runMigrations`:
 * re-keying stored plugin-pack findings to the rule's own id
 * (`../localRuleIds.ts` — it needs sha256 and the plugin's packs). It changes
 * values, never the schema, commits in batches, and records how far it got in
 * `schema_meta`, so every start carries on from there.
 *
 * ---- Numbering convention ------------------------------------------------
 *
 *   - `NNN` is three digits, zero-padded (`004_scan_owner.sql`). The number IS
 *     the schema version the file brings the database to; `name` is free text.
 *   - Take the next unused number. Numbers are unique — two files with the
 *     same number make {@link listMigrations} throw, because the runner would
 *     otherwise apply one, record that version, and silently never run the
 *     other. Branches written in parallel that both took the same number must
 *     be renumbered when they meet; that is a merge-time job, never a runtime
 *     one.
 *   - A number that has shipped is never reused, renumbered or edited: a
 *     database that already recorded it will not run the file again. Change a
 *     shipped schema with a NEW migration.
 *   - Each file is additive (new tables, new nullable/defaulted columns,
 *     backfills) so a database written by an older build keeps working, and
 *     so does an older build still sharing the file with a newer one.
 *
 * ---- Concurrency -----------------------------------------------------------
 *
 * Several processes open one database at once (the plugin's MCP server, a
 * project-level one, the CLI). Each migration therefore runs inside
 * `BEGIN IMMEDIATE` and RE-READS the version once it holds the write lock:
 * the version read before taking the lock is only a fast path, and another
 * process may have applied the same migration in the meantime. Without the
 * re-read, the loser re-ran a migration that had already been applied.
 */
import { rekeyStoredLocalRuleIds } from '../localRuleIds.js';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
/**
 * Where the `NNN_name.sql` files live at runtime. Resolved by probing, because
 * the path differs across the three ways this module runs:
 *   - tsc output / tsx tests → this module sits beside the .sql files;
 *   - esbuild bundle (dist/server.js) → `import.meta.url` collapses to `dist/`,
 *     so the assets are one level down in `dist/storage/migrations/` (where
 *     `scripts/copy-assets.mjs` mirrors them).
 */
function resolveMigrationsDir() {
    const here = dirname(fileURLToPath(import.meta.url));
    const candidates = [here, join(here, 'storage', 'migrations'), join(here, 'migrations')];
    for (const dir of candidates) {
        try {
            if (existsSync(dir) && readdirSync(dir).some((f) => MIGRATION_FILE.test(f)))
                return dir;
        }
        catch {
            /* unreadable candidate — try the next one */
        }
    }
    return here;
}
const MIGRATION_FILE = /^(\d+)_(.+)\.sql$/;
const MIGRATIONS_DIR = resolveMigrationsDir();
export function runMigrations(db) {
    const migrations = listMigrations();
    ensureSchemaMetaTable(db);
    for (const migration of migrations) {
        // Unlocked fast path: an up-to-date database — every open after the
        // first — never takes the write lock here at all.
        if (migration.version <= getCurrentVersion(db))
            continue;
        applyMigration(db, migration);
    }
    // Fails open: a database this step could not re-key keeps working exactly
    // as before (the old ids simply stay), and the next start tries again.
    try {
        rekeyStoredLocalRuleIds(db);
    }
    catch {
        /* see above */
    }
}
function ensureSchemaMetaTable(db) {
    // schema_meta is also created by 001_initial.sql, but we need it to exist
    // BEFORE we read the current version on a brand-new DB.
    db.exec(`
    CREATE TABLE IF NOT EXISTS schema_meta (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )
  `);
}
function getCurrentVersion(db) {
    const row = db
        .prepare("SELECT value FROM schema_meta WHERE key = 'version'")
        .get();
    if (!row)
        return 0;
    const n = Number.parseInt(row.value, 10);
    return Number.isFinite(n) ? n : 0;
}
function setVersion(db, version) {
    db.prepare(`INSERT INTO schema_meta(key, value) VALUES('version', ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(String(version));
}
/**
 * Every `NNN_name.sql` in `dir`, in version order. Throws on a duplicated
 * number — see the numbering convention in this module's header.
 */
export function listMigrations(dir = MIGRATIONS_DIR) {
    const migrations = [];
    for (const f of readdirSync(dir)) {
        const match = MIGRATION_FILE.exec(f);
        if (!match)
            continue;
        const versionPart = match[1];
        const namePart = match[2];
        if (versionPart === undefined || namePart === undefined)
            continue;
        migrations.push({
            version: Number.parseInt(versionPart, 10),
            name: namePart,
            filePath: join(dir, f),
        });
    }
    migrations.sort((a, b) => a.version - b.version);
    for (let i = 1; i < migrations.length; i++) {
        const prev = migrations[i - 1];
        const cur = migrations[i];
        if (prev !== undefined && cur !== undefined && prev.version === cur.version) {
            throw new Error(`Duplicate migration number ${cur.version}: '${prev.name}' and '${cur.name}' in ${dir}. ` +
                'Renumber one of them to the next unused number.');
        }
    }
    return migrations;
}
function applyMigration(db, migration) {
    const sql = readFileSync(migration.filePath, 'utf8');
    db.transaction(() => {
        // Re-read under the write lock — see "Concurrency" in the module header.
        if (migration.version <= getCurrentVersion(db))
            return;
        db.exec(sql);
        setVersion(db, migration.version);
    })();
}
//# sourceMappingURL=runner.js.map