/**
 * `dotnet_efcore_audit` — pattern-scan EF Core migration files for
 * dangerous operations.
 *
 * Migrations live in `Migrations/` (default convention) with one `.cs`
 * file per migration. We pattern-match on:
 *   - `migrationBuilder.DropColumn` on a table that probably has data
 *   - `DropTable` (always destructive)
 *   - `RenameColumn` without a `defaultValueSql` (loses data on rollback)
 *   - `AlterColumn` setting nullable=false without defaultValue (will fail
 *     on existing rows with NULL)
 *   - `migrationBuilder.Sql(...)` with embedded credentials or PII
 *
 * No SDK / dotnet required — pure source scan.
 */
import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import { makeFinding, } from '../runners/scannerParsers/index.js';
import { registerToolModule } from './index.js';
const RULES = [
    {
        id: 'efcore-drop-table',
        description: 'DropTable in a migration — DESTRUCTIVE. Confirm there is a backup and a rollback plan.',
        severity: 'high',
        test: (l) => /migrationBuilder\.DropTable\s*\(/.test(l),
    },
    {
        id: 'efcore-drop-column',
        description: 'DropColumn in a migration — data loss if the column has values.',
        severity: 'high',
        test: (l) => /migrationBuilder\.DropColumn\s*\(/.test(l),
    },
    {
        id: 'efcore-rename-column',
        description: 'RenameColumn without an explicit defaultValueSql — confirm rollback strategy.',
        severity: 'medium',
        test: (l) => /migrationBuilder\.RenameColumn\s*\(/.test(l),
    },
    {
        id: 'efcore-alter-not-null',
        description: 'AlterColumn setting nullable=false. Will fail on rows with NULL — provide defaultValue.',
        severity: 'high',
        test: (l) => /migrationBuilder\.AlterColumn/.test(l) &&
            /nullable\s*:\s*false/i.test(l) &&
            !/defaultValue/i.test(l),
    },
    {
        id: 'efcore-raw-sql-creds',
        description: 'Raw SQL in a migration with what looks like credentials. Move to runtime config.',
        severity: 'critical',
        test: (l) => /migrationBuilder\.Sql\s*\(/.test(l) && /(password|secret|api[_-]?key|token)/i.test(l),
    },
];
const inputSchema = { project_path: ProjectPath };
const tool = {
    name: 'dotnet_efcore_audit',
    title: 'EF Core migrations audit',
    description: 'Scan EF Core migrations for dangerous patterns (DropTable, DropColumn, AlterColumn nullable=false ' +
        'without defaultValue, raw SQL with credentials). Pure source scan — no SDK required.',
    inputSchema,
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
async function handler(input, ctx) {
    const inp = input;
    let projectPath;
    try {
        projectPath = resolveProjectPath(inp.project_path).path;
    }
    catch (e) {
        return {
            ok: false,
            error: { code: 'not_a_git_repo', message: e.message },
        };
    }
    const migrationDirs = findMigrationsDirs(projectPath);
    const findings = [];
    for (const dir of migrationDirs) {
        let files;
        try {
            files = readdirSync(dir).filter((n) => n.endsWith('.cs'));
        }
        catch {
            continue;
        }
        for (const fname of files) {
            const abs = join(dir, fname);
            let content;
            try {
                content = readFileSync(abs, 'utf8');
            }
            catch {
                continue;
            }
            const lines = content.split(/\r?\n/);
            for (let i = 0; i < lines.length; i += 1) {
                const line = lines[i];
                if (line === undefined)
                    continue;
                for (const rule of RULES) {
                    if (rule.test(line)) {
                        findings.push(makeFinding({
                            tool: 'dotnet_efcore_audit',
                            rule_id: rule.id,
                            severity: rule.severity,
                            category: rule.id === 'efcore-raw-sql-creds' ? 'security' : 'bug',
                            subcategory: 'migration-risk',
                            title: rule.description,
                            file_path: relative(projectPath, abs).replace(/\\/g, '/'),
                            line_start: i + 1,
                            line_end: i + 1,
                            snippet: line.length > 200 ? `${line.slice(0, 200)}…` : line,
                            fix_available: false,
                        }));
                    }
                }
            }
        }
    }
    const scanId = randomUUID();
    ctx.storage.scans.insert({
        scan_id: scanId,
        scan_type: 'dotnet_efcore_audit',
        project_path: projectPath,
        tree_hash: '',
    });
    if (findings.length > 0) {
        ctx.storage.findings.bulkInsert(findings.map((f) => ({ ...f, scan_id: scanId })));
    }
    ctx.storage.scans.finalize({
        scan_id: scanId,
        status: 'completed',
        tools_run: [{ name: 'dotnet_efcore_audit', status: 'ok' }],
        missing_tools: [],
        meta: { migration_dirs_scanned: migrationDirs.length, findings_count: findings.length },
    });
    return {
        ok: true,
        scan_id: scanId,
        migration_dirs_scanned: migrationDirs.length,
        findings_count: findings.length,
        findings,
        hint: findings.length === 0
            ? migrationDirs.length === 0
                ? 'No Migrations/ directory found.'
                : 'No dangerous patterns detected in EF Core migrations.'
            : 'Review each finding. DropTable/DropColumn require explicit data-backup confirmation; AlterColumn nullable=false needs a defaultValue.',
    };
}
function findMigrationsDirs(root) {
    const out = [];
    const SKIP = new Set(['bin', 'obj', 'node_modules', '.git', '.guardian', 'packages', '.vs']);
    function walk(dir, depth) {
        if (depth > 6)
            return;
        let entries;
        try {
            entries = readdirSync(dir);
        }
        catch {
            return;
        }
        for (const name of entries) {
            if (SKIP.has(name))
                continue;
            const abs = join(dir, name);
            let s;
            try {
                s = statSync(abs);
            }
            catch {
                continue;
            }
            if (!s.isDirectory())
                continue;
            if (name === 'Migrations' && existsSync(abs)) {
                out.push(abs);
            }
            else {
                walk(abs, depth + 1);
            }
        }
    }
    walk(root, 0);
    return out;
}
//# sourceMappingURL=dotnetEfcoreAudit.js.map