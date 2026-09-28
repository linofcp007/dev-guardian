/**
 * `dotnet_efcore_audit` — `efcore-raw-sql-creds` matches raw SQL that embeds
 * a password/secret/api key/token in a migration, and the whole matched line
 * used to be stored verbatim as the finding's snippet (Task 12). These tests
 * pin that: (1) the rule is classified as a credential finding
 * (`isCredentialFinding`), and (2) its snippet is redacted before persistence
 * and before the tool's own response.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import type { PluginContext } from '../../../src/context.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { Storage } from '../../../src/storage/index.js';
import { TOOLS } from '../../../src/tools/index.js';
import { makeTempDir, cleanupTempDirs } from '../../helpers/tempDir.js';

beforeAll(async () => {
  await import('../../../src/tools/dotnetEfcoreAudit.js');
});

afterAll(cleanupTempDirs);

function getTool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

function makePlugin(projectPath: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  const storage = new Storage(db);
  return {
    storage,
    shell: { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' },
    scriptsDir: projectPath,
    progressNotifier: { send: () => {} },
  };
}

describe('dotnet_efcore_audit', () => {
  it('redacts the raw-SQL-with-credentials snippet in both the response and the stored finding', async () => {
    const project = makeTempDir('efcore-audit-');
    const migrationsDir = join(project, 'Migrations');
    mkdirSync(migrationsDir, { recursive: true });
    writeFileSync(
      join(migrationsDir, '20240101000000_Seed.cs'),
      [
        'public partial class Seed : Migration',
        '{',
        '    protected override void Up(MigrationBuilder migrationBuilder)',
        '    {',
        '        migrationBuilder.Sql("UPDATE Users SET password = \'Sup3rS3cret!\' WHERE Id = 1");',
        '    }',
        '}',
        '',
      ].join('\n'),
      'utf8',
    );

    const plugin = makePlugin(project);
    const tool = getTool('dotnet_efcore_audit');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      scan_id: string;
      findings: Array<{ rule_id?: string; subcategory?: string; snippet?: string }>;
    };
    expect(r.ok).toBe(true);
    const credFinding = r.findings.find((f) => f.rule_id === 'efcore-raw-sql-creds');
    expect(credFinding).toBeDefined();
    expect(credFinding?.snippet).toBeDefined();
    expect(credFinding?.snippet).not.toContain('Sup3rS3cret!');

    const stored = plugin.storage.findings.listByScan(r.scan_id);
    const storedCred = stored.find((f) => f.rule_id === 'efcore-raw-sql-creds');
    expect(storedCred).toBeDefined();
    expect(storedCred?.snippet).not.toContain('Sup3rS3cret!');
  });
});
