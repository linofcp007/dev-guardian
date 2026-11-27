/**
 * review_pr's squawk pass against the REAL squawk (`runners/squawkRun.ts`, squawk-cli 2.71.0 from PyPI): what the
 * runner hands it is what squawk reads — its JSON report through the parser, the root `.squawk.toml` by name
 * (`excluded_paths` applied to a file handed on the command line, `excluded_rules` honoured), a file name holding
 * `[` handed as a literal, and a file it cannot parse named partial, never a finding.
 *
 * Gated on squawk being installed; `GUARDIAN_REQUIRE_SQUAWK=1` (`npm run test:docker -- --toolchain`) turns the skip
 * into a failure.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { squawkParser } from '../../src/runners/scannerParsers/squawk.js';
import { squawkMigrations } from '../../src/runners/squawkRun.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

vi.setConfig({ testTimeout: 120_000 });

const INSTALLED = await isInstalled('squawk');
if (!INSTALLED && process.env['GUARDIAN_REQUIRE_SQUAWK'] === '1') {
  throw new Error('GUARDIAN_REQUIRE_SQUAWK=1 but squawk is not installed');
}

afterAll(cleanupTempDirs);

function write(dir: string, path: string, content: string): void {
  const abs = join(dir, path);
  mkdirSync(join(abs, '..'), { recursive: true });
  writeFileSync(abs, content);
}

describe('squawk over the changed migrations (real squawk, gated)', () => {
  it.skipIf(!INSTALLED)('a NOT NULL column added is a low adding-required-field; the config excludes a rule and a path; [ ] names itself; a broken file is partial', async () => {
    const dir = makeTempDir('squawk-e2e-');
    write(dir, '.squawk.toml', 'excluded_rules = ["prefer-robust-stmts"]\nexcluded_paths = ["db/excluded/*.sql"]\nassume_in_transaction = true\n');
    write(dir, 'db/001_tenant.sql', '\nALTER TABLE "Booking" ADD COLUMN "tenantId" INTEGER NOT NULL;\n');
    write(dir, 'db/[region]/002.sql', 'ALTER TABLE "Region" ADD COLUMN "code" INTEGER NOT NULL;\n');
    write(dir, 'db/excluded/003.sql', 'ALTER TABLE "Excluded" ADD COLUMN "x" INTEGER NOT NULL;\n');
    write(dir, 'db/004_broken.sql', 'ALTER TABLE foo ALTER CONSTRAINT bar RENAME TO quux;\n');
    const files = ['db/001_tenant.sql', 'db/[region]/002.sql', 'db/excluded/003.sql', 'db/004_broken.sql'];
    const pass = await squawkMigrations({ scanRoot: dir, files, signal: new AbortController().signal });
    expect(pass.toolRun.status, pass.toolRun.reason).toBe('ok');
    expect(pass.toolRun.honoured_config).toEqual(['.squawk.toml']);
    expect(pass.toolRun.partially_parsed?.map((p) => p.file)).toEqual(['db/004_broken.sql']);
    expect(pass.missing).toBe(true);
    const findings = pass.reports.flatMap((r) => squawkParser.parse(r, { project_path: dir }).findings);
    const at = findings.map((f) => `${f.rule_id ?? ''} ${f.file_path ?? ''}:${String(f.line_start)}`);
    expect(at).toContain('adding-required-field db/001_tenant.sql:2');
    expect(at).toContain('adding-required-field db/[region]/002.sql:1');
    expect(findings.every((f) => f.severity === 'low' && f.subcategory === 'migration-safety')).toBe(true);
    // The config's rule exclusion and its path exclusion, on a file handed on the command line.
    expect(findings.some((f) => f.rule_id === 'prefer-robust-stmts')).toBe(false);
    expect(findings.some((f) => (f.file_path ?? '').startsWith('db/excluded/'))).toBe(false);
    expect(findings.some((f) => f.rule_id === 'syntax-error')).toBe(false);
  });

  it.skipIf(!INSTALLED)('every file the config excludes: exit 0, nothing printed — checked, no violation', async () => {
    const dir = makeTempDir('squawk-e2e-');
    write(dir, '.squawk.toml', 'excluded_paths = ["db/*.sql"]\n');
    write(dir, 'db/001.sql', 'ALTER TABLE "A" ADD COLUMN "x" INTEGER NOT NULL;\n');
    const pass = await squawkMigrations({ scanRoot: dir, files: ['db/001.sql'], signal: new AbortController().signal });
    expect(pass.toolRun.status, pass.toolRun.reason).toBe('ok');
    expect(pass.reports.flatMap((r) => squawkParser.parse(r).findings)).toEqual([]);
    expect(pass.missing).toBe(false);
  });
});
