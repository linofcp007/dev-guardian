/**
 * scan_sast and scan_wordpress against the REAL Psalm (`runners/psalmRun.ts`):
 *
 *   - `fixtures/psalm/project`: shell, SQL (PDO), include and XSS sinks —
 *     one reached across files, one in a `.phtml`, one in an `.inc` — and a
 *     `psalm.xml` of the project's own that would switch TaintedShell off,
 *     never read. `vendor/` and `node_modules/` (gitignored in this
 *     repository) are written by the test: committed there, they are still
 *     left out, and `vendor/autoload.php` — which leaves a marker if it ever
 *     runs — never runs;
 *   - `fixtures/psalm/wp-plugin`: a plugin whose `$wpdb` queries are sinks
 *     only with dev-guardian's WordPress stub, its escapes safe.
 *
 * Gated on php (8.2 or newer) and Psalm (`psalm.phar` or `psalm` on PATH);
 * `GUARDIAN_REQUIRE_PSALM=1` turns the skip into a failure.
 */

import { cpSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execa } from 'execa';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { ensureUserBinOnPath } from '../../src/platform/userBin.js';
import { findPsalm } from '../../src/runners/psalmRun.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { resetScannerCache } from '../../src/tools/scanHelpers.js';
import type { Finding, ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

vi.setConfig({ testTimeout: 600_000 });

const FIXTURES = resolve(dirname(fileURLToPath(import.meta.url)), '../fixtures/psalm');
ensureUserBinOnPath();
const PSALM = findPsalm() !== null && (await isInstalled('php'));
if (!PSALM && process.env['GUARDIAN_REQUIRE_PSALM'] === '1') {
  throw new Error('GUARDIAN_REQUIRE_PSALM=1 but php or Psalm (psalm.phar) is not on PATH');
}

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/scanSast.js');
  await import('../../src/tools/scanWordpress.js');
  resetScannerCache();
});

interface ScanOut {
  scan_id: string;
  tools_run: ToolRun[];
  missing_tools: string[];
}

function copy(name: string, extra: Record<string, string> = {}): string {
  const dir = resolveProjectPath(makeTempDir('psalm-e2e-')).path;
  cpSync(join(FIXTURES, name), dir, { recursive: true });
  for (const [rel, body] of Object.entries(extra)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), body);
  }
  return dir;
}

async function scan(tool: string, dir: string, input: Record<string, unknown> = {}): Promise<{ out: ScanOut; findings: Finding[] }> {
  const db = new Database(':memory:');
  runMigrations(db);
  const p: PluginContext = { storage: new Storage(db), shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
  const t = TOOLS.find((x) => x.name === tool);
  if (!t) throw new Error(`${tool} not registered`);
  const r = await t.handler({ project_path: dir, force: true, ...(tool === 'scan_sast' ? { local_only: true } : {}), ...input }, p);
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  const out = r as unknown as ScanOut;
  return { out, findings: p.storage.findings.listByScan(out.scan_id).filter((f) => f.tool === 'psalm') };
}

const at = (findings: Finding[]): string[] => findings.map((f) => `${f.rule_id ?? ''} ${f.file_path ?? ''}:${String(f.line_start)}`).sort();

const PLAIN = [
  'TaintedHtml src/view.phtml:1',
  'TaintedHtml src/xss.php:2',
  'TaintedInclude src/legacy.inc:2',
  'TaintedShell src/cmd.php:3',
  'TaintedShell src/lib/helpers.php:6',
  'TaintedSql src/sqli.php:3',
  'TaintedTextWithQuotes src/view.phtml:1',
  'TaintedTextWithQuotes src/xss.php:2',
];

describe('scan_sast: Psalm taint analysis over the PHP (real Psalm, gated)', () => {
  it.skipIf(!PSALM)("whole project: every sink, across files too; the project's own psalm.xml and autoloader never used", async () => {
    const dependencies = {
      'vendor/autoload.php': "<?php\nfile_put_contents(__DIR__ . '/../autoload-ran', 'x');\n",
      'vendor/evil/v.php': "<?php\nsystem($_GET['vendor']);\n",
      'node_modules/x/n.php': "<?php\nsystem($_GET['nm']);\n",
    };
    const dir = copy('project', dependencies);
    const git = (...args: string[]) => execa('git', ['-c', 'user.email=t@example.com', '-c', 'user.name=t', ...args], { cwd: dir });
    await git('init', '-q');
    await git('add', '-A');
    await git('add', '-f', 'vendor', 'node_modules');
    await git('commit', '-q', '-m', 'fixture');

    const { out, findings } = await scan('scan_sast', dir);
    const run = out.tools_run.find((t) => t.name === 'psalm');
    expect(run?.status).toBe('ok');
    expect(run?.reason).toMatch(/^7 PHP file\(s\) analysed for taint; vendor\/ not analysed: a call into it ends a flow; PHP \d+\.\d+/);
    expect(run?.version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(out.missing_tools).not.toContain('psalm');
    expect(at(findings)).toEqual(PLAIN);
    expect(findings.find((f) => f.rule_id === 'TaintedSql')).toMatchObject({ severity: 'high', cwe: ['CWE-89'], category: 'security' });
    // The cross-file flow, source first.
    expect(findings.find((f) => f.file_path === 'src/lib/helpers.php')?.message).toMatch(/^Detected tainted shell code: \$_GET → .*src\/interproc\.php:\d+.*→ call to shell_exec/);
    expect(existsSync(join(dir, 'autoload-ran'))).toBe(false);
  });

  it.skipIf(!PSALM)("a scope: the whole project's PHP is read, and only the scope's findings are kept", async () => {
    const { out, findings } = await scan('scan_sast', copy('project'), { scope: { paths: ['src/lib/helpers.php'] } });
    const run = out.tools_run.find((t) => t.name === 'psalm');
    expect(run?.reason).toMatch(
      /^7 PHP file\(s\) analysed for taint — the whole project's, for a scope of 1 file\(s\), since a flow crosses files; only the scope's findings are kept;/,
    );
    expect(at(findings)).toEqual(['TaintedShell src/lib/helpers.php:6']);
  });

  it.skipIf(!PSALM)('.guardianignore keeps a file from Psalm', async () => {
    const { out, findings } = await scan('scan_sast', copy('project', { '.guardianignore': 'src/cmd.php\nsrc/legacy.inc\n' }));
    expect(out.tools_run.find((t) => t.name === 'psalm')?.reason).toMatch(/^5 PHP file\(s\) analysed/);
    expect(findings.some((f) => f.file_path === 'src/cmd.php' || f.file_path === 'src/legacy.inc')).toBe(false);
  });
});

const WORDPRESS = [
  'TaintedHtml dg-test.php:15',
  'TaintedHtml dg-test.php:18',
  'TaintedSSRF dg-test.php:26',
  'TaintedShell dg-test.php:27',
  'TaintedSql dg-test.php:12',
  'TaintedSql dg-test.php:9',
  'TaintedTextWithQuotes dg-test.php:15',
  'TaintedTextWithQuotes dg-test.php:18',
  'TaintedUnserialize dg-test.php:25',
];

describe("WordPress: $wpdb's queries are sinks and its escapes safe (real Psalm, gated)", () => {
  it.skipIf(!PSALM)('scan_sast on a plugin models the WordPress APIs', async () => {
    const { out, findings } = await scan('scan_sast', copy('wp-plugin'));
    expect(out.tools_run.find((t) => t.name === 'psalm')?.reason).toMatch(/WordPress's APIs modelled/);
    expect(at(findings)).toEqual(WORDPRESS);
  });

  it.skipIf(!PSALM)('scan_wordpress runs the same pass', async () => {
    const { out, findings } = await scan('scan_wordpress', copy('wp-plugin'));
    expect(out.tools_run.find((t) => t.name === 'psalm')?.status).toBe('ok');
    expect(at(findings)).toEqual(WORDPRESS);
  });
});
