/**
 * scan_sast and review_pr against the REAL gosec and Go toolchain, over
 * `fixtures/gosec/project` (`runners/gosecRun.ts`):
 *
 *   - `vendored/` is reported from — gosec's own `./...` skips any directory
 *     whose name starts with `vendor`, so its package directories are handed
 *     to it one by one;
 *   - `broken/` does not type-check and `syntaxerr/` does not parse: gosec is
 *     `ok` with both named (`partially_parsed`) and listed missing;
 *   - `ignored/` is left out by `//go:build ignore`: listed, not analysed, and
 *     the reason counts it; `testdata/`, `_private/` and `main_test.go` are
 *     never handed to gosec at all;
 *   - the `#nosec G401` in main.go is honoured;
 *   - a scope hands gosec the scope's packages, a `.guardianignore` keeps a
 *     directory out, and review_pr keeps the findings to the changed files.
 *
 * Gated on gosec and go being on PATH (a skip reports as a skip);
 * `GUARDIAN_REQUIRE_GOSEC=1` turns the skip into a failure.
 */

import { execa } from 'execa';
import { cpSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { resetScannerCache } from '../../src/tools/scanHelpers.js';
import type { Finding, ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

vi.setConfig({ testTimeout: 300_000 });

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(here, '../fixtures/gosec/project');

const TOOLCHAIN = (await isInstalled('gosec')) && (await isInstalled('go'));
if (!TOOLCHAIN && process.env['GUARDIAN_REQUIRE_GOSEC'] === '1') {
  throw new Error('GUARDIAN_REQUIRE_GOSEC=1 but gosec or go is not on PATH');
}

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/scanSast.js');
  await import('../../src/tools/reviewPr.js');
  resetScannerCache();
});

interface ScanOut {
  scan_id: string;
  coverage: string;
  tools_run: ToolRun[];
  missing_tools: string[];
}

function project(extra: Record<string, string> = {}): string {
  const dir = resolveProjectPath(makeTempDir('gosec-e2e-')).path;
  cpSync(FIXTURE, dir, { recursive: true });
  for (const [rel, body] of Object.entries(extra)) writeFileSync(join(dir, rel), body);
  return dir;
}

function context(dir: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
}

async function call(name: string, input: Record<string, unknown>, p: PluginContext): Promise<ScanOut> {
  const tool = TOOLS.find((t) => t.name === name);
  if (!tool) throw new Error(`${name} not registered`);
  const r = await tool.handler(input, p);
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return r as unknown as ScanOut;
}

const gosecFindings = (p: PluginContext, scanId: string): Finding[] =>
  p.storage.findings.listByScan(scanId).filter((f) => f.tool === 'gosec');

describe('scan_sast: gosec over the Go packages (real gosec, gated)', () => {
  it.skipIf(!TOOLCHAIN)('whole project: vendored/ reported, the type and syntax errors named, the build-constrained file counted', async () => {
    const dir = project();
    const p = context(dir);
    const out = await call('scan_sast', { project_path: dir, force: true, local_only: true }, p);

    const gosec = out.tools_run.find((t) => t.name === 'gosec');
    expect(gosec?.status).toBe('ok');
    expect(gosec?.reason).toMatch(/^6 package directories, 6 Go file\(s\): 5 analysed; 1 left out by the platform's build constraints/);
    expect(gosec?.partially_parsed).toEqual([
      { file: 'broken/b.go', type: 'Type error', message: 'undefined: undefinedThing' },
      { file: 'syntaxerr/s.go', type: 'Syntax error', message: "expected ')', found '{'" },
    ]);
    expect(out.missing_tools).toContain('gosec');

    const findings = gosecFindings(p, out.scan_id);
    const rules = new Set(findings.map((f) => `${f.rule_id} ${f.file_path ?? ''}`));
    expect([...rules]).toEqual(expect.arrayContaining(['G701 main.go', 'G702 main.go', 'G101 creds/creds.go', 'G306 vendored/v.go']));
    // Honoured #nosec; never-listed directories and test files report nothing.
    expect(findings.some((f) => f.rule_id === 'G401')).toBe(false);
    expect(findings.filter((f) => /^(testdata|_private|ignored)\/|_test\.go$/.test(f.file_path ?? ''))).toEqual([]);
    // G101's snippet never holds the value.
    expect(findings.find((f) => f.rule_id === 'G101')?.snippet ?? '').not.toContain('fixture-not-a-real-password');
  });

  it.skipIf(!TOOLCHAIN)('a scope hands gosec its packages, and the findings stay inside it', async () => {
    const dir = project();
    const p = context(dir);
    const out = await call('scan_sast', { project_path: dir, force: true, local_only: true, scope: { paths: ['creds/creds.go'] } }, p);
    const gosec = out.tools_run.find((t) => t.name === 'gosec');
    expect(gosec?.status).toBe('ok');
    expect(gosec?.reason).toMatch(/^1 package directory, 1 Go file\(s\): 1 analysed$/);
    expect(gosecFindings(p, out.scan_id).map((f) => `${f.rule_id} ${f.file_path ?? ''}`)).toEqual(['G101 creds/creds.go']);
  });

  it.skipIf(!TOOLCHAIN)('.guardianignore keeps a directory from gosec', async () => {
    const dir = project({ '.guardianignore': 'vendored/\nbroken/\nsyntaxerr/\n' });
    const p = context(dir);
    const out = await call('scan_sast', { project_path: dir, force: true, local_only: true }, p);
    const gosec = out.tools_run.find((t) => t.name === 'gosec');
    expect(gosec?.status).toBe('ok');
    expect(gosec?.partially_parsed).toBeUndefined();
    expect(gosec?.reason).toMatch(/^3 package directories, 3 Go file\(s\): 2 analysed/);
    expect(out.missing_tools).not.toContain('gosec');
    expect(gosecFindings(p, out.scan_id).some((f) => (f.file_path ?? '').startsWith('vendored/'))).toBe(false);
  });
});

describe('review_pr: gosec over the changed packages (real gosec, gated)', () => {
  it.skipIf(!TOOLCHAIN)('the changed file’s findings only, though gosec read its whole package', async () => {
    const dir = project();
    const git = (...args: string[]) => execa('git', args, { cwd: dir });
    await git('init', '-q', '-b', 'main');
    await git('-c', 'user.email=t@example.com', '-c', 'user.name=t', 'add', '-A');
    await git('-c', 'user.email=t@example.com', '-c', 'user.name=t', 'commit', '-q', '-m', 'base');
    await git('switch', '-q', '-c', 'feature');
    writeFileSync(
      join(dir, 'creds', 'more.go'),
      'package creds\n\nimport "os"\n\nfunc Dump() error { return os.WriteFile("/tmp/dump", []byte(dbPassword), 0o666) }\n',
    );
    await git('-c', 'user.email=t@example.com', '-c', 'user.name=t', 'add', '-A');
    await git('-c', 'user.email=t@example.com', '-c', 'user.name=t', 'commit', '-q', '-m', 'feature');

    const p = context(dir);
    const out = await call('review_pr', { project_path: dir, base_ref: 'main', head_ref: 'feature', local_only: true, force: true }, p);
    expect(out.tools_run.find((t) => t.name === 'gosec')?.status).toBe('ok');
    const files = new Set(gosecFindings(p, out.scan_id).map((f) => f.file_path));
    // creds.go's G101 is in the package gosec read, but not in the change.
    expect(files).toEqual(new Set(['creds/more.go']));
  });
});
