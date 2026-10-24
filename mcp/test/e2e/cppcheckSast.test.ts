/**
 * scan_sast against the REAL cppcheck, over `fixtures/cppcheck/project`
 * (`runners/cppcheckRun.ts`):
 *
 *   - `src/vuln.c`: seven defects (null and out-of-memory dereferences, an
 *     out-of-bounds write, an overrun, a leak, `gets`, an uninitialised read);
 *   - `src/syntax.c`, `src/macro.cpp` and `src/novalid.c` (its own `#error`)
 *     are analysed only in part or not at all — each named;
 *   - `src/configs.c` (21 `#ifdef` configurations) and `src/missinc.c` (a
 *     project header that is not there) are checked, and noted;
 *   - `include/orphan.h` is a header nothing includes: never handed over;
 *   - review_pr hands cppcheck the changed translation units only.
 *
 * Gated on cppcheck being on PATH (2.13 or newer); `GUARDIAN_REQUIRE_CPPCHECK=1`
 * turns the skip into a failure.
 */

import { cpSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execa } from 'execa';
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

const FIXTURE = resolve(dirname(fileURLToPath(import.meta.url)), '../fixtures/cppcheck/project');
const CPPCHECK = await isInstalled('cppcheck');
if (!CPPCHECK && process.env['GUARDIAN_REQUIRE_CPPCHECK'] === '1') {
  throw new Error('GUARDIAN_REQUIRE_CPPCHECK=1 but cppcheck is not on PATH');
}

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/scanSast.js');
  await import('../../src/tools/reviewPr.js');
  resetScannerCache();
});

interface ScanOut {
  scan_id: string;
  tools_run: ToolRun[];
  missing_tools: string[];
}

function project(extra: Record<string, string> = {}): string {
  const dir = resolveProjectPath(makeTempDir('cppcheck-e2e-')).path;
  cpSync(FIXTURE, dir, { recursive: true });
  for (const [rel, body] of Object.entries(extra)) writeFileSync(join(dir, rel), body);
  return dir;
}

async function scan(dir: string, input: Record<string, unknown> = {}): Promise<{ out: ScanOut; findings: Finding[] }> {
  const db = new Database(':memory:');
  runMigrations(db);
  const p: PluginContext = { storage: new Storage(db), shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
  const tool = TOOLS.find((t) => t.name === 'scan_sast');
  if (!tool) throw new Error('scan_sast not registered');
  const r = await tool.handler({ project_path: dir, force: true, local_only: true, ...input }, p);
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  const out = r as unknown as ScanOut;
  return { out, findings: p.storage.findings.listByScan(out.scan_id).filter((f) => f.tool === 'cppcheck') };
}

const at = (findings: Finding[]): string[] =>
  findings.map((f) => `${f.rule_id ?? ''} ${f.file_path ?? ''}:${String(f.line_start)}`).sort();

const VULN = [
  'arrayIndexOutOfBounds src/vuln.c:13',
  'bufferAccessOutOfBounds src/vuln.c:23',
  'getsCalled src/vuln.c:27',
  'memleak src/vuln.c:19',
  'nullPointer src/vuln.c:8',
  'nullPointerOutOfMemory src/vuln.c:18',
  'uninitvar src/vuln.c:32',
];

describe('scan_sast: cppcheck over the C/C++ translation units (real cppcheck, gated)', () => {
  it.skipIf(!CPPCHECK)('whole project: the defects found; each file not analysed or cut short named; the limits noted', async () => {
    const { out, findings } = await scan(project());
    const run = out.tools_run.find((t) => t.name === 'cppcheck');
    expect(run?.status).toBe('ok');
    expect(run?.reason).toMatch(/^7 translation unit\(s\) checked \(error and warning checks\)/);
    expect(run?.reason).toMatch(/1 file\(s\) checked less deeply [^;]*src\/configs\.c/);
    expect(run?.reason).toMatch(/1 file\(s\) include a project header cppcheck did not find/);
    expect(run?.partially_parsed?.map((x) => [x.file, x.type]).sort()).toEqual([
      ['src/macro.cpp', 'Unknown macro'],
      ['src/novalid.c', 'Not analysed'],
      ['src/syntax.c', 'Syntax error'],
    ]);
    expect(out.missing_tools).toContain('cppcheck');
    expect(at(findings.filter((f) => f.file_path === 'src/vuln.c'))).toEqual(VULN);
    expect(findings.find((f) => f.rule_id === 'nullPointer' && f.file_path === 'src/vuln.c')).toMatchObject({ severity: 'high', cwe: ['CWE-476'] });
    // Only defects: never a coverage result as a finding.
    expect(findings.some((f) => /^(syntaxError|unknownMacro|missingInclude|toomanyconfigs|preprocessorErrorDirective)$/.test(f.rule_id ?? ''))).toBe(false);
  });

  it.skipIf(!CPPCHECK)('a scope hands cppcheck its translation units only, never a header', async () => {
    const { out, findings } = await scan(project(), { scope: { paths: ['src/vuln.c', 'include/orphan.h'] } });
    const run = out.tools_run.find((t) => t.name === 'cppcheck');
    expect(run?.status).toBe('ok');
    expect(run?.reason).toBe('1 translation unit(s) checked (error and warning checks)');
    expect(run?.partially_parsed).toBeUndefined();
    expect(at(findings)).toEqual(VULN);
  });

  it.skipIf(!CPPCHECK)('.guardianignore keeps a file from cppcheck', async () => {
    const dir = project({ '.guardianignore': 'src/syntax.c\nsrc/macro.cpp\nsrc/novalid.c\n' });
    const { out } = await scan(dir);
    const run = out.tools_run.find((t) => t.name === 'cppcheck');
    expect(run?.status).toBe('ok');
    expect(run?.reason).toMatch(/^4 translation unit\(s\) checked/);
    expect(run?.partially_parsed).toBeUndefined();
    expect(out.missing_tools).not.toContain('cppcheck');
  });

  it.skipIf(!CPPCHECK)("the project's compile_commands.json is used, and named; what it does not list is checked too; a scope runs without it", async () => {
    const entry = (file: string) => ({ directory: '.', file, command: `cc -c ${file}` });
    const dir = project();
    writeFileSync(join(dir, 'compile_commands.json'), JSON.stringify([entry('src/vuln.c'), entry('src/clean.cpp'), entry('src/gone.c')]));
    const { out, findings } = await scan(dir);
    const run = out.tools_run.find((t) => t.name === 'cppcheck');
    expect(run?.status).toBe('ok');
    expect(run?.reason).toMatch(/^the translation units of compile_commands\.json, and 5 it does not list, checked/);
    expect(run?.honoured_config).toEqual(['compile_commands.json']);
    // The database's entry not on disk, and the files it does not list, judged as without it.
    expect(run?.partially_parsed?.map((x) => [x.file, x.type]).sort()).toEqual([
      ['src/gone.c', 'Not analysed'],
      ['src/macro.cpp', 'Unknown macro'],
      ['src/novalid.c', 'Not analysed'],
      ['src/syntax.c', 'Syntax error'],
    ]);
    expect(at(findings.filter((f) => f.file_path === 'src/vuln.c'))).toEqual(VULN);
    expect(findings.some((f) => f.file_path === 'src/configs.c')).toBe(true);

    writeFileSync(join(dir, 'compile_commands.json'), JSON.stringify([entry('src/vuln.c'), entry('src/clean.cpp')]));
    writeFileSync(join(dir, '.guardianignore'), 'src/syntax.c\nsrc/macro.cpp\nsrc/novalid.c\nsrc/configs.c\nsrc/missinc.c\n');
    const all = await scan(dir);
    const listed = all.out.tools_run.find((t) => t.name === 'cppcheck');
    expect(listed?.reason).toMatch(/^the translation units of compile_commands\.json checked \(error and warning checks\); honoured/);
    expect(listed?.partially_parsed).toBeUndefined();
    expect(at(all.findings)).toEqual(VULN);

    const scoped = await scan(dir, { scope: { paths: ['src/vuln.c'] } });
    expect(scoped.out.tools_run.find((t) => t.name === 'cppcheck')?.reason).toMatch(
      /^1 translation unit\(s\) \(from the scope's files: compile_commands\.json is not used for a scope\) checked \(error and warning checks\)/,
    );
  });
});

describe('review_pr: cppcheck over the changed translation units (real cppcheck, gated)', () => {
  it.skipIf(!CPPCHECK)('the changed C file only, read from the head checked out for the review', async () => {
    const dir = project();
    const git = (...args: string[]) => execa('git', ['-c', 'user.email=t@example.com', '-c', 'user.name=t', ...args], { cwd: dir });
    await git('init', '-q', '-b', 'main');
    await git('add', '-A');
    await git('commit', '-q', '-m', 'base');
    await git('switch', '-q', '-c', 'feature');
    writeFileSync(join(dir, 'src', 'added.c'), '#include <stddef.h>\n\nint added(void) {\n    int *p = NULL;\n    return *p;\n}\n');
    await git('add', '-A');
    await git('commit', '-q', '-m', 'feature');
    await git('switch', '-q', 'main');

    const db = new Database(':memory:');
    runMigrations(db);
    const p: PluginContext = { storage: new Storage(db), shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
    const tool = TOOLS.find((t) => t.name === 'review_pr');
    if (!tool) throw new Error('review_pr not registered');
    const r = await tool.handler({ project_path: dir, base_ref: 'main', head_ref: 'feature', local_only: true, force: true }, p);
    if (!r.ok) throw new Error(JSON.stringify(r.error));
    const out = r as unknown as ScanOut;
    const run = out.tools_run.find((t) => t.name === 'cppcheck');
    expect(run?.status).toBe('ok');
    expect(run?.reason).toMatch(/^1 translation unit\(s\) checked/);
    const findings = p.storage.findings.listByScan(out.scan_id).filter((f) => f.tool === 'cppcheck');
    expect(at(findings)).toEqual(['nullPointer src/added.c:5']);
  });
});
