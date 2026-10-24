/**
 * scan_sast over a project holding a file at a path of 260 characters or more
 * — against the REAL Semgrep, on Windows (review 8, finding 2).
 *
 * Measured with Windows' default `LongPathsEnabled=0`: a JavaScript file at a
 * 301-character path holding `exec('ls ' + req.query.dir)` and `eval(...)` was
 * missing from Semgrep's `paths.scanned`, with no error; the CI gate read
 * coverage full and exited 0. The invariant held here: the file is either
 * scanned (its finding is there) or named as a gap — `partially_parsed`, type
 * `Path too long`, the run partial — never neither.
 *
 * Gated on Windows and Semgrep being on PATH.
 */

import { mkdirSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { WINDOWS_MAX_PATH } from '../../src/frameworks/projectLanguages.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { PATH_TOO_LONG_TYPE } from '../../src/runners/semgrepCoverageGaps.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { resetScannerCache } from '../../src/tools/scanHelpers.js';
import type { Finding, ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

vi.setConfig({ testTimeout: 300_000 });

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/scanSast.js');
  resetScannerCache();
});

const READY = process.platform === 'win32' && (await isInstalled('semgrep'));
const BANDIT_READY = READY && (await isInstalled('bandit'));

const RULES =
  'rules:\n  - id: js-eval\n    languages: [javascript]\n    severity: ERROR\n    message: eval of data\n' +
  '    pattern: eval($X)\n';

describe('scan_sast: a file at a path too long for Windows is scanned or named, never silently skipped', () => {
  it.skipIf(!READY)('the long-path file is either found in or named as a Path too long gap', async () => {
    const dir = resolveProjectPath(makeTempDir('sast-longpath-')).path;
    writeFileSync(join(dir, '.semgrep.yml'), RULES);
    writeFileSync(join(dir, 'short.js'), 'eval(process.argv[2]);\n');
    // Directories of 40 characters until the file's absolute path passes 300.
    const segments: string[] = [];
    while (join(dir, ...segments, 'deep.js').length < 300) segments.push('d'.repeat(40));
    mkdirSync(join(dir, ...segments), { recursive: true });
    const longFile = join(dir, ...segments, 'deep.js');
    expect(longFile.length).toBeGreaterThanOrEqual(WINDOWS_MAX_PATH);
    writeFileSync(longFile, 'eval(process.argv[3]);\n');
    const longRel = [...segments, 'deep.js'].join('/');

    const tool = TOOLS.find((t) => t.name === 'scan_sast');
    if (!tool) throw new Error('scan_sast not registered');
    const db = new Database(':memory:');
    runMigrations(db);
    const storage = new Storage(db);
    const p: PluginContext = { storage, shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
    const r = await tool.handler({ project_path: dir, force: true, local_only: true }, p);
    if (!r.ok) throw new Error(JSON.stringify(r.error));
    const out = r as unknown as { scan_id: string; coverage: string; tools_run: ToolRun[]; missing_tools: string[] };
    const semgrep = out.tools_run.find((t) => t.name === 'semgrep');
    expect(semgrep?.status).toBe('ok');

    const findings: Finding[] = storage.findings.listByScan(out.scan_id);
    const files = findings.map((f) => (f.file_path ?? '').split(String.fromCharCode(92)).join('/'));
    expect(files.some((f) => f.endsWith('short.js'))).toBe(true);
    const found = files.some((f) => f.endsWith(longRel));
    const named = (semgrep?.partially_parsed ?? []).some((pp) => pp.file === longRel && pp.type === PATH_TOO_LONG_TYPE);
    // The invariant: one or the other — and not both.
    expect(found || named).toBe(true);
    expect(found && named).toBe(false);
    if (named) {
      expect(out.coverage).toBe('partial');
      expect(out.missing_tools).toContain('semgrep');
      expect(semgrep?.reason).toMatch(/at a path of 260 characters or more, or in a directory of 248 or more, were not scanned/);
    }
  });

  // A directory at a path of 256-259 characters holding no source (WooCommerce's
  // `email-editor/.../Blocks/icons/*`, PNGs only, under a deep folder) made Semgrep 1.176.1's
  // walk fail the whole listing: nothing scanned, `failed`. The run is repeated with that
  // directory excluded (runners/semgrepLongDirs.ts): the rest is scanned, and a source file in
  // a directory of 248 or more is named.
  it.skipIf(!READY)('a directory too long for Semgrep to list never fails the scan of the rest', async () => {
    const dir = resolveProjectPath(makeTempDir('sast-longdir-')).path;
    writeFileSync(join(dir, '.semgrep.yml'), RULES);
    writeFileSync(join(dir, 'short.js'), 'eval(process.argv[2]);\n');
    const real = realpathSync.native(dir);
    let deep = join(real, 'd');
    while (deep.length < 258 - 12) deep = join(deep, 'dddddddddd');
    deep = join(deep, 'x'.repeat(258 - deep.length - 1));
    expect(deep.length).toBe(258);
    mkdirSync(deep, { recursive: true });
    writeFileSync(join(deep, 'icon.png'), 'png');
    // A source file beside it, in a directory past 248: named, whatever Semgrep did with it.
    const near = dirname(deep);
    writeFileSync(join(near, 'n.js'), 'eval(process.argv[3]);\n');
    const nearRel = relative(real, join(near, 'n.js')).split(sep).join('/');

    const tool = TOOLS.find((t) => t.name === 'scan_sast');
    if (!tool) throw new Error('scan_sast not registered');
    const db = new Database(':memory:');
    runMigrations(db);
    const storage = new Storage(db);
    const p: PluginContext = { storage, shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
    const r = await tool.handler({ project_path: dir, force: true, local_only: true }, p);
    if (!r.ok) throw new Error(JSON.stringify(r.error));
    const out = r as unknown as { scan_id: string; tools_run: ToolRun[]; missing_tools: string[] };
    const semgrep = out.tools_run.find((t) => t.name === 'semgrep');
    expect(semgrep?.status).toBe('ok');
    const files = storage.findings.listByScan(out.scan_id).map((f) => (f.file_path ?? '').split(String.fromCharCode(92)).join('/'));
    expect(files.some((f) => f.endsWith('short.js'))).toBe(true);
    const found = files.some((f) => f.endsWith(nearRel));
    const named = (semgrep?.partially_parsed ?? []).some((pp) => pp.file === nearRel && pp.type === PATH_TOO_LONG_TYPE);
    expect(found || named).toBe(true);
    expect(found && named).toBe(false);
    if (/Semgrep could not list the project on Windows/.test(semgrep?.reason ?? '')) expect(named).toBe(true);
  });

  // Bandit too: it sometimes reported such a file and sometimes dropped it
  // silently. A Python file at a long path is analysed (in its `metrics`) or
  // named — never neither.
  it.skipIf(!BANDIT_READY)('Bandit: the long-path Python file is either analysed or named as a Path too long gap', async () => {
    const dir = resolveProjectPath(makeTempDir('sast-longpath-py-')).path;
    writeFileSync(join(dir, '.semgrep.yml'), RULES);
    writeFileSync(join(dir, 'short.py'), 'import pickle\n\n\ndef f(x):\n    return pickle.loads(x)\n');
    const segments: string[] = [];
    while (join(dir, ...segments, 'deep.py').length < 300) segments.push('p'.repeat(40));
    mkdirSync(join(dir, ...segments), { recursive: true });
    writeFileSync(join(dir, ...segments, 'deep.py'), 'import pickle\n\n\ndef g(y):\n    return pickle.loads(y)\n');
    const longRel = [...segments, 'deep.py'].join('/');

    const tool = TOOLS.find((t) => t.name === 'scan_sast');
    if (!tool) throw new Error('scan_sast not registered');
    const db = new Database(':memory:');
    runMigrations(db);
    const storage = new Storage(db);
    const p: PluginContext = { storage, shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
    const r = await tool.handler({ project_path: dir, force: true, local_only: true }, p);
    if (!r.ok) throw new Error(JSON.stringify(r.error));
    const out = r as unknown as { scan_id: string; tools_run: ToolRun[]; missing_tools: string[] };
    const bandit = out.tools_run.find((t) => t.name === 'bandit');
    expect(bandit?.status).toBe('ok');
    const files = storage.findings
      .listByScan(out.scan_id)
      .filter((f) => f.tool === 'bandit')
      .map((f) => (f.file_path ?? '').split(String.fromCharCode(92)).join('/'));
    expect(files.some((f) => f.endsWith('short.py'))).toBe(true);
    const found = files.some((f) => f.endsWith(longRel));
    const named = (bandit?.partially_parsed ?? []).some((pp) => pp.file === longRel && pp.type === PATH_TOO_LONG_TYPE);
    expect(found || named).toBe(true);
    if (named) expect(out.missing_tools).toContain('bandit');
  });
});
