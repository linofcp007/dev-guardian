/**
 * `runners/semgrepRun.ts`: a run whose report is Semgrep's own placeholder
 * — `<ERROR: missing output>`, which pysemgrep 1.182.0 writes when the
 * semgrep-core child that formats the report does not answer
 * (`semgrep/rpc_call.py#format`) — is run once more. Seen under the full
 * suite's load as "unparseable output: Unexpected token '<', \"<ERROR: mi\"…",
 * a different scan each time. The runs here are injected, so no Semgrep runs.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import type { ProcessRunOptions, ProcessRunResult } from '../../../src/runners/processRunner.js';
import { runSemgrep } from '../../../src/runners/semgrepRun.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const REPORT = '{"results": [], "errors": [], "paths": {"scanned": ["a.py"]}}';
const done = (stdout = ''): ProcessRunResult => ({ outcome: 'completed', exitCode: 0, stdout, stderr: '', truncated: false });

/** A run that writes each of `reports` in turn to the `--output` file (or stdout without one), counting the runs. */
function writing(reports: string[]): { run: (o: ProcessRunOptions) => Promise<ProcessRunResult>; runs: () => number } {
  let n = 0;
  return {
    runs: () => n,
    run: async (o) => {
      const text = reports[Math.min(n, reports.length - 1)] ?? '';
      n += 1;
      const args = o.args ?? [];
      const at = args.indexOf('--output');
      const out = at >= 0 ? args[at + 1] : undefined;
      if (out === undefined) return done(text);
      writeFileSync(out, text);
      return done();
    },
  };
}

describe("a report Semgrep's formatter lost is run once more", () => {
  it('the --output file holds the placeholder: the second run is the result', async () => {
    const dir = makeTempDir('lost-report-');
    const out = join(dir, 'semgrep.json');
    const f = writing(['<ERROR: missing output>', REPORT]);
    const r = await runSemgrep({ args: ['--config=r.yml', '--json', '--output', out, dir], cwd: dir }, f.run, 'linux');
    expect(f.runs()).toBe(2);
    expect(r.reportLostOnce).toBe(true);
    expect(readFileSync(out, 'utf8')).toBe(REPORT);
  });

  it('on stdout, with no --output: the same', async () => {
    const dir = makeTempDir('lost-report-');
    const f = writing(['<ERROR: missing output>\n', REPORT]);
    const r = await runSemgrep({ args: ['--config=r.yml', '--json', dir], cwd: dir }, f.run, 'linux');
    expect(f.runs()).toBe(2);
    expect(r.stdout).toBe(REPORT);
  });

  it("SARIF's placeholder too", async () => {
    const dir = makeTempDir('lost-report-');
    const f = writing(['<ERROR: no SARIF output>', '{"version": "2.1.0", "runs": []}']);
    await runSemgrep({ args: ['--sarif', dir], cwd: dir }, f.run, 'linux');
    expect(f.runs()).toBe(2);
  });

  it('once only: a second lost report stands, for the caller to judge as before', async () => {
    const dir = makeTempDir('lost-report-');
    const out = join(dir, 'semgrep.json');
    const f = writing(['<ERROR: missing output>']);
    const r = await runSemgrep({ args: ['--json', '--output', out, dir], cwd: dir }, f.run, 'linux');
    expect(f.runs()).toBe(2);
    expect(readFileSync(out, 'utf8')).toBe('<ERROR: missing output>');
    expect(r.reportLostOnce).toBe(true);
  });

  it('a report, or any other unreadable output, is never run again', async () => {
    const dir = makeTempDir('lost-report-');
    for (const text of [REPORT, '', 'not json', 'Traceback (most recent call last):\n<ERROR: missing output>']) {
      const f = writing([text]);
      const r = await runSemgrep({ args: ['--json', '--output', join(dir, 'r.json'), dir], cwd: dir }, f.run, 'linux');
      expect(f.runs(), JSON.stringify(text)).toBe(1);
      expect(r.reportLostOnce).toBeUndefined();
    }
  });

  it('a cancelled run is not run again', async () => {
    const dir = makeTempDir('lost-report-');
    let n = 0;
    const run = async (o: ProcessRunOptions): Promise<ProcessRunResult> => {
      n += 1;
      const args = o.args ?? [];
      writeFileSync(args[args.indexOf('--output') + 1] ?? join(dir, 'x'), '<ERROR: missing output>');
      return { outcome: 'cancelled', exitCode: null, stdout: '', stderr: '', truncated: false };
    };
    await runSemgrep({ args: ['--json', '--output', join(dir, 'r.json'), dir], cwd: dir }, run, 'linux');
    expect(n).toBe(1);
  });
});
