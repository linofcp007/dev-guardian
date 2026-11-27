/**
 * 3.18.0 (DG-2): `baseline update` records the files whose taint analysis
 * Semgrep gave up on, with their content as git stores it, and `scan` does
 * not count a Semgrep finding the baseline lacks in such a file as new while
 * the file is unchanged — through the real CLI, real git and the real Semgrep
 * (`--local-only`), on a fixture whose one function Semgrep's taint analysis
 * always gives up on (`--jobs 1` included: a loop over a chain of 1,500
 * assignments written backwards, so the fixpoint takes one round per link).
 *
 * The finding the baseline lacks is the honest late finding: a rule added to
 * the project's `.semgrep.yml` after the baseline (no `--rules-ref`), which
 * matches old code. In the recorded file left as it was it reads not new; in
 * the recorded file the change edited it is new — the blob is what decides.
 */

import { execa } from 'execa';
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { spawnSyncCapped, timeoutAbove } from '../helpers/spawnCap.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

const here = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(here, '..', '..', '..', 'cli', 'dev-guardian.mjs');
/** A hang-breaker for one CLI run of the pipeline; nothing asserts by reaching it. */
const RUN_TIMEOUT_MS = 600_000;
vi.setConfig({ testTimeout: timeoutAbove(RUN_TIMEOUT_MS), hookTimeout: timeoutAbove(2 * RUN_TIMEOUT_MS) });
afterAll(cleanupTempDirs);

const SEMGREP_INSTALLED = await isInstalled('semgrep');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

/** The taint rule the baseline is recorded with: request data reaching `exec`. */
const TAINT_RULE = `  - id: fixture-exec-taint
    mode: taint
    languages: [javascript]
    severity: ERROR
    message: request data reaches exec
    pattern-sources:
      - pattern: $REQ.query.$X
    pattern-sinks:
      - pattern: exec(...)
`;
/** The rule added after the baseline: every exec call, old ones included. */
const LATE_RULE = `  - id: fixture-exec-any
    languages: [javascript]
    severity: ERROR
    message: exec call
    pattern: exec(...)
`;

/** `heavy` (taint analysis gives up on it) and `plain` (it does not), each with one exec. */
function heavySource(links: number): string {
  const lines = ["const { exec } = require('child_process');", 'function heavy(req, n) {', '  let a0 = req.query.cmd;'];
  for (let i = 1; i <= links; i++) lines.push(`  let a${i} = '';`);
  lines.push('  while (n-- > 0) {');
  for (let i = links; i >= 1; i--) lines.push(`    a${i} = a${i - 1} + '';`);
  lines.push('  }', `  exec(a${links});`, '}', 'function plain(req) {', '  exec(req.query.other);', '}', 'module.exports = { heavy, plain };');
  return `${lines.join('\n')}\n`;
}

interface Verdict {
  new_findings: Array<{ file_path?: string; rule_id?: string }>;
  taint_incomplete_at_baseline: Array<{ file_path?: string; rule_id?: string }>;
  taint_incomplete_at_baseline_count: number;
  coverage_notes: string[];
}

function cli(args: string[]): { status: number | null; stdout: string; stderr: string } {
  return spawnSyncCapped(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: RUN_TIMEOUT_MS, env: process.env });
}

describe('taint-incomplete files: recorded by baseline update, read by scan (real Semgrep)', () => {
  it.runIf(REQUIRE_SEMGREP)('GUARDIAN_REQUIRE_SEMGREP=1 — this suite must be runnable', () => {
    expect(SEMGREP_INSTALLED, 'GUARDIAN_REQUIRE_SEMGREP=1 but semgrep is not on PATH').toBe(true);
  });

  let dir = '';
  let update = { status: null as number | null, stdout: '', stderr: '' };
  let verdict: Verdict | null = null;
  let blobs: Record<string, string> = {};

  beforeAll(async () => {
    if (!SEMGREP_INSTALLED) return;
    dir = makeTempDir('ci-taint-incomplete-');
    const git = async (...args: string[]): Promise<string> =>
      (await execa('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'core.autocrlf=false', ...args], { cwd: dir })).stdout.trim();
    await git('init', '-q');
    await git('config', 'core.autocrlf', 'false');
    writeFileSync(join(dir, 'heavy.js'), heavySource(1500));
    writeFileSync(join(dir, 'heavy2.js'), heavySource(1501));
    writeFileSync(join(dir, '.semgrep.yml'), `rules:\n${TAINT_RULE}`);
    await git('add', '-A');
    await git('commit', '-qm', 'base');
    update = cli(['baseline', 'update', '--project', dir, '--local-only']);
    blobs = { 'heavy.js': await git('hash-object', 'heavy.js'), 'heavy2.js': await git('hash-object', 'heavy2.js') };
    // The change: a rule the project adds (read from the tree, no --rules-ref), and an edit to one recorded file.
    writeFileSync(join(dir, '.semgrep.yml'), `rules:\n${TAINT_RULE}${LATE_RULE}`);
    appendFileSync(join(dir, 'heavy2.js'), '// edited by the change\n');
    const scan = cli(['scan', '--project', dir, '--local-only', '--format', 'json']);
    verdict = JSON.parse(scan.stdout) as Verdict;
  });

  it.skipIf(!SEMGREP_INSTALLED)('baseline update records both heavy files, each with its git blob, and says what that does', () => {
    expect(update.status, update.stderr).not.toBe(3);
    const baseline = JSON.parse(readFileSync(join(dir, '.guardian', 'baseline.json'), 'utf8')) as {
      version: number;
      taint_incomplete?: Array<{ tool: string; file: string; blob: string; pack_only?: true }>;
    };
    expect(baseline.version).toBe(1);
    expect(baseline.taint_incomplete).toEqual([
      { tool: 'semgrep', file: 'heavy.js', blob: blobs['heavy.js'] },
      { tool: 'semgrep', file: 'heavy2.js', blob: blobs['heavy2.js'] },
    ]);
    expect(update.stdout).toMatch(
      /^taint analysis gave up in 2 file\(s\), now recorded in \.guardian\/baseline\.json \(taint_incomplete\): while such a file is unchanged, a later scan does not count its Semgrep findings as new\.$/m,
    );
  });

  it.skipIf(!SEMGREP_INSTALLED)('scan: the late rule’s findings in the unchanged file are not new; in the edited one they are', () => {
    expect(verdict).not.toBeNull();
    const v = verdict as Verdict;
    const late = (list: Verdict['new_findings']) =>
      list.filter((f) => (f.rule_id ?? '').endsWith('fixture-exec-any')).map((f) => f.file_path).sort();
    expect(late(v.taint_incomplete_at_baseline)).toEqual(['heavy.js', 'heavy.js']);
    expect(v.taint_incomplete_at_baseline_count).toBe(v.taint_incomplete_at_baseline.length);
    expect(late(v.new_findings)).toEqual(['heavy2.js', 'heavy2.js']);
    expect(v.new_findings.filter((f) => f.file_path === 'heavy.js')).toEqual([]);
    expect(v.coverage_notes.filter((n) => /^semgrep: \d+ finding\(s\) in 1 file\(s\) not counted as new — .*: heavy\.js$/.test(n))).toHaveLength(1);
  });
});
