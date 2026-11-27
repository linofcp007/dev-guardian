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

/**
 * 3.18.0 review 1 (DGBASE-1), the reviewer's repro: a change puts new code between a recorded file's `$Id:` and the
 * next `$`, then adds `<file> ident` to `.gitattributes` — git's clean step collapses `$Id:<anything>$` to `$Id$`, so
 * `git hash-object` printed the recorded blob and the edit's finding read "not new" (exit 0). A file git stores as
 * other than its bytes is never unchanged: the finding is new, both in a CI clone gated with `--baseline-ref main`
 * and in the working tree with no ref (dev-spec-driven's finish gate); heavy2.js, the same edit without the
 * attribute, is the control.
 */
describe('taint-incomplete files: an edit git’s `ident` hides is new (real Semgrep)', () => {
  const EVAL_RULE = `  - id: fixture-eval-any
    languages: [javascript]
    severity: ERROR
    message: eval call
    pattern: eval(...)
`;
  const ATTACK = "/* $Id: */ eval(require('fs').readFileSync(0, 'utf8')); /* $ */";
  let work = '';
  let recorded: string[] = [];
  let hashes: Record<string, string> = {};
  const scans: Record<'local' | 'ci', { status: number | null; verdict: Verdict | null }> = {
    local: { status: null, verdict: null },
    ci: { status: null, verdict: null },
  };

  beforeAll(async () => {
    if (!SEMGREP_INSTALLED) return;
    work = makeTempDir('ci-taint-ident-');
    const origin = join(work, 'origin');
    const ci = join(work, 'ci');
    const gitIn = async (cwd: string, ...args: string[]): Promise<string> =>
      (await execa('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'core.autocrlf=false', ...args], { cwd })).stdout.trim();
    await execa('git', ['init', '-q', '-b', 'main', origin]);
    await gitIn(origin, 'config', 'core.autocrlf', 'false');
    for (const [file, links] of [['heavy.js', 1500], ['heavy2.js', 1501]] as const) writeFileSync(join(origin, file), `/* $Id$ */\n${heavySource(links)}`);
    writeFileSync(join(origin, '.semgrep.yml'), `rules:\n${TAINT_RULE}${EVAL_RULE}`);
    await gitIn(origin, 'add', '-A');
    await gitIn(origin, 'commit', '-qm', 'base');
    cli(['baseline', 'update', '--project', origin, '--local-only']);
    const baseline = JSON.parse(readFileSync(join(origin, '.guardian', 'baseline.json'), 'utf8')) as { taint_incomplete?: Array<{ file: string }> };
    recorded = (baseline.taint_incomplete ?? []).map((r) => r.file);
    await gitIn(origin, 'add', '-f', '.guardian/baseline.json');
    await gitIn(origin, 'commit', '-qm', 'baseline');
    // The change, two commits: the edit (git stores the bytes as written), then the attribute for heavy.js only.
    await gitIn(origin, 'checkout', '-q', '-b', 'pr');
    for (const file of ['heavy.js', 'heavy2.js']) writeFileSync(join(origin, file), readFileSync(join(origin, file), 'utf8').replace('/* $Id$ */', ATTACK));
    await gitIn(origin, 'add', 'heavy.js', 'heavy2.js');
    await gitIn(origin, 'commit', '-qm', 'pr: the change');
    writeFileSync(join(origin, '.gitattributes'), 'heavy.js ident\n');
    await gitIn(origin, 'add', '.gitattributes');
    await gitIn(origin, 'commit', '-qm', 'pr: attributes');
    hashes = { 'heavy.js': await gitIn(origin, 'hash-object', 'heavy.js'), recorded: await gitIn(origin, 'rev-parse', 'main:heavy.js') };

    const local = cli(['scan', '--project', origin, '--local-only', '--format', 'json']);
    scans.local = { status: local.status, verdict: JSON.parse(local.stdout) as Verdict };
    await execa('git', ['clone', '-q', '--no-local', origin, ci]);
    await gitIn(ci, 'checkout', '-q', 'pr');
    await gitIn(ci, 'branch', '-q', 'main', 'origin/main');
    const inCi = cli(['scan', '--project', ci, '--local-only', '--baseline-ref', 'main', '--format', 'json']);
    scans.ci = { status: inCi.status, verdict: JSON.parse(inCi.stdout) as Verdict };
  });

  it.skipIf(!SEMGREP_INSTALLED)('the premise: both files recorded, and git hashes the edited heavy.js to its recorded blob', () => {
    expect(recorded).toEqual(['heavy.js', 'heavy2.js']);
    expect(hashes['heavy.js']).toBe(hashes['recorded']);
  });

  for (const where of ['local', 'ci'] as const) {
    it.skipIf(!SEMGREP_INSTALLED)(`${where === 'ci' ? 'a CI clone, --baseline-ref main' : 'the working tree, no ref'}: the edit's finding is new in both files, and blocks`, () => {
      const { status, verdict } = scans[where];
      expect(verdict).not.toBeNull();
      const v = verdict as Verdict;
      const evals = (list: Verdict['new_findings']) =>
        list.filter((f) => (f.rule_id ?? '').endsWith('fixture-eval-any')).map((f) => f.file_path).sort();
      expect(evals(v.new_findings)).toEqual(['heavy.js', 'heavy2.js']);
      expect(evals(v.taint_incomplete_at_baseline)).toEqual([]);
      expect(status).toBe(1);
    });
  }
});
