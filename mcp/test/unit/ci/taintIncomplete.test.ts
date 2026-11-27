/**
 * `ci/taintIncomplete.ts` (3.18.0, DG-2): the files whose taint analysis the
 * baseline's run gave up on, recorded with their content as git stores it,
 * and read at the gate only while that content is unchanged — against real
 * git repositories, with steps built the way the scan builds them
 * (`checkSemgrepReport` over a report carrying `time.fixpoint_timeouts`).
 */
import { spawnSync } from 'node:child_process';
import { appendFileSync, mkdirSync, rmSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { recordTaintIncomplete, taintIncompleteOf, unchangedTaintIncomplete } from '../../../src/ci/taintIncomplete.js';
import type { ScanStepResult, TaintIncompleteRecord } from '../../../src/ci/types.js';
import { git as realGit, type GitRunner } from '../../../src/runners/git.js';
import { pluginPackRuleIds } from '../../../src/runners/semgrepConfigs.js';
import { checkSemgrepReport, withPluginPackFixpoint } from '../../../src/runners/semgrepReport.js';
import type { Finding, ToolRun } from '../../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

function repo(dir = makeTempDir('taint-incomplete-'), autocrlf = 'false'): { dir: string; git: (...args: string[]) => string } {
  const git = (...args: string[]): string => {
    const r = spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', ...args], { cwd: dir, encoding: 'utf8' });
    if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
    return r.stdout.trim();
  };
  git('init', '-q');
  git('config', 'core.autocrlf', autocrlf);
  return { dir, git };
}

/** Every git call the code under test makes, through the real git. */
function counting(): { run: GitRunner; calls: string[][] } {
  const calls: string[][] = [];
  return { calls, run: async (cwd, args) => { calls.push([...args]); return realGit(cwd, args); } };
}

// The 1.182.0 shape of a `time.fixpoint_timeouts` entry (measured on dev-spec-driven's engine, Windows):
// `location.path` with backslashes, the function's name span on one line.
const fixpoint = (path: string, line: number, rule = 'javascript.lang.security.audit.path-traversal.path-join-resolve-traversal') => ({
  error_type: 'Fixpoint timeout',
  severity: 'warn',
  message: `Fixpoint timeout while performing taint analysis at ${path}:${line}:9 [rules: 1, first: ${rule}]`,
  location: { path, start: { line, col: 9, offset: 100 }, end: { line, col: 20, offset: 111 } },
});

/** The pack rule as Semgrep spells it in a run (the config-path prefix), and as it is stored. */
const PACK_RAW = 'guardian-packs.web-js-path-traversal';

/** A Semgrep ToolRun as scan_sast builds it from a report: partially_parsed, the pack's own timeouts appended. */
function semgrepRun(entries: unknown[], scanned: string[]): ToolRun {
  const check = checkSemgrepReport({
    raw: JSON.stringify({ results: [], errors: [], paths: { scanned }, time: { fixpoint_timeouts: entries } }),
    exitCode: 0,
    outcome: 'completed',
    targets: 1,
    pluginPackCheckIds: new Set([PACK_RAW]),
    nonPackTaintRules: true,
  });
  const run: ToolRun = { name: 'semgrep', status: 'ok', ...(check.reason !== undefined ? { reason: check.reason } : {}) };
  if (check.partial !== undefined) run.partially_parsed = check.partial;
  return withPluginPackFixpoint(run, check.plugin_pack_fixpoint);
}

function step(tools_run: ToolRun[], ran = true): ScanStepResult {
  return { tool: 'security_scan_full', ran, tools_run, missing_tools: [] };
}

function finding(over: Partial<Finding> = {}): Finding {
  return { fingerprint: 'fp', tool: 'semgrep', category: 'security', severity: 'high', title: 't', file_path: 'src/heavy.js', ...over } as Finding;
}

const BODY = "function heavy(req) {\n  return require('path').join('/srv', req.query.name);\n}\n";

describe('taintIncompleteOf: the files a Semgrep run of the scan gave up the taint analysis of', () => {
  it('from the report: posix paths, sorted, pack-only only when every timeout there was the pack rule’s; a failed run and a step that did not run ignored', () => {
    const steps = [
      step([
        semgrepRun(
          [
            fixpoint('mcp\\lib\\engine\\breakpoints.js', 323),
            fixpoint('mcp\\lib\\engine\\breakpoints.js', 401),
            fixpoint('src\\chat.ts', 12, PACK_RAW),
            fixpoint('src\\both.js', 3, PACK_RAW),
          ],
          ['mcp/lib/engine/breakpoints.js', 'src/chat.ts', 'src/both.js'],
        ),
        { name: 'bandit', status: 'ok' },
      ]),
      step([semgrepRun([fixpoint('src\\both.js', 9)], ['src/both.js'])]),
      step([{ ...semgrepRun([fixpoint('src\\failed.js', 1)], ['src/failed.js']), status: 'failed' }]),
      step([semgrepRun([fixpoint('src\\skipped.js', 1)], ['src/skipped.js'])], false),
    ];
    // The real shape: the scan's timeouts under one type, the pack's under its own.
    expect(steps[0]?.tools_run[0]?.partially_parsed?.map((p) => [p.file, p.type])).toEqual([
      ['mcp/lib/engine/breakpoints.js', 'Fixpoint timeout'],
      ['src/chat.ts', 'Fixpoint timeout (plugin pack)'],
      ['src/both.js', 'Fixpoint timeout (plugin pack)'],
    ]);
    expect(taintIncompleteOf(steps)).toEqual([
      { file: 'mcp/lib/engine/breakpoints.js', packOnly: false },
      { file: 'src/both.js', packOnly: false },
      { file: 'src/chat.ts', packOnly: true },
    ]);
  });

  it('a file outside the project, or not one project file, is never recorded; another type of gap is not a taint timeout', () => {
    const run: ToolRun = {
      name: 'semgrep',
      status: 'ok',
      partially_parsed: [
        { file: '/opt/elsewhere/x.js', type: 'Fixpoint timeout', message: 'm' },
        { file: '../up.js', type: 'Fixpoint timeout', message: 'm' },
        { file: './src/dot.js', type: 'Fixpoint timeout', message: 'm' },
        { file: 'src/parse.js', type: 'Syntax error', message: 'm' },
        { file: 'src/slow.js', type: 'Timeout', message: 'm' },
      ],
    };
    expect(taintIncompleteOf([step([run])])).toEqual([{ file: 'src/dot.js', packOnly: false }]);
  });
});

describe('recordTaintIncomplete: what baseline update writes', () => {
  const steps = (...files: string[]): ScanStepResult[] => [
    step([semgrepRun(files.map((f, i) => fixpoint(f.replace(/\//g, '\\'), i + 1)), files)]),
  ];

  it("each file's git blob after the scan — `git hash-object`'s — in one rev-parse and one hash-object call", async () => {
    const { dir, git } = repo();
    mkdirSync(join(dir, 'src'));
    writeFileSync(join(dir, 'src', 'heavy.js'), BODY);
    writeFileSync(join(dir, 'src', 'other.js'), BODY + '// other\n');
    git('add', '-A');
    git('commit', '-qm', 'base');
    const { run, calls } = counting();
    const r = await recordTaintIncomplete(dir, steps('src/other.js', 'src/heavy.js'), Date.now() + 60_000, { run });
    expect(r.changedDuringScan).toEqual([]);
    expect(r.records).toEqual([
      { tool: 'semgrep', file: 'src/heavy.js', blob: git('hash-object', 'src/heavy.js') },
      { tool: 'semgrep', file: 'src/other.js', blob: git('hash-object', 'src/other.js') },
    ]);
    expect(r.records[0]?.blob).toMatch(/^[0-9a-f]{40}$/);
    expect(calls.map((c) => c[0])).toEqual(['rev-parse', 'hash-object']);
  });

  it('a file written at or after the scan started is not recorded, and is named', async () => {
    const { dir, git } = repo();
    mkdirSync(join(dir, 'src'));
    writeFileSync(join(dir, 'src', 'heavy.js'), BODY);
    writeFileSync(join(dir, 'src', 'late.js'), BODY);
    git('add', '-A');
    git('commit', '-qm', 'base');
    const startedAt = Date.now();
    const at = (ms: number): Date => new Date(ms);
    utimesSync(join(dir, 'src', 'heavy.js'), at(startedAt - 60_000), at(startedAt - 60_000));
    utimesSync(join(dir, 'src', 'late.js'), at(startedAt + 5_000), at(startedAt + 5_000));
    const r = await recordTaintIncomplete(dir, steps('src/heavy.js', 'src/late.js'), startedAt);
    expect(r.records.map((x) => x.file)).toEqual(['src/heavy.js']);
    expect(r.changedDuringScan).toEqual(['src/late.js']);
  });

  it('outside a git work tree, nothing is recorded — git is asked once, and hashes nothing', async () => {
    const dir = makeTempDir('taint-incomplete-nogit-');
    mkdirSync(join(dir, 'src'));
    writeFileSync(join(dir, 'src', 'heavy.js'), BODY);
    const { run, calls } = counting();
    expect(await recordTaintIncomplete(dir, steps('src/heavy.js'), Date.now() + 60_000, { run })).toEqual({ records: [], changedDuringScan: [] });
    expect(calls.map((c) => c[0])).toEqual(['rev-parse']);
  });

  it('a file gone after the scan is not recorded; no timeout, no git call at all', async () => {
    const { dir, git } = repo();
    writeFileSync(join(dir, 'kept.js'), BODY);
    git('add', '-A');
    git('commit', '-qm', 'base');
    const r = await recordTaintIncomplete(dir, steps('kept.js', 'gone.js'), Date.now() + 60_000);
    expect(r.records.map((x) => x.file)).toEqual(['kept.js']);
    const { run, calls } = counting();
    expect(await recordTaintIncomplete(dir, [step([{ name: 'semgrep', status: 'ok' }])], Date.now(), { run })).toEqual({
      records: [],
      changedDuringScan: [],
    });
    expect(calls).toEqual([]);
  });

  it.skipIf(process.platform === 'win32')('a link is not a regular file: never hashed, never recorded', async () => {
    const { dir, git } = repo();
    writeFileSync(join(dir, 'real.js'), BODY);
    symlinkSync('real.js', join(dir, 'link.js'));
    git('add', '-A');
    git('commit', '-qm', 'base');
    const r = await recordTaintIncomplete(dir, steps('link.js', 'real.js'), Date.now() + 60_000);
    expect(r.records.map((x) => x.file)).toEqual(['real.js']);
  });

  it("a project in a repository's subdirectory: records relative to the project, its blob git's", async () => {
    const { dir, git } = repo();
    const project = join(dir, 'packages', 'api');
    mkdirSync(join(project, 'src'), { recursive: true });
    writeFileSync(join(project, 'src', 'heavy.js'), BODY);
    git('add', '-A');
    git('commit', '-qm', 'base');
    const r = await recordTaintIncomplete(project, steps('src/heavy.js'), Date.now() + 60_000);
    expect(r.records).toEqual([{ tool: 'semgrep', file: 'src/heavy.js', blob: git('hash-object', 'packages/api/src/heavy.js') }]);
  });
});

describe('unchangedTaintIncomplete: what the gate reads against the records', () => {
  async function recorded(dir: string, ...files: string[]): Promise<TaintIncompleteRecord[]> {
    const steps = [step([semgrepRun(files.map((f, i) => fixpoint(f, i + 1)), files)])];
    return (await recordTaintIncomplete(dir, steps, Date.now() + 60_000)).records;
  }

  it('no Semgrep finding in a recorded file: nothing to relax, and git is not asked', async () => {
    const { dir, git } = repo();
    writeFileSync(join(dir, 'heavy.js'), BODY);
    git('add', '-A');
    git('commit', '-qm', 'base');
    const records = await recorded(dir, 'heavy.js');
    const { run, calls } = counting();
    for (const findings of [
      [],
      [finding({ file_path: 'elsewhere.js' })],
      [finding({ tool: 'bandit', file_path: 'heavy.js' })],
    ]) {
      expect(await unchangedTaintIncomplete(dir, records, findings, { run })).toBeUndefined();
    }
    expect(calls).toEqual([]);
    expect(await unchangedTaintIncomplete(dir, [], [finding({ file_path: 'heavy.js' })], { run })).toBeUndefined();
    expect(calls).toEqual([]);
  });

  it('every record hashed at once: one rev-parse and one hash-object; an edited file is no longer unchanged', async () => {
    const { dir, git } = repo();
    for (const f of ['a.js', 'b.js', 'c.js']) writeFileSync(join(dir, f), BODY);
    git('add', '-A');
    git('commit', '-qm', 'base');
    const records = await recorded(dir, 'a.js', 'b.js', 'c.js');
    expect(records).toHaveLength(3);
    appendFileSync(join(dir, 'b.js'), "require('child_process').exec(process.argv[2]);\n");
    const { run, calls } = counting();
    const r = await unchangedTaintIncomplete(dir, records, [finding({ file_path: './a.js' })], { run });
    expect(r?.unchanged).toEqual([
      { file: 'a.js', packOnly: false },
      { file: 'c.js', packOnly: false },
    ]);
    expect(r?.packRuleIds).toBe(pluginPackRuleIds());
    expect(calls.map((c) => c[0])).toEqual(['rev-parse', 'hash-object']);
  });

  it('a pack-only record says so; a finding path spelt with backslashes or ./ is the same file', async () => {
    const { dir, git } = repo();
    mkdirSync(join(dir, 'src'));
    writeFileSync(join(dir, 'src', 'chat.ts'), BODY);
    git('add', '-A');
    git('commit', '-qm', 'base');
    const steps = [step([semgrepRun([fixpoint('src\\chat.ts', 2, PACK_RAW)], ['src/chat.ts'])])];
    const records = (await recordTaintIncomplete(dir, steps, Date.now() + 60_000)).records;
    expect(records).toEqual([{ tool: 'semgrep', file: 'src/chat.ts', blob: git('hash-object', 'src/chat.ts'), pack_only: true }]);
    for (const path of ['src\\chat.ts', './src/chat.ts']) {
      expect((await unchangedTaintIncomplete(dir, records, [finding({ file_path: path })]))?.unchanged).toEqual([{ file: 'src/chat.ts', packOnly: true }]);
    }
  });

  // The case the record exists for after `--jobs 1`: a baseline recorded on Windows (core.autocrlf=true, CRLF bytes
  // on disk) gated on a Linux checkout of the same commit (LF bytes). Raw bytes would never match there.
  it('a record made on a CRLF checkout (core.autocrlf=true) matches the LF checkout of the same commit', async () => {
    const lf = "function heavy(req) {\n  return 1;\n}\n";
    const windows = repo(makeTempDir('taint-incomplete-crlf-'), 'true');
    writeFileSync(join(windows.dir, 'heavy.js'), lf);
    windows.git('add', '-A');
    windows.git('commit', '-qm', 'base');
    writeFileSync(join(windows.dir, 'heavy.js'), lf.replace(/\n/g, '\r\n'));
    const records = await recorded(windows.dir, 'heavy.js');
    expect(records).toHaveLength(1);

    const linux = makeTempDir('taint-incomplete-lf-');
    const clone = spawnSync('git', ['-c', 'core.autocrlf=false', 'clone', '-q', windows.dir, linux], { encoding: 'utf8' });
    expect(clone.status, clone.stderr).toBe(0);
    spawnSync('git', ['config', 'core.autocrlf', 'false'], { cwd: linux });
    const r = await unchangedTaintIncomplete(linux, records, [finding({ file_path: 'heavy.js' })]);
    expect(r?.unchanged).toEqual([{ file: 'heavy.js', packOnly: false }]);
  });

  it('an index flag hides nothing: a recorded file marked assume-unchanged with an injection appended is changed', async () => {
    const { dir, git } = repo();
    writeFileSync(join(dir, 'heavy.js'), BODY);
    git('add', '-A');
    git('commit', '-qm', 'base');
    const records = await recorded(dir, 'heavy.js');
    git('update-index', '--assume-unchanged', 'heavy.js');
    appendFileSync(join(dir, 'heavy.js'), "require('child_process').exec('cat ' + process.argv[2]);\n");
    expect(git('diff', '--name-only')).toBe('');
    expect(await unchangedTaintIncomplete(dir, records, [finding({ file_path: 'heavy.js' })])).toBeUndefined();
  });

  it('records of a checkout, the gate in a tree that is no git work tree (an export of the same files): nothing relaxed', async () => {
    const { dir, git } = repo();
    writeFileSync(join(dir, 'heavy.js'), BODY);
    git('add', '-A');
    git('commit', '-qm', 'base');
    const records = await recorded(dir, 'heavy.js');
    const exported = makeTempDir('taint-incomplete-export-');
    writeFileSync(join(exported, 'heavy.js'), BODY);
    // git itself would hash the exported file to the recorded blob.
    expect(spawnSync('git', ['hash-object', 'heavy.js'], { cwd: exported, encoding: 'utf8' }).stdout.trim()).toBe(records[0]?.blob);
    expect(await unchangedTaintIncomplete(exported, records, [finding({ file_path: 'heavy.js' })])).toBeUndefined();
  });

  it('git that cannot hash: nothing relaxed — "could not compare" is never "unchanged"', async () => {
    const { dir, git } = repo();
    writeFileSync(join(dir, 'heavy.js'), BODY);
    git('add', '-A');
    git('commit', '-qm', 'base');
    const records = await recorded(dir, 'heavy.js');
    const failing: GitRunner = async (cwd, args) =>
      args[0] === 'hash-object' ? { exitCode: 128, stdout: '', stderr: 'fatal: cannot hash' } : realGit(cwd, args);
    expect(await unchangedTaintIncomplete(dir, records, [finding({ file_path: 'heavy.js' })], { run: failing })).toBeUndefined();
    rmSync(join(dir, 'heavy.js'));
    expect(await unchangedTaintIncomplete(dir, records, [finding({ file_path: 'heavy.js' })])).toBeUndefined();
  });
});
