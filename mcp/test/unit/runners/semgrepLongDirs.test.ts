/**
 * Semgrep's walk and Windows' path limits (`runners/semgrepLongDirs.ts`): a
 * run whose walk could not list the tree is repeated with the directories too
 * long for Windows excluded, and the files too long for its walk are read on
 * their own as extended-length paths (`runners/semgrepRun.ts#runSemgrep`). The real
 * Semgrep case is `e2e/sastLongPath.test.ts`; here the decisions, on any host
 * (the platform is a parameter, and Windows' path rules are `path.win32`).
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, win32 } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import type { ProcessRunOptions, ProcessRunResult } from '../../../src/runners/processRunner.js';
import {
  extendedLengthPath,
  failedToListTargets,
  longDirsUnder,
  longPathWalk,
  rewriteReportPaths,
  semgrepExcludeForDir,
  semgrepIgnores,
  WINDOWS_DIR_MAX,
  WINDOWS_MAX_PATH,
} from '../../../src/runners/semgrepLongDirs.js';
import { longDirsNote, runSemgrep } from '../../../src/runners/semgrepRun.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

/** A project holding `a/`, a chain whose last directory passes the limit, and the chain's own child. */
function project(): { root: string; long: string } {
  const root = makeTempDir('semgrep-longdirs-');
  mkdirSync(join(root, 'a'));
  writeFileSync(join(root, 'a', 'x.js'), 'x');
  let rel = 'deep';
  while (`${root}/${rel}`.length < WINDOWS_DIR_MAX + 4) rel = `${rel}/dddddddddd`;
  mkdirSync(join(root, ...rel.split('/'), 'below'), { recursive: true });
  mkdirSync(join(root, '.git', ...rel.split('/').slice(1)), { recursive: true });
  // The first directory of the chain past the limit is the one to exclude.
  const parts = rel.split('/');
  let cut = 1;
  while (`${root}/${parts.slice(0, cut).join('/')}`.length < WINDOWS_DIR_MAX) cut++;
  return { root, long: parts.slice(0, cut).join('/') };
}

describe('failedToListTargets', () => {
  it("Semgrep's own message, in its report, stdout or stderr", () => {
    expect(failedToListTargets(null, '', '[ERROR] Failed to obtain target files from semgrep-core\n')).toBe(true);
    expect(failedToListTargets('{"errors":[{"message":"SemgrepError: Failed to obtain target files from semgrep-core"}]}')).toBe(true);
    expect(failedToListTargets('{"errors":[{"message":"Invalid rule"}]}', 'x', undefined)).toBe(false);
  });
});

describe('longDirsUnder', () => {
  it('the top-most directories at the limit or past it, never below one, never .git; nothing off Windows', () => {
    const { root, long } = project();
    expect(longDirsUnder(root, 'win32')).toEqual([long]);
    expect(longDirsUnder(root, 'linux')).toEqual([]);
  });
});

describe('semgrepExcludeForDir', () => {
  it('a project-relative --exclude with no leading /, its glob characters escaped', () => {
    expect(semgrepExcludeForDir('a/b c')).toBe('--exclude=a/b c');
    expect(semgrepExcludeForDir('x/[v1]!/#y')).toBe('--exclude=x/\\[v1\\]\\!/\\#y');
  });
});

describe('runSemgrep: the Windows retry', () => {
  const failed = (stderr: string): ProcessRunResult => ({ outcome: 'failed', exitCode: 2, stdout: '', stderr, truncated: false });
  const ok: ProcessRunResult = { outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false };
  const listingFailed = failed('[ERROR] Failed to obtain target files from semgrep-core\n');

  it('a walk that could not list the tree is run once more, the long directories excluded before the target', async () => {
    const { root, long } = project();
    const run = vi.fn<(o: ProcessRunOptions) => Promise<ProcessRunResult>>().mockResolvedValueOnce(listingFailed).mockResolvedValueOnce(ok);
    const r = await runSemgrep({ args: ['--config=r.yml', '--json', root], cwd: root }, run, 'win32');
    expect(run).toHaveBeenCalledTimes(2);
    expect(run.mock.calls[1]?.[0].args).toEqual(['--config=r.yml', '--json', `--exclude=${long}`, root]);
    expect(r).toMatchObject({ exitCode: 0, excludedLongDirs: [long] });
    expect(longDirsNote(r)).toMatch(/^Semgrep could not list the project on Windows: 1 directory at a path of 248 characters or more was left out/);
  });

  it('no retry off Windows, after a run that did not fail, after another failure, or with no long directory', async () => {
    const { root } = project();
    const plain = makeTempDir('semgrep-longdirs-none-');
    const cases: Array<[ProcessRunResult, string, NodeJS.Platform]> = [
      [listingFailed, root, 'linux'],
      [ok, root, 'win32'],
      [failed('[ERROR] Invalid rule schema\n'), root, 'win32'],
      [listingFailed, plain, 'win32'],
    ];
    for (const [first, target, platform] of cases) {
      const run = vi.fn<(o: ProcessRunOptions) => Promise<ProcessRunResult>>().mockResolvedValue(first);
      const r = await runSemgrep({ args: ['--json', target], cwd: target }, run, platform);
      expect(run).toHaveBeenCalledTimes(1);
      expect(r.excludedLongDirs).toBeUndefined();
      expect(longDirsNote(r)).toBeNull();
    }
  });
});

describe('extendedLengthPath and rewriteReportPaths', () => {
  it('the extended form of a drive path and a share', () => {
    expect(extendedLengthPath('C:\\p\\a.js')).toBe('\\\\?\\C:\\p\\a.js');
    expect(extendedLengthPath('\\\\host\\share\\a.js')).toBe('\\\\?\\UNC\\host\\share\\a.js');
  });

  it("every path of a report — results, errors and their spans, scanned and skipped — rewritten; one the map does not know kept", () => {
    const raw = {
      results: [{ path: 'L1', check_id: 'r' }],
      errors: [{ path: 'L1', spans: [{ file: 'L1' }] }, { message: 'no path' }],
      paths: { scanned: ['L1', 'short.js'], skipped: [{ path: 'L1', reason: 'x' }] },
    };
    const out = rewriteReportPaths(raw, (p) => (p === 'L1' ? 'deep/a.js' : null)) as typeof raw;
    expect(out.results[0]?.path).toBe('deep/a.js');
    expect(out.errors[0]).toEqual({ path: 'deep/a.js', spans: [{ file: 'deep/a.js' }] });
    expect(out.errors[1]).toEqual({ message: 'no path' });
    expect(out.paths).toEqual({ scanned: ['deep/a.js', 'short.js'], skipped: [{ path: 'deep/a.js', reason: 'x' }] });
  });
});

/** A project with a short source, a source too long for Windows, one a .semgrepignore leaves out, and one an --exclude does. */
function longFilesProject(): { root: string; long: string; ignored: string; excluded: string } {
  const root = makeTempDir('semgrep-longfiles-');
  writeFileSync(join(root, 'short.js'), 'x');
  let rel = 'deep';
  while (`${root}/${rel}/name.js`.length < WINDOWS_MAX_PATH + 4) rel = `${rel}/dddddddddd`;
  mkdirSync(join(root, ...rel.split('/'), 'skipme'), { recursive: true });
  mkdirSync(join(root, ...rel.split('/'), 'gone'), { recursive: true });
  writeFileSync(join(root, ...rel.split('/'), 'name.js'), 'x');
  writeFileSync(join(root, ...rel.split('/'), 'skipme', 'i.js'), 'x');
  writeFileSync(join(root, ...rel.split('/'), 'gone', 'e.js'), 'x');
  writeFileSync(join(root, ...rel.split('/'), 'note.png'), 'x');
  writeFileSync(join(root, '.semgrepignore'), 'skipme/\n');
  return { root, long: `${rel}/name.js`, ignored: `${rel}/skipme/i.js`, excluded: `${rel}/gone/e.js` };
}

describe('longPathWalk and semgrepIgnores', () => {
  it('the source files too long for Windows, a .semgrepignore read where it sits; nothing off Windows', () => {
    const { root, long, ignored, excluded } = longFilesProject();
    const walk = longPathWalk(root, 'win32');
    expect(walk.files).toEqual([excluded, long, ignored].sort());
    expect(semgrepIgnores(walk, ignored)).toBe(true);
    expect(semgrepIgnores(walk, long)).toBe(false);
    expect(longPathWalk(root, 'linux')).toEqual({ dirs: [], files: [], semgrepignores: [] });
  });
});

describe('runSemgrep: the files too long for Windows, read on their own', () => {
  it('as extended-length targets — never one an --exclude or a .semgrepignore leaves out — merged back under the walk\'s paths', async () => {
    const { root, long } = longFilesProject();
    const reportDir = makeTempDir('semgrep-longfiles-report-');
    const out = join(reportDir, 'sast.json');
    const calls: string[][] = [];
    const run = vi.fn(async (o: ProcessRunOptions): Promise<ProcessRunResult> => {
      const args = o.args ?? [];
      calls.push(args);
      const at = args.indexOf('--output');
      const file = args[at + 1] ?? '';
      if (calls.length === 1) {
        writeFileSync(file, JSON.stringify({ results: [{ path: join(root, 'short.js'), check_id: 'r' }], errors: [], paths: { scanned: [join(root, 'short.js')] } }));
      } else {
        const target = args.at(-1) ?? '';
        writeFileSync(file, JSON.stringify({ results: [{ path: target, check_id: 'r' }], errors: [], paths: { scanned: [target] } }));
      }
      return { outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false };
    });
    const r = await runSemgrep({ args: ['--config=r.yml', '--exclude=gone', '--json', '--output', out, root], cwd: root }, run, 'win32');
    expect(run).toHaveBeenCalledTimes(2);
    const second = calls[1] ?? [];
    expect(second.slice(0, 3)).toEqual(['--config=r.yml', '--exclude=gone', '--json']);
    expect(second.at(-1)).toMatch(/^\\\\\?\\.*name\.js$/);
    expect(second.filter((a) => a.startsWith('\\\\?\\'))).toHaveLength(1);
    expect(r.longFilesRead).toBe(1);
    const merged = JSON.parse(readFileSync(out, 'utf8')) as { results: Array<{ path: string }>; paths: { scanned: string[] } };
    const given = win32.join(root, ...long.split('/'));
    expect(merged.results.map((x) => x.path)).toEqual([join(root, 'short.js'), given]);
    expect(merged.paths.scanned).toEqual([join(root, 'short.js'), given]);
    expect(longDirsNote(r)).toBe('1 file(s) at a path too long for Windows read on their own, as extended-length paths');
  });

  it('nothing more when the walk read them (long paths enabled), off Windows, or with no report', async () => {
    const { root, long, ignored, excluded } = longFilesProject();
    const reportDir = makeTempDir('semgrep-longfiles-report-');
    const out = join(reportDir, 'sast.json');
    const all = [long, ignored, excluded].map((rel) => win32.join(root, ...rel.split('/')));
    const run = vi.fn(async (): Promise<ProcessRunResult> => {
      writeFileSync(out, JSON.stringify({ results: [], errors: [], paths: { scanned: all } }));
      return { outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false };
    });
    expect((await runSemgrep({ args: ['--json', '--output', out, root], cwd: root }, run, 'win32')).longFilesRead).toBeUndefined();
    expect(run).toHaveBeenCalledTimes(1);
    run.mockClear();
    await runSemgrep({ args: ['--json', '--output', out, root], cwd: root }, run, 'linux');
    expect(run).toHaveBeenCalledTimes(1);
    run.mockClear();
    await runSemgrep({ args: ['--json', root], cwd: root }, run, 'win32');
    expect(run).toHaveBeenCalledTimes(1);
  });
});
