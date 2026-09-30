/**
 * A binary the scanned project planted in its own root is never what runs
 * (review of 3.0, W2E: `platform/binaryPath.ts`).
 *
 * Claude Code starts a project's MCP server in the project root, and the
 * scanners run with `cwd` = the project. On Windows `where` — what
 * `resolveBinary` asked — searches the current directory first, and so do
 * libuv's and `cmd.exe`'s own searches unless `NoDefaultCurrentDirectoryInExePath`
 * is set: a repository carrying `nuclei.bat` had it reported as the installed
 * scanner, and spawned. Each Windows case below first proves the plant WOULD
 * run (the control, with the variable removed), then that it does not.
 *
 * On POSIX the current directory is searched only through an empty or
 * relative PATH entry; the same shape is held there.
 */
import { copyFileSync, chmodSync, existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { delimiter, join } from 'node:path';
import { execa } from 'execa';
import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest';
import { commandFor, findOnPath, hardenCommandSearch, searchDirs } from '../../src/platform/binaryPath.js';
import { execGit, execGitSync } from '../../src/platform/gitSafety.js';
import { resolveBinary } from '../../src/platform/pkgManagerDetect.js';
import { runProcess } from '../../src/runners/processRunner.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const WIN = process.platform === 'win32';
const NO_CWD = 'NoDefaultCurrentDirectoryInExePath';

describe('searchDirs — only absolute entries are searched', () => {
  it('Windows: empty, ".", relative, drive-relative and network entries are skipped; quotes are removed', () => {
    expect(searchDirs(';.;bin;C:tools;\\\\host\\share\\bin;"C:\\Program Files\\x";C:\\a\\;D:/b', 'win32')).toEqual([
      'C:\\Program Files\\x',
      'C:\\a\\',
      'D:/b',
    ]);
  });

  it('POSIX: empty, "." and relative entries are skipped', () => {
    expect(searchDirs(':.:bin:/usr/bin::./x:/opt/bin', 'linux')).toEqual(['/usr/bin', '/opt/bin']);
  });

  it('a name that is not bare is never looked up', () => {
    for (const name of ['./node', '../node', 'bin/node', 'C:node', '.', '..', '']) expect(findOnPath(name)).toBeNull();
  });
});

describe('hardenCommandSearch — the process-wide layer', () => {
  let saved: NodeJS.ProcessEnv;
  beforeEach(() => {
    saved = { ...process.env };
  });
  afterEach(() => {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    Object.assign(process.env, saved);
  });

  it('drops empty and relative PATH entries, names the non-empty ones, and keeps the rest in order', () => {
    const key = WIN ? (Object.keys(process.env).find((k) => k.toUpperCase() === 'PATH') ?? 'PATH') : 'PATH';
    const abs = WIN ? ['C:\\one', 'C:\\two'] : ['/one', '/two'];
    process.env[key] = ['', abs[0], '.', 'rel', '', abs[1], ''].join(delimiter);
    expect(hardenCommandSearch()).toEqual(['.', 'rel']);
    expect(process.env[key]).toBe(abs.join(delimiter));
    if (WIN) expect(process.env[NO_CWD]).toBe('1');
    // Idempotent.
    expect(hardenCommandSearch()).toEqual([]);
    expect(process.env[key]).toBe(abs.join(delimiter));
  });
});

describe.runIf(WIN)('Windows — a .bat, .cmd or .exe planted in the project never answers', () => {
  let project: string;
  let marker: string;
  let savedFlag: string | undefined;
  let savedCwd: string;

  beforeEach(() => {
    project = makeTempDir('dg-planted-');
    marker = join(project, 'PLANTED-RAN');
    // A planted `node` in all three spellings, and one binary found ONLY here.
    writeFileSync(join(project, 'node.cmd'), `@echo off\r\necho cmd>"${marker}"\r\necho PLANTED\r\n`);
    writeFileSync(join(project, 'node.bat'), `@echo off\r\necho bat>"${marker}"\r\necho PLANTED\r\n`);
    copyFileSync('C:\\Windows\\System32\\whoami.exe', join(project, 'node.exe'));
    copyFileSync('C:\\Windows\\System32\\whoami.exe', join(project, 'dgplanted.exe'));
    writeFileSync(join(project, 'nuclei.bat'), `@echo off\r\necho nuclei>"${marker}"\r\n`);
    // The control: the variable Claude Code's own shell happens to set is removed, as a host may not set it.
    savedFlag = process.env[NO_CWD];
    delete process.env[NO_CWD];
    savedCwd = process.cwd();
    process.chdir(project);
  });

  afterEach(() => {
    process.chdir(savedCwd);
    if (savedFlag === undefined) delete process.env[NO_CWD];
    else process.env[NO_CWD] = savedFlag;
    rmSync(marker, { force: true });
  });

  it('the control: a bare-name spawn in the project runs the plant when nothing stops it', async () => {
    const r = await execa('dgplanted', [], { cwd: project, reject: false });
    expect(r.exitCode, 'whoami, planted as dgplanted.exe, ran from the current directory').toBe(0);
    expect(String(r.stdout).trim()).toMatch(/\\/);
  });

  it('resolveBinary never names a file in the current directory', async () => {
    expect(await resolveBinary('dgplanted')).toBeNull();
    expect(await resolveBinary('nuclei')).not.toBe(join(project, 'nuclei.bat'));
    const node = await resolveBinary('node');
    expect(node).not.toBeNull();
    expect(node?.toLowerCase().startsWith(project.toLowerCase())).toBe(false);
  });

  it('runProcess by bare name runs the PATH binary, not the plant, with cwd = the project', async () => {
    const r = await runProcess({ command: 'node', args: ['-e', 'process.stdout.write("real node")'], cwd: project, timeoutMs: 60_000 });
    expect(r.stdout).toBe('real node');
    expect(existsSync(marker)).toBe(false);
    const planted = await runProcess({ command: 'dgplanted', cwd: project, timeoutMs: 60_000 });
    expect(planted.outcome).toBe('failed');
    expect(planted.stdout).toBe('');
  });

  it('commandFor hands a direct spawn the absolute path; with the process-wide layer, a name found nowhere else fails', async () => {
    expect(commandFor('node').toLowerCase().startsWith(project.toLowerCase())).toBe(false);
    expect(commandFor('dgplanted')).toBe('dgplanted');
    writeFileSync(join(project, 'dgplantedbat.bat'), `@echo off\r\necho bat>"${marker}"\r\n`);
    // The control for the .bat route (cross-spawn hands it to cmd.exe, whose search starts in the current directory).
    await execa('dgplantedbat', [], { cwd: project, reject: false });
    expect(existsSync(marker), 'the planted .bat ran through cmd.exe').toBe(true);
    rmSync(marker, { force: true });
    process.env[NO_CWD] = '1'; // what hardenCommandSearch sets at startup
    const exe = await execa(commandFor('dgplanted'), [], { cwd: project, reject: false });
    expect(exe.exitCode).not.toBe(0);
    await execa(commandFor('dgplantedbat'), [], { cwd: project, reject: false });
    expect(existsSync(marker)).toBe(false);
  });

  // platform/gitSafety.ts spawns git with no `cwd`: the process's own, which
  // is the project for the hook and the server.
  it('execGit and execGitSync run the git on PATH, never a git.exe planted in the current directory', async () => {
    copyFileSync('C:\\Windows\\System32\\whoami.exe', join(project, 'git.exe'));
    const control = await execa('git', [], { reject: false });
    expect(String(control.stdout), 'the planted git.exe (whoami) answered a bare-name spawn').toMatch(/\\/);
    const sync = execGitSync(project, ['--version']);
    expect(sync.stdout).toMatch(/^git version /);
    const async_ = await execGit(project, ['--version']);
    expect(async_.stdout).toMatch(/^git version /);
  });
});

describe.runIf(!WIN)('POSIX — a planted executable reached through an empty PATH entry never answers', () => {
  let project: string;
  let marker: string;

  beforeEach(() => {
    project = makeTempDir('dg-planted-');
    marker = join(project, 'PLANTED-RAN');
    mkdirSync(join(project, 'sub'));
    for (const name of ['node', 'dgplanted']) {
      writeFileSync(join(project, name), `#!/bin/sh\necho planted > '${marker}'\necho PLANTED\n`);
      chmodSync(join(project, name), 0o755);
    }
  });

  afterEach(() => {
    rmSync(marker, { force: true });
  });

  it('an empty or "." PATH entry is not searched: the PATH binary runs, and a name found only here does not', async () => {
    const path = `:.:${process.env['PATH'] ?? ''}`;
    expect(findOnPath('dgplanted', { PATH: path })).toBeNull();
    const r = await runProcess({
      command: 'node',
      args: ['-e', 'process.stdout.write("real node")'],
      cwd: project,
      env: { ...process.env, PATH: path },
      timeoutMs: 60_000,
    });
    expect(r.stdout).toBe('real node');
    const planted = await runProcess({ command: 'dgplanted', cwd: project, env: { ...process.env, PATH: path }, timeoutMs: 60_000 });
    expect(planted.stdout).not.toContain('PLANTED');
    expect(existsSync(marker)).toBe(false);
  });
});
