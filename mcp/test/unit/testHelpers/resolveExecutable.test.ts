/**
 * `test/helpers/resolveExecutable.ts` — how `ciInitCli.test.ts` turns the bash
 * it probed into the absolute path it then spawns (re-review follow-up to I6).
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { delimiter, join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { isWslLauncher, resolveExecutable } from '../../helpers/resolveExecutable.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

describe('resolveExecutable', () => {
  it('returns the first match on PATH as an absolute path, in PATH order', () => {
    const root = makeTempDir('guardian-resolve-exe-');
    const first = join(root, 'first');
    const second = join(root, 'second');
    mkdirSync(first);
    mkdirSync(second);
    writeFileSync(join(second, 'tool'), '');
    writeFileSync(join(first, 'tool'), '');
    const path = [join(root, 'missing'), first, second].join(delimiter);
    expect(resolveExecutable('tool', { path, platform: 'linux' })).toBe(join(first, 'tool'));
  });

  it('tries PATHEXT extensions for a Windows name without one', () => {
    const dir = makeTempDir('guardian-resolve-exe-win-');
    writeFileSync(join(dir, 'bash.exe'), '');
    expect(resolveExecutable('bash', { path: dir, pathext: '.com;.exe', platform: 'win32' })).toBe(join(dir, 'bash.exe'));
    expect(resolveExecutable('bash.exe', { path: dir, platform: 'win32' })).toBe(join(dir, 'bash.exe'));
  });

  it('keeps an absolute path that exists, and is null for one that does not or a name not on PATH', () => {
    const dir = makeTempDir('guardian-resolve-exe-abs-');
    const f = join(dir, 'x');
    writeFileSync(f, '');
    expect(resolveExecutable(f)).toBe(f);
    expect(resolveExecutable(join(dir, 'nope'))).toBeNull();
    expect(resolveExecutable('guardian-no-such-binary', { path: dir, platform: 'linux' })).toBeNull();
  });

  it('never resolves to a directory of the same name', () => {
    const dir = makeTempDir('guardian-resolve-exe-dir-');
    mkdirSync(join(dir, 'bash'));
    expect(resolveExecutable('bash', { path: dir, platform: 'linux' })).toBeNull();
  });
});

describe('isWslLauncher', () => {
  it.each([
    ['C:\\Windows\\System32\\bash.exe', true],
    ['c:/windows/system32/BASH.EXE', true],
    ['C:\\Windows\\SysWOW64\\bash.exe', true],
    ['C:\\Program Files\\Git\\bin\\bash.exe', false],
    ['C:\\Program Files\\Git\\usr\\bin\\bash.exe', false],
    ['/usr/bin/bash', false],
  ] as const)('%s -> %s', (p, expected) => {
    expect(isWslLauncher(p, 'C:\\Windows')).toBe(expected);
  });
});
