/**
 * `test/helpers/tempDir.ts` — the end-of-run removal of what a test's cleanup
 * could not remove. It deletes directories named in a plain file, so what it
 * refuses matters as much as what it removes; the refusals are checked on the
 * predicate, never by letting it loose on a real directory.
 */

import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { cleanupTempDirs, isDisposable, makeTempDir, removeLeftovers, rmDirOrDefer } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

describe('rmDirOrDefer / removeLeftovers', () => {
  it('removes a directory nothing holds, and lists nothing', () => {
    const base = makeTempDir('guardian-tempdir-');
    const list = join(base, 'list.txt');
    const dir = join(base, 'victim');
    mkdirSync(join(dir, 'sub'), { recursive: true });
    writeFileSync(join(dir, 'sub', 'f'), 'x');
    rmDirOrDefer(dir, list);
    expect(existsSync(dir)).toBe(false);
    expect(existsSync(list)).toBe(false);
  });

  it('removes a listed directory in the temp dir, and the list with it', () => {
    const base = makeTempDir('guardian-tempdir-');
    const list = join(base, 'list.txt');
    // A direct child of the temp dir: the shape every test directory has.
    const dir = mkdtempSync(join(tmpdir(), 'guardian-tempdir-left-'));
    writeFileSync(join(dir, 'f'), 'x');
    writeFileSync(list, `${dir}\n${dir}\n`);
    removeLeftovers(list);
    expect(existsSync(dir)).toBe(false);
    expect(existsSync(list)).toBe(false);
  });

  it('drops a listed path that is already gone', () => {
    const base = makeTempDir('guardian-tempdir-');
    const list = join(base, 'list.txt');
    writeFileSync(list, `${join(base, 'never-existed')}\n`);
    removeLeftovers(list);
    expect(existsSync(list)).toBe(false);
  });

  it('a missing list is nothing to do', () => {
    expect(() => removeLeftovers(join(makeTempDir('guardian-tempdir-'), 'none.txt'))).not.toThrow();
  });

  // Exercised on a directory this test made — never on anything real. The
  // first version listed this repository's own test directory, and when the
  // checkout sat in /tmp (a container, a CI runner) the removal took it.
  it('never touches a listed directory outside what a test makes — it is dropped, not removed', () => {
    const base = makeTempDir('guardian-tempdir-');
    const list = join(base, 'list.txt');
    const nested = join(base, 'nested', 'keep');
    mkdirSync(nested, { recursive: true });
    writeFileSync(join(nested, 'f'), 'x');
    writeFileSync(list, `${nested}\n`);
    removeLeftovers(list);
    expect(readFileSync(join(nested, 'f'), 'utf8')).toBe('x');
    expect(existsSync(list)).toBe(false);
  });
});

describe('isDisposable', () => {
  it('is a directory inside the temp dir', () => {
    expect(isDisposable(makeTempDir('guardian-tempdir-'))).toBe(true);
  });

  it('is never the temp dir itself, its parent, the home directory, or a home directory it did not make', () => {
    expect(isDisposable(tmpdir())).toBe(false);
    expect(isDisposable(dirname(tmpdir()))).toBe(false);
    expect(isDisposable(homedir())).toBe(false);
    expect(isDisposable(dirname(homedir()))).toBe(false);
  });

  it('is never a directory deeper in the temp dir, nor this checkout wherever it sits', () => {
    const nested = join(makeTempDir('guardian-tempdir-'), 'nested');
    mkdirSync(nested);
    expect(isDisposable(nested)).toBe(false);
    const here = dirname(fileURLToPath(import.meta.url));
    const checkout = join(here, '..', '..', '..', '..');
    for (const dir of [here, join(here, '..'), join(here, '..', '..'), checkout, process.cwd()]) {
      expect(isDisposable(dir)).toBe(false);
    }
  });

  it('is a dev-guardian-test-* directly in the home directory, and nothing else there', () => {
    const made = join(homedir(), `dev-guardian-test-disposable-${process.pid}`);
    mkdirSync(made, { recursive: true });
    try {
      expect(isDisposable(made)).toBe(true);
    } finally {
      rmDirOrDefer(made);
    }
  });

  it('is not a path that does not exist', () => {
    expect(isDisposable(join(tmpdir(), `guardian-tempdir-missing-${process.pid}-${Date.now()}`))).toBe(false);
  });
});
