/**
 * `ensureGuardianIgnored` runs at server startup, before any tool call, on
 * whatever directory the host started the server in — a repository the user
 * may have just cloned. Measured on 3.0.0: `existsSync` is false for a
 * dangling `.gitignore` link, and `writeFileSync` follows it, so startup
 * CREATED `<outside>/planted.conf` with the three-line block; pointed at
 * `~/.gitconfig` it would break every git command. `.gitignore -> /dev/zero`
 * OOM-killed the server in 21 s, before it listened.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { ensureGuardianIgnored } from '../../src/gitignoreGuard.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { CAN_SYMLINK, POSIX } from '../helpers/fsCapabilities.js';

afterAll(cleanupTempDirs);

function repo(): string {
  const dir = makeTempDir('guard-hostile-');
  mkdirSync(join(dir, '.git'));
  return dir;
}

describe('ensureGuardianIgnored — a hostile .gitignore', () => {
  it.skipIf(!CAN_SYMLINK)('never creates the target of a dangling .gitignore link outside the project', () => {
    const outside = makeTempDir('guard-outside-');
    const planted = join(outside, 'planted.conf');
    const dir = repo();
    symlinkSync(planted, join(dir, '.gitignore'), 'file');

    const r = ensureGuardianIgnored(dir);

    expect(existsSync(planted)).toBe(false);
    expect(r.updated).toBe(false);
    expect(r.reason).toBe('refused');
  });

  it.skipIf(!CAN_SYMLINK)('never rewrites a file outside the project through a .gitignore link', () => {
    const outside = makeTempDir('guard-outside-');
    const gitconfig = join(outside, '.gitconfig');
    writeFileSync(gitconfig, '[user]\n\tname = someone\n', 'utf8');
    const dir = repo();
    symlinkSync(gitconfig, join(dir, '.gitignore'), 'file');

    const r = ensureGuardianIgnored(dir);

    expect(readFileSync(gitconfig, 'utf8')).toBe('[user]\n\tname = someone\n');
    expect(r).toMatchObject({ updated: false, reason: 'refused' });
  });

  it.skipIf(!CAN_SYMLINK)('refuses a .gitignore that is a link even when it stays inside the project', () => {
    const dir = repo();
    writeFileSync(join(dir, 'real-ignore'), 'node_modules/\n', 'utf8');
    symlinkSync(join(dir, 'real-ignore'), join(dir, '.gitignore'), 'file');

    expect(ensureGuardianIgnored(dir)).toMatchObject({ updated: false, reason: 'refused' });
    expect(readFileSync(join(dir, 'real-ignore'), 'utf8')).toBe('node_modules/\n');
  });

  it.skipIf(POSIX)('refuses a .gitignore that is a junction (Windows)', () => {
    const outside = makeTempDir('guard-outside-');
    const dir = repo();
    symlinkSync(outside, join(dir, '.gitignore'), 'junction');

    const r = ensureGuardianIgnored(dir);

    expect(r).toMatchObject({ updated: false, reason: 'refused' });
    expect(existsSync(join(outside, '.gitignore'))).toBe(false);
  });

  it.skipIf(!POSIX)('refuses a .gitignore link to /dev/zero at once instead of reading it without end (POSIX)', () => {
    const dir = repo();
    symlinkSync('/dev/zero', join(dir, '.gitignore'));
    const t0 = Date.now();
    const r = ensureGuardianIgnored(dir);
    expect(Date.now() - t0).toBeLessThan(2000);
    expect(r).toMatchObject({ updated: false, reason: 'refused' });
  });

  it.skipIf(!POSIX)('refuses a FIFO .gitignore without waiting for a writer (POSIX)', () => {
    const dir = repo();
    expect(spawnSync('mkfifo', [join(dir, '.gitignore')]).status).toBe(0);
    const t0 = Date.now();
    const r = ensureGuardianIgnored(dir);
    expect(Date.now() - t0).toBeLessThan(2000);
    expect(r).toMatchObject({ updated: false, reason: 'refused' });
  });

  it('refuses an oversized .gitignore and leaves it byte-for-byte alone', () => {
    const dir = repo();
    const big = `${'x'.repeat(1023)}\n`.repeat(5 * 1024); // 5 MiB
    writeFileSync(join(dir, '.gitignore'), big, 'utf8');

    const r = ensureGuardianIgnored(dir);

    expect(r).toMatchObject({ updated: false, reason: 'refused' });
    expect(readFileSync(join(dir, '.gitignore'), 'utf8')).toBe(big);
  });

  it.skipIf(!CAN_SYMLINK)('a refused .gitignore leaves no temp file behind', () => {
    const dir = repo();
    const outside = makeTempDir('guard-outside-');
    symlinkSync(join(outside, 'x'), join(dir, '.gitignore'), 'file');
    ensureGuardianIgnored(dir);
    expect(readdirSync(dir).sort()).toEqual(['.git', '.gitignore']);
  });

  it('a plain .gitignore is still upgraded, through a temp file renamed over it, with no temp file left', () => {
    const dir = repo();
    writeFileSync(join(dir, '.gitignore'), 'node_modules/\r\n.guardian/\r\n', 'utf8');
    expect(ensureGuardianIgnored(dir)).toEqual({ updated: true, reason: 'upgraded' });
    expect(readFileSync(join(dir, '.gitignore'), 'utf8')).toBe(
      'node_modules/\r\n# dev-guardian outputs\r\n**/.guardian/*\r\n!**/.guardian/baseline.json\r\n',
    );
    expect(readdirSync(dir).sort()).toEqual(['.git', '.gitignore']);
  });
});
