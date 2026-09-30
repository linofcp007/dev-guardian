/**
 * `platform/projectFs.ts` — the one way dev-guardian reads and writes a file
 * inside the scanned project, whose contents may be hostile. Every hostile
 * shape the review measured against the raw `fs` calls it replaces: a
 * dangling link written through, `/dev/zero` read without end, a FIFO that
 * blocks the open, a junction or a directory link out of the project, and an
 * oversized file.
 */
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  existsSync,
  linkSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  hashProjectFile,
  listProjectDir,
  listProjectDirOrNull,
  readProjectBytes,
  readProjectHead,
  readProjectJson,
  readProjectText,
  realpathInProject,
  writeProjectFile,
} from '../../../src/platform/projectFs.js';
import { CAN_SYMLINK, POSIX } from '../../helpers/fsCapabilities.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const fast = <T>(fn: () => T): T => {
  const t0 = Date.now();
  const out = fn();
  expect(Date.now() - t0).toBeLessThan(2000);
  return out;
};

describe('readProjectText', () => {
  it('reads a regular file inside the project, stripping a byte-order mark', () => {
    const root = makeTempDir('pfs-');
    writeFileSync(join(root, 'a.txt'), '\uFEFFhello', 'utf8');
    expect(readProjectText(root, 'a.txt')).toEqual({ status: 'ok', text: 'hello' });
    expect(readProjectText(root, join(root, 'a.txt'))).toEqual({ status: 'ok', text: 'hello' });
  });

  it('keeps legitimate non-ASCII names and content', () => {
    const root = makeTempDir('pfs-');
    writeFileSync(join(root, '日本.py'), 'print("こんにちは")\n', 'utf8');
    expect(readProjectText(root, '日本.py')).toEqual({ status: 'ok', text: 'print("こんにちは")\n' });
  });

  it('is absent for a missing file', () => {
    const root = makeTempDir('pfs-');
    expect(readProjectText(root, 'nope')).toEqual({ status: 'absent' });
  });

  it('refuses a path outside the project without looking at it', () => {
    const root = makeTempDir('pfs-');
    const other = makeTempDir('pfs-other-');
    writeFileSync(join(other, 'secret'), 'x', 'utf8');
    expect(readProjectText(root, join(other, 'secret'))).toEqual({ status: 'refused', reason: 'outside-project' });
    expect(readProjectText(root, '../x')).toEqual({ status: 'refused', reason: 'outside-project' });
  });

  it('refuses a directory', () => {
    const root = makeTempDir('pfs-');
    mkdirSync(join(root, 'd'));
    expect(readProjectText(root, 'd')).toEqual({ status: 'refused', reason: 'not-a-regular-file' });
  });

  it('refuses a file over the cap, and reads one at the cap', () => {
    const root = makeTempDir('pfs-');
    writeFileSync(join(root, 'big'), 'x'.repeat(1025));
    writeFileSync(join(root, 'edge'), 'x'.repeat(1024));
    expect(readProjectText(root, 'big', 1024)).toEqual({ status: 'refused', reason: 'too-large' });
    expect(readProjectText(root, 'edge', 1024).status).toBe('ok');
  });

  it.skipIf(!CAN_SYMLINK)('refuses a link that leaves the project, and is absent for a dangling one', () => {
    const root = makeTempDir('pfs-');
    const other = makeTempDir('pfs-other-');
    writeFileSync(join(other, 'secret'), 'AKIA-DO-NOT-READ', 'utf8');
    symlinkSync(join(other, 'secret'), join(root, 'leak'), 'file');
    symlinkSync(join(other, 'gone'), join(root, 'dangling'), 'file');
    expect(readProjectText(root, 'leak')).toEqual({ status: 'refused', reason: 'outside-project' });
    expect(readProjectText(root, 'dangling')).toEqual({ status: 'absent' });
  });

  it.skipIf(!CAN_SYMLINK)('follows a link that stays inside the project', () => {
    const root = makeTempDir('pfs-');
    mkdirSync(join(root, 'shared'));
    writeFileSync(join(root, 'shared', 'real.json'), '{"a":1}', 'utf8');
    symlinkSync(join(root, 'shared', 'real.json'), join(root, 'alias.json'), 'file');
    expect(readProjectJson(root, 'alias.json')).toEqual({ a: 1 });
  });

  it.skipIf(!CAN_SYMLINK)('refuses a file reached through a directory link out of the project', () => {
    const root = makeTempDir('pfs-');
    const other = makeTempDir('pfs-other-');
    writeFileSync(join(other, 'credentials'), 'x', 'utf8');
    symlinkSync(other, join(root, 'docs'), POSIX ? 'dir' : 'junction');
    expect(readProjectText(root, 'docs/credentials')).toEqual({ status: 'refused', reason: 'outside-project' });
    expect(realpathInProject(root, 'docs')).toBeNull();
  });

  it.skipIf(POSIX)('refuses a file reached through a junction out of the project (Windows)', () => {
    const root = makeTempDir('pfs-');
    const other = makeTempDir('pfs-other-');
    writeFileSync(join(other, 'credentials'), 'x', 'utf8');
    symlinkSync(other, join(root, 'j'), 'junction');
    expect(readProjectText(root, 'j/credentials')).toEqual({ status: 'refused', reason: 'outside-project' });
  });

  it.skipIf(!POSIX)('refuses a link to /dev/zero at once (POSIX)', () => {
    const root = makeTempDir('pfs-');
    symlinkSync('/dev/zero', join(root, 'zero'));
    expect(fast(() => readProjectText(root, 'zero'))).toEqual({ status: 'refused', reason: 'outside-project' });
    expect(fast(() => readProjectBytes(root, 'zero'))).toEqual({ status: 'refused', reason: 'outside-project' });
  });

  it.skipIf(!POSIX)('refuses a FIFO without waiting for a writer (POSIX)', () => {
    const root = makeTempDir('pfs-');
    expect(spawnSync('mkfifo', [join(root, 'pipe')]).status).toBe(0);
    expect(fast(() => readProjectText(root, 'pipe'))).toEqual({ status: 'refused', reason: 'not-a-regular-file' });
    expect(fast(() => readProjectBytes(root, 'pipe'))).toEqual({ status: 'refused', reason: 'not-a-regular-file' });
  });
});

describe('readProjectBytes', () => {
  it('returns the bytes as they are, byte-order mark included', () => {
    const root = makeTempDir('pfs-');
    const bytes = Buffer.from([0xef, 0xbb, 0xbf, 0x61, 0xff]);
    writeFileSync(join(root, 'b'), bytes);
    const r = readProjectBytes(root, 'b');
    expect(r.status).toBe('ok');
    if (r.status === 'ok') expect(Buffer.compare(r.bytes, bytes)).toBe(0);
  });

  it('refuses over the cap', () => {
    const root = makeTempDir('pfs-');
    writeFileSync(join(root, 'b'), Buffer.alloc(11));
    expect(readProjectBytes(root, 'b', 10)).toEqual({ status: 'refused', reason: 'too-large' });
  });
});

describe('readProjectHead', () => {
  it('reads the first N bytes of a file of any size, and a short file whole, stripping a byte-order mark', () => {
    const root = makeTempDir('pfs-');
    writeFileSync(join(root, 'big'), `﻿Plugin Name: x\n${'a'.repeat(100_000)}`);
    writeFileSync(join(root, 'small'), 'tiny');
    // 18 bytes: the 3-byte mark, then the 15-byte header line.
    const head = readProjectHead(root, 'big', 18);
    expect(head).toEqual({ status: 'ok', text: 'Plugin Name: x\n' });
    expect(readProjectHead(root, 'small', 1024)).toEqual({ status: 'ok', text: 'tiny' });
    expect(readProjectHead(root, 'missing', 1024)).toEqual({ status: 'absent' });
  });

  it('refuses a directory and a path outside the project', () => {
    const root = makeTempDir('pfs-');
    mkdirSync(join(root, 'd'));
    expect(readProjectHead(root, 'd', 10)).toEqual({ status: 'refused', reason: 'not-a-regular-file' });
    expect(readProjectHead(root, '../x', 10)).toEqual({ status: 'refused', reason: 'outside-project' });
  });

  it.skipIf(!CAN_SYMLINK)('refuses a link out of the project', () => {
    const root = makeTempDir('pfs-');
    const outside = makeTempDir('pfs-out-');
    writeFileSync(join(outside, 'secret'), 'SECRET');
    symlinkSync(join(outside, 'secret'), join(root, 'l'), 'file');
    expect(readProjectHead(root, 'l', 10)).toEqual({ status: 'refused', reason: 'outside-project' });
  });

  it.skipIf(!POSIX)('refuses a FIFO without waiting for a writer, and a link to /dev/zero (POSIX)', () => {
    const root = makeTempDir('pfs-');
    expect(spawnSync('mkfifo', [join(root, 'pipe')]).status).toBe(0);
    symlinkSync('/dev/zero', join(root, 'zero'));
    expect(fast(() => readProjectHead(root, 'pipe', 64))).toEqual({ status: 'refused', reason: 'not-a-regular-file' });
    expect(fast(() => readProjectHead(root, 'zero', 64))).toEqual({ status: 'refused', reason: 'outside-project' });
  });
});

describe('listProjectDirOrNull', () => {
  it('tells an empty directory from one it never listed', () => {
    const root = makeTempDir('pfs-');
    mkdirSync(join(root, 'empty'));
    writeFileSync(join(root, 'f'), 'x');
    expect(listProjectDirOrNull(root, join(root, 'empty'))).toEqual([]);
    expect(listProjectDirOrNull(root, join(root, 'missing'))).toBeNull();
    expect(listProjectDirOrNull(root, join(root, 'f'))).toBeNull();
    expect(listProjectDir(root, join(root, 'missing'))).toEqual([]);
  });

  it.skipIf(!CAN_SYMLINK)('is null for a directory reached through a link out of the project', () => {
    const root = makeTempDir('pfs-');
    const outside = makeTempDir('pfs-out-');
    writeFileSync(join(outside, 'secret'), 'x');
    symlinkSync(outside, join(root, 'out'), POSIX ? 'dir' : 'junction');
    expect(listProjectDirOrNull(root, join(root, 'out'))).toBeNull();
  });
});

describe('hashProjectFile', () => {
  it('hashes a regular file by content', async () => {
    const root = makeTempDir('pfs-');
    writeFileSync(join(root, 'f'), 'abc');
    expect(await hashProjectFile(root, 'f')).toBe(createHash('sha256').update('abc').digest('hex'));
  });

  it('is `missing` for a path that is not there', async () => {
    const root = makeTempDir('pfs-');
    expect(await hashProjectFile(root, 'nope')).toBe('missing');
  });

  it.skipIf(!CAN_SYMLINK)('hashes a link by its target text and never opens it', async () => {
    const root = makeTempDir('pfs-');
    const other = makeTempDir('pfs-other-');
    writeFileSync(join(other, 'x'), 'outside');
    symlinkSync(join(other, 'x'), join(root, 'l'), 'file');
    expect(await hashProjectFile(root, 'l')).toBe(`link:${join(other, 'x')}`);
  });

  it.skipIf(!POSIX)('a link to /dev/zero and a FIFO are hashed at once, never read (POSIX)', async () => {
    const root = makeTempDir('pfs-');
    symlinkSync('/dev/zero', join(root, 'zero'));
    expect(spawnSync('mkfifo', [join(root, 'pipe')]).status).toBe(0);
    const t0 = Date.now();
    expect(await hashProjectFile(root, 'zero')).toBe('link:/dev/zero');
    expect(await hashProjectFile(root, 'pipe')).toBe('special');
    expect(Date.now() - t0).toBeLessThan(2000);
  });
});

describe('writeProjectFile', () => {
  it('creates a file and the directories on the way, leaving no temp file', () => {
    const root = makeTempDir('pfs-');
    expect(writeProjectFile(root, 'src/deep/a.ts', 'x', { mode: 'create' })).toEqual({ ok: true, bytes: 1 });
    expect(readFileSync(join(root, 'src', 'deep', 'a.ts'), 'utf8')).toBe('x');
    expect(readdirSync(join(root, 'src', 'deep'))).toEqual(['a.ts']);
  });

  it('`create` refuses an existing file and leaves it alone', () => {
    const root = makeTempDir('pfs-');
    writeFileSync(join(root, 'a'), 'mine');
    expect(writeProjectFile(root, 'a', 'theirs', { mode: 'create' })).toEqual({ ok: false, reason: 'exists' });
    expect(readFileSync(join(root, 'a'), 'utf8')).toBe('mine');
  });

  it('`replace` replaces a regular file, leaving no temp file', () => {
    const root = makeTempDir('pfs-');
    writeFileSync(join(root, 'a'), 'old');
    expect(writeProjectFile(root, 'a', 'new', { mode: 'replace' }).ok).toBe(true);
    expect(readFileSync(join(root, 'a'), 'utf8')).toBe('new');
    expect(readdirSync(root)).toEqual(['a']);
  });

  it('`replace` replaces a hard-linked file by name, never writing into the inode another name shares', () => {
    const root = makeTempDir('pfs-');
    const other = makeTempDir('pfs-other-');
    writeFileSync(join(other, 'gitconfig'), 'keep');
    linkSync(join(other, 'gitconfig'), join(root, 'a'));
    expect(writeProjectFile(root, 'a', 'new', { mode: 'replace' }).ok).toBe(true);
    expect(readFileSync(join(other, 'gitconfig'), 'utf8')).toBe('keep');
    expect(readFileSync(join(root, 'a'), 'utf8')).toBe('new');
  });

  it('refuses a target outside the project, or the project itself', () => {
    const root = makeTempDir('pfs-');
    const other = makeTempDir('pfs-other-');
    expect(writeProjectFile(root, join(other, 'x'), 'x', { mode: 'create' })).toEqual({
      ok: false,
      reason: 'outside-project',
    });
    expect(writeProjectFile(root, '.', 'x', { mode: 'replace' })).toEqual({ ok: false, reason: 'outside-project' });
    expect(existsSync(join(other, 'x'))).toBe(false);
  });

  it('refuses a directory at the target', () => {
    const root = makeTempDir('pfs-');
    mkdirSync(join(root, 'd'));
    expect(writeProjectFile(root, 'd', 'x', { mode: 'replace' })).toEqual({ ok: false, reason: 'not-a-regular-file' });
  });

  it.skipIf(!CAN_SYMLINK)('never creates the target of a dangling link, in either mode', () => {
    const root = makeTempDir('pfs-');
    const other = makeTempDir('pfs-other-');
    symlinkSync(join(other, 'planted.conf'), join(root, 'a'), 'file');
    for (const mode of ['create', 'replace'] as const) {
      expect(writeProjectFile(root, 'a', 'x', { mode })).toEqual({ ok: false, reason: 'link' });
    }
    expect(existsSync(join(other, 'planted.conf'))).toBe(false);
    expect(readdirSync(root)).toEqual(['a']);
  });

  it.skipIf(!CAN_SYMLINK)('never writes through a link to an existing file, even one inside the project', () => {
    const root = makeTempDir('pfs-');
    writeFileSync(join(root, 'real'), 'keep');
    symlinkSync(join(root, 'real'), join(root, 'a'), 'file');
    expect(writeProjectFile(root, 'a', 'x', { mode: 'replace' })).toEqual({ ok: false, reason: 'link' });
    expect(readFileSync(join(root, 'real'), 'utf8')).toBe('keep');
  });

  it.skipIf(!CAN_SYMLINK)('refuses a directory on the way that links out of the project, creating nothing outside', () => {
    const root = makeTempDir('pfs-');
    const other = makeTempDir('pfs-other-');
    symlinkSync(other, join(root, 'src'), POSIX ? 'dir' : 'junction');
    const r = writeProjectFile(root, 'src/sub/logger.ts', 'x', { mode: 'create' });
    expect(r).toMatchObject({ ok: false, reason: 'escaping-directory' });
    expect(readdirSync(other)).toEqual([]);
  });

  it.skipIf(POSIX)('refuses a junction on the way out of the project (Windows)', () => {
    const root = makeTempDir('pfs-');
    const other = makeTempDir('pfs-other-');
    symlinkSync(other, join(root, 'app'), 'junction');
    expect(writeProjectFile(root, 'app/metrics.py', 'x', { mode: 'create' })).toMatchObject({
      ok: false,
      reason: 'escaping-directory',
    });
    expect(readdirSync(other)).toEqual([]);
  });

  it.skipIf(!CAN_SYMLINK)('allows a directory link that stays inside the project', () => {
    const root = makeTempDir('pfs-');
    mkdirSync(join(root, 'real'));
    symlinkSync(join(root, 'real'), join(root, 'alias'), POSIX ? 'dir' : 'junction');
    expect(writeProjectFile(root, 'alias/a', 'x', { mode: 'create' }).ok).toBe(true);
    expect(readFileSync(join(root, 'real', 'a'), 'utf8')).toBe('x');
  });

  it.skipIf(!POSIX)('refuses a FIFO at the target without opening it (POSIX)', () => {
    const root = makeTempDir('pfs-');
    expect(spawnSync('mkfifo', [join(root, 'pipe')]).status).toBe(0);
    expect(fast(() => writeProjectFile(root, 'pipe', 'x', { mode: 'replace' }))).toEqual({
      ok: false,
      reason: 'not-a-regular-file',
    });
  });
});
