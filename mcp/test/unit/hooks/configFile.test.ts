/**
 * `readSmallJsonFile` / `readSmallTextFile` — how the hook dispatcher (and
 * the install hook's registry-context reader) read a file the project or the
 * user controls. Task 23 fix round 2, N1: `readJsonFile` did `existsSync` and a
 * synchronous read with no check on what the path was, so a FIFO or a link to
 * `/dev/zero` at `.guardian/hooks.config.json` blocked the hook until Claude
 * Code killed it at its 15 s timeout — and the tool call then ran unguarded.
 */

import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { MAX_HOOK_CONFIG_BYTES, readSmallJsonFile, readSmallTextFile } from '../../../src/hooks/configFile.js';

const POSIX = process.platform !== 'win32';

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'hook-config-file-'));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('readSmallJsonFile', () => {
  it('caps a hook config file at 64 KiB', () => {
    expect(MAX_HOOK_CONFIG_BYTES).toBe(64 * 1024);
  });

  it('reads a small regular JSON file', () => {
    const p = join(dir, 'a.json');
    writeFileSync(p, '{"secrets":{"block":true}}');
    expect(readSmallJsonFile(p)).toEqual({ status: 'ok', value: { secrets: { block: true } } });
  });

  it('strips a leading UTF-8 byte-order mark (PowerShell 5 writes one)', () => {
    const p = join(dir, 'bom.json');
    writeFileSync(p, '﻿{"enabled":true}', 'utf8');
    expect(readSmallJsonFile(p)).toEqual({ status: 'ok', value: { enabled: true } });
  });

  it('a missing path is absent', () => {
    expect(readSmallJsonFile(join(dir, 'nope.json'))).toEqual({ status: 'absent' });
  });

  it('a file of exactly the cap is read; one byte more is refused as too large', () => {
    const exact = join(dir, 'exact.json');
    const body = '{"pad":"' + 'x'.repeat(MAX_HOOK_CONFIG_BYTES - 10) + '"}';
    expect(Buffer.byteLength(body)).toBe(MAX_HOOK_CONFIG_BYTES);
    writeFileSync(exact, body);
    expect(readSmallJsonFile(exact).status).toBe('ok');

    const over = join(dir, 'over.json');
    writeFileSync(over, body + ' ');
    expect(readSmallJsonFile(over)).toMatchObject({ status: 'refused', reason: 'too-large' });
  });

  it('a directory is refused, not read', () => {
    const p = join(dir, 'hooks.config.json');
    mkdirSync(p);
    expect(readSmallJsonFile(p)).toMatchObject({ status: 'refused', reason: 'not-a-regular-file' });
  });

  it('a small regular file that is not JSON is invalid', () => {
    const p = join(dir, 'broken.json');
    writeFileSync(p, '{"enabled": fal');
    expect(readSmallJsonFile(p)).toEqual({ status: 'invalid' });
  });

  it.skipIf(!POSIX)('a FIFO is refused at once, never opened (POSIX only: Windows has no FIFOs)', () => {
    const p = join(dir, 'hooks.config.json');
    const made = spawnSync('mkfifo', [p]);
    expect(made.status).toBe(0);
    const t0 = Date.now();
    expect(readSmallJsonFile(p)).toMatchObject({ status: 'refused', reason: 'not-a-regular-file' });
    expect(Date.now() - t0).toBeLessThan(1000);
  });

  it.skipIf(!POSIX)('a symlink to /dev/zero is refused (POSIX only: Windows has no /dev/zero)', () => {
    const p = join(dir, 'hooks.config.json');
    symlinkSync('/dev/zero', p);
    const t0 = Date.now();
    expect(readSmallJsonFile(p)).toMatchObject({ status: 'refused', reason: 'not-a-regular-file' });
    expect(Date.now() - t0).toBeLessThan(1000);
  });

  it('a symlink to a small regular file is followed and read', () => {
    const target = join(dir, 'real.json');
    writeFileSync(target, '{"a":1}');
    const link = join(dir, 'link.json');
    try {
      symlinkSync(target, link);
    } catch {
      return; // Windows without the symlink privilege: nothing to check here
    }
    expect(readSmallJsonFile(link)).toEqual({ status: 'ok', value: { a: 1 } });
  });
});

describe('readSmallTextFile', () => {
  it('reads a small file, and returns undefined past its cap or for a non-file', () => {
    const p = join(dir, '.npmrc');
    writeFileSync(p, 'registry=https://npm.acme.local/\n');
    expect(readSmallTextFile(p, 1024)).toBe('registry=https://npm.acme.local/\n');
    expect(readSmallTextFile(p, 8)).toBeUndefined();
    expect(readSmallTextFile(dir, 1024)).toBeUndefined();
    expect(readSmallTextFile(join(dir, 'missing'), 1024)).toBeUndefined();
  });
});
