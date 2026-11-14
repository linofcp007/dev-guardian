/**
 * `test/helpers/toolchain.ts#isInstalled` — the probe every scanner-gated test
 * skips or runs on. It answers as the server does: a binary in the per-user
 * tools directory (`~/.local/bin`) is installed, PATH or no PATH.
 */

import { chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import { delimiter, join } from 'node:path';
import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';
import { isInstalled } from '../../helpers/toolchain.js';

/** A name no machine has on PATH. */
const TOOL = `dg-probe-tool-${process.pid}`;

let pathBefore: string | undefined;
beforeEach(() => {
  pathBefore = process.env['PATH'];
});
afterEach(() => {
  if (pathBefore === undefined) delete process.env['PATH'];
  else process.env['PATH'] = pathBefore;
});
afterAll(cleanupTempDirs);

/** A home whose `.local/bin` exists and, when asked, holds {@link TOOL} as something `where` / `which` accepts. */
function home(withTool: boolean): { home: string; bin: string } {
  const dir = makeTempDir('guardian-probe-home-');
  const bin = join(dir, '.local', 'bin');
  mkdirSync(bin, { recursive: true });
  if (withTool && process.platform === 'win32') writeFileSync(join(bin, `${TOOL}.cmd`), '@echo off\r\n');
  if (withTool && process.platform !== 'win32') {
    writeFileSync(join(bin, TOOL), '#!/bin/sh\n');
    chmodSync(join(bin, TOOL), 0o755);
  }
  return { home: dir, bin };
}

describe('isInstalled', () => {
  it('a binary in the per-user tools directory, which is not on PATH, is installed — as the server finds it', async () => {
    const { home: dir, bin } = home(true);
    expect((process.env['PATH'] ?? '').split(delimiter)).not.toContain(bin);
    expect(await isInstalled(TOOL, dir)).toBe(true);
  });

  it('a binary neither on PATH nor in that directory is not installed', async () => {
    // The directory is there without the binary; then there is no such directory at all.
    expect(await isInstalled(TOOL, home(false).home)).toBe(false);
    expect(await isInstalled(TOOL, makeTempDir('guardian-probe-nohome-'))).toBe(false);
    // And with the user's own home, where no such binary is.
    expect(await isInstalled(TOOL)).toBe(false);
  });

  it('the directory goes at the END of PATH, once: nothing on the PATH the process had is shadowed', async () => {
    const { home: dir, bin } = home(true);
    const before = process.env['PATH'] ?? '';
    await isInstalled(TOOL, dir);
    const after = process.env['PATH'] ?? '';
    expect(after.startsWith(before)).toBe(true);
    expect(after.split(delimiter).filter((entry) => entry !== '').at(-1)).toBe(bin);
    await isInstalled(TOOL, dir);
    expect(process.env['PATH']).toBe(after);
  });

  it('a directory that does not exist is not put on PATH', async () => {
    const dir = makeTempDir('guardian-probe-nohome-');
    await isInstalled(TOOL, dir);
    expect((process.env['PATH'] ?? '').split(delimiter)).not.toContain(join(dir, '.local', 'bin'));
  });
});
