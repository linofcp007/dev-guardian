/**
 * `hooks/dataRegistry.ts`: where dev-guardian's registry of trusted databases
 * lives, and which writes reach it (review 3.0 wave 2, round 2).
 */

import { linkSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { registryDir, userDataDir, writesRegistry } from '../../../src/hooks/dataRegistry.js';

const WIN = process.platform === 'win32';

describe('userDataDir — as the storage module places it', () => {
  it('is GUARDIAN_DATA_DIR when set, resolved', () => {
    const dir = join(tmpdir(), 'dg-data');
    expect(userDataDir({ env: { GUARDIAN_DATA_DIR: ` ${dir} ` } })).toBe(dir);
  });

  it.runIf(WIN)('is %LOCALAPPDATA%\\dev-guardian on Windows, else AppData\\Local under home', () => {
    expect(userDataDir({ env: { LOCALAPPDATA: 'C:\\Users\\u\\AppData\\Local' }, platform: 'win32' })).toBe(
      'C:\\Users\\u\\AppData\\Local\\dev-guardian',
    );
    expect(userDataDir({ env: {}, platform: 'win32', home: 'C:\\Users\\u' })).toBe('C:\\Users\\u\\AppData\\Local\\dev-guardian');
  });

  it.runIf(!WIN)('is $XDG_DATA_HOME/dev-guardian (absolute only), else ~/.local/share/dev-guardian', () => {
    expect(userDataDir({ env: { XDG_DATA_HOME: '/data/xdg' }, platform: 'linux', home: '/home/u' })).toBe('/data/xdg/dev-guardian');
    expect(userDataDir({ env: { XDG_DATA_HOME: 'relative' }, platform: 'linux', home: '/home/u' })).toBe(
      '/home/u/.local/share/dev-guardian',
    );
    expect(userDataDir({ env: {}, platform: 'linux', home: '/home/u' })).toBe('/home/u/.local/share/dev-guardian');
  });

  it('the registry is its registry/ directory', () => {
    const dir = join(tmpdir(), 'dg-data');
    expect(registryDir({ env: { GUARDIAN_DATA_DIR: dir } })).toBe(join(dir, 'registry'));
  });
});

describe('writesRegistry', () => {
  let data: string;
  let other: string;
  const ctx = (): { env: Record<string, string> } => ({ env: { GUARDIAN_DATA_DIR: data } });

  beforeEach(() => {
    data = mkdtempSync(join(tmpdir(), 'dg-registry-data-'));
    other = mkdtempSync(join(tmpdir(), 'dg-registry-other-'));
  });
  afterEach(() => {
    rmSync(data, { recursive: true, force: true });
    rmSync(other, { recursive: true, force: true });
  });

  it('a path in the registry, or the registry itself, is — whether or not it exists yet', () => {
    expect(writesRegistry(join(data, 'registry', 'abc.json'), ctx())).toBe(true);
    expect(writesRegistry(join(data, 'registry'), ctx())).toBe(true);
    expect(writesRegistry(join(data, 'registry', 'sub', 'x.json'), ctx())).toBe(true);
  });

  it('the rest of the data directory, and anything else, is not', () => {
    expect(writesRegistry(join(data, 'fallback.db'), ctx())).toBe(false);
    expect(writesRegistry(data, ctx())).toBe(false);
    expect(writesRegistry(join(data, 'registry-old', 'x.json'), ctx())).toBe(false);
    expect(writesRegistry(join(other, 'registry', 'x.json'), ctx())).toBe(false);
  });

  it.runIf(WIN)('in the spellings Windows opens as the same file', () => {
    mkdirSync(join(data, 'registry'));
    expect(writesRegistry(`${join(data, 'registry', 'abc.json')}::$DATA`, ctx())).toBe(true);
    expect(writesRegistry(`${join(data, 'registry', 'abc.json')}.`, ctx())).toBe(true);
    expect(writesRegistry(`${join(data, 'registry')}. \\abc.json`, ctx())).toBe(true);
    expect(writesRegistry(join(data, 'REGISTRY', 'abc.json'), ctx())).toBe(true);
  });

  it('a hard link to an entry, under any name, is — a hard link between other files is not', () => {
    mkdirSync(join(data, 'registry'));
    writeFileSync(join(data, 'registry', 'abc.json'), '{}');
    linkSync(join(data, 'registry', 'abc.json'), join(other, 'notes.json'));
    expect(writesRegistry(join(other, 'notes.json'), ctx())).toBe(true);
    writeFileSync(join(other, 'a.json'), '{}');
    linkSync(join(other, 'a.json'), join(other, 'b.json'));
    expect(writesRegistry(join(other, 'b.json'), ctx())).toBe(false);
  });

  it('a symbolic link into the registry is', (testCtx) => {
    mkdirSync(join(data, 'registry'));
    writeFileSync(join(data, 'registry', 'abc.json'), '{}');
    try {
      symlinkSync(join(data, 'registry', 'abc.json'), join(other, 'link.json'));
    } catch {
      testCtx.skip(); // Windows without Developer Mode cannot make one.
      return;
    }
    expect(writesRegistry(join(other, 'link.json'), ctx())).toBe(true);
  });
});
