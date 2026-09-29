import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { guardedPath, windowsName } from '../../../src/hooks/guardedPath.js';

// Review of 3.0.0, M1: Windows reads each of these spellings as the file
// itself (or a stream of it), and each got past the Write/Edit guards.
describe('windowsName', () => {
  it.each([
    ['C:\\p\\.guardian\\hooks.config.json::$DATA', 'C:\\p\\.guardian\\hooks.config.json'],
    ['C:\\p\\.guardian\\hooks.config.json::$data', 'C:\\p\\.guardian\\hooks.config.json'],
    ['C:\\p\\.guardian\\hooks.config.json:hidden', 'C:\\p\\.guardian\\hooks.config.json'],
    ['C:\\p\\.guardian\\hooks.config.json:hidden:$DATA', 'C:\\p\\.guardian\\hooks.config.json'],
    ['C:\\p\\.guardian\\hooks.config.json.', 'C:\\p\\.guardian\\hooks.config.json'],
    ['C:\\p\\.guardian\\hooks.config.json . .', 'C:\\p\\.guardian\\hooks.config.json'],
    ['C:\\p\\.guardian.\\hooks.config.json', 'C:\\p\\.guardian\\hooks.config.json'],
    ['C:\\p\\.guardian::$INDEX_ALLOCATION\\hooks.config.json', 'C:\\p\\.guardian\\hooks.config.json'],
    ['C:/p/.claude/settings.json::$DATA', 'C:/p/.claude/settings.json'],
    ['\\\\server\\share\\x\\hooks.json::$DATA', '\\\\server\\share\\x\\hooks.json'],
    // The shell guard's POSIX reading drops an unquoted `\`: the drive stays.
    ['C:proj.guardianhooks.config.json::$DATA', 'C:proj.guardianhooks.config.json'],
  ])('%s', (path, expected) => expect(windowsName(path)).toBe(expected));

  it.each([
    'C:\\p\\.guardian\\hooks.config.json',
    'C:\\p\\...\\x',
    '/home/u/.config/dev-guardian/hooks.json',
    'relative/path.txt',
    'C:',
  ])('leaves %s as it is', (path) => expect(windowsName(path)).toBe(path));

  it('keeps trailing dots in a \\\\?\\ path, where Windows keeps them — the stream still goes', () => {
    expect(windowsName('\\\\?\\C:\\p\\hooks.config.json.')).toBe('\\\\?\\C:\\p\\hooks.config.json.');
    expect(windowsName('\\\\?\\C:\\p\\hooks.config.json::$DATA')).toBe('\\\\?\\C:\\p\\hooks.config.json');
  });
});

describe('guardedPath', () => {
  let dir: string;
  beforeEach(() => {
    dir = realpathSync.native(mkdtempSync(join(tmpdir(), 'guarded-path-')));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('drops the Windows spellings only on win32', () => {
    const none = (): string => {
      throw new Error('absent');
    };
    expect(guardedPath('C:\\p\\hooks.json::$DATA', { platform: 'win32', realpath: none })).toBe('C:\\p\\hooks.json');
    expect(guardedPath('/p/hooks.json::$DATA', { platform: 'linux', realpath: none })).toBe('/p/hooks.json::$DATA');
  });

  it('resolves the existing part and appends the rest', () => {
    mkdirSync(join(dir, '.guardian'));
    expect(guardedPath(join(dir, '.guardian', 'hooks.config.json'))).toBe(join(dir, '.guardian', 'hooks.config.json'));
  });

  it('a link resolves to what it points at', () => {
    mkdirSync(join(dir, '.guardian'));
    writeFileSync(join(dir, '.guardian', 'hooks.config.json'), '{}');
    try {
      symlinkSync(join(dir, '.guardian', 'hooks.config.json'), join(dir, 'innocent.json'));
    } catch {
      return; // no symlink privilege here
    }
    expect(guardedPath(join(dir, 'innocent.json'))).toBe(join(dir, '.guardian', 'hooks.config.json'));
  });

  it.runIf(process.platform === 'win32')('an 8.3 short name resolves to the long one', () => {
    mkdirSync(join(dir, '.guardian'));
    const file = join(dir, '.guardian', 'hooks.config.json');
    writeFileSync(file, '{}');
    const r = spawnSync('cmd.exe', ['/d', '/s', '/c', `"for %I in ("${file}") do @echo %~sI"`], {
      encoding: 'utf8',
      windowsVerbatimArguments: true,
    });
    const short = (r.stdout ?? '').trim();
    if (short === '' || short.toLowerCase() === file.toLowerCase()) return; // 8.3 names off on this volume
    expect(guardedPath(short).toLowerCase()).toBe(file.toLowerCase());
    expect(guardedPath(`${short}::$DATA`).toLowerCase()).toBe(file.toLowerCase());
  });
});
