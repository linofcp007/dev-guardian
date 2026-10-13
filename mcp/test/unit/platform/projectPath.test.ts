import { mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join, parse, relative } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  InvalidProjectPathError,
  isNetworkPath,
  projectPathErrorCode,
  resolveProjectPath,
} from '../../../src/platform/projectPath.js';
import { makeTempDir, cleanupTempDirs, rmDirOrDefer } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

function tempProject(): string {
  return makeTempDir('dev-guardian-test-');
}

const isWindows = process.platform === 'win32';

describe('resolveProjectPath', () => {
  it('defaults to process.cwd() when input is missing', () => {
    const r = resolveProjectPath();
    expect(r.path).toBe(realpathSync.native(process.cwd()));
  });

  it('accepts a valid existing directory', () => {
    const dir = tempProject();
    expect(resolveProjectPath(dir).path).toBe(realpathSync.native(dir));
  });

  it('rejects a path that does not exist', () => {
    expect(() => resolveProjectPath(join(tmpdir(), 'nope-' + Date.now()))).toThrowError(
      InvalidProjectPathError,
    );
  });

  it('rejects a path that points at a file', () => {
    const dir = tempProject();
    const file = join(dir, 'README');
    writeFileSync(file, 'hi');
    expect(() => resolveProjectPath(file)).toThrowError(InvalidProjectPathError);
  });

  it('rejects the filesystem root', () => {
    const root = parse(process.cwd()).root;
    expect(() => resolveProjectPath(root)).toThrowError(InvalidProjectPathError);
  });

  it('rejects the user-home root', () => {
    expect(() => resolveProjectPath(homedir())).toThrowError(InvalidProjectPathError);
  });

  // A direct child of home, not of tmpdir (on Linux /tmp is not under home) —
  // so `makeTempDir` cannot make it, and it is removed here. Without this, every
  // run left one `~/dev-guardian-test-<ms>` behind: 377 had piled up.
  it('accepts subdirectories of home', () => {
    const sub = mkdtempSync(join(homedir(), 'dev-guardian-test-'));
    try {
      expect(resolveProjectPath(sub).path).toBe(realpathSync.native(sub));
    } finally {
      rmDirOrDefer(sub);
    }
  });
});

// Every scan, finding and snapshot is keyed by the project_path string. The
// live database held the same project twice — `C:\Users\ADMINI~1\…` and
// `C:\Users\Administrator\…` — so a project's history split in two, and a
// project-scoped lookup through one spelling missed everything stored under
// the other.
describe('resolveProjectPath returns one canonical spelling per project', () => {
  it('resolves a link (symlink / junction) to the directory it points at', () => {
    const base = tempProject();
    const real = join(base, 'real-project');
    const link = join(base, 'linked-project');
    mkdirSync(real);
    symlinkSync(real, link, 'junction');

    expect(resolveProjectPath(link).path).toBe(resolveProjectPath(real).path);
    expect(resolveProjectPath(link).path).toBe(realpathSync.native(real));
  });

  // os.tmpdir() is itself an 8.3 short name on many Windows machines
  // (C:\Users\ADMINI~1\…), and a symlink on macOS. test/setup/canonicalTmpdir.ts
  // canonicalises it for the suite and keeps the original spelling here; where
  // the OS has no such alias the case cannot arise, and the test is skipped.
  const rawTmpdir = process.env['GUARDIAN_TEST_RAW_TMPDIR'];
  it.skipIf(rawTmpdir === undefined)('resolves the OS temp-dir alias (8.3 short name / symlink) to the canonical path', () => {
    const dir = tempProject();
    const viaAlias = join(rawTmpdir ?? '', relative(tmpdir(), dir));
    expect(viaAlias).not.toBe(dir);
    expect(resolveProjectPath(viaAlias).path).toBe(realpathSync.native(dir));
    expect(resolveProjectPath(viaAlias).path).toBe(resolveProjectPath(dir).path);
  });

  it.runIf(isWindows)('upper-cases the drive letter', () => {
    const dir = tempProject();
    const lower = dir.replace(/^([A-Za-z]):/, (_m, d: string) => `${d.toLowerCase()}:`);
    expect(resolveProjectPath(lower).path).toMatch(/^[A-Z]:\\/);
    expect(resolveProjectPath(lower).path).toBe(resolveProjectPath(dir).path);
  });

  it.runIf(isWindows)('normalises forward slashes to backslashes', () => {
    const dir = tempProject();
    const forward = dir.replace(/\\/g, '/');
    expect(resolveProjectPath(forward).path).not.toContain('/');
    expect(resolveProjectPath(forward).path).toBe(resolveProjectPath(dir).path);
  });

  it('refuses the home directory reached through a different spelling', () => {
    const home = homedir();
    const spelled = isWindows ? home.replace(/\\/g, '/') : `${home}/.`;
    expect(() => resolveProjectPath(spelled)).toThrowError(InvalidProjectPathError);
  });
});

// Review 8, finding 8: `existsSync` / `statSync` / `realpathSync` on a UNC path
// whose host does not answer block the event loop for about 21 s each — the
// whole server froze on one `detect_stack`. The path is refused on its spelling,
// before any file-system call.
describe('a network (UNC) project_path is refused before any file-system call', () => {
  it('reads two leading separators as a network path on Windows only', () => {
    for (const p of ['\\\\host\\share\\proj', '//host/share/proj', '\\/host/share', '\\\\?\\C:\\x', '\\\\.\\pipe\\x']) {
      expect(isNetworkPath(p, 'win32')).toBe(true);
      expect(isNetworkPath(p, 'linux')).toBe(false);
    }
    for (const p of ['C:\\Users\\x', 'C:/Users/x', '\\Users\\x', 'relative\\dir', '/home/x']) {
      expect(isNetworkPath(p, 'win32')).toBe(false);
    }
  });

  // A non-routable address: a regression (an fs call first) blocks ~21 s and
  // fails on the test's timeout rather than on its assertion.
  it.runIf(isWindows)('refuses \\\\host\\share with reason network_path, without touching it', () => {
    for (const p of ['\\\\10.255.255.7\\share\\proj', '//10.255.255.7/share/proj']) {
      let error: unknown;
      try {
        resolveProjectPath(p);
      } catch (e) {
        error = e;
      }
      expect(error).toBeInstanceOf(InvalidProjectPathError);
      expect((error as InvalidProjectPathError).reason).toBe('network_path');
      expect((error as Error).message).toMatch(/network \(UNC\) path/);
      expect(projectPathErrorCode(error)).toBe('unsupported_target');
    }
  }, 5_000);
});

// Review 8, finding 16: every tool answered a refused project_path with
// `not_a_git_repo`, a cause none of these has.
describe('projectPathErrorCode', () => {
  it('names a missing path target_not_found and an unusable one unsupported_target', () => {
    const dir = tempProject();
    const file = join(dir, 'README');
    writeFileSync(file, 'hi');
    const codeOf = (p: string): string => {
      try {
        resolveProjectPath(p);
      } catch (e) {
        return projectPathErrorCode(e);
      }
      return 'resolved';
    };
    expect(codeOf(join(dir, 'missing'))).toBe('target_not_found');
    expect(codeOf(file)).toBe('unsupported_target');
    expect(codeOf(homedir())).toBe('unsupported_target');
    expect(codeOf(parse(process.cwd()).root)).toBe('unsupported_target');
    expect(projectPathErrorCode(new Error('anything else'))).toBe('unsupported_target');
  });
});
