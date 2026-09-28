import { mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join, parse, relative } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  InvalidProjectPathError,
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
