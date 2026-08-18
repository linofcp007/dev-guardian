import { mkdirSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join, parse, resolve } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  InvalidProjectPathError,
  resolveProjectPath,
} from '../../../src/platform/projectPath.js';
import { makeTempDir, cleanupTempDirs } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

function tempProject(): string {
  return makeTempDir('dev-guardian-test-');
}

describe('resolveProjectPath', () => {
  it('defaults to process.cwd() when input is missing', () => {
    const r = resolveProjectPath();
    expect(r.path).toBe(resolve(process.cwd()));
  });

  it('accepts a valid existing directory', () => {
    const dir = tempProject();
    expect(resolveProjectPath(dir).path).toBe(resolve(dir));
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

  it('accepts subdirectories of home', () => {
    const sub = join(homedir(), `dev-guardian-test-${Date.now()}`);
    mkdirSync(sub, { recursive: true });
    expect(resolveProjectPath(sub).path).toBe(resolve(sub));
  });
});
