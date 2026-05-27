import { describe, expect, it } from 'vitest';
import { fromWsl, toShellPath, toWsl } from '../../../src/platform/pathTranslate.js';

describe('toWsl', () => {
  it('translates uppercase drive paths with backslashes', () => {
    expect(toWsl('C:\\Users\\foo\\proj')).toBe('/mnt/c/Users/foo/proj');
  });

  it('translates lowercase drive paths with forward slashes', () => {
    expect(toWsl('d:/code/proj')).toBe('/mnt/d/code/proj');
  });

  it('lowercases the drive letter only', () => {
    expect(toWsl('C:\\Projects\\App')).toBe('/mnt/c/Projects/App');
  });

  it('leaves UNC paths unchanged', () => {
    expect(toWsl('\\\\server\\share\\dir')).toBe('\\\\server\\share\\dir');
  });

  it('leaves relative paths unchanged', () => {
    expect(toWsl('src\\app.ts')).toBe('src\\app.ts');
    expect(toWsl('./src/app.ts')).toBe('./src/app.ts');
  });
});

describe('fromWsl', () => {
  it('inverts toWsl', () => {
    expect(fromWsl('/mnt/c/Users/foo')).toBe('C:\\Users\\foo');
  });

  it('is identity for non-/mnt paths', () => {
    expect(fromWsl('/home/foo')).toBe('/home/foo');
  });
});

describe('toShellPath', () => {
  it('translates when shell needs WSL paths', () => {
    expect(toShellPath('C:\\proj', { needs_wsl_path_translate: true })).toBe('/mnt/c/proj');
  });

  it('is identity when shell does not need WSL paths', () => {
    expect(toShellPath('C:\\proj', { needs_wsl_path_translate: false })).toBe('C:\\proj');
  });
});
