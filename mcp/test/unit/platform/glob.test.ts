import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { expandGlob, globToRegExp, hasGlobMagic, matchesAny } from '../../../src/platform/glob.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

describe('glob', () => {
  it('matches *, ?, ** and {a,b} over POSIX relative paths', () => {
    expect(globToRegExp('packages/*').test('packages/web')).toBe(true);
    expect(globToRegExp('packages/*').test('packages/web/sub')).toBe(false);
    expect(globToRegExp('packages/**').test('packages/web/sub')).toBe(true);
    expect(globToRegExp('**/rules/*.yml').test('rules/a.yml')).toBe(true);
    expect(globToRegExp('**/rules/*.yml').test('x/y/rules/a.yml')).toBe(true);
    expect(globToRegExp('rules/*.{yml,yaml}').test('rules/a.yaml')).toBe(true);
    expect(globToRegExp('r?.yml').test('r1.yml')).toBe(true);
    expect(globToRegExp('./apps/*/').test('apps/api')).toBe(true);
    expect(globToRegExp('a.b').test('axb')).toBe(false);
  });

  it('honours later negations', () => {
    expect(matchesAny('packages/web', ['packages/**', '!**/test/**'])).toBe(true);
    expect(matchesAny('packages/test/x', ['packages/**', '!**/test/**'])).toBe(false);
    expect(matchesAny('tools/x', ['packages/*'])).toBe(false);
  });

  it('knows a literal path from a pattern', () => {
    expect(hasGlobMagic('rules/a.yml')).toBe(false);
    expect(hasGlobMagic('rules/*.yml')).toBe(true);
  });

  it('expands a pattern to the paths that exist, never into node_modules or .git', () => {
    const root = makeTempDir('glob-');
    mkdirSync(join(root, 'rules', 'nested'), { recursive: true });
    mkdirSync(join(root, 'node_modules', 'rules'), { recursive: true });
    writeFileSync(join(root, 'rules', 'a.yml'), '');
    writeFileSync(join(root, 'rules', 'nested', 'b.yaml'), '');
    writeFileSync(join(root, 'rules', 'c.txt'), '');
    writeFileSync(join(root, 'node_modules', 'rules', 'd.yml'), '');
    const rel = expandGlob(root, 'rules/**/*.{yml,yaml}').map((p) => p.slice(root.length + 1).replace(/\\/g, '/'));
    expect(rel).toEqual(['rules/a.yml', 'rules/nested/b.yaml']);
  });
});
