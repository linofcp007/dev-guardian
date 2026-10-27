import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { compileGlob, expandGlob, hasGlobMagic, matchesAny } from '../../../src/platform/glob.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';
import { expectLinear } from '../../helpers/timing.js';

afterAll(cleanupTempDirs);

describe('glob', () => {
  it('matches *, ?, ** and {a,b} over POSIX relative paths', () => {
    expect(compileGlob('packages/*').test('packages/web')).toBe(true);
    expect(compileGlob('packages/*').test('packages/web/sub')).toBe(false);
    expect(compileGlob('packages/**').test('packages/web/sub')).toBe(true);
    expect(compileGlob('**/rules/*.yml').test('rules/a.yml')).toBe(true);
    expect(compileGlob('**/rules/*.yml').test('x/y/rules/a.yml')).toBe(true);
    expect(compileGlob('rules/*.{yml,yaml}').test('rules/a.yaml')).toBe(true);
    expect(compileGlob('r?.yml').test('r1.yml')).toBe(true);
    expect(compileGlob('./apps/*/').test('apps/api')).toBe(true);
    expect(compileGlob('a.b').test('axb')).toBe(false);
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

/**
 * What `compileGlob` was until it stopped backtracking: the same pattern as an
 * anchored regular expression. Every match it makes, the matcher makes.
 */
function asRegExp(pattern: string): RegExp {
  const escape = (text: string): string => text.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  const p = pattern.replace(/\\/g, '/').replace(/^(\.\/)+/, '').replace(/\/+$/, '');
  let re = '';
  for (let i = 0; i < p.length; i++) {
    const c = p.charAt(i);
    if (c === '*') {
      if (p.charAt(i + 1) === '*') {
        const atSegmentStart = i === 0 || p.charAt(i - 1) === '/';
        const atSegmentEnd = i + 2 === p.length || p.charAt(i + 2) === '/';
        if (atSegmentStart && atSegmentEnd) {
          if (i + 2 === p.length) {
            re += '.*';
            i += 1;
          } else {
            re += '(?:[^/]*/)*';
            i += 2;
          }
          continue;
        }
        re += '[^/]*';
        i += 1;
        continue;
      }
      re += '[^/]*';
    } else if (c === '?') {
      re += '[^/]';
    } else if (c === '{') {
      const close = p.indexOf('}', i);
      if (close === -1) {
        re += '\\{';
        continue;
      }
      re += `(?:${p.slice(i + 1, close).split(',').map(escape).join('|')})`;
      i = close;
    } else {
      re += escape(c);
    }
  }
  return new RegExp(`^${re}$`);
}

describe('compileGlob matches exactly what the regular expression did', () => {
  // A small deterministic generator: every pattern piece against every path
  // shape, short enough for the expression to answer at once.
  let seed = 7;
  const next = (n: number): number => {
    seed = (seed * 1103515245 + 12345) % 2147483648;
    return seed % n;
  };
  const PATTERN_PIECES = ['a', 'b', '/', '*', '**', '**/', '?', '{a,b}', '{,a/b}', '{', '}', '.', '\\', './', ','];
  const PATH_PIECES = ['a', 'b', '/', '.', '{', '}', ',', '\n', 'ab/', 'a/b'];
  const build = (pieces: readonly string[], count: number): string =>
    Array.from({ length: count }, () => pieces[next(pieces.length)] ?? '').join('');

  it('on 4 000 generated pattern and path pairs', () => {
    for (let i = 0; i < 4_000; i++) {
      const pattern = build(PATTERN_PIECES, 1 + next(6));
      const path = build(PATH_PIECES, next(7));
      expect(compileGlob(pattern).test(path), `${JSON.stringify(pattern)} against ${JSON.stringify(path)}`).toBe(
        asRegExp(pattern).test(path),
      );
    }
  });
});

// A pattern is the scanned repository's (a workspace manifest): each shape
// hands a backtracking matcher a choice at every wildcard.
describe('compileGlob stays linear in the path, whatever the wildcards', () => {
  it.each([
    ['eight ** segments, a deep path that does not match', '**/'.repeat(8) + 'z', (n: number): string => `${'a/'.repeat(n / 2)}y`],
    ['*a six times, a long name that does not match', '*a'.repeat(6) + '*b', (n: number): string => 'a'.repeat(n)],
  ])('%s: a path eight times as long costs well under 22.6 times as much', (label, pattern, path) => {
    const glob = compileGlob(pattern);
    expectLinear(label, (n) => glob.test(path(n)), 64);
  }, 120_000);

  it('a pattern of slashes is trimmed in one pass', () => {
    expectLinear('trailing slashes', (n) => compileGlob(`${'/'.repeat(n)}x`), 4_000);
  }, 120_000);
});
