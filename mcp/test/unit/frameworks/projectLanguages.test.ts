/**
 * A project's source languages, which OWASP coverage is judged against:
 * the detect_stack snapshot when there is one, else the files' extensions.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { canonicalLanguage, languageOfFile } from '../../../src/frameworks/languages.js';
import { languagesFromFiles, resolveProjectLanguages } from '../../../src/frameworks/projectLanguages.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

function project(files: Record<string, string>): string {
  const dir = makeTempDir('proj-langs-');
  for (const [rel, text] of Object.entries(files)) {
    const abs = join(dir, rel);
    mkdirSync(join(abs, '..'), { recursive: true });
    writeFileSync(abs, text);
  }
  return dir;
}

function stack(languages: unknown, captured_at = '2026-09-28T10:00:00.000Z') {
  return { getLatestForProject: () => ({ captured_at, snapshot: { languages } }) };
}
const NO_STACK = { getLatestForProject: () => null };

describe('languageOfFile / canonicalLanguage', () => {
  it.each([
    ['a.js', 'javascript'],
    ['a.MJS', 'javascript'],
    ['a.tsx', 'typescript'],
    ['types.d.ts', 'typescript'],
    ['a.py', 'python'],
    ['main.go', 'go'],
    ['A.java', 'java'],
    ['b.kts', 'kotlin'],
    ['P.cs', 'csharp'],
    ['i.php', 'php'],
    ['r.rb', 'ruby'],
    ['main.rs', 'rust'],
    ['v.swift', 'swift'],
    ['x.c', 'c'],
    ['x.hpp', 'cpp'],
    ['m.ex', 'elixir'],
  ])('%s → %s', (name, lang) => {
    expect(languageOfFile(name)).toBe(lang);
  });

  it.each(['index.html', 'a.yml', 'main.tf', 'Dockerfile', 'run.sh', 'README.md', 'a.json'])(
    '%s is not a source language',
    (name) => {
      expect(languageOfFile(name)).toBeNull();
    },
  );

  it('reads the names Semgrep and detect_stack use', () => {
    expect(canonicalLanguage('js')).toBe('javascript');
    expect(canonicalLanguage('C#')).toBe('csharp');
    expect(canonicalLanguage('kt')).toBe('kotlin');
    expect(canonicalLanguage('golang')).toBe('go');
    expect(canonicalLanguage('generic')).toBeNull();
    expect(canonicalLanguage('hcl')).toBeNull();
  });
});

describe('languagesFromFiles', () => {
  it('lists the source languages present, skipping dependency and hidden directories', () => {
    const dir = project({
      'src/main.rs': 'fn main() {}',
      'web/index.html': '<p>x</p>',
      'node_modules/x/index.js': '',
      '.venv/lib/a.py': '',
      'Cargo.toml': '',
    });
    expect(languagesFromFiles(dir)).toEqual({ languages: ['rust'], complete: true });
  });

  it('answers null for a directory it cannot read', () => {
    expect(languagesFromFiles(join(makeTempDir('proj-langs-'), 'missing')).languages).toBeNull();
  });
});

describe('resolveProjectLanguages', () => {
  it('prefers the detect_stack snapshot for the languages it detects', () => {
    // A stray script is not a project language when detect_stack says so.
    const dir = project({ 'main.go': '', 'tools/gen.py': '' });
    const r = resolveProjectLanguages(stack(['go']), dir);
    expect(r.languages).toEqual(['go']);
    expect(r.source).toMatch(/detect_stack snapshot of 2026-09-28T10:00:00\.000Z/);
  });

  // detect_stack knows nine languages; C#, Swift, C and the rest are
  // invisible to it, so a snapshot's silence about them says nothing.
  it('adds, from the files, the languages detect_stack cannot detect', () => {
    const dir = project({ 'App.csproj': '', 'Program.cs': '', 'web/app.js': '' });
    const r = resolveProjectLanguages(stack(['javascript']), dir);
    expect(r.languages).toEqual(['csharp', 'javascript']);
    expect(r.source).toMatch(/file extensions for csharp/);
  });

  it('falls back to the files when there is no snapshot', () => {
    const dir = project({ 'src/main.rs': '', 'Cargo.toml': '' });
    const r = resolveProjectLanguages(NO_STACK, dir);
    expect(r.languages).toEqual(['rust']);
    expect(r.source).toMatch(/file extensions \(no detect_stack snapshot\)/);
  });

  it('ignores a snapshot whose languages field is not a list of strings', () => {
    const dir = project({ 'a.py': '' });
    expect(resolveProjectLanguages(stack('python'), dir).languages).toEqual(['python']);
  });

  it('is unknown — never "no language" — when the project cannot be read', () => {
    const r = resolveProjectLanguages(NO_STACK, join(makeTempDir('proj-langs-'), 'gone'));
    expect(r.languages).toBeNull();
    expect(r.source).toMatch(/could not be determined/);
  });
});
