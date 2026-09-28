/**
 * A project's source languages, which OWASP coverage is judged against:
 * the union of the detect_stack snapshot and the languages of the files the
 * scanners would read — never the snapshot's silence alone, never a
 * truncated listing passed off as complete.
 */

import { execFileSync } from 'node:child_process';
import { mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { canonicalLanguage, languageOfFile } from '../../../src/frameworks/languages.js';
import {
  languagesFromFiles,
  languagesFromFilesAsync,
  languagesOfRuns,
  recordedLanguages,
  resolveProjectLanguages,
} from '../../../src/frameworks/projectLanguages.js';
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
    ['a.py', 'python'],
    ['main.go', 'go'],
    ['A.java', 'java'],
    ['Main.kt', 'kotlin'],
    ['tool.kts', 'kotlin'],
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

  it.each([
    'index.html', 'a.yml', 'main.tf', 'Dockerfile', 'run.sh', 'README.md', 'a.json',
    // A build script, not the product's code.
    'build.gradle.kts', 'settings.gradle.kts',
    // A header belongs to C, C++ or Objective-C alike: the .c/.cpp beside it decides.
    'include/a.h',
    // Declarations carry no code for a rule to match.
    'types/index.d.ts',
    // Minified or generated.
    'app.min.js', 'api.pb.go', 'schema_pb2.py',
  ])('%s is not counted as a source language', (name) => {
    expect(languageOfFile(name)).toBeNull();
  });

  it('reads the names Semgrep and detect_stack use', () => {
    expect(canonicalLanguage('js')).toBe('javascript');
    expect(canonicalLanguage('C#')).toBe('csharp');
    expect(canonicalLanguage('kt')).toBe('kotlin');
    expect(canonicalLanguage('golang')).toBe('go');
    expect(canonicalLanguage('generic')).toBeNull();
  });
});

describe('languagesFromFiles — the files the scanners would read', () => {
  // Exactly what Semgrep 1.176.1 skips by default (measured: build/ vendor/
  // dist/ node_modules/ test/ tests/ testsuite/ at any depth, *_test.go,
  // *.min.js, .venv/ .env/ .tox/ .npm/ .yarn/ _opam/ _build/ _cargo/) — and
  // nothing else: examples, docs, third-party code and hidden directories
  // are scanned, so their languages count. Seen ONLY under a conventional
  // non-product top-level directory, a language is marked peripheral.
  it('excludes what Semgrep excludes, and marks languages seen only under non-product directories', () => {
    const dir = project({
      'src/main.rs': 'fn main() {}',
      'third_party/zlib/inflate.c': '',
      'examples/demo.rb': '',
      'test/fixtures/x.go': '',
      'tests/t.py': '',
      'docs/Sample.java': '',
      'vendor/lib.php': '',
      'Pods/Lib/a.swift': '',
      'node_modules/x/index.js': '',
      '.venv/lib/a.py': '',
      'pkg/a_test.go': '',
      '.github/scripts/release.ts': '',
      'web/index.html': '<p>x</p>',
    });
    expect(languagesFromFiles(dir)).toEqual({
      languages: ['c', 'java', 'ruby', 'rust', 'swift', 'typescript'],
      listing: 'walk',
      peripheral: { c: ['third_party/'], java: ['docs/'], ruby: ['examples/'], swift: ['Pods/'] },
    });
  });

  // R3-1: `com.example` is the Android Studio and Spring Initializr default
  // package; a directory-name exclusion at any depth hid the whole app.
  it('never hides code under a package segment named like a non-product directory', () => {
    const dir = project({
      'app/build.gradle': '',
      'app/src/main/java/com/example/myapplication/MainActivity.kt': 'class MainActivity',
      'src/main/java/com/acme/repository/spec/UserSpec.java': 'class UserSpec {}',
      'src/generated/client.rs': '',
    });
    expect(languagesFromFiles(dir)).toEqual({ languages: ['java', 'kotlin', 'rust'], listing: 'walk' });
  });

  it('honours .guardianignore and a project .semgrepignore', () => {
    const dir = project({
      'app/main.go': '',
      'scripts/gen.py': '',
      'legacy/old.php': '',
      '.guardianignore': 'scripts/\n',
      '.semgrepignore': 'legacy/\n',
    });
    expect(languagesFromFiles(dir).languages).toEqual(['go']);
  });

  it('reads the file list from git inside a work tree, so .gitignore applies', () => {
    const dir = project({ 'src/app.ts': '', 'out-gen/client.java': '', '.gitignore': 'out-gen/\n' });
    execFileSync('git', ['init', '-q'], { cwd: dir });
    const r = languagesFromFiles(dir);
    expect(r).toEqual({ languages: ['typescript'], listing: 'git' });
  });

  it('the async listing agrees', async () => {
    const dir = project({ 'src/app.ts': '', 'out-gen/client.java': '', '.gitignore': 'out-gen/\n' });
    execFileSync('git', ['init', '-q'], { cwd: dir });
    expect(await languagesFromFilesAsync(dir)).toEqual({ languages: ['typescript'], listing: 'git' });
  });

  it('a .h beside .cpp files is C++, never C as well', () => {
    expect(languagesFromFiles(project({ 'include/a.h': '', 'src/a.cpp': '' })).languages).toEqual(['cpp']);
  });

  // Semgrep reads a .h as C: headers with no C++ file in the project are C.
  it('.h files with no C++ file are C', () => {
    expect(languagesFromFiles(project({ 'include/api.h': '', 'README.md': '' })).languages).toEqual(['c']);
    expect(languagesFromFiles(project({ 'include/api.h': '', 'src/impl.hpp': '' })).languages).toEqual(['cpp']);
  });

  // A sparse checkout lists skip-worktree entries that are not on disk.
  it('leaves out skip-worktree entries of a sparse checkout', () => {
    const dir = project({ 'core/a.c': 'int a;', 'tools/b.py': 'x = 1' });
    execFileSync('git', ['init', '-q'], { cwd: dir });
    execFileSync('git', ['add', '-A'], { cwd: dir });
    execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '-m', 'x'], { cwd: dir });
    execFileSync('git', ['update-index', '--skip-worktree', 'tools/b.py'], { cwd: dir });
    rmSync(join(dir, 'tools'), { recursive: true });
    expect(languagesFromFiles(dir)).toEqual({ languages: ['c'], listing: 'git' });
  });

  // N2: 20 050 empty directories used to hide a Rust file and read complete.
  it('a walk stopped at its directory limit is incomplete, and says so', () => {
    const dir = project({ 'z/index.js': '', 'a/lib.rs': '', 'm/1/x': '', 'm/2/x': '', 'm/3/x': '' });
    const r = languagesFromFiles(dir, { useGit: false, maxDirs: 3 });
    expect(r.incomplete).toMatch(/the file walk stopped after 3 directories/);
  });

  // M-a: an unreadable directory used to be skipped silently.
  it('the async walk honours the same limit', async () => {
    const dir = project({ 'z/index.js': '', 'a/lib.rs': '', 'm/1/x': '', 'm/2/x': '', 'm/3/x': '' });
    const r = await languagesFromFilesAsync(dir, { useGit: false, maxDirs: 3 });
    expect(r.incomplete).toMatch(/the file walk stopped after 3 directories/);
  });

  it('an unreadable subdirectory makes the walk incomplete, and is named', () => {
    const dir = project({ 'src/a.js': '', 'locked/b.rs': '' });
    const r = languagesFromFiles(dir, {
      useGit: false,
      readDir: (abs) => {
        if (abs.endsWith('locked')) throw new Error('EACCES: permission denied');
        return readdirSync(abs, { withFileTypes: true });
      },
    });
    expect(r.languages).toEqual(['javascript']);
    expect(r.incomplete).toMatch(/could not read locked/);
  });

  it('answers null for a directory it cannot read', () => {
    expect(languagesFromFiles(join(makeTempDir('proj-langs-'), 'missing')).languages).toBeNull();
  });
});

describe('resolveProjectLanguages — the snapshot AND the files (N1)', () => {
  it('Kotlin sources with a Groovy build.gradle: the snapshot says java, the files add kotlin', () => {
    const dir = project({ 'build.gradle': '', 'app/src/Main.kt': 'fun main() {}' });
    const r = resolveProjectLanguages(stack(['java']), dir);
    expect(r.languages).toEqual(['java', 'kotlin']);
    expect(r.source).toMatch(/detect_stack snapshot of 2026-09-28T10:00:00\.000Z/);
    expect(r.source).toMatch(/kotlin found in the files but not in the snapshot/);
    expect(r.incomplete).toBeUndefined();
  });

  it('names a language seen only under a non-product directory in the source', () => {
    const dir = project({ 'package.json': '{}', 'src/app.js': '', 'examples/demo/src/main.rs': '' });
    const r = resolveProjectLanguages(NO_STACK, dir);
    expect(r.languages).toEqual(['javascript', 'rust']);
    expect(r.peripheral).toEqual({ rust: ['examples/'] });
    expect(r.source).toMatch(/rust only under examples\//);
  });

  it('a stale snapshot does not hide a language added since', () => {
    const dir = project({ 'package.json': '{}', 'web/app.js': '', 'native/Cargo.toml': '', 'native/src/lib.rs': '' });
    expect(resolveProjectLanguages(stack(['javascript']), dir).languages).toEqual(['javascript', 'rust']);
  });

  it('keeps a snapshot language the files do not show (union, never intersection)', () => {
    const dir = project({ 'main.go': '' });
    expect(resolveProjectLanguages(stack(['go', 'python']), dir).languages).toEqual(['go', 'python']);
  });

  it('falls back to the files when there is no snapshot, and to them alone when the snapshot is malformed', () => {
    const dir = project({ 'src/main.rs': '' });
    const r = resolveProjectLanguages(NO_STACK, dir);
    expect(r.languages).toEqual(['rust']);
    expect(r.source).toMatch(/no detect_stack snapshot/);
    expect(resolveProjectLanguages(stack('python'), dir).languages).toEqual(['rust']);
  });

  it('carries an incomplete listing through', () => {
    const dir = project({ 'a/b/c/d.js': '' });
    const r = resolveProjectLanguages(NO_STACK, dir, { walk: { useGit: false, maxDirs: 1 } });
    expect(r.incomplete).toMatch(/stopped after 1 director/);
  });

  it('is unknown — never "no language" — when the project cannot be read', () => {
    const r = resolveProjectLanguages(NO_STACK, join(makeTempDir('proj-langs-'), 'gone'));
    expect(r.languages).toBeNull();
    expect(r.source).toMatch(/could not be determined/);
  });
});

describe('languages recorded at scan time (M-b)', () => {
  it('reads a recorded value back, and refuses a malformed one', () => {
    expect(recordedLanguages({ project_languages: { languages: ['go'], source: 's' } })).toEqual({ languages: ['go'], source: 's' });
    expect(recordedLanguages({ project_languages: { languages: ['go'], source: 's', incomplete: 'why' } })?.incomplete).toBe('why');
    expect(recordedLanguages({ project_languages: { languages: 'go', source: 's' } })).toBeNull();
    expect(recordedLanguages({})).toBeNull();
    expect(recordedLanguages(undefined)).toBeNull();
  });

  const run = (scan_type: string, meta?: Record<string, unknown>) => ({
    scan_id: `${scan_type}-1`,
    scan_type,
    tools_run: [],
    missing_tools: [],
    ...(meta !== undefined ? { meta } : {}),
  });
  const today = { languages: ['javascript'], source: 'file extensions (no detect_stack snapshot)' };

  it('judges against what the scans recorded, not today\'s tree', () => {
    const r = languagesOfRuns([run('sast', { project_languages: { languages: ['rust'], source: 'x' } })], () => today);
    expect(r.languages).toEqual(['rust']);
    expect(r.source).toMatch(/recorded when the scan ran/);
  });

  it('unions several scans, and falls back to today\'s tree for a scan that predates the record — saying so', () => {
    const r = languagesOfRuns(
      [run('sast', { project_languages: { languages: ['go'], source: 'x' } }), run('secrets', {})],
      () => today,
    );
    expect(r.languages).toEqual(['go', 'javascript']);
    expect(r.source).toMatch(/1 older scan predates that record and is judged against today's tree/);
  });

  it('ignores scans no OWASP detector reads (a quality run records nothing)', () => {
    const r = languagesOfRuns([run('sast', { project_languages: { languages: ['go'], source: 'x' } }), run('quality', {})], () => today);
    expect(r.languages).toEqual(['go']);
  });

  it('a language is peripheral only if every scan saw it only under non-product directories', () => {
    const both = languagesOfRuns(
      [
        run('sast', { project_languages: { languages: ['javascript', 'rust'], source: 'x', peripheral: { rust: ['examples/'] } } }),
        run('bugs', { project_languages: { languages: ['javascript', 'rust'], source: 'x' } }),
      ],
      () => today,
    );
    expect(both.peripheral).toBeUndefined();
    const one = languagesOfRuns(
      [run('sast', { project_languages: { languages: ['javascript', 'rust'], source: 'x', peripheral: { rust: ['examples/'] } } })],
      () => today,
    );
    expect(one.peripheral).toEqual({ rust: ['examples/'] });
  });

  it('carries a recorded incomplete listing through', () => {
    const r = languagesOfRuns([run('sast', { project_languages: { languages: ['go'], source: 'x', incomplete: 'walk stopped' } })], () => today);
    expect(r.incomplete).toMatch(/walk stopped/);
  });

  it('uses today\'s tree when no scan is in play', () => {
    expect(languagesOfRuns([], () => today)).toEqual(today);
  });
});
