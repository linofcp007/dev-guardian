/**
 * gosec's report, judged (`runners/gosecRun.ts`), and the package directories
 * it is handed. The reports under `fixtures/scanners/gosec/` are real gosec
 * 2.30.0 output, written in golang:1.25-alpine on 2026-10-24 with
 * `gosec -no-fail -fmt=json -out=<f> -log=<l> -- <dirs>`:
 *
 *   - `project.json`: `fixtures/gosec/project` mounted at /src, the six
 *     directories {@link goPackageDirs} lists for it;
 *   - `go-missing.json`: the same, with no `go` on PATH;
 *   - `go-too-new.json`: a `go.mod` asking for go 1.99, `GOTOOLCHAIN=local`;
 *   - `missing-dep.json`: a module whose one dependency is not in the module
 *     cache, `GOPROXY=off` (at /w/dep/app);
 *   - `not-found.json`: a directory that does not exist.
 */

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  checkGosecReport,
  GOSEC_PACKAGE_NOT_LOADED,
  GOSEC_SYNTAX_ERROR,
  GOSEC_TYPE_ERROR,
  goPackageDirs,
  goToolEnv,
  gosecIssuesIn,
  isGoSource,
} from '../../../src/runners/gosecRun.js';
import { listProjectFiles } from '../../../src/runners/projectFiles.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): string => readFileSync(resolve(here, '../../fixtures/scanners/gosec', name), 'utf8');
const PROJECT = resolve(here, '../../fixtures/gosec/project');

const judge = (raw: string | null, exitCode: number | null = 0, outcome: 'completed' | 'failed' | 'timed_out' = 'completed') =>
  checkGosecReport({ raw, exitCode, outcome });

describe('goPackageDirs', () => {
  it('the fixture project: every package directory, the ones go ignores left out', () => {
    expect(goPackageDirs(listProjectFiles(PROJECT))).toEqual({
      dirs: ['.', 'broken', 'creds', 'ignored', 'syntaxerr', 'vendored'],
      goFiles: 6,
    });
  });

  it('vendor, testdata, dot and underscore directories and files, and tests are not packages', () => {
    const files = [
      'a.go',
      'a_test.go',
      'vendor/x/y.go',
      'pkg/vendor/z.go',
      'testdata/t.go',
      'pkg/testdata/t.go',
      '.hidden/h.go',
      '_tools/t.go',
      'pkg/_x.go',
      'pkg/.x.go',
      'vendored/v.go',
      'vendors/v.go',
      'pkg/sub/b.go',
      'README.md',
      'pkg/x.GO',
    ];
    expect(goPackageDirs(files)).toEqual({ dirs: ['.', 'pkg/sub', 'vendored', 'vendors'], goFiles: 4 });
  });

  it('Windows separators read as POSIX', () => {
    expect(goPackageDirs(['cmd\\api\\main.go'])).toEqual({ dirs: ['cmd/api'], goFiles: 1 });
  });

  it('isGoSource is the same test, one file', () => {
    expect(isGoSource('cmd/main.go')).toBe(true);
    expect(isGoSource('cmd/main_test.go')).toBe(false);
    expect(isGoSource('vendor/a/b.go')).toBe(false);
    expect(isGoSource('main.py')).toBe(false);
  });
});

describe('checkGosecReport', () => {
  it('the fixture project: ok, the type error and the syntax error each named once by its own key', () => {
    const r = judge(fixture('project.json'));
    expect(r.ok).toBe(true);
    expect(r.scanned).toBe(5);
    // The `""` compile summary repeats both files and adds no entry.
    expect(r.partial).toEqual([
      { file: '/src/broken/b.go', type: GOSEC_TYPE_ERROR, message: 'undefined: undefinedThing' },
      { file: '/src/syntaxerr/s.go', type: GOSEC_SYNTAX_ERROR, message: "expected ')', found '{'" },
    ]);
  });

  it('a dependency not in the module cache: the file is a type error, the run ok with what the AST rules found', () => {
    const r = judge(fixture('missing-dep.json'));
    expect(r).toEqual({
      ok: true,
      scanned: 1,
      partial: [{ file: '/w/dep/app/main.go', type: GOSEC_TYPE_ERROR, message: 'could not import github.com/google/uuid (invalid package name: "")' }],
    });
  });

  it('no go on PATH: nothing analysed, every package not loaded — failed, the cause named', () => {
    const r = judge(fixture('go-missing.json'));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/^gosec analysed no file: go command required, not found/);
  });

  it('a go.mod asking for a newer Go: failed, the requirement named', () => {
    const r = judge(fixture('go-too-new.json'));
    expect(r.ok).toBe(false);
    expect(r.reason).toContain('go.mod requires go >= 1.99');
  });

  it('a package not loaded beside one that was: ok, the directory named', () => {
    const raw = JSON.stringify({
      'Golang errors': { pkg: [{ line: 0, column: 0, error: 'loading files from package "pkg": err: exit status 1: stderr: boom' }] },
      Issues: [],
      Stats: { files: 3, lines: 10, nosec: 0, found: 0 },
    });
    expect(judge(raw).partial).toEqual([{ file: 'pkg', type: GOSEC_PACKAGE_NOT_LOADED, message: 'exit status 1: stderr: boom' }]);
  });

  it('a compile summary naming a file no entry names: that file, typed by its message', () => {
    const raw = JSON.stringify({
      'Golang errors': { '': [{ line: 0, column: 0, error: '# example.com/m/a\na/x.go:3:1: syntax error: non-declaration statement outside function body' }] },
      Issues: [],
      Stats: { files: 2, lines: 10, nosec: 0, found: 0 },
    });
    expect(judge(raw).partial).toEqual([
      { file: 'a/x.go', type: GOSEC_SYNTAX_ERROR, message: 'syntax error: non-declaration statement outside function body' },
    ]);
  });

  it('an error that names no file at all: failed, never a clean run', () => {
    const raw = JSON.stringify({
      'Golang errors': { '': [{ line: 0, column: 0, error: '# runtime/cgo\ncgo: C compiler "gcc" not found' }] },
      Issues: [],
      Stats: { files: 4, lines: 10, nosec: 0, found: 0 },
    });
    const r = judge(raw);
    expect(r.ok).toBe(false);
    expect(r.reason).toContain('cgo: C compiler "gcc" not found');
  });

  it('a directory that does not exist: ok, nothing analysed (the caller judges zero)', () => {
    expect(judge(fixture('not-found.json'))).toEqual({ ok: true, scanned: 0 });
  });

  it('no report (what -quiet writes for a clean run), a flag error, an unfinished run: failed', () => {
    expect(judge(null)).toEqual({ ok: false, reason: 'gosec wrote no JSON report' });
    expect(judge('{"Issues": []}')).toEqual({ ok: false, reason: 'gosec wrote no JSON report' });
    expect(judge(null, 2, 'failed')).toEqual({ ok: false, reason: 'exit 2' });
    expect(judge(fixture('project.json'), null, 'timed_out')).toEqual({ ok: false, reason: 'gosec did not finish (timed_out)' });
  });
});

describe('goToolEnv', () => {
  it('-mod=mod, which lets go rewrite go.mod and go.sum, runs as -mod=readonly, and says so', () => {
    const r = goToolEnv({ GOFLAGS: '-trimpath -mod=mod -v', PATH: '/bin' });
    expect(r.env).toEqual({ GOFLAGS: '-trimpath -mod=readonly -v', PATH: '/bin' });
    expect(r.note).toContain('-mod=readonly');
  });

  it('anything else is passed as it is', () => {
    const env = { GOFLAGS: '-mod=vendor', PATH: '/bin' };
    expect(goToolEnv(env)).toEqual({ env, note: null });
    expect(goToolEnv({ PATH: '/bin' }).note).toBeNull();
    expect(goToolEnv({ GOFLAGS: '-mod=modcacherw' }).note).toBeNull();
  });
});

describe('gosecIssuesIn', () => {
  it('keeps the issues of the files asked about, the rest of the report as it was', () => {
    const raw = fixture('project.json');
    const kept = JSON.parse(gosecIssuesIn(raw, '/src', (f) => f === 'creds/creds.go')) as {
      Issues: Array<{ rule_id: string }>;
      Stats: unknown;
      'Golang errors': unknown;
    };
    expect(kept.Issues.map((i) => i.rule_id)).toEqual(['G101']);
    const all = JSON.parse(raw) as { Stats: unknown; 'Golang errors': unknown };
    expect(kept.Stats).toEqual(all.Stats);
    expect(kept['Golang errors']).toEqual(all['Golang errors']);
  });
});
