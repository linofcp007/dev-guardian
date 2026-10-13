/**
 * One reading of a requirements file, and one finder for them (review 8,
 * finding 5): `deps_update_plan`, `validate_finding`'s PyPI pins and
 * `scan_skill` each parsed `requirements.txt` their own way — three cut a line
 * at ANY `#` (a URL fragment, `pkg==1.0#x`), one joined continuations with a
 * space, one did not join them at all — and `deps_audit`, `deps_update_plan`
 * and `create_fix_pr` each found the files their own way.
 */
import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { exactPin, findRequirementFiles, parseRequirementSpec, requirementMentions } from '../../../src/deps/pipRequirements.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

describe('requirementMentions — the lines pip reads', () => {
  it('a pip-compile hash-pinned entry: the continuation joined, the hashes dropped', () => {
    const text = ['django==4.2.0 \\', '    --hash=sha256:aaaa \\', '    --hash=sha256:bbbb', 'six==1.16.0', ''].join('\n');
    expect(requirementMentions(text)).toEqual([
      { line: 1, name: 'django', specifier: '==4.2.0' },
      { line: 4, name: 'six', specifier: '==1.16.0' },
    ]);
  });

  it('extras, markers, ranges, bare names and old-style parentheses', () => {
    const text = [
      'celery[redis]==5.3.0 ; python_version >= "3.8"',
      'requests>=2,<3  # pinned by hand',
      'flask',
      'bar (>=1.0)',
      'local==1.0+abc',
    ].join('\r\n');
    expect(requirementMentions(text)).toEqual([
      { line: 1, name: 'celery', extras: '[redis]', specifier: '==5.3.0' },
      { line: 2, name: 'requests', specifier: '>=2,<3' },
      { line: 3, name: 'flask', specifier: '' },
      { line: 4, name: 'bar', specifier: '>=1.0' },
      { line: 5, name: 'local', specifier: '==1.0+abc' },
    ]);
  });

  it('a # is a comment only at the start or after whitespace, as pip reads it', () => {
    // `split('#')` read `pkg==1.0#egg` as a pin of 1.0; pip reads one requirement it cannot parse.
    expect(requirementMentions('# all of it\npkg==1.0#egg\nok==2.0 #note\n')).toEqual([{ line: 3, name: 'ok', specifier: '==2.0' }]);
  });

  it('options, includes, editables, URLs, paths and direct references name no registry package', () => {
    const text = [
      '-r base.txt',
      '--index-url https://pypi.example.com/simple',
      '-e .',
      '-e git+https://github.com/a/b.git#egg=b',
      'foo @ https://example.com/foo-1.0.whl',
      'https://example.com/bar-1.0.tar.gz',
      './vendor/baz',
      'user/repo#main',
    ].join('\n');
    expect(requirementMentions(text)).toEqual([]);
  });

  it('a continuation joins with NOTHING between, as pip does — not with a space', () => {
    // `--ind\` + `ex-url` is `--index-url` to pip: one option line, no requirement.
    expect(requirementMentions('--ind\\\nex-url https://x\nreal==1.0\n')).toEqual([{ line: 3, name: 'real', specifier: '==1.0' }]);
  });
});

describe('parseRequirementSpec / exactPin', () => {
  it.each([
    ['urllib3==1.26.0; python_version >= "3.8"', { name: 'urllib3', specifier: '==1.26.0' }],
    ['pkg[a,b]~=1.4', { name: 'pkg', extras: '[a,b]', specifier: '~=1.4' }],
    ['name @ git+https://x', null],
    ['-e .', null],
    ['', null],
  ] as const)('%s', (spec, expected) => {
    expect(parseRequirementSpec(spec)).toEqual(expected);
  });

  it('an exact pin is one == or === clause, no wildcard', () => {
    expect(exactPin('==1.2.3')).toBe('1.2.3');
    expect(exactPin('===2.0')).toBe('2.0');
    expect(exactPin('==1.2.*')).toBeUndefined();
    expect(exactPin('==1.2,!=1.2.1')).toBeUndefined();
    expect(exactPin('>=1')).toBeUndefined();
    expect(exactPin('')).toBeUndefined();
  });
});

describe('findRequirementFiles — the one finder', () => {
  it('requirements*.txt at the root and *.txt one level into requirements/, as project-relative / paths', () => {
    const project = makeTempDir('reqfiles-');
    writeFileSync(join(project, 'requirements.txt'), 'a==1\n');
    writeFileSync(join(project, 'Requirements-dev.txt'), 'b==1\n');
    writeFileSync(join(project, 'requirements.in'), 'c\n');
    mkdirSync(join(project, 'requirements', 'deeper'), { recursive: true });
    writeFileSync(join(project, 'requirements', 'base.txt'), 'd==1\n');
    writeFileSync(join(project, 'requirements', 'deeper', 'never.txt'), 'e==1\n');
    mkdirSync(join(project, 'requirements-dir.txt'));
    const found = findRequirementFiles(project);
    expect(found.files.sort()).toEqual(['Requirements-dev.txt', 'requirements.txt', 'requirements/base.txt']);
    expect(found.outside).toEqual([]);
  });

  it.runIf(process.platform !== 'win32')('a candidate linked out of the project is outside — never a file to read', () => {
    const project = makeTempDir('reqfiles-link-');
    const elsewhere = join(tmpdir(), `reqfiles-out-${process.pid}.txt`);
    writeFileSync(elsewhere, 'x==1\n');
    symlinkSync(elsewhere, join(project, 'requirements.txt'));
    expect(findRequirementFiles(project)).toEqual({ files: [], outside: ['requirements.txt'], other: [] });
  });
});
