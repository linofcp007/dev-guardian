/**
 * `skillaudit/deps.ts` — the manifest parsers behind `scan_skill`'s OSV
 * lookup (review 3.0, R7-I4: they had no test of their own).
 *
 * What each parser owes OSV: the right ecosystem name (OSV's vocabulary, not
 * the file's), the package name exactly as the registry spells it, and a
 * version only when the manifest pins a concrete one — a range or a tag
 * becomes no version, which makes OSV report every known vulnerability of the
 * package (over-reporting, which the caller flags), never a guessed version.
 */

import { describe, expect, it } from 'vitest';
import { extractDependencies } from '../../../src/skillaudit/deps.js';

const one = (relPath: string, content: string) => extractDependencies([{ relPath, content }]);

describe('extractDependencies — package.json', () => {
  it('reads dependencies, devDependencies and optionalDependencies as npm', () => {
    expect(
      one(
        'package.json',
        JSON.stringify({
          dependencies: { lodash: '4.17.20' },
          devDependencies: { vitest: '^5.0.1' },
          optionalDependencies: { fsevents: '~2.3.3' },
          peerDependencies: { react: '18.0.0' },
        }),
      ),
    ).toEqual([
      { ecosystem: 'npm', name: 'lodash', version: '4.17.20' },
      { ecosystem: 'npm', name: 'vitest', version: '5.0.1' },
      { ecosystem: 'npm', name: 'fsevents', version: '2.3.3' },
    ]);
  });

  it('keeps a prerelease or build suffix, and drops the version of a range or tag it cannot pin', () => {
    expect(
      one('package.json', JSON.stringify({ dependencies: { a: '1.2.3-beta.1', b: 'latest', c: '*', d: '>=2' } })),
    ).toEqual([
      { ecosystem: 'npm', name: 'a', version: '1.2.3-beta.1' },
      { ecosystem: 'npm', name: 'b' },
      { ecosystem: 'npm', name: 'c' },
      { ecosystem: 'npm', name: 'd' },
    ]);
  });

  it('skips what no registry serves: git, http, file, link and workspace specifiers', () => {
    expect(
      one(
        'package.json',
        JSON.stringify({
          dependencies: {
            g: 'git+https://example.test/g.git',
            h: 'https://example.test/h.tgz',
            f: 'file:../f',
            l: 'link:../l',
            w: 'workspace:*',
            kept: '1.0.0',
          },
        }),
      ),
    ).toEqual([{ ecosystem: 'npm', name: 'kept', version: '1.0.0' }]);
  });

  it('a non-string version is a package with no version; a malformed manifest is nothing, never a throw', () => {
    expect(one('package.json', JSON.stringify({ dependencies: { odd: { version: '1.0.0' } } }))).toEqual([
      { ecosystem: 'npm', name: 'odd' },
    ]);
    expect(one('package.json', '{ "dependencies": { "a": ')).toEqual([]);
  });
});

describe('extractDependencies — requirements.txt', () => {
  it('reads name==version as PyPI, and a bare or ranged requirement with no version', () => {
    expect(
      one(
        'requirements.txt',
        ['requests==2.31.0', 'Django>=4.2', 'flask', 'urllib3 == 1.26.18', 'pyyaml==6.0.1; python_version >= "3.8"'].join(
          '\n',
        ),
      ),
    ).toEqual([
      { ecosystem: 'PyPI', name: 'requests', version: '2.31.0' },
      { ecosystem: 'PyPI', name: 'Django' },
      { ecosystem: 'PyPI', name: 'flask' },
      { ecosystem: 'PyPI', name: 'urllib3', version: '1.26.18' },
      { ecosystem: 'PyPI', name: 'pyyaml', version: '6.0.1' },
    ]);
  });

  it('ignores comments, blank lines and pip options (-r, -e, --index-url), CRLF included', () => {
    expect(
      one(
        'requirements.txt',
        ['# pinned', '', '-r base.txt', '-e .', '--index-url https://example.test/simple', 'six==1.16.0  # trailing'].join(
          '\r\n',
        ),
      ),
    ).toEqual([{ ecosystem: 'PyPI', name: 'six', version: '1.16.0' }]);
  });

  it('a two-part pin is sent with no version: OSV matches a point version, and 2.0 is not one', () => {
    expect(one('requirements.txt', 'click==8.1')).toEqual([{ ecosystem: 'PyPI', name: 'click' }]);
  });
});

describe('extractDependencies — go.mod', () => {
  it('reads a require block as Go, with the version OSV expects (no leading v)', () => {
    const gomod = [
      'module example.test/app',
      '',
      'go 1.22',
      '',
      'require (',
      '\tgolang.org/x/net v0.23.0',
      '\tgithub.com/google/uuid v1.6.0 // indirect',
      '\tgithub.com/x/pre v1.2.3-rc.1',
      ')',
    ].join('\n');
    expect(one('go.mod', gomod)).toEqual([
      { ecosystem: 'Go', name: 'golang.org/x/net', version: '0.23.0' },
      { ecosystem: 'Go', name: 'github.com/google/uuid', version: '1.6.0' },
      { ecosystem: 'Go', name: 'github.com/x/pre', version: '1.2.3-rc.1' },
    ]);
  });

  it('never reports the module line or the go directive as a dependency', () => {
    expect(one('go.mod', 'module example.test/m\n\ngo 1.21\n')).toEqual([]);
  });
});

describe('extractDependencies — Cargo.toml', () => {
  it('reads [dependencies], [dev-dependencies] and [build-dependencies] as crates.io, string and table forms', () => {
    const cargo = [
      '[package]',
      'name = "app"',
      'version = "0.1.0"',
      '',
      '[dependencies]',
      'serde = "1.0.197"',
      'tokio = { version = "1.36.0", features = ["full"] }',
      '# a comment',
      'rand = "0.8"',
      '',
      '[dev-dependencies]',
      'proptest = "=1.4.0"',
      '',
      '[build-dependencies]',
      'cc = { version = "1.0.90" }',
      '',
      '[features]',
      'default = "1.2.3"',
    ].join('\n');
    expect(one('Cargo.toml', cargo)).toEqual([
      { ecosystem: 'crates.io', name: 'serde', version: '1.0.197' },
      { ecosystem: 'crates.io', name: 'tokio', version: '1.36.0' },
      { ecosystem: 'crates.io', name: 'rand' },
      { ecosystem: 'crates.io', name: 'proptest', version: '1.4.0' },
      { ecosystem: 'crates.io', name: 'cc', version: '1.0.90' },
    ]);
  });

  it('never reads [package] metadata as a dependency', () => {
    expect(one('Cargo.toml', '[package]\nname = "app"\nversion = "1.2.3"\n')).toEqual([]);
  });
});

describe('extractDependencies — composer.json', () => {
  it('reads require and require-dev as Packagist, skipping the platform (php, ext-*)', () => {
    expect(
      one(
        'composer.json',
        JSON.stringify({
          require: { php: '>=8.1', 'ext-json': '*', 'guzzlehttp/guzzle': '7.8.1', 'monolog/monolog': '^3.0' },
          'require-dev': { 'phpunit/phpunit': '10.5.0' },
        }),
      ),
    ).toEqual([
      { ecosystem: 'Packagist', name: 'guzzlehttp/guzzle', version: '7.8.1' },
      { ecosystem: 'Packagist', name: 'monolog/monolog' },
      { ecosystem: 'Packagist', name: 'phpunit/phpunit', version: '10.5.0' },
    ]);
  });

  it('a malformed composer.json is nothing, never a throw', () => {
    expect(one('composer.json', '{"require": ')).toEqual([]);
  });
});

describe('extractDependencies — Gemfile.lock', () => {
  it('reads the four-space-indented specs as RubyGems, not the six-space dependency lines under them', () => {
    const lock = [
      'GEM',
      '  remote: https://rubygems.org/',
      '  specs:',
      '    rack (2.2.8)',
      '    rails (7.1.3)',
      '      actionpack (= 7.1.3)',
      '',
      'PLATFORMS',
      '  ruby',
    ].join('\n');
    expect(one('Gemfile.lock', lock)).toEqual([
      { ecosystem: 'RubyGems', name: 'rack', version: '2.2.8' },
      { ecosystem: 'RubyGems', name: 'rails', version: '7.1.3' },
    ]);
  });
});

describe('extractDependencies — across files', () => {
  it('matches the manifest by its base name, in any directory and any case', () => {
    expect(
      extractDependencies([
        { relPath: 'server/PACKAGE.JSON', content: JSON.stringify({ dependencies: { a: '1.0.0' } }) },
        { relPath: 'py/Requirements.TXT', content: 'b==2.0.0' },
      ]),
    ).toEqual([
      { ecosystem: 'npm', name: 'a', version: '1.0.0' },
      { ecosystem: 'PyPI', name: 'b', version: '2.0.0' },
    ]);
  });

  it('ignores files that are not manifests it knows — a lockfile it does not parse included', () => {
    expect(
      extractDependencies([
        { relPath: 'package-lock.json', content: JSON.stringify({ dependencies: { a: { version: '1.0.0' } } }) },
        { relPath: 'README.md', content: 'requests==2.31.0' },
        { relPath: 'pyproject.toml', content: '[project]\ndependencies = ["x==1.0.0"]\n' },
      ]),
    ).toEqual([]);
  });

  it('reports a package once per (ecosystem, name, version), however many manifests declare it', () => {
    expect(
      extractDependencies([
        { relPath: 'a/package.json', content: JSON.stringify({ dependencies: { lodash: '4.17.21' } }) },
        { relPath: 'b/package.json', content: JSON.stringify({ devDependencies: { lodash: '^4.17.21' } }) },
        { relPath: 'c/package.json', content: JSON.stringify({ dependencies: { lodash: '4.17.20' } }) },
        { relPath: 'requirements.txt', content: 'lodash==4.17.21' },
      ]),
    ).toEqual([
      { ecosystem: 'npm', name: 'lodash', version: '4.17.21' },
      { ecosystem: 'npm', name: 'lodash', version: '4.17.20' },
      { ecosystem: 'PyPI', name: 'lodash', version: '4.17.21' },
    ]);
  });
});
