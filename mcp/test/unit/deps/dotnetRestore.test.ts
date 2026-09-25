/**
 * `../../../src/deps/dotnetRestore.ts` — the restore plan `deps_audit` and
 * `deps_update_plan` share. The measured SDK behaviour behind each rule is in
 * that module's own header; these tests pin the pure half (target and lock
 * discovery, restore arguments, failure classification) without an SDK.
 */

import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  classifyRestoreFailure,
  findDotnetTargets,
  lockFileCandidates,
  planDotnetRestore,
  projectsForTarget,
  readPackageReferences,
  removeCreatedLockFiles,
} from '../../../src/deps/dotnetRestore.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const PLAIN = '<Project Sdk="Microsoft.NET.Sdk"></Project>';
const OPTED_IN =
  '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile></PropertyGroup></Project>';

function write(root: string, rel: string, content: string): string {
  const abs = join(root, rel);
  mkdirSync(join(abs, '..'), { recursive: true });
  writeFileSync(abs, content, 'utf8');
  return abs;
}

/** A `.sln` the way `dotnet sln add` writes it: backslash paths, plus a
 *  solution folder whose "path" is not a project file. */
function sln(entries: Array<[string, string]>): string {
  const lines = ['Microsoft Visual Studio Solution File, Format Version 12.00'];
  lines.push('Project("{2150E333-8FDC-42A3-9474-1A3956D46DE8}") = "src", "src", "{11111111-1111-1111-1111-111111111111}"', 'EndProject');
  for (const [name, path] of entries) {
    lines.push(`Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "${name}", "${path}", "{22222222-2222-2222-2222-222222222222}"`, 'EndProject');
  }
  return lines.join('\r\n');
}

describe('findDotnetTargets', () => {
  it('prefers a root solution over the project files under it', () => {
    const root = makeTempDir('dn-targets-');
    write(root, 'App.sln', sln([['App', 'src\\App\\App.csproj']]));
    write(root, 'src/App/App.csproj', PLAIN);
    expect(findDotnetTargets(root)).toEqual([join(root, 'App.sln')]);
  });

  it('accepts a .slnx (the SDK 10 default) when there is no .sln', () => {
    const root = makeTempDir('dn-targets-');
    write(root, 'App.slnx', '<Solution><Project Path="src/App/App.csproj" /></Solution>');
    expect(findDotnetTargets(root)).toEqual([join(root, 'App.slnx')]);
  });

  it('finds a project file deeper than the old depth-4 walk when there is no solution', () => {
    const root = makeTempDir('dn-targets-');
    const deep = write(root, 'a/b/c/d/e/Deep.csproj', PLAIN);
    write(root, 'node_modules/x/Ignored.csproj', PLAIN);
    expect(findDotnetTargets(root)).toEqual([deep]);
  });
});

describe('projectsForTarget', () => {
  it('reads a .sln project list (backslash paths, solution folders skipped) and closes over ProjectReference', () => {
    const root = makeTempDir('dn-projects-');
    const solution = write(root, 'Root.sln', sln([['App', 'src\\a\\b\\c\\App\\App.csproj']]));
    const app = write(
      root,
      'src/a/b/c/App/App.csproj',
      '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><ProjectReference Include="..\\..\\..\\..\\..\\lib\\Lib\\Lib.csproj" /></ItemGroup></Project>',
    );
    const lib = write(root, 'lib/Lib/Lib.csproj', PLAIN);
    const projects = projectsForTarget(solution).map((p) => p.toLowerCase());
    expect(projects).toEqual([app.toLowerCase(), lib.toLowerCase()]);
  });

  it('reads a .slnx project list', () => {
    const root = makeTempDir('dn-projects-');
    const solution = write(root, 'Root.slnx', '<Solution><Folder Name="/src/"><Project Path="src/App/App.csproj" /></Folder></Solution>');
    const app = write(root, 'src/App/App.csproj', PLAIN);
    expect(projectsForTarget(solution).map((p) => p.toLowerCase())).toEqual([app.toLowerCase()]);
  });
});

describe('lockFileCandidates', () => {
  it("names NuGet's project-specific lock file as well as the default one", () => {
    const root = makeTempDir('dn-lock-');
    const project = join(root, 'My App.csproj');
    expect(lockFileCandidates(project)).toEqual([
      join(root, 'packages.lock.json'),
      join(root, 'packages.My App.lock.json'),
      join(root, 'packages.My_App.lock.json'),
    ]);
  });
});

describe('planDotnetRestore', () => {
  it('always passes --locked-mode, and stops lock-file creation when no project has a lock', () => {
    const root = makeTempDir('dn-plan-');
    const project = write(root, 'App.csproj', OPTED_IN);
    const plan = planDotnetRestore(root, project);
    expect(plan.args).toEqual([
      'restore',
      project,
      '--locked-mode',
      '--nologo',
      '--verbosity',
      'quiet',
      '-p:RestorePackagesWithLockFile=false',
    ]);
    expect(plan.blocked).toBeUndefined();
  });

  it('finds a lock five directories down through the solution list — and then must NOT pass the false property (NU1005)', () => {
    const root = makeTempDir('dn-plan-');
    const solution = write(root, 'Root.sln', sln([['App', 'src\\a\\b\\c\\App\\App.csproj']]));
    write(root, 'src/a/b/c/App/App.csproj', OPTED_IN);
    const lock = write(root, 'src/a/b/c/App/packages.lock.json', '{}');
    const plan = planDotnetRestore(root, solution);
    expect(plan.lockFiles.map((l) => l.toLowerCase())).toEqual([lock.toLowerCase()]);
    expect(plan.args).toContain('--locked-mode');
    expect(plan.args).not.toContain('-p:RestorePackagesWithLockFile=false');
    expect(plan.blocked).toBeUndefined();
  });

  it('counts packages.<project>.lock.json as a lock', () => {
    const root = makeTempDir('dn-plan-');
    const project = write(root, 'App.csproj', OPTED_IN);
    write(root, 'packages.App.lock.json', '{}');
    const plan = planDotnetRestore(root, project);
    expect(plan.lockFiles).toHaveLength(1);
    expect(plan.args).not.toContain('-p:RestorePackagesWithLockFile=false');
  });

  it('refuses to restore when one project has a lock and another opts in without one (a lock would be created)', () => {
    const root = makeTempDir('dn-plan-');
    const solution = write(root, 'Root.sln', sln([['A', 'A\\A.csproj'], ['B', 'B\\B.csproj']]));
    write(root, 'A/A.csproj', OPTED_IN);
    write(root, 'A/packages.lock.json', '{}');
    write(root, 'B/B.csproj', PLAIN);
    // B opts in through Directory.Build.props, not its own project file.
    write(root, 'B/Directory.Build.props', OPTED_IN);
    const plan = planDotnetRestore(root, solution);
    expect(plan.blocked?.code).toBe('lock_file_would_be_created');
    expect(plan.blocked?.reason).toMatch(/B\.csproj/);
  });

  it('does not refuse a mixed solution whose lock-less project never opts in', () => {
    const root = makeTempDir('dn-plan-');
    const solution = write(root, 'Root.sln', sln([['A', 'A\\A.csproj'], ['B', 'B\\B.csproj']]));
    write(root, 'A/A.csproj', OPTED_IN);
    write(root, 'A/packages.lock.json', '{}');
    write(root, 'B/B.csproj', PLAIN);
    expect(planDotnetRestore(root, solution).blocked).toBeUndefined();
  });
});

describe('removeCreatedLockFiles', () => {
  it('deletes a lock file that appeared during the restore, and only that one', () => {
    const root = makeTempDir('dn-created-');
    const project = write(root, 'App.csproj', PLAIN);
    const plan = planDotnetRestore(root, project);
    const created = write(root, 'packages.lock.json', '{}'); // what a restore would have written
    expect(removeCreatedLockFiles(plan)).toEqual([created]);
    expect(existsSync(created)).toBe(false);
  });

  it('leaves a lock file that was already there', () => {
    const root = makeTempDir('dn-created-');
    const project = write(root, 'App.csproj', PLAIN);
    const lock = write(root, 'packages.lock.json', '{}');
    const plan = planDotnetRestore(root, project);
    expect(removeCreatedLockFiles(plan)).toEqual([]);
    expect(existsSync(lock)).toBe(true);
  });
});

describe('classifyRestoreFailure', () => {
  const at = 'C:\\repo\\App.csproj';
  it('NU1004 is a lock out of sync — and the version range inside the message survives', () => {
    const f = classifyRestoreFailure(
      `${at} : error NU1004: The package reference Newtonsoft.Json version has changed from [12.0.1, ) to [12.0.3, ). [${at}]`,
      '',
    );
    expect(f.code).toBe('NU1004');
    expect(f.kind).toBe('lock_out_of_sync');
    expect(f.reason).toContain('[12.0.1, ) to [12.0.3, )');
    expect(f.reason).not.toContain(`[${at}]`);
  });

  it('NU1101 (package not found) and NU1301 (feed unreachable) are told apart from NU1004', () => {
    expect(classifyRestoreFailure(`${at} : error NU1101: Unable to find package Zz.Nope.`, '')).toMatchObject({
      code: 'NU1101',
      kind: 'package_not_found',
    });
    expect(classifyRestoreFailure('', `${at} : error NU1301: Unable to load the service index for source https://feed/index.json.`)).toMatchObject({
      code: 'NU1301',
      kind: 'feed_unreachable',
    });
  });

  it('skips the NU1903 vulnerability WARNING that restore prints before the real error', () => {
    const f = classifyRestoreFailure(
      [
        `${at} : warning NU1903: Package 'Newtonsoft.Json' 12.0.1 has a known high severity vulnerability`,
        `${at} : error NU1101: Unable to find package Zz.Nope.`,
      ].join('\n'),
      '',
    );
    expect(f.code).toBe('NU1101');
  });

  it('falls back to restore_failed when no error code is printed', () => {
    expect(classifyRestoreFailure('', 'something went wrong')).toMatchObject({ code: 'restore_failed', kind: 'other' });
  });
});

describe('readPackageReferences', () => {
  it('maps each PackageReference (Include or Update) to the project that declares it, lowercased', () => {
    const root = makeTempDir('dn-refs-');
    const app = write(
      root,
      'App.csproj',
      '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.*" /><PackageReference Update="Serilog" /></ItemGroup></Project>',
    );
    const refs = readPackageReferences([app]);
    expect(refs.get('newtonsoft.json')).toBe(app);
    expect(refs.get('serilog')).toBe(app);
  });
});
