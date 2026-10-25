/**
 * `commitScopeFor` — the paths a fix's commit may hold: its own files, and
 * its ecosystem's manifest and lock files. Everything else the worktree
 * gained (an install, a restore's obj/, a test run's coverage/) is not.
 */
import { describe, expect, it } from 'vitest';
import { commitScopeFor } from '../../../src/fixpr/commitScope.js';
import type { FixCandidate, FixGroup, UpgradeStep } from '../../../src/fixpr/types.js';

function step(over: Partial<UpgradeStep>): UpgradeStep {
  return {
    package_name: 'lodash', installed_version: '4.17.20', latest_version: '4.17.21',
    classification: 'security', ecosystem: 'npm', upgrade_command: 'npm install lodash@4.17.21', ...over,
  };
}

function group(source: 'deps' | 'semgrep', candidates: Partial<FixCandidate>[]): FixGroup {
  return {
    source, key: source === 'deps' ? 'npm' : 'semgrep', severity: 'high', hash: 'h',
    candidates: candidates.map((c) => ({ source, fingerprints: ['f'], severity: 'high', command: null, label: 'x', ...c })),
  };
}

describe('commitScopeFor', () => {
  it('npm: the manifest and locks in the project, and a workspace root lock above it — nothing else', () => {
    const scope = commitScopeFor(group('deps', [{ steps: [step({})] }]), 'packages/api/');
    for (const p of ['packages/api/package.json', 'packages/api/package-lock.json', 'packages/package-lock.json', 'package-lock.json']) {
      expect(scope.allows(p), p).toBe(true);
    }
    for (const p of ['package.json', 'packages/api/node_modules/lodash/package.json', 'packages/api/coverage/', 'packages/api/src/a.js']) {
      expect(scope.allows(p), p).toBe(false);
    }
  });

  it('pip: only the file the step edits', () => {
    const scope = commitScopeFor(group('deps', [{ steps: [step({ ecosystem: 'pip', file: 'requirements/base.txt' })] }]), '');
    expect(scope.allows('requirements/base.txt')).toBe(true);
    expect(scope.allows('requirements.txt')).toBe(false);
    expect(scope.allows('__pycache__/x.pyc')).toBe(false);
  });

  it('dotnet: the project file in the project directory, never obj/', () => {
    const scope = commitScopeFor(group('deps', [{ steps: [step({ ecosystem: 'dotnet' })] }]), 'src/App/');
    expect(scope.allows('src/App/App.csproj')).toBe(true);
    expect(scope.allows('src/App/packages.lock.json')).toBe(true);
    expect(scope.allows('Directory.Packages.props')).toBe(true);
    expect(scope.allows('src/App/obj/project.assets.json')).toBe(false);
    expect(scope.allows('src/Other/Other.csproj')).toBe(false);
  });

  it('composer: composer.json and composer.lock, never vendor/', () => {
    const scope = commitScopeFor(group('deps', [{ steps: [step({ ecosystem: 'composer' })] }]), '');
    expect(scope.allows('composer.lock')).toBe(true);
    expect(scope.allows('vendor/')).toBe(false);
  });

  it('semgrep: the target findings’ files only', () => {
    const scope = commitScopeFor(group('semgrep', [{ file_path: 'src/db.ts' }, { file_path: 'src/api.ts' }]), 'app/');
    expect(scope.allows('app/src/db.ts')).toBe(true);
    expect(scope.allows('app/src/api.ts')).toBe(true);
    expect(scope.allows('app/src/other.ts')).toBe(false);
    expect(scope.allows('app/package-lock.json')).toBe(false);
  });
});
