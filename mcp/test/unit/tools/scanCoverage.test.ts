import { describe, expect, it } from 'vitest';
import { assessCoverage, computeCoverage } from '../../../src/tools/scanCoverage.js';
import type { ToolRun } from '../../../src/types.js';

const ok = (name: string): ToolRun => ({ name, status: 'ok' });
const skipped = (name: string, reason = 'not_installed'): ToolRun => ({
  name,
  status: 'skipped',
  reason,
});
const failed = (name: string): ToolRun => ({ name, status: 'failed' });

describe('computeCoverage', () => {
  it('is full when every attempted scanner ran ok and nothing is missing', () => {
    expect(computeCoverage([ok('semgrep'), ok('bandit')], [])).toBe('full');
  });

  it('is full when there was simply nothing to scan (skip not in missing_tools)', () => {
    // scan_containers with no Dockerfile: a skip that is NOT a coverage gap.
    expect(computeCoverage([skipped('trivy', 'no_dockerfile_or_image')], [])).toBe('full');
  });

  it('is none when the only scanner was missing (the 0-critical trap)', () => {
    expect(computeCoverage([skipped('semgrep')], ['semgrep'])).toBe('none');
  });

  it('is none when every scanner that ran failed', () => {
    expect(computeCoverage([failed('semgrep')], [])).toBe('none');
  });

  it('is partial when one ran ok but another was missing', () => {
    expect(computeCoverage([ok('semgrep'), skipped('bandit')], ['bandit'])).toBe('partial');
  });

  it('is partial when one ran ok and another failed', () => {
    expect(computeCoverage([ok('trivy'), failed('npm')], [])).toBe('partial');
  });
});

describe('assessCoverage', () => {
  it('returns no warning for full coverage', () => {
    expect(assessCoverage('sast', [ok('semgrep')], []).warning).toBeNull();
  });

  it('warns loudly that 0 findings is not clean when coverage is none', () => {
    const { coverage, warning } = assessCoverage('sast', [skipped('semgrep')], ['semgrep']);
    expect(coverage).toBe('none');
    expect(warning).toContain('semgrep');
    expect(warning).toMatch(/not a clean bill of health/i);
    expect(warning).toMatch(/0 findings/);
  });

  it('names the missing tool in a partial warning', () => {
    const { coverage, warning } = assessCoverage('deps', [ok('trivy'), skipped('npm')], ['npm']);
    expect(coverage).toBe('partial');
    expect(warning).toContain('npm');
    expect(warning?.toLowerCase()).toContain('partial');
    expect(warning).toMatch(/npm did not run/);
  });

  it('does not say a scanner "did not run" when its own tools_run entry is ok (bug_hunt reduced-coverage retry)', () => {
    // The shape bug_hunt produces after one local `--config` pack fails to
    // load and it retries with the surviving registry packs: semgrep's own
    // tools_run entry is 'ok' (with the detail in `reason`), yet
    // missing_tools still carries 'semgrep' so coverage stays 'partial'.
    const { coverage, warning } = assessCoverage(
      'bugs',
      [{ name: 'semgrep', status: 'ok', reason: 'ran with p/r2c-bug-scan, p/security-audit only' }],
      ['semgrep'],
    );
    expect(coverage).toBe('partial');
    expect(warning).not.toMatch(/semgrep did not run/);
    expect(warning).toMatch(/reduced coverage/);
  });

  // Follow-up 2, item 3: Trivy installed, the only manifest one it cannot
  // read without a lock file. The warning said "NO scanner ran … Install
  // trivy" — advice that sends the user to reinstall a working scanner.
  describe('a manifest Trivy ran on but could not read (no_supported_manifest)', () => {
    const noManifest = skipped('trivy', 'no_supported_manifest');

    it('coverage none: says Trivy ran, names the manifest, and gives the Gradle fix — never "Install trivy"', () => {
      const { coverage, warning } = assessCoverage('deps', [noManifest], ['trivy'], {
        manifestGaps: [{ ecosystem: 'gradle', files: ['build.gradle'] }],
      });
      expect(coverage).toBe('none');
      expect(warning).not.toMatch(/Install trivy/);
      expect(warning).not.toMatch(/NO scanner ran/);
      expect(warning).toMatch(/trivy is installed and ran/);
      expect(warning).toContain('gradle (build.gradle)');
      expect(warning).toMatch(/dependencyLocking \{ lockAllConfigurations\(\) \}/);
      expect(warning).toContain('gradle dependencies --write-locks');
      expect(warning).toMatch(/not a clean bill of health/i);
      expect(warning).toMatch(/0 findings/);
    });

    it('names the Python fix: a lock file Trivy reads, or pinned requirements', () => {
      const { warning } = assessCoverage('deps', [noManifest], ['trivy'], {
        manifestGaps: [{ ecosystem: 'python', files: ['pyproject.toml'] }],
      });
      expect(warning).toContain('python (pyproject.toml)');
      expect(warning).toMatch(/poetry\.lock.*uv\.lock.*Pipfile\.lock/);
      expect(warning).toMatch(/requirements\.txt/);
    });

    it('beside an auditor that is genuinely not installed: install that one, not Trivy', () => {
      const { warning } = assessCoverage('deps_audit', [noManifest, skipped('pip-audit')], ['trivy', 'pip-audit'], {
        manifestGaps: [{ ecosystem: 'python', files: ['pyproject.toml'] }],
      });
      expect(warning).toMatch(/Install pip-audit/);
      expect(warning).not.toMatch(/Install trivy/);
      expect(warning).not.toMatch(/Install[^.]*trivy/);
    });

    it('without the gap list: still no "Install trivy", and the generic fix', () => {
      const { warning } = assessCoverage('deps', [noManifest], ['trivy']);
      expect(warning).not.toMatch(/Install trivy/);
      expect(warning).toMatch(/lock file/);
    });

    it('coverage partial (npm covered, gradle not): trivy ran, gradle not covered, with the fix', () => {
      const { coverage, warning } = assessCoverage(
        'deps',
        [{ name: 'trivy', status: 'ok', reason: 'no_supported_manifest' }],
        ['trivy:gradle'],
        { manifestGaps: [{ ecosystem: 'gradle', files: ['build.gradle.kts'] }] },
      );
      expect(coverage).toBe('partial');
      expect(warning).not.toMatch(/trivy:gradle did not run/);
      expect(warning).toMatch(/trivy ran, but gradle \(build\.gradle\.kts\) was not covered/);
      expect(warning).toContain('gradle dependencies --write-locks');
    });
  });

  it('splits the warning when some gap tools ran ok and others genuinely did not run', () => {
    const { warning } = assessCoverage(
      'bugs',
      [
        { name: 'semgrep', status: 'ok', reason: 'ran with survivors only' },
        skipped('gitleaks'),
      ],
      ['semgrep', 'gitleaks'],
    );
    expect(warning).toMatch(/gitleaks did not run/);
    expect(warning).toMatch(/semgrep ran with reduced coverage/);
  });
});

/**
 * Fix round 3: a scanner that ran but whose rules did not load
 * (`ToolRun.rule_config_error`) is not a missing scanner — the warning names
 * the rule error and never says "install it".
 */
describe('assessCoverage: rules that did not load are not "install"', () => {
  const ruleError: ToolRun = { name: 'semgrep', status: 'failed', reason: 'no rule loaded', rule_config_error: true };

  it('coverage none: says Semgrep ran and its rules did not load — never "NO scanner ran" or "Install semgrep"', () => {
    const { coverage, warning } = assessCoverage('sast', [ruleError], []);
    expect(coverage).toBe('none');
    expect(warning).toMatch(/semgrep ran, but its rules did not load/);
    expect(warning).toMatch(/NOT a clean bill of health/);
    expect(warning).not.toMatch(/install semgrep/i);
    expect(warning).not.toMatch(/NO scanner ran/);
  });

  it('beside a scanner that is not installed: install advice for that one only', () => {
    const { warning } = assessCoverage('sast', [ruleError, skipped('bandit')], ['bandit']);
    expect(warning).toMatch(/semgrep ran, but its rules did not load/);
    expect(warning).toMatch(/install or fix it/);
    expect(warning).toMatch(/bandit/);
    expect(warning).not.toMatch(/install semgrep/i);
  });

  it('partial coverage: the same clause, never "semgrep did not run"', () => {
    const { coverage, warning } = assessCoverage('sast', [ruleError, ok('bandit')], []);
    expect(coverage).toBe('partial');
    expect(warning).toMatch(/semgrep ran, but its rules did not load/);
    expect(warning).not.toMatch(/semgrep did not run/);
  });

  it('control: a crashed scanner (no rule error) keeps the install advice', () => {
    expect(assessCoverage('sast', [failed('semgrep')], []).warning).toMatch(/Install semgrep/);
  });
});
