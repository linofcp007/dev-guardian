import { describe, expect, it } from 'vitest';
import { assessCoverage, computeCoverage, repoSuppressionWarnings } from '../../../src/tools/scanCoverage.js';
import type { ToolRun } from '../../../src/types.js';

const ok = (name: string): ToolRun => ({ name, status: 'ok' });
const skipped = (name: string, reason = 'not_installed'): ToolRun => ({
  name,
  status: 'skipped',
  reason,
});
const failed = (name: string): ToolRun => ({ name, status: 'failed' });

describe('assessCoverage — the manifest walk gap (round 2, item 7)', () => {
  it('trivy ok beside trivy:manifest-walk is partial, worded as a check cut short', () => {
    const a = assessCoverage(
      'deps',
      [{ name: 'trivy', status: 'ok', reason: 'the manifest walk stopped after 20000 directories — manifests below were not checked' }],
      ['trivy:manifest-walk'],
    );
    expect(a.coverage).toBe('partial');
    expect(a.warning).toMatch(/trivy ran, but the check of which dependency manifests it read stopped early/);
    expect(a.warning).not.toMatch(/manifest-walk was not covered/);
  });
});

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

/**
 * Round 4, item 5: a manifest nobody ships (an example, the docs, a test
 * fixture) is still a gap Trivy did not read — the advice names the way to
 * say so, `.guardianignore`, rather than excluding such directories blindly.
 */
/**
 * Review 3.0, wave 2 (c): a package.json with only devDependencies beside a
 * committed lock read "NOTHING was scanned … commit the lock file" — the
 * lock is there; Trivy skips dev dependencies by default.
 */
describe('assessCoverage: a manifest with only devDependencies beside its lock file', () => {
  const noManifest = skipped('trivy', 'no_supported_manifest');

  it('coverage none: says why (only devDependencies, which Trivy skips), never "commit the lock file"', () => {
    const { coverage, warning } = assessCoverage('deps', [noManifest], ['trivy'], {
      manifestGaps: [{ ecosystem: 'npm', files: ['package.json'], dev_only: ['package.json'] }],
    });
    expect(coverage).toBe('none');
    expect(warning).toContain('npm (package.json): only devDependencies, which Trivy skips by default');
    expect(warning).not.toMatch(/commit the lock file/);
    expect(warning).not.toMatch(/has a lock file it can read/);
    expect(warning).toMatch(/not a clean bill of health/i);
  });

  it('the old advice still stands for a manifest with no lock file', () => {
    const { warning } = assessCoverage('deps', [noManifest], ['trivy'], {
      manifestGaps: [{ ecosystem: 'npm', files: ['package.json'] }],
    });
    expect(warning).toMatch(/no dependency manifest here has a lock file it can read/);
    expect(warning).toContain('npm (package.json): commit the lock file your package manager writes');
    expect(warning).not.toMatch(/devDependencies/);
  });

  it('both in one ecosystem: each manifest gets its own advice (none and partial)', () => {
    const gaps = [{ ecosystem: 'npm', files: ['a/package.json', 'b/package.json'], dev_only: ['b/package.json'] }];
    for (const [runs, missing] of [
      [[noManifest], ['trivy']],
      [[ok('trivy')], ['trivy:npm']],
    ] as const) {
      const warning = assessCoverage('deps', runs, missing, { manifestGaps: gaps }).warning ?? '';
      expect(warning).toContain('npm (a/package.json): commit the lock file your package manager writes');
      expect(warning).toContain('npm (b/package.json): only devDependencies, which Trivy skips by default');
    }
  });
});

describe('assessCoverage: manifest advice names .guardianignore', () => {
  it('partial and none both say a manifest that is not shipped can be listed in .guardianignore', () => {
    const gaps = [{ ecosystem: 'npm', files: ['examples/demo/package.json'] }];
    const partial = assessCoverage('deps', [ok('trivy')], ['trivy:npm'], { manifestGaps: gaps }).warning ?? '';
    expect(partial).toMatch(/examples\/demo\/package\.json/);
    expect(partial).toMatch(/\.guardianignore/);
    const none = assessCoverage('deps', [skipped('trivy', 'no_supported_manifest')], ['trivy'], { manifestGaps: gaps }).warning ?? '';
    expect(none).toMatch(/\.guardianignore/);
  });
});

/**
 * Round 4, item 2: findings the repository's own `.trivyignore` suppressed
 * are named in the scan's warnings — counted, never a coverage gap.
 */
describe('repoSuppressionWarnings', () => {
  it('names each run whose repository configuration suppressed findings; coverage untouched', () => {
    const runs: ToolRun[] = [
      {
        name: 'trivy',
        status: 'ok',
        honoured_config: ['.trivyignore'],
        suppressed_by_repo_config: { file: '.trivyignore', count: 2, ids: ['CVE-2020-8203', 'NSWG-ECO-516'], findings: [] },
      },
      {
        name: 'trivy-config',
        status: 'ok',
        honoured_config: ['.trivyignore'],
        suppressed_by_repo_config: {
          file: '.trivyignore',
          count: null,
          ids: [],
          findings: [],
          unlisted_because: 'trivy config has no --show-suppressed',
        },
      },
      ok('semgrep'),
    ];
    expect(repoSuppressionWarnings(runs)).toEqual([
      "trivy: 2 findings suppressed by the repository's .trivyignore: CVE-2020-8203, NSWG-ECO-516 — not reported, " +
        'not counted; remove the entries to see them',
      "trivy-config: what the repository's .trivyignore suppressed cannot be listed (trivy config has no " +
        '--show-suppressed) — its entries are not reported',
    ]);
    expect(assessCoverage('deps', runs, []).coverage).toBe('full');
    expect(repoSuppressionWarnings([ok('trivy')])).toEqual([]);
  });
});
