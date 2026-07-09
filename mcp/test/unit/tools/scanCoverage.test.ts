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
  });
});
