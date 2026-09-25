/**
 * The budgets module (task 15, brief item 4): three different budget files
 * were referenced across this codebase's docs (`.guardian/budgets.yml`
 * among them) and nothing read any of them. `loadBudgets` reads the one
 * real file; `evaluatePerfBudgets` / `evaluateQualityBudgets` compare
 * measurements against it; `budgetViolationFindings` turns a violation into
 * the same `Finding` shape every scanner produces, so a budget breach shows
 * up next to every other finding rather than in a shape only this feature
 * understands.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  budgetViolationFindings,
  evaluatePerfBudgets,
  evaluateQualityBudgets,
  loadBudgets,
} from '../../../src/budgets/budgets.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

function writeBudgets(projectPath: string, yaml: string): void {
  mkdirSync(join(projectPath, '.guardian'), { recursive: true });
  writeFileSync(join(projectPath, '.guardian', 'budgets.yml'), yaml, 'utf8');
}

describe('loadBudgets', () => {
  it('reports kind=none when .guardian/budgets.yml does not exist', () => {
    const project = makeTempDir('budgets-');
    expect(loadBudgets(project)).toEqual({ kind: 'none' });
  });

  it('loads perf and quality budgets from .guardian/budgets.yml', () => {
    const project = makeTempDir('budgets-');
    writeBudgets(
      project,
      'perf:\n  lcp_ms: 2500\n  inp_ms: 200\n  cls: 0.1\n  tbt_ms: 300\n  bundle_size_kb: 500\n' +
        'quality:\n  duplication_pct: 5\n  complexity: 15\n',
    );
    const result = loadBudgets(project);
    expect(result.kind).toBe('loaded');
    if (result.kind !== 'loaded') return;
    expect(result.budgets.perf).toEqual({
      lcp_ms: 2500,
      inp_ms: 200,
      cls: 0.1,
      tbt_ms: 300,
      bundle_size_kb: 500,
    });
    expect(result.budgets.quality).toEqual({ duplication_pct: 5, complexity: 15 });
    expect(result.path).toBe(join(project, '.guardian', 'budgets.yml'));
  });

  it('loads a partial file (perf only, or quality only) without complaint', () => {
    const project = makeTempDir('budgets-');
    writeBudgets(project, 'quality:\n  duplication_pct: 3\n');
    const result = loadBudgets(project);
    expect(result.kind).toBe('loaded');
    if (result.kind !== 'loaded') return;
    expect(result.budgets.quality).toEqual({ duplication_pct: 3 });
    expect(result.budgets.perf).toBeUndefined();
  });

  it('reports kind=invalid on unparseable YAML, naming the path', () => {
    const project = makeTempDir('budgets-');
    writeBudgets(project, 'perf: [this is not: valid: yaml');
    const result = loadBudgets(project);
    expect(result.kind).toBe('invalid');
    if (result.kind !== 'invalid') return;
    expect(result.path).toBe(join(project, '.guardian', 'budgets.yml'));
    expect(result.error.length).toBeGreaterThan(0);
  });

  it('reports kind=invalid when a numeric field is not actually a number', () => {
    const project = makeTempDir('budgets-');
    writeBudgets(project, 'perf:\n  lcp_ms: "fast please"\n');
    const result = loadBudgets(project);
    expect(result.kind).toBe('invalid');
  });

  it('reports kind=invalid when the document is not a mapping at all', () => {
    const project = makeTempDir('budgets-');
    writeBudgets(project, '- just\n- a\n- list\n');
    expect(loadBudgets(project).kind).toBe('invalid');
  });
});

describe('evaluatePerfBudgets', () => {
  it('flags every metric that exceeds its budget', () => {
    const violations = evaluatePerfBudgets(
      { lcp_ms: 4000, inp_ms: 150, cls: 0.3, tbt_ms: 200, bundle_size_kb: 900 },
      { lcp_ms: 2500, inp_ms: 200, cls: 0.1, tbt_ms: 300, bundle_size_kb: 500 },
    );
    const names = violations.map((v) => v.budget).sort();
    expect(names).toEqual(['perf.bundle_size_kb', 'perf.cls', 'perf.lcp_ms']);
  });

  it('reports no violations when every measurement is within budget', () => {
    const violations = evaluatePerfBudgets(
      { lcp_ms: 1000, inp_ms: 50, cls: 0.01, tbt_ms: 50, bundle_size_kb: 100 },
      { lcp_ms: 2500, inp_ms: 200, cls: 0.1, tbt_ms: 300, bundle_size_kb: 500 },
    );
    expect(violations).toEqual([]);
  });

  it('skips a metric with no budget set, and one with no measurement', () => {
    const violations = evaluatePerfBudgets({ lcp_ms: 9999 }, { inp_ms: 200 });
    expect(violations).toEqual([]);
  });

  it('returns no violations when no perf budgets are configured at all', () => {
    expect(evaluatePerfBudgets({ lcp_ms: 9999 }, undefined)).toEqual([]);
  });

  it('carries the measured value, the limit and a unit', () => {
    const [v] = evaluatePerfBudgets({ lcp_ms: 4000 }, { lcp_ms: 2500 });
    expect(v).toMatchObject({ budget: 'perf.lcp_ms', measured: 4000, limit: 2500, unit: 'ms' });
  });
});

describe('evaluateQualityBudgets', () => {
  it('flags duplication over budget', () => {
    const violations = evaluateQualityBudgets({ duplication_pct: 12 }, { duplication_pct: 5 });
    expect(violations).toEqual([{ budget: 'quality.duplication_pct', measured: 12, limit: 5, unit: '%' }]);
  });

  it('flags complexity over budget', () => {
    const violations = evaluateQualityBudgets({ complexity: 22 }, { complexity: 15 });
    expect(violations).toEqual([{ budget: 'quality.complexity', measured: 22, limit: 15, unit: '' }]);
  });

  it('reports no violations within budget, or with nothing configured', () => {
    expect(evaluateQualityBudgets({ duplication_pct: 2 }, { duplication_pct: 5 })).toEqual([]);
    expect(evaluateQualityBudgets({ duplication_pct: 99 }, undefined)).toEqual([]);
  });
});

describe('budgetViolationFindings', () => {
  it('maps a perf.* violation to category=performance', () => {
    const [f] = budgetViolationFindings(
      [{ budget: 'perf.lcp_ms', measured: 4000, limit: 2500, unit: 'ms' }],
      '.guardian/budgets.yml',
    );
    expect(f?.category).toBe('performance');
    expect(f?.tool).toBe('budgets');
    expect(f?.rule_id).toBe('perf.lcp_ms');
    expect(f?.file_path).toBe('.guardian/budgets.yml');
    expect(f?.title).toContain('4000');
    expect(f?.title).toContain('2500');
  });

  it('maps a quality.* violation to category=quality', () => {
    const [f] = budgetViolationFindings(
      [{ budget: 'quality.duplication_pct', measured: 12, limit: 5, unit: '%' }],
      '.guardian/budgets.yml',
    );
    expect(f?.category).toBe('quality');
  });

  it('returns one finding per violation, in order', () => {
    const findings = budgetViolationFindings(
      [
        { budget: 'perf.lcp_ms', measured: 4000, limit: 2500, unit: 'ms' },
        { budget: 'perf.cls', measured: 0.3, limit: 0.1, unit: '' },
      ],
      '.guardian/budgets.yml',
    );
    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.rule_id)).toEqual(['perf.lcp_ms', 'perf.cls']);
  });

  it('names the tools that actually read the budgets file, not the CI gate (which does not)', () => {
    const [f] = budgetViolationFindings(
      [{ budget: 'perf.lcp_ms', measured: 4000, limit: 2500, unit: 'ms' }],
      '.guardian/budgets.yml',
    );
    expect(f?.message).not.toMatch(/CI gate/i);
    expect(f?.message).toMatch(/perf_check/);
    expect(f?.message).toMatch(/quality_check/);
  });
});
