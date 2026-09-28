/**
 * OWASP Top 10:2025 coverage: a category is `tested` only when, for EVERY
 * source language of the project, a capable detector that ran fully ok has
 * at least MIN_RULES rules for that (category, language). 1–2 rules is
 * `partial` ("thin"), a language with none is `partial` naming the covered
 * and uncovered languages, and nothing at all is `not_tested`. Zero
 * findings from a scanner whose rules cannot see the project's language is
 * "not tested", never a clean bill.
 */

import { describe, expect, it } from 'vitest';
import {
  coverageRunsOf,
  MIN_RULES,
  OWASP_DETECTORS,
  owaspCoverage,
  type CoverageRun,
} from '../../../src/frameworks/coverage.js';
import type { ProjectLanguages } from '../../../src/frameworks/projectLanguages.js';
import { OWASP_2025_IDS, type Owasp2025Id } from '../../../src/frameworks/owaspTop10_2025.js';
import type { ToolRun } from '../../../src/types.js';

function run(scan_type: string, tools_run: ToolRun[], extra: Partial<CoverageRun> = {}): CoverageRun {
  return { scan_id: `${scan_type}-1`, scan_type, tools_run, missing_tools: [], meta: { local_only: false }, ...extra };
}

const langs = (...languages: string[]): ProjectLanguages => ({ languages, source: 'test' });
type Cov = ReturnType<typeof owaspCoverage>;
const statusOf = (cov: Cov): Record<string, string> => Object.fromEntries(cov.categories.map((c) => [c.id, c.status]));
const cat = (cov: Cov, id: Owasp2025Id) => {
  const c = cov.categories.find((x) => x.id === id);
  if (c === undefined) throw new Error(id);
  return c;
};
const tested = (cov: Cov): string[] => cov.categories.filter((c) => c.status === 'tested').map((c) => c.id);
const SAST = (tools: ToolRun[] = [{ name: 'semgrep', status: 'ok' }], extra: Partial<CoverageRun> = {}) => run('sast', tools, extra);

describe('owaspCoverage — per (category, language)', () => {
  it('claims nothing when nothing ran', () => {
    const cov = owaspCoverage([], [], langs('javascript'));
    expect(cov.categories.map((c) => c.id)).toEqual([...OWASP_2025_IDS]);
    expect(cov.categories.every((c) => c.status === 'not_tested')).toBe(true);
  });

  // The review's reproduction: a Rust project, scan_sast ok, 0 findings,
  // used to read A01/A02/A04–A08 "tested". p/default has 1 A05 rule and 3
  // A07 rules for Rust, and none for the rest.
  it('a Rust project: the registry tests A07 (3 rules), A05 is thin, the rest was never looked for', () => {
    const cov = owaspCoverage([SAST()], [], langs('rust'));
    expect(tested(cov)).toEqual(['A07:2025']);
    expect(cat(cov, 'A05:2025').status).toBe('partial');
    expect(cat(cov, 'A05:2025').reasons.join(' ')).toMatch(/thin: 1 rule\(s\) for rust/);
    for (const id of ['A01:2025', 'A02:2025', 'A03:2025', 'A04:2025', 'A06:2025', 'A08:2025', 'A09:2025', 'A10:2025'] as const) {
      expect(cat(cov, id).status, id).toBe('not_tested');
    }
  });

  it('bug_hunt on Rust tests nothing: bugfix-rs has no A10 rule', () => {
    const cov = owaspCoverage([run('bugs', [{ name: 'semgrep', status: 'ok' }])], [], langs('rust'));
    expect(tested(cov)).toEqual([]);
    expect(statusOf(cov)['A10:2025']).toBe('not_tested');
  });

  it('bug_hunt on Go tests A10 (5 rules); on PHP it is thin (2)', () => {
    const bugs = [run('bugs', [{ name: 'semgrep', status: 'ok' }])];
    expect(statusOf(owaspCoverage(bugs, [], langs('go')))['A10:2025']).toBe('tested');
    const php = owaspCoverage(bugs, [], langs('php'));
    expect(cat(php, 'A10:2025').status).toBe('partial');
    expect(cat(php, 'A10:2025').reasons.join(' ')).toMatch(/thin: 2 rule\(s\) for php/);
  });

  it('a Go project with an RGPD run: the pack has no Go rule, so neither A01 nor A09 was tested', () => {
    const cov = owaspCoverage([run('compliance', [{ name: 'semgrep-rgpd', status: 'ok' }, { name: 'trivy', status: 'ok' }])], [], langs('go'));
    expect(tested(cov)).toEqual([]);
    expect(statusOf(cov)['A01:2025']).toBe('not_tested');
    expect(statusOf(cov)['A09:2025']).toBe('not_tested');
    // compliance_check's Trivy pass is license-only.
    expect(statusOf(cov)['A03:2025']).toBe('not_tested');
  });

  it('the RGPD pack is thin for A09 — one rule per language — and claims nothing for A01', () => {
    const cov = owaspCoverage([run('compliance', [{ name: 'semgrep-rgpd', status: 'ok' }])], [], langs('javascript'));
    expect(cat(cov, 'A09:2025').status).toBe('partial');
    expect(cat(cov, 'A09:2025').reasons.join(' ')).toMatch(/thin: 1 rule\(s\) for javascript/);
    expect(cat(cov, 'A01:2025').status).toBe('not_tested');
  });

  it('Python + JS, local_only: Bandit covers Python only, so every category it reaches is partial', () => {
    const cov = owaspCoverage(
      [SAST([{ name: 'semgrep', status: 'ok' }, { name: 'bandit', status: 'ok' }], { meta: { local_only: true } })],
      [],
      langs('javascript', 'python'),
    );
    expect(tested(cov)).toEqual([]);
    const a05 = cat(cov, 'A05:2025');
    expect(a05.status).toBe('partial');
    expect(a05.reasons.join(' ')).toMatch(/covers python; nothing for javascript/);
    expect(a05.languages).toEqual([
      { language: 'javascript', coverage: 'none' },
      { language: 'python', coverage: 'full' },
    ]);
  });

  it('JS + Python with the registry: tested where both have enough rules', () => {
    const cov = owaspCoverage([SAST()], [], langs('javascript', 'python'));
    expect(statusOf(cov)['A05:2025']).toBe('tested');
    expect(statusOf(cov)['A06:2025']).toBe('tested'); // 12 and 5
    expect(statusOf(cov)['A09:2025']).toBe('partial'); // python 1, javascript 0
    expect(cat(cov, 'A09:2025').reasons.join(' ')).toMatch(/thin: 1 rule\(s\) for python/);
    expect(cat(cov, 'A09:2025').reasons.join(' ')).toMatch(/nothing for javascript/);
  });

  it('a Kotlin project: the registry is thin for A05 and A07', () => {
    const cov = owaspCoverage([SAST()], [], langs('kotlin'));
    expect(statusOf(cov)['A05:2025']).toBe('partial');
    expect(statusOf(cov)['A07:2025']).toBe('partial');
    expect(statusOf(cov)['A04:2025']).toBe('tested'); // 11 rules
  });

  it('a project with no source language: only language-agnostic detectors count — and a narrow one only in part', () => {
    const cov = owaspCoverage([SAST(), run('secrets', [{ name: 'gitleaks', status: 'ok' }])], [], langs());
    expect(tested(cov)).toEqual([]);
    expect(statusOf(cov)['A07:2025']).toBe('partial');
    expect(cat(cov, 'A07:2025').reasons.join(' ')).toMatch(/hard-coded credentials only/);
    expect(statusOf(cov)['A05:2025']).toBe('not_tested');
  });

  it('languages that could not be determined make a language-specific claim partial, never tested', () => {
    const cov = owaspCoverage([SAST()], [], { languages: null, source: 'could not be determined' });
    expect(statusOf(cov)['A05:2025']).toBe('partial');
    expect(cat(cov, 'A05:2025').reasons.join(' ')).toMatch(/project languages could not be determined/);
  });

  it('a local_only scan_sast claims nothing from the registry', () => {
    expect(tested(owaspCoverage([SAST([{ name: 'semgrep', status: 'ok' }], { meta: { local_only: true } })], [], langs('javascript')))).toEqual([]);
  });

  it.each(['failed', 'skipped'] as const)('a Semgrep that %s claims nothing', (status) => {
    const cov = owaspCoverage([SAST([{ name: 'semgrep', status, reason: 'x' }])], [], langs('javascript'));
    expect(cov.categories.every((c) => c.status === 'not_tested')).toBe(true);
  });

  it('a partly parsed, rule-losing, listed-missing or scoped run is partial', () => {
    const js = langs('javascript');
    const pp = owaspCoverage([SAST([{ name: 'semgrep', status: 'ok', partially_parsed: [{ file: 'a.js', type: 'PartialParsing', message: 'm' }] }])], [], js);
    expect(statusOf(pp)['A05:2025']).toBe('partial');
    const fr = owaspCoverage([SAST([{ name: 'semgrep', status: 'ok', failed_rules: [{ rule_id: 'r', message: 'm' }] }])], [], js);
    expect(statusOf(fr)['A05:2025']).toBe('partial');
    const lm = owaspCoverage([SAST([{ name: 'semgrep', status: 'ok' }], { missing_tools: ['semgrep'] })], [], js);
    expect(statusOf(lm)['A05:2025']).toBe('partial');
    const sc = owaspCoverage([SAST([{ name: 'semgrep', status: 'ok' }], { meta: { local_only: false, scope: { kind: 'diff' } } })], [], js);
    expect(statusOf(sc)['A05:2025']).toBe('partial');
  });

  it('one complete run beats an incomplete one for the same language', () => {
    const cov = owaspCoverage(
      [
        SAST([{ name: 'semgrep', status: 'ok' }], { scan_id: 'a', missing_tools: ['semgrep'] }),
        SAST([{ name: 'semgrep', status: 'ok' }], { scan_id: 'b' }),
      ],
      [],
      langs('javascript'),
    );
    expect(statusOf(cov)['A05:2025']).toBe('tested');
  });

  it('an orchestrated security_full row claims no registry coverage on its own', () => {
    const cov = owaspCoverage(
      [run('security_full', [{ name: 'semgrep', status: 'ok' }, { name: 'trivy', status: 'ok' }], { meta: { child_scans: [] } })],
      [],
      langs('javascript'),
    );
    expect(tested(cov)).toEqual([]);
    expect(statusOf(cov)['A03:2025']).toBe('partial');
    expect(statusOf(cov)['A05:2025']).toBe('not_tested');
  });
});

describe('owaspCoverage — a narrow language-agnostic detector never tests a category on its own', () => {
  it('gitleaks alone leaves A07 partial, its scope named; the registry with >= 3 rules per language tests it', () => {
    const secrets = run('secrets', [{ name: 'gitleaks', status: 'ok' }]);
    const alone = owaspCoverage([secrets], [], langs('javascript'));
    expect(statusOf(alone)['A07:2025']).toBe('partial');
    expect(cat(alone, 'A07:2025').reasons.join(' ')).toMatch(/gitleaks \(scan_secrets\): hard-coded credentials only/);
    expect(cat(alone, 'A07:2025').languages).toEqual([{ language: 'javascript', coverage: 'narrow' }]);
    // JavaScript has 9 registry A07 rules: the rule-based detector meets the bar.
    expect(statusOf(owaspCoverage([secrets, SAST()], [], langs('javascript')))['A07:2025']).toBe('tested');
    // Kotlin has 2: thin, and gitleaks cannot make up the difference.
    expect(statusOf(owaspCoverage([secrets, SAST()], [], langs('kotlin')))['A07:2025']).toBe('partial');
  });

  it.each([
    ['trivy', 'deps'],
    ['npm', 'deps_audit'],
  ])('%s alone leaves A03 partial: known-vulnerable dependencies only', (tool, type) => {
    const cov = owaspCoverage([run(type, [{ name: tool, status: 'ok' }])], [], langs('javascript'));
    expect(statusOf(cov)['A03:2025']).toBe('partial');
    expect(cat(cov, 'A03:2025').reasons.join(' ')).toMatch(
      /known-vulnerable dependencies only; build and distribution integrity not assessed/,
    );
  });

  it('every language-agnostic or database detector names its narrow scope', () => {
    for (const d of OWASP_DETECTORS) {
      const kinds = Object.values(d.reach).map((r) => r?.kind);
      if (kinds.some((k) => k === 'any-language' || k === 'languages')) expect(d.narrow, d.id).toBeDefined();
    }
  });
});

describe('owaspCoverage — a multi-pass detector is incomplete when another of its passes is not ok (I1)', () => {
  const js = langs('javascript');
  it('gitleaks failed, working tree ok → A07 partial', () => {
    const cov = owaspCoverage(
      [run('secrets', [{ name: 'gitleaks', status: 'failed', reason: 'x' }, { name: 'gitleaks-working-tree', status: 'ok' }])],
      [],
      langs(),
    );
    expect(statusOf(cov)['A07:2025']).toBe('partial');
    expect(cat(cov, 'A07:2025').reasons.join(' ')).toMatch(/gitleaks failed/);
  });

  it('gitleaks ok, working tree failed → A07 partial', () => {
    const cov = owaspCoverage(
      [run('secrets', [{ name: 'gitleaks', status: 'ok' }, { name: 'gitleaks-working-tree', status: 'failed', reason: 'x' }])],
      [],
      langs(),
    );
    expect(statusOf(cov)['A07:2025']).toBe('partial');
  });

  it('a pass skipped as not applicable (not listed missing) is no gap', () => {
    const cov = owaspCoverage(
      [run('secrets', [{ name: 'gitleaks', status: 'ok' }, { name: 'gitleaks-working-tree', status: 'skipped', reason: 'nothing uncommitted' }])],
      [],
      langs(),
    );
    // Partial for gitleaks' narrow scope alone — no "failed", no "missing".
    expect(statusOf(cov)['A07:2025']).toBe('partial');
    expect(cat(cov, 'A07:2025').reasons).toEqual(['gitleaks (scan_secrets): hard-coded credentials only']);
  });

  it('deps_audit: trivy failed, npm ok, pip-audit failed → A03 partial', () => {
    const cov = owaspCoverage(
      [
        run('deps_audit', [
          { name: 'trivy', status: 'failed', reason: 'x' },
          { name: 'npm', status: 'ok' },
          { name: 'pip-audit', status: 'failed', reason: 'y' },
        ]),
      ],
      [],
      js,
    );
    expect(statusOf(cov)['A03:2025']).toBe('partial');
    expect(cat(cov, 'A03:2025').reasons.join(' ')).toMatch(/pip-audit failed/);
  });

  it('npm audit reaches the JavaScript dependencies of a JavaScript project — narrowly', () => {
    const cov = owaspCoverage(
      [run('deps_audit', [{ name: 'trivy', status: 'failed', reason: 'x' }, { name: 'npm', status: 'ok' }])],
      [],
      js,
    );
    expect(statusOf(cov)['A03:2025']).toBe('partial');
    expect(cat(cov, 'A03:2025').languages).toEqual([{ language: 'javascript', coverage: 'narrow' }]);
    // …and nothing of a Python project's.
    const py = owaspCoverage(
      [run('deps_audit', [{ name: 'trivy', status: 'failed', reason: 'x' }, { name: 'npm', status: 'ok' }])],
      [],
      langs('python'),
    );
    expect(statusOf(py)['A03:2025']).toBe('not_tested');
  });

  it('Trivy is language-agnostic for A03 (narrowly); a per-ecosystem gap is an incomplete run', () => {
    const rust = owaspCoverage([run('deps', [{ name: 'trivy', status: 'ok' }])], [], langs('rust'));
    expect(statusOf(rust)['A03:2025']).toBe('partial');
    expect(rust.categories.find((c) => c.id === 'A03:2025')?.languages).toEqual([{ language: 'rust', coverage: 'narrow' }]);
    const gap = owaspCoverage([run('deps', [{ name: 'trivy', status: 'ok' }], { missing_tools: ['trivy:npm'] })], [], js);
    expect(statusOf(gap)['A03:2025']).toBe('partial');
    expect(cat(gap, 'A03:2025').reasons.join(' ')).toMatch(/trivy:npm/);
  });
});

describe('owaspCoverage — review_pr (I2)', () => {
  it('a local_only review claims nothing from the registry', () => {
    const cov = owaspCoverage([run('review_pr', [{ name: 'semgrep', status: 'ok' }], { meta: { local_only: true } })], [], langs('javascript'));
    expect(statusOf(cov)['A05:2025']).toBe('not_tested');
  });

  it('a review row that does not say whether it was local_only claims nothing from the registry', () => {
    const cov = owaspCoverage([run('review_pr', [{ name: 'semgrep', status: 'ok' }], { meta: {} })], [], langs('javascript'));
    expect(statusOf(cov)['A05:2025']).toBe('not_tested');
  });

  it('a registry review is partial: a diff review looks only at changed files', () => {
    const cov = owaspCoverage([run('review_pr', [{ name: 'semgrep', status: 'ok' }], { meta: { local_only: false } })], [], langs('javascript'));
    expect(statusOf(cov)['A05:2025']).toBe('partial');
    expect(cat(cov, 'A05:2025').reasons.join(' ')).toMatch(/diff review/);
  });
});

describe('owaspCoverage — findings and hints', () => {
  it('counts findings per category, and the unmapped ones apart, independently of coverage', () => {
    const cov = owaspCoverage([], [{ owasp: ['A05:2025'] }, { owasp: ['A04:2025', 'A07:2025'] }, { owasp: [] }, {}, { owasp: ['A05:2025'] }], langs('go'));
    expect(cat(cov, 'A05:2025').findings).toBe(2);
    expect(cov.findings_total).toBe(5);
    expect(cov.findings_unmapped).toBe(2);
    expect(statusOf(cov)['A05:2025']).toBe('not_tested');
  });

  it('points only at detectors that reach the project languages, with their rule counts', () => {
    const go = owaspCoverage([], [], langs('go'));
    // Nothing dev-guardian runs has an A09 rule for Go.
    expect(cat(go, 'A09:2025').could_be_tested_by).toEqual([]);
    const js = owaspCoverage([], [], langs('javascript'));
    const hints = cat(js, 'A09:2025').could_be_tested_by.join(' | ');
    // The RGPD pack is named for what it is — personal data in logs, one rule.
    expect(hints).toMatch(/RGPD pack[^|]*javascript 1 \(thin\)[^|]*personal data written to logs only/);
    expect(cat(js, 'A05:2025').could_be_tested_by.join(' | ')).toMatch(/Semgrep registry[^|]*javascript 60/);
  });

  it('records the languages it judged against, and where they came from', () => {
    const cov = owaspCoverage([], [], { languages: ['go'], source: 'detect_stack snapshot of X' });
    expect(cov.languages).toEqual(['go']);
    expect(cov.languages_source).toBe('detect_stack snapshot of X');
  });
});

describe('OWASP_DETECTORS', () => {
  it('uses the threshold the ruling set', () => {
    expect(MIN_RULES).toBe(3);
  });

  it('has unique ids, a basis and a measurement date for each claim, and positive counts only', () => {
    expect(new Set(OWASP_DETECTORS.map((d) => d.id)).size).toBe(OWASP_DETECTORS.length);
    for (const d of OWASP_DETECTORS) {
      expect(d.basis.length, d.id).toBeGreaterThan(20);
      expect(d.measured, d.id).toMatch(/2026-09-28/);
      for (const reach of Object.values(d.reach)) {
        if (reach?.kind !== 'rules') continue;
        for (const n of Object.values(reach.perLanguage)) expect(Number.isInteger(n) && (n ?? 0) > 0).toBe(true);
      }
    }
  });

  it('records the registry measurement the review reproduced', () => {
    const registry = OWASP_DETECTORS.find((d) => d.id === 'semgrep-registry');
    const rules = (id: Owasp2025Id) => {
      const r = registry?.reach[id];
      return r?.kind === 'rules' ? r.perLanguage : {};
    };
    expect(rules('A05:2025').rust).toBe(1);
    expect(rules('A07:2025').rust).toBe(3);
    expect(rules('A01:2025').rust).toBeUndefined();
    expect(rules('A02:2025').php).toBeUndefined();
    expect(rules('A02:2025').ruby).toBeUndefined();
  });

  it('never claims A01 for the RGPD pack', () => {
    expect(OWASP_DETECTORS.find((d) => d.id === 'rgpd-pack')?.reach['A01:2025']).toBeUndefined();
  });
});

describe('coverageRunsOf', () => {
  it('joins each bookkeeping view to its scan, and drops a view whose scan is unknown', () => {
    const runs = coverageRunsOf(
      [
        { scan_id: 's1', tools_run: [{ name: 'semgrep', status: 'ok' }], missing_tools: [] },
        { scan_id: 'gone', tools_run: [{ name: 'gitleaks', status: 'ok' }], missing_tools: [] },
      ],
      [{ scan_id: 's1', scan_type: 'sast', meta: { local_only: false } }],
    );
    expect(runs).toEqual([
      { scan_id: 's1', scan_type: 'sast', meta: { local_only: false }, tools_run: [{ name: 'semgrep', status: 'ok' }], missing_tools: [] },
    ]);
  });
});
