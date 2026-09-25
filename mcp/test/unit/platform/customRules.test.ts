/**
 * `resolveCustomSemgrepConfigs` — the reading side of `register_custom_rules`
 * — and `validateSemgrepRulesFile`, which both sides use.
 *
 * The read half of this feature did not exist until 2026-08-18. Task 11 of
 * the 2026-09-25 review fixed three more things it did wrong:
 *
 *   - registration was GLOBAL: project A's rules ran on every scan of project
 *     B served by the same database. It is keyed per canonical project now;
 *     the old global key still counts, but only for entries inside the
 *     project being scanned (it cannot say which project registered them);
 *   - any YAML counted, so `rules/` full of Prometheus alerts was registered
 *     and every later scan_sast died with exit 7, 0 files scanned. Each file
 *     is validated as a Semgrep rules file, at registration AND at read;
 *   - `rules: []` gave exit 0 with nothing scanned. Empty is invalid.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  CUSTOM_RULES_META_KEY,
  customRulesMetaKey,
  inspectCustomSemgrepConfigs,
  legacyRegistrationNote,
  legacyRegistrationsNotApplied,
  resolveCustomSemgrepConfigs,
  validateSemgrepRulesFile,
} from '../../../src/platform/customRules.js';
import type { PluginContext } from '../../../src/context.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const VALID = [
  'rules:',
  '  - id: no-eval',
  '    message: no eval',
  '    languages: [javascript]',
  '    severity: ERROR',
  '    pattern: eval(...)',
  '',
].join('\n');

/** Minimal stand-in for the runtime_meta methods the resolver touches. */
function ctxWith(entries: Record<string, unknown>, throws = false): PluginContext {
  const runtimeMeta = {
    getJson<T>(key: string): T | null {
      if (throws) throw new Error('runtime_meta unreadable');
      return key in entries ? (entries[key] as T) : null;
    },
  };
  return { storage: { runtimeMeta } } as unknown as PluginContext;
}

function ruleFile(dir: string, name = 'rules.yml', text = VALID): string {
  const file = join(dir, name);
  writeFileSync(file, text);
  return file;
}

describe('validateSemgrepRulesFile', () => {
  it('accepts a file whose every rule has id, message, languages and a pattern key', () => {
    const dir = makeTempDir('guardian-customrules-');
    expect(validateSemgrepRulesFile(ruleFile(dir))).toEqual({ ok: true, rules: 1 });
    const taint = ruleFile(
      dir,
      'taint.yml',
      [
        'rules:',
        '  - id: t',
        '    mode: taint',
        '    message: m',
        '    languages: [python]',
        '    severity: ERROR',
        '    pattern-sources: [{pattern: source()}]',
        '    pattern-sinks: [{pattern: sink(...)}]',
        '',
      ].join('\n'),
    );
    expect(validateSemgrepRulesFile(taint).ok).toBe(true);
  });

  it('rejects YAML that is not a Semgrep rules file (a Prometheus alerts file)', () => {
    const dir = makeTempDir('guardian-customrules-');
    const alerts = ruleFile(dir, 'alerts.yml', 'groups:\n  - name: node\n    rules:\n      - alert: HighLoad\n        expr: up == 0\n');
    const verdict = validateSemgrepRulesFile(alerts);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/rules/);
  });

  it('rejects an empty rules list — Semgrep exits 0 and scans nothing for it', () => {
    const dir = makeTempDir('guardian-customrules-');
    const verdict = validateSemgrepRulesFile(ruleFile(dir, 'empty.yml', 'rules: []\n'));
    expect(verdict).toEqual({ ok: false, reason: 'empty `rules:` list' });
  });

  it('names the rule and the missing key', () => {
    const dir = makeTempDir('guardian-customrules-');
    const noLanguages = ruleFile(dir, 'x.yml', 'rules:\n  - id: a\n    message: m\n    pattern: f()\n');
    expect(validateSemgrepRulesFile(noLanguages)).toEqual({ ok: false, reason: "rule 'a' has no `languages`" });
    const noPattern = ruleFile(dir, 'y.yml', 'rules:\n  - id: b\n    message: m\n    languages: [js]\n');
    expect(validateSemgrepRulesFile(noPattern)).toEqual({ ok: false, reason: "rule 'b' has no pattern key" });
    const noId = ruleFile(dir, 'z.yml', 'rules:\n  - message: m\n    languages: [js]\n    pattern: f()\n');
    expect(validateSemgrepRulesFile(noId)).toEqual({ ok: false, reason: 'rule #1 has no `id`' });
  });

  it('requires a severity Semgrep accepts — without one Semgrep exits 7 and scans nothing', () => {
    // Measured on Semgrep 1.176.1: no `severity` → InvalidRuleSchemaError,
    // exit 7, paths.scanned 0 — once registered it would abort every scan.
    // Lower-case values fail the same way; the legacy and the newer
    // upper-case levels load.
    const dir = makeTempDir('guardian-customrules-');
    const withSeverity = (severity: string | null): string =>
      ruleFile(
        dir,
        `sev-${severity ?? 'none'}.yml`,
        `rules:\n  - id: s\n    message: m\n    languages: [javascript]\n${severity === null ? '' : `    severity: ${severity}\n`}    pattern: f()\n`,
      );
    expect(validateSemgrepRulesFile(withSeverity(null))).toEqual({ ok: false, reason: "rule 's' has no `severity`" });
    expect(validateSemgrepRulesFile(withSeverity('warning'))).toEqual({
      ok: false,
      reason: "rule 's' has severity 'warning', which Semgrep rejects (expected one of INFO, WARNING, ERROR, LOW, MEDIUM, HIGH, CRITICAL, EXPERIMENT, INVENTORY)",
    });
    for (const ok of ['INFO', 'WARNING', 'ERROR', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']) {
      expect(validateSemgrepRulesFile(withSeverity(ok)).ok).toBe(true);
    }
  });

  it('rejects invalid YAML and a missing file', () => {
    const dir = makeTempDir('guardian-customrules-');
    expect(validateSemgrepRulesFile(ruleFile(dir, 'bad.yml', 'rules: [\n')).ok).toBe(false);
    expect(validateSemgrepRulesFile(join(dir, 'nope.yml')).ok).toBe(false);
  });
});

describe('resolveCustomSemgrepConfigs', () => {
  it('returns only THIS project\'s registration, never another project\'s', () => {
    const a = makeTempDir('guardian-customrules-a-');
    const b = makeTempDir('guardian-customrules-b-');
    const aRules = ruleFile(a);
    const bRules = ruleFile(b);
    const ctx = ctxWith({ [customRulesMetaKey(a)]: [aRules], [customRulesMetaKey(b)]: [bRules] });
    expect(resolveCustomSemgrepConfigs(ctx, a)).toEqual([aRules]);
    expect(resolveCustomSemgrepConfigs(ctx, b)).toEqual([bRules]);
  });

  it('reads the legacy global key only for entries inside the project being scanned', () => {
    const a = makeTempDir('guardian-customrules-a-');
    const b = makeTempDir('guardian-customrules-b-');
    const aRules = ruleFile(a);
    const bRules = ruleFile(b);
    const ctx = ctxWith({ [CUSTOM_RULES_META_KEY]: [aRules, bRules] });
    expect(resolveCustomSemgrepConfigs(ctx, a)).toEqual([aRules]);
    expect(resolveCustomSemgrepConfigs(ctx, b)).toEqual([bRules]);
  });

  it('names the 2.0.x registrations it no longer applies, and says how to re-register them', () => {
    const a = makeTempDir('guardian-customrules-a-');
    const b = makeTempDir('guardian-customrules-b-');
    const aRules = ruleFile(a);
    const bRules = ruleFile(b);
    const ctx = ctxWith({ [CUSTOM_RULES_META_KEY]: [aRules, bRules] });
    expect(legacyRegistrationsNotApplied(ctx, a)).toEqual([bRules]);
    const note = legacyRegistrationNote(legacyRegistrationsNotApplied(ctx, a));
    expect(note).toContain(bRules);
    expect(note).toContain('register_custom_rules');
    expect(legacyRegistrationNote([])).toBeNull();
  });

  it('drops a registered path that no longer exists, rather than passing it on', () => {
    // Load-bearing: semgrep aborts the WHOLE scan when any --config fails to
    // resolve (exit 7, results:[], paths.scanned:[]).
    const project = makeTempDir('guardian-customrules-');
    const alive = ruleFile(project);
    const dead = join(project, 'deleted-subdir');
    expect(resolveCustomSemgrepConfigs(ctxWith({ [customRulesMetaKey(project)]: [alive, dead] }), project)).toEqual([alive]);
  });

  it('expands a registered directory into its valid rule files, and reports the rest', () => {
    const project = makeTempDir('guardian-customrules-');
    const dir = join(project, '.semgrep');
    mkdirSync(join(dir, 'deep'), { recursive: true });
    const good = ruleFile(dir, 'a.yml');
    const nested = ruleFile(join(dir, 'deep'), 'b.yaml');
    ruleFile(dir, 'alerts.yml', 'groups: []\n');
    writeFileSync(join(dir, 'README.md'), '# not yaml');
    const inspection = inspectCustomSemgrepConfigs(ctxWith({ [customRulesMetaKey(project)]: [dir] }), project);
    expect(inspection.usable).toEqual([good, nested]);
    expect(inspection.unusable).toEqual([{ path: join(dir, 'alerts.yml'), reason: 'no `rules:` list' }]);
  });

  it('drops a registered file that stopped being a valid rules file since it was registered', () => {
    const project = makeTempDir('guardian-customrules-');
    const file = ruleFile(project, 'rules.yml', 'rules: []\n');
    const inspection = inspectCustomSemgrepConfigs(ctxWith({ [customRulesMetaKey(project)]: [file] }), project);
    expect(inspection.usable).toEqual([]);
    expect(inspection.unusable).toEqual([{ path: file, reason: 'empty `rules:` list' }]);
  });

  it('returns [] when nothing is registered, and for a hand-edited non-array value', () => {
    const project = makeTempDir('guardian-customrules-');
    expect(resolveCustomSemgrepConfigs(ctxWith({}), project)).toEqual([]);
    expect(resolveCustomSemgrepConfigs(ctxWith({ [customRulesMetaKey(project)]: '.semgrep' }), project)).toEqual([]);
  });

  it('ignores non-string and empty entries inside the array', () => {
    const project = makeTempDir('guardian-customrules-');
    const alive = ruleFile(project);
    expect(
      resolveCustomSemgrepConfigs(ctxWith({ [customRulesMetaKey(project)]: [alive, '', 42, null] }), project),
    ).toEqual([alive]);
  });

  it('degrades to [] when runtime_meta itself throws', () => {
    const project = makeTempDir('guardian-customrules-');
    expect(resolveCustomSemgrepConfigs(ctxWith({}, true), project)).toEqual([]);
  });
});
