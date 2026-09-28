/**
 * Global Constraint 3 for one Semgrep run: exit 0/1 is necessary, never
 * sufficient. The report must exist, parse, have scanned something when there
 * were targets, and carry no `errors`.
 */

import { describe, expect, it } from 'vitest';
import { checkSemgrepReport, describePartialParse, describeRulesNotLoaded } from '../../../src/runners/semgrepReport.js';

const report = (over: Record<string, unknown> = {}): string =>
  JSON.stringify({ results: [], errors: [], paths: { scanned: ['a.py'] }, ...over });

describe('checkSemgrepReport', () => {
  it('accepts exit 0 with files scanned and no errors', () => {
    expect(checkSemgrepReport({ raw: report(), exitCode: 0, outcome: 'completed', targets: 1 })).toEqual({
      ok: true,
      verdict: 'ok',
      scanned: 1,
      errors: 0,
    });
  });

  it('accepts exit 1 (findings) the same way', () => {
    const r = checkSemgrepReport({ raw: report(), exitCode: 1, outcome: 'failed', targets: 1 });
    expect(r.ok).toBe(true);
  });

  it('fails exit 7 (registry unreachable, bad config) — never "findings"', () => {
    const raw = report({
      paths: { scanned: [] },
      errors: [{ type: 'SemgrepError', level: 'error', message: 'Failed to download configuration from https://semgrep.dev/c/auto' }],
    });
    const r = checkSemgrepReport({ raw, exitCode: 7, outcome: 'failed', targets: 3 });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/exit 7/);
    expect(r.reason).toMatch(/Failed to download configuration/);
  });

  it('fails exit 0 that scanned nothing although targets were given', () => {
    const r = checkSemgrepReport({
      raw: report({ paths: { scanned: [] } }),
      exitCode: 0,
      outcome: 'completed',
      targets: 2,
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/scanned 0 of 2/);
  });

  it('fails exit 0 with a non-empty errors array', () => {
    const raw = report({
      errors: [{ type: ['PartialParsing', []], level: 'warn', message: 'Syntax error at line broken.py:1' }],
    });
    const r = checkSemgrepReport({ raw, exitCode: 0, outcome: 'completed', targets: 1 });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/1 Semgrep error/);
    expect(r.reason).toMatch(/Syntax error/);
  });

  it('fails when no report was written, or it is not JSON', () => {
    expect(checkSemgrepReport({ raw: null, exitCode: 0, outcome: 'completed', targets: 1 }).ok).toBe(false);
    expect(checkSemgrepReport({ raw: '{nope', exitCode: 0, outcome: 'completed', targets: 1 }).ok).toBe(false);
  });

  it('fails a run that was cancelled or timed out whatever the report says', () => {
    const r = checkSemgrepReport({ raw: report(), exitCode: null, outcome: 'timed_out', targets: 1 });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/timed_out/);
  });
});

/**
 * Follow-up X1: the per-file / warn-level classification `map_attack_surface`
 * had on its own now lives in the one judge, as a `partial` verdict, so
 * scan_sast, map_attack_surface and the batched runs agree: `paths.scanned > 0`
 * with only per-file non-fatal errors is partial coverage with the files
 * named; anything fatal stays `failed`. `ok` stays true only for a complete
 * run — a caller that reads nothing else keeps failing a partial one.
 */
describe('checkSemgrepReport verdicts: ok, partial, scanned_nothing, failed', () => {
  // Verbatim from Semgrep 1.176.1 over the WordPress fixture (`const NAMESPACE`).
  const WORDPRESS_WARNING = {
    code: 3,
    level: 'warn',
    type: ['PartialParsing', [{ path: 'rest-controller.php', start: { line: 20, col: 2, offset: 0 }, end: { line: 20, col: 34, offset: 32 } }]],
    message: "Syntax error at line rest-controller.php:20:\n `const NAMESPACE = 'guardian/v2';` was unexpected",
    path: 'rest-controller.php',
    spans: [{ file: 'rest-controller.php', start: { line: 20, col: 2, offset: 0 }, end: { line: 20, col: 34, offset: 32 } }],
  };
  const check = (over: Record<string, unknown>, exitCode = 0, targets = 1) =>
    checkSemgrepReport({ raw: report(over), exitCode, outcome: exitCode === 0 ? 'completed' : 'failed', targets });

  it('partial: a warn-level PartialParsing on a scanned file — not ok, the file named', () => {
    const r = check({ paths: { scanned: ['rest-controller.php'] }, errors: [WORDPRESS_WARNING] });
    expect(r.ok).toBe(false);
    expect(r.verdict).toBe('partial');
    expect(r.partial).toEqual([
      { file: 'rest-controller.php', type: 'PartialParsing', message: 'Syntax error at line rest-controller.php:20:' },
    ]);
    // The reason still says what happened, for callers that print it.
    expect(r.reason).toMatch(/1 Semgrep error/);
  });

  it('partial on exit 1 too (findings beside the warning), and for a per-file error named only by a span', () => {
    const r = check(
      { paths: { scanned: ['a.js', 'b.js'] }, errors: [{ level: 'error', type: 'Syntax error', message: 'bad', spans: [{ file: 'b.js' }] }] },
      1,
    );
    expect(r.verdict).toBe('partial');
    expect(r.partial?.map((p) => p.file)).toEqual(['b.js']);
  });

  it('partial names the files project-relative when given the project', () => {
    const r = checkSemgrepReport({
      raw: report({ paths: { scanned: ['/p/wp.php'] }, errors: [{ ...WORDPRESS_WARNING, path: '/p/wp.php', type: ['PartialParsing', []], spans: [] }] }),
      exitCode: 0,
      outcome: 'completed',
      targets: 1,
      projectPath: '/p',
    });
    expect(r.partial?.map((p) => p.file)).toEqual(['wp.php']);
  });

  it('scanned_nothing: a clean exit, no error, nothing scanned although there were targets', () => {
    expect(check({ paths: { scanned: [] } }, 0, 2).verdict).toBe('scanned_nothing');
    // No targets asked for: nothing to scan is no gap.
    expect(check({ paths: { scanned: [] } }, 0, 0).verdict).toBe('ok');
  });

  it.each([
    ['a rule error, even naming a target', { level: 'error', type: 'Rule parse error', message: 'bad pattern', path: 'a.js' }],
    ['an invalid rule schema', { level: 'error', type: 'InvalidRuleSchemaError', message: '' }],
    ['a SemgrepError', { level: 'error', type: 'SemgrepError', message: 'invalid configuration file found' }],
    ['an error tied to no target file', { level: 'warn', type: 'Timeout', message: 'rule timed out' }],
    ['an error naming a YAML file (it cannot be told from the rule pack)', { level: 'warn', type: 'Other syntax error', message: 'x', path: 'rules.yml' }],
  ])('failed: %s is fatal, even beside a per-file one', (_label, fatal) => {
    const r = check({ paths: { scanned: ['rest-controller.php'] }, errors: [WORDPRESS_WARNING, fatal] });
    expect(r.verdict).toBe('failed');
    expect(r.partial).toBeUndefined();
  });

  it('failed: per-file errors on a run that scanned nothing, on an unclean exit, or on a run that did not finish', () => {
    expect(check({ paths: { scanned: [] }, errors: [WORDPRESS_WARNING] }).verdict).toBe('failed');
    expect(check({ paths: { scanned: ['rest-controller.php'] }, errors: [WORDPRESS_WARNING] }, 2).verdict).toBe('failed');
    const timedOut = checkSemgrepReport({
      raw: report({ paths: { scanned: ['rest-controller.php'] }, errors: [WORDPRESS_WARNING] }),
      exitCode: null,
      outcome: 'timed_out',
      targets: 1,
    });
    expect(timedOut.verdict).toBe('failed');
  });
});

describe('checkSemgrepReport: the partial list is per file (fix round 1)', () => {
  it('collapses repeated errors of one type on one file, keeps each type, and counts files', () => {
    const entry = (type: string, path: string) => ({ level: 'warn', type, message: `${type} at ${path}`, path });
    const r = checkSemgrepReport({
      raw: report({
        paths: { scanned: ['a.php', 'b.php'] },
        errors: [entry('PartialParsing', 'a.php'), entry('PartialParsing', 'a.php'), entry('Timeout', 'a.php'), entry('PartialParsing', 'b.php')],
      }),
      exitCode: 0,
      outcome: 'completed',
      targets: 1,
    });
    expect(r.verdict).toBe('partial');
    expect(r.partial?.map((p) => `${p.type}:${p.file}`)).toEqual(['PartialParsing:a.php', 'Timeout:a.php', 'PartialParsing:b.php']);
    expect(describePartialParse(r.partial ?? [], 'x')).toMatch(/^partial: 2 file\(s\) only partly parsed/);
  });
});

describe('describePartialParse', () => {
  it('names every file and its error type, and what may be missing', () => {
    expect(
      describePartialParse(
        [
          { file: 'rest-controller.php', type: 'PartialParsing', message: 'x' },
          { file: 'b.js', type: 'Syntax error', message: 'y' },
        ],
        'findings in the unparsed spans may be missing',
      ),
    ).toBe(
      'partial: 2 file(s) only partly parsed — findings in the unparsed spans may be missing ' +
        '(PartialParsing: rest-controller.php; Syntax error: b.js)',
    );
  });
});

/**
 * Fix round 2: the judge tells "a rule did not compile" from "semgrep did
 * not run". Both are `failed` to a caller that reads the verdict alone; a
 * run whose only errors are rules that did not load (and per-file problems)
 * also names those rules, so bug_hunt can record Semgrep as run, with a
 * narrower gap, instead of coverage none and "install semgrep".
 */
describe('checkSemgrepReport: rules that did not load while the others ran', () => {
  // The 1.176.1 shape, measured: a local rule file with one bad pattern —
  // exit 2, the good rule's result reported, the file scanned.
  const PREFIX = 'C.Users.dev..claude.plugins.cache.dev-guardian.2.0.0.configs.semgrep';
  const RULE_ERROR = {
    code: 2,
    level: 'error',
    type: 'Rule parse error',
    rule_id: `${PREFIX}.broken-rule`,
    message:
      `Rule parse error in rule ${PREFIX}.broken-rule:\n Invalid pattern for JavaScript: Stdlib.Parsing.Parse_error\n` +
      '----- pattern -----\nfoo((((\n----- end pattern -----\n',
  };
  const WARNING = { code: 3, level: 'warn', type: ['PartialParsing', []], message: 'Syntax error at line wp/a.php:3', path: 'wp/a.php' };
  const strip = (id: string): string => (id.startsWith(`${PREFIX}.`) ? id.slice(PREFIX.length + 1) : id);

  it('names each rule by its stored id and what is wrong with it; the verdict stays failed', () => {
    const r = checkSemgrepReport({
      raw: report({ errors: [RULE_ERROR, RULE_ERROR], paths: { scanned: ['app.js'] } }),
      exitCode: 2,
      outcome: 'failed',
      targets: 1,
      ruleIdOf: strip,
    });
    expect(r.verdict).toBe('failed');
    expect(r.ok).toBe(false);
    expect(r.rules_not_loaded).toEqual([{ rule_id: 'broken-rule', message: 'Invalid pattern for JavaScript: Stdlib.Parsing.Parse_error' }]);
    expect(r.partial).toBeUndefined();
  });

  it('keeps the per-file problems beside it, project-relative', () => {
    const r = checkSemgrepReport({
      raw: report({ errors: [RULE_ERROR, { ...WARNING, path: '/p/wp/a.php' }], paths: { scanned: ['app.js', 'wp/a.php'] } }),
      exitCode: 2,
      outcome: 'failed',
      targets: 1,
      projectPath: '/p',
    });
    expect(r.rules_not_loaded?.map((x) => x.rule_id)).toEqual([`${PREFIX}.broken-rule`]);
    expect(r.partial?.map((p) => p.file)).toEqual(['wp/a.php']);
  });

  it.each([
    ['a rule error that names no rule', { errors: [{ type: 'Rule parse error', level: 'error', message: 'bad' }] }, 2],
    ['beside a config error', { errors: [RULE_ERROR, { type: 'SemgrepError', level: 'error', message: 'Invalid YAML file' }] }, 2],
    ['beside an error that is not tied to a file', { errors: [RULE_ERROR, { type: 'Timeout', level: 'error', message: 'x' }] }, 2],
    ['on a whole-project run that scanned nothing', { errors: [RULE_ERROR], paths: { scanned: [] } }, 2],
    ['on exit 7 (the whole config did not load)', { errors: [RULE_ERROR] }, 7],
  ])('never on %s — that is semgrep failing', (_label, over, exitCode) => {
    const r = checkSemgrepReport({ raw: report(over), exitCode, outcome: 'failed', targets: 1 });
    expect(r.verdict).toBe('failed');
    expect(r.rules_not_loaded).toBeUndefined();
  });

  it('on a batch judged with targets 0 (its caller judges "scanned" over the run): a batch no rule applies to still names the rule', () => {
    // Measured on 1.176.1: a .py batch under a JavaScript pack with one bad
    // rule exits 2 with the rule error and `paths.scanned: []`.
    const r = checkSemgrepReport({ raw: report({ errors: [RULE_ERROR], paths: { scanned: [] } }), exitCode: 2, outcome: 'failed', targets: 0, ruleIdOf: strip });
    expect(r.rules_not_loaded?.map((x) => x.rule_id)).toEqual(['broken-rule']);
  });

  it('describeRulesNotLoaded says Semgrep ran, names each rule and why, and never "install"', () => {
    const text = describeRulesNotLoaded([{ rule_id: 'y', message: 'Invalid pattern' }, { rule_id: 'z', message: 'bad' }], 3);
    expect(text).toBe(
      'Semgrep ran, but 2 rule(s) did not load: y — Invalid pattern; z — bad. ' +
        'Findings of the other rules over 3 file(s) are kept; fix or remove the rule and re-run',
    );
    expect(text).not.toMatch(/install/i);
  });

  it('never on a run that did not finish', () => {
    const r = checkSemgrepReport({ raw: report({ errors: [RULE_ERROR] }), exitCode: 2, outcome: 'timed_out', targets: 1 });
    expect(r.rules_not_loaded).toBeUndefined();
  });
});

/**
 * Fix round 3: a run whose rule configuration Semgrep refused names the rule
 * error (`rule_config_error`), so no caller says "install semgrep" for it.
 */
describe('checkSemgrepReport: a refused rule configuration', () => {
  // Measured on 1.176.1: a rule with `languages: [klingon]` — exit 8, nothing
  // scanned, an entry with no `message`, only short_msg / long_msg.
  const UNKNOWN_LANGUAGE = {
    code: 8,
    level: 'error',
    type: 'UnknownLanguageError',
    long_msg: 'unsupported language: klingon. supported languages are: apex, bash, c\n\nYou may need to update your version of Semgrep.',
    short_msg: 'invalid language: klingon',
    spans: [],
  };

  it('an unknown language: failed, the rule error named — its text read from short_msg', () => {
    const r = checkSemgrepReport({ raw: report({ errors: [UNKNOWN_LANGUAGE], paths: { scanned: [] } }), exitCode: 8, outcome: 'failed', targets: 1 });
    expect(r.verdict).toBe('failed');
    expect(r.rule_config_error).toBe('UnknownLanguageError: invalid language: klingon');
    expect(r.reason).toContain('UnknownLanguageError: invalid language: klingon');
    expect(r.reason).not.toContain('(no message)');
  });

  it('a rule missing a key (InvalidRuleSchemaError beside a SemgrepError) is one too', () => {
    const r = checkSemgrepReport({
      raw: report({
        errors: [
          { type: 'InvalidRuleSchemaError', level: 'error', message: 'One of these properties is missing: languages' },
          { type: 'SemgrepError', level: 'error', message: 'invalid configuration file found (1 configs were invalid)' },
        ],
        paths: { scanned: [] },
      }),
      exitCode: 7,
      outcome: 'failed',
      targets: 1,
    });
    expect(r.rule_config_error).toMatch(/^InvalidRuleSchemaError: One of these properties is missing: languages/);
  });

  it.each([
    ['a registry download', { errors: [{ type: 'SemgrepError', level: 'error', message: 'Failed to download configuration from https://semgrep.dev/c/auto' }], paths: { scanned: [] } }, 7],
    ['a crash', { errors: [{ type: 'SomeOtherError', level: 'error', message: 'boom' }], paths: { scanned: [] } }, 3],
    ['a file that did not parse', { errors: [{ type: 'Syntax error', level: 'error', message: 'x', path: 'a.js' }], paths: { scanned: [] } }, 3],
  ])('never for %s', (_label, over, exitCode) => {
    expect(checkSemgrepReport({ raw: report(over), exitCode, outcome: 'failed', targets: 1 }).rule_config_error).toBeUndefined();
  });

  it('not when some rules ran: that is rules_not_loaded', () => {
    const r = checkSemgrepReport({
      raw: report({ errors: [{ type: 'Rule parse error', level: 'error', rule_id: 'y', message: 'Rule parse error in rule y:\n bad' }], paths: { scanned: ['a.js'] } }),
      exitCode: 2,
      outcome: 'failed',
      targets: 1,
    });
    expect(r.rules_not_loaded?.map((x) => x.rule_id)).toEqual(['y']);
    expect(r.rule_config_error).toBeUndefined();
  });
});

describe('fromContainerPath: the host file behind a /src path', () => {
  it('maps the mount back to the project; leaves any other path alone', async () => {
    const { fromContainerPath, toContainerPath } = await import('../../../src/runners/dockerScanner.js');
    const { join, resolve } = await import('node:path');
    const project = resolve('/work/my app');
    expect(fromContainerPath(project, '/src/.semgrep.yml')).toBe(join(project, '.semgrep.yml'));
    expect(fromContainerPath(project, '/src/rules/team.yml')).toBe(join(project, 'rules', 'team.yml'));
    expect(fromContainerPath(project, toContainerPath(project, join(project, 'a', 'b.yml')))).toBe(join(project, 'a', 'b.yml'));
    expect(fromContainerPath(project, '/srcx/a.yml')).toBe('/srcx/a.yml');
    expect(fromContainerPath(project, 'auto')).toBe('auto');
  });
});
