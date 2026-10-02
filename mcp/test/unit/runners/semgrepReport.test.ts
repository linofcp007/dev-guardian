/**
 * Global Constraint 3 for one Semgrep run: exit 0/1 is necessary, never
 * sufficient. The report must exist, parse, have scanned something when there
 * were targets, and carry no `errors`.
 */

import { afterAll, describe, expect, it } from 'vitest';
import { cleanupTempDirs } from '../../helpers/tempDir.js';
import {
  checkSemgrepReport,
  describePartialParse,
  describeRulesNotLoaded,
  FIXPOINT_TIMEOUT_PACK_TYPE,
  FIXPOINT_TIMEOUT_TYPE,
  semgrepEngineOf,
  withPluginPackFixpoint,
} from '../../../src/runners/semgrepReport.js';
import { semgrepEngineNote } from '../../../src/runners/semgrepConfigs.js';

afterAll(cleanupTempDirs);

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
    // T-03: a configuration type stays fatal when it names a YAML file — the type decides, not the extension.
    ['T-03 an invalid rule schema naming a YAML file', { level: 'error', type: 'InvalidRuleSchemaError', message: 'missing key', path: 'rules.yml' }],
    ['T-03 an invalid YAML configuration naming a YAML file', { level: 'error', type: 'SemgrepError', message: 'Invalid YAML file', path: '.semgrep.yml' }],
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

  // Bugfix sast-partial-parse-as-failed. Measured on Semgrep 1.176.1
  // (2026-10-02): a GitHub Actions workflow whose `run:` block a bash
  // sub-pattern cannot read (`typescript@${{ env.X }}`) is reported as this
  // warn-level PartialParsing on the TARGET, on exit 0, with the run's
  // results intact — 12 of the 55 errors that made scan_sast `failed`, with
  // coverage `none`, on OWASP Juice Shop. A broken rule pack is reported
  // differently: `SemgrepError` (exit 7) or `Rule parse error` (exit 2), with
  // no path and nothing scanned — so the extension never told them apart.
  const WORKFLOW = '.github/workflows/ci.yml';
  const WORKFLOW_WARNING = {
    level: 'warn',
    type: ['PartialParsing', [{ path: WORKFLOW, start: { line: 281, col: 41, offset: 13569 }, end: { line: 281, col: 44, offset: 13572 } }]],
    message: `Syntax error at line ${WORKFLOW}:281:`,
    path: WORKFLOW,
    spans: [{ file: WORKFLOW, start: { line: 281, col: 41, offset: 13569 }, end: { line: 281, col: 44, offset: 13572 } }],
  };

  it('T-01 partial: a warn-level PartialParsing on a YAML target (a workflow) — the file named, never failed', () => {
    // Semgrep repeats the entry per rule: one per (file, type) (EC-2).
    const r = check({ paths: { scanned: [WORKFLOW, 'routes/login.ts'] }, errors: [WORKFLOW_WARNING, WORKFLOW_WARNING, WORDPRESS_WARNING] }, 1);
    expect(r.verdict).toBe('partial');
    expect(r.partial).toEqual([
      { file: WORKFLOW, type: 'PartialParsing', message: `Syntax error at line ${WORKFLOW}:281:` },
      { file: 'rest-controller.php', type: 'PartialParsing', message: 'Syntax error at line rest-controller.php:20:' },
    ]);
    // What the old rule held fatal ("a YAML file cannot be told from the rule
    // pack") is a target too: a per-file type, a path, a clean exit, files read.
    const old = check({ paths: { scanned: ['rules.yml'] }, errors: [{ level: 'warn', type: 'Other syntax error', message: 'x', path: 'rules.yml' }] });
    expect(old.verdict).toBe('partial');
    // The project's own rules file scanned as a target (EC-3): its rules loaded.
    const own = check({ paths: { scanned: ['.semgrep.yml'] }, errors: [{ ...WORKFLOW_WARNING, path: '.semgrep.yml', type: ['PartialParsing', []], spans: [] }] });
    expect(own.verdict).toBe('partial');
    // An absolute workflow path under the project (a whole-project run is given the project's absolute path).
    const absolute = checkSemgrepReport({
      raw: report({ paths: { scanned: ['/p/.github/workflows/ci.yml'] }, errors: [{ ...WORKFLOW_WARNING, path: '/p/.github/workflows/ci.yml', type: ['PartialParsing', []], spans: [] }] }),
      exitCode: 0,
      outcome: 'completed',
      targets: 1,
      projectPath: '/p',
    });
    expect(absolute.verdict).toBe('partial');
    expect(absolute.partial?.map((x) => x.file)).toEqual(['.github/workflows/ci.yml']);
  });

  it('T-03 failed: a YAML file outside the scanned project — a rule file (the I3 ruling) — or absolute with no project known', () => {
    const outside = { level: 'warn', type: 'Syntax error', message: 'x', path: '/r/routes.yml' };
    const withProject = checkSemgrepReport({
      raw: report({ paths: { scanned: ['/p/wp.php'] }, errors: [outside] }),
      exitCode: 0,
      outcome: 'completed',
      targets: 1,
      projectPath: '/p',
    });
    expect(withProject.verdict).toBe('failed');
    expect(check({ paths: { scanned: ['wp.php'] }, errors: [outside] }).verdict).toBe('failed');
    expect(check({ paths: { scanned: ['wp.php'] }, errors: [{ ...outside, path: '../rules/routes.yml' }] }).verdict).toBe('failed');
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

/**
 * Review of the LLM pack, round 2 (I-C): a taint rule whose dataflow analysis
 * of one function runs past its budget is given up on that function. Semgrep
 * says so only under `time.fixpoint_timeouts` — never in `errors[]`, and
 * `paths.scanned` stays full — so the judge read such a run as complete. It
 * is the same class as a per-rule Timeout: the file was not fully analysed.
 */
describe('checkSemgrepReport: taint fixpoint timeouts (time.fixpoint_timeouts)', () => {
  // The 1.176.1 shape, verbatim but for the path (LangChain experimental, measured).
  const fixpoint = (path: string, line = 152): Record<string, unknown> => ({
    error_type: 'Fixpoint timeout',
    severity: 'warn',
    message: `Fixpoint timeout while performing taint analysis at ${path}:${line}:4 [rules: 1, first: python.lang.security.audit.eval-detected]`,
    location: { path, start: { line, col: 5, offset: 5084 }, end: { line, col: 34, offset: 5113 } },
  });
  const time = (...entries: unknown[]): Record<string, unknown> => ({ time: { fixpoint_timeouts: entries } });
  const check = (over: Record<string, unknown>, exitCode = 0, projectPath?: string) =>
    checkSemgrepReport({
      raw: report(over),
      exitCode,
      outcome: exitCode === 0 ? 'completed' : 'failed',
      targets: 1,
      ...(projectPath !== undefined ? { projectPath } : {}),
    });

  it('errors: [] and every file scanned, but a fixpoint timeout: partial, the file named — never ok', () => {
    const r = check({ paths: { scanned: ['sql/base.py', 'b.ts'] }, ...time(fixpoint('sql/base.py', 113)) });
    expect(r.ok).toBe(false);
    expect(r.verdict).toBe('partial');
    expect(r.errors).toBe(0);
    expect(r.partial).toEqual([
      {
        file: 'sql/base.py',
        type: FIXPOINT_TIMEOUT_TYPE,
        message: 'taint analysis gave up on 1 function(s) here (Semgrep fixpoint timeout)',
        functions: 1,
      },
    ]);
    expect(r.reason).toBe('taint analysis incomplete (Semgrep fixpoint timeout) in 1 function(s) across 1 file(s): sql/base.py');
  });

  it('one entry per file, the functions counted; project-relative and /-separated (Windows, the container)', () => {
    const win = check(
      { ...time(fixpoint('libs\\sql\\base.py', 113), fixpoint('libs\\sql\\base.py', 200), fixpoint('C:\\p\\b.ts')) },
      1,
      'C:\\p',
    );
    expect(win.verdict).toBe('partial');
    expect(win.partial?.map((p) => [p.file, p.functions])).toEqual([['libs/sql/base.py', 2], ['b.ts', 1]]);
    expect(win.reason).toMatch(/in 3 function\(s\) across 2 file\(s\): libs\/sql\/base\.py, b\.ts$/);
    const container = check({ ...time(fixpoint('/src/app/x.py')) }, 0, '/src');
    expect(container.partial?.map((p) => p.file)).toEqual(['app/x.py']);
  });

  it('names a few files, then "+N more"', () => {
    const r = check({ ...time(...Array.from({ length: 8 }, (_, i) => fixpoint(`f${i}.py`))) });
    expect(r.partial).toHaveLength(8);
    expect(r.reason).toBe(
      'taint analysis incomplete (Semgrep fixpoint timeout) in 8 function(s) across 8 file(s): f0.py, f1.py, f2.py, f3.py, f4.py, +3 more',
    );
  });

  it('beside a per-file parse error: partial, both kept', () => {
    const parse = { level: 'warn', type: 'PartialParsing', message: 'Syntax error at a.php:3', path: 'a.php' };
    const r = check({ errors: [parse], ...time(fixpoint('b.py')) });
    expect(r.verdict).toBe('partial');
    expect(r.partial?.map((p) => `${p.type}:${p.file}`)).toEqual(['PartialParsing:a.php', 'Fixpoint timeout:b.py']);
  });

  it('beside rules that did not load: the fixpoint files join the per-file problems', () => {
    const rule = { code: 2, level: 'error', type: 'Rule parse error', rule_id: 'y', message: 'Rule parse error in rule y:\n bad' };
    const r = check({ errors: [rule], ...time(fixpoint('b.py')) }, 2);
    expect(r.rules_not_loaded?.map((x) => x.rule_id)).toEqual(['y']);
    expect(r.partial?.map((p) => `${p.type}:${p.file}`)).toEqual(['Fixpoint timeout:b.py']);
  });

  it('an entry that names no file cannot be scoped: failed, the conservative reading (as for an error naming none)', () => {
    const r = check({ ...time({ error_type: 'Fixpoint timeout', severity: 'warn', message: 'Fixpoint timeout' }) });
    expect(r.verdict).toBe('failed');
    expect(r.reason).toMatch(/taint analysis incomplete \(Semgrep fixpoint timeout\) in 1 function\(s\), 1 of them in no named file/);
  });

  it('an empty list, or none at all (engines before 1.170): ok', () => {
    expect(check({ ...time() }).verdict).toBe('ok');
    expect(check({}).verdict).toBe('ok');
  });

  it('describePartialParse: the parse files as before, the fixpoint files bounded, each with its own consequence', () => {
    const parse = { file: 'a.php', type: 'PartialParsing', message: 'x' };
    const fix = (file: string, functions: number) => ({ file, type: FIXPOINT_TIMEOUT_TYPE, message: 'm', functions });
    expect(describePartialParse([parse, fix('b.py', 2), fix('c.ts', 1)], 'findings in the unparsed spans may be missing')).toBe(
      'partial: 1 file(s) only partly parsed — findings in the unparsed spans may be missing (PartialParsing: a.php); ' +
        'partial: taint analysis incomplete (Semgrep fixpoint timeout) in 3 function(s) across 2 file(s): b.py, c.ts — ' +
        'taint findings in those functions may be missing',
    );
    const many = Array.from({ length: 7 }, (_, i) => fix(`f${i}.py`, 1));
    expect(describePartialParse(many, 'x')).toMatch(/across 7 file\(s\): f0\.py, f1\.py, f2\.py, f3\.py, f4\.py, \+2 more — /);
  });
});

/**
 * Review of the LLM pack, round 3 (N-1): the pack's JS taint rules have no
 * literal to prefilter on, so they time out on code with no model call in it
 * (this repo's mcp/src: 6 to 22 per run). A fixpoint timeout whose only rule
 * is a plugin-pack rule is the PACK's gap — recorded, noted, never the run's
 * partial verdict. Any other stays the scan's.
 */
describe('checkSemgrepReport: fixpoint timeouts attributed by rule', () => {
  const PREFIX = 'C.Users.dev..claude.plugins.cache.dev-guardian.3.0.0.configs.semgrep';
  // The pack's rules as Semgrep spells them in the run (pluginPackCheckIds): prefixed, never bare.
  const PACK = new Set([`${PREFIX}.llm-output-to-interpreter-js`, `${PREFIX}.llm-request-in-system-prompt-js`]);
  const strip = (id: string): string => (id.startsWith(`${PREFIX}.`) ? id.slice(PREFIX.length + 1) : id);
  const at = (path: string, rules: string) => ({
    error_type: 'Fixpoint timeout',
    severity: 'warn',
    message: `Fixpoint timeout while performing taint analysis at ${path}:10:2 [${rules}]`,
    location: { path, start: { line: 10, col: 3, offset: 0 }, end: { line: 10, col: 9, offset: 6 } },
  });
  const judge = (...entries: unknown[]) =>
    checkSemgrepReport({
      raw: report({ paths: { scanned: ['hooks/bashGuard.ts', 'app.py'] }, time: { fixpoint_timeouts: entries } }),
      exitCode: 0,
      outcome: 'completed',
      targets: 1,
      ruleIdOf: strip,
      pluginPackCheckIds: PACK,
    });

  it('only a pack rule: the run stays ok, the pack gap recorded with its own type', () => {
    const r = judge(
      at('hooks/bashGuard.ts', `rules: 1, first: ${PREFIX}.llm-output-to-interpreter-js`),
      at('hooks/bashGuard.ts', `rules: 1, first: ${PREFIX}.llm-request-in-system-prompt-js`),
    );
    expect(r.verdict).toBe('ok');
    expect(r.ok).toBe(true);
    expect(r.partial).toBeUndefined();
    expect(r.plugin_pack_fixpoint).toEqual({
      files: [
        {
          file: 'hooks/bashGuard.ts',
          type: FIXPOINT_TIMEOUT_PACK_TYPE,
          message: 'taint analysis gave up on 2 function(s) here (Semgrep fixpoint timeout)',
          functions: 2,
        },
      ],
      functions: 2,
    });
  });

  it.each([
    ['a registry rule', 'rules: 1, first: javascript.lang.security.audit.detect-eval'],
    ['a project rule', 'rules: 1, first: my-rules.no-exec'],
    // Round 4, A-1: a project-root rule named like a pack rule is spelled bare.
    ['a project-root rule whose id equals a pack rule\'s', 'rules: 1, first: llm-output-to-interpreter-js'],
    ['more than one rule, the first a pack rule (the others are unknown)', `rules: 2, first: ${PREFIX}.llm-output-to-interpreter-js`],
    ['a message that names no rule', 'no rule list here'],
  ])('%s: the scan\'s — partial, as before', (_label, rules) => {
    const r = judge(at('app.py', rules));
    expect(r.verdict).toBe('partial');
    expect(r.partial?.map((p) => `${p.type}:${p.file}`)).toEqual(['Fixpoint timeout:app.py']);
    expect(r.plugin_pack_fixpoint).toBeUndefined();
  });

  it('mixed: the scan\'s files make it partial, the pack\'s are kept apart', () => {
    const r = judge(
      at('hooks/bashGuard.ts', `rules: 1, first: ${PREFIX}.llm-output-to-interpreter-js`),
      at('app.py', 'rules: 1, first: python.lang.security.audit.eval-detected'),
    );
    expect(r.verdict).toBe('partial');
    expect(r.partial?.map((p) => `${p.type}:${p.file}`)).toEqual(['Fixpoint timeout:app.py']);
    expect(r.plugin_pack_fixpoint?.files.map((p) => `${p.type}:${p.file}`)).toEqual([`${FIXPOINT_TIMEOUT_PACK_TYPE}:hooks/bashGuard.ts`]);
    expect(r.reason).not.toMatch(/bashGuard/);
  });

  it('several rules, the first a pack rule: the pack\'s only when no other config can hold a taint rule', () => {
    const entry = at('hooks/bashGuard.ts', `rules: 2, first: ${PREFIX}.llm-request-in-system-prompt-js`);
    const raw = report({ paths: { scanned: ['hooks/bashGuard.ts'] }, time: { fixpoint_timeouts: [entry] } });
    const base = { raw, exitCode: 0, outcome: 'completed' as const, targets: 1, ruleIdOf: strip, pluginPackCheckIds: PACK };
    expect(checkSemgrepReport({ ...base, nonPackTaintRules: false }).verdict).toBe('ok');
    expect(checkSemgrepReport({ ...base, nonPackTaintRules: false }).plugin_pack_fixpoint?.functions).toBe(1);
    expect(checkSemgrepReport({ ...base, nonPackTaintRules: true }).verdict).toBe('partial');
    // Never a first rule that is not the pack's, whatever the configs.
    const other = at('app.py', 'rules: 2, first: my-rules.no-exec');
    expect(
      checkSemgrepReport({ ...base, raw: report({ time: { fixpoint_timeouts: [other] } }), nonPackTaintRules: false }).verdict,
    ).toBe('partial');
  });

  it('without the pack ids (a caller that runs no plugin pack) every timeout is the scan\'s', () => {
    const r = checkSemgrepReport({
      raw: report({ time: { fixpoint_timeouts: [at('a.ts', `rules: 1, first: ${PREFIX}.llm-output-to-interpreter-js`)] } }),
      exitCode: 0,
      outcome: 'completed',
      targets: 1,
      ruleIdOf: strip,
    });
    expect(r.verdict).toBe('partial');
  });

  it('withPluginPackFixpoint: a note, the files kept for history, plugin_packs.llm partial — status untouched', () => {
    const gap = judge(...Array.from({ length: 7 }, (_, i) => at(`src/f${i}.ts`, `rules: 1, first: ${PREFIX}.llm-output-to-interpreter-js`)))
      .plugin_pack_fixpoint;
    const run = withPluginPackFixpoint({ name: 'semgrep', status: 'ok', reason: 'ran via x' }, gap);
    expect(run.status).toBe('ok');
    const note =
      "the plugin's LLM pack: taint analysis incomplete (Semgrep fixpoint timeout) in 7 function(s) across 7 file(s): " +
      'src/f0.ts, src/f1.ts, src/f2.ts, src/f3.ts, src/f4.ts, +2 more — its findings in those functions may be missing; ' +
      'the rest of the scan is not affected';
    expect(run.reason).toBe(`ran via x; ${note}`);
    expect(run.partially_parsed).toHaveLength(7);
    expect(run.plugin_packs).toEqual({ llm: { status: 'partial', reason: note } });
    expect(withPluginPackFixpoint({ name: 'semgrep', status: 'ok' }, undefined)).toEqual({ name: 'semgrep', status: 'ok' });
  });
});

describe('mayHoldTaintRules', () => {
  const SEARCH = 'rules:\n  - id: s\n    languages: [python]\n    severity: WARNING\n    message: m\n    pattern: eval($X)\n';
  const TAINT =
    'rules:\n  - id: t\n    mode: taint\n    languages: [python]\n    severity: WARNING\n    message: m\n' +
    '    pattern-sources:\n      - pattern: input()\n    pattern-sinks:\n      - pattern: eval(...)\n';

  it('a registry pack, auto or a URL may; a local file answers from its rules', async () => {
    const { mayHoldTaintRules } = await import('../../../src/runners/semgrepRuleIds.js');
    const { makeTempDir } = await import('../../helpers/tempDir.js');
    const { mkdirSync, writeFileSync } = await import('node:fs');
    const { join } = await import('node:path');
    const dir = makeTempDir('taint-rules-');
    writeFileSync(join(dir, 'search.yml'), SEARCH);
    writeFileSync(join(dir, 'taint.yml'), TAINT);
    writeFileSync(join(dir, 'broken.yml'), 'rules: [\n');
    expect(mayHoldTaintRules(['auto'])).toBe(true);
    expect(mayHoldTaintRules(['p/default'])).toBe(true);
    expect(mayHoldTaintRules([join(dir, 'search.yml')])).toBe(false);
    expect(mayHoldTaintRules([join(dir, 'search.yml'), join(dir, 'taint.yml')])).toBe(true);
    expect(mayHoldTaintRules([join(dir, 'broken.yml')])).toBe(true);
    expect(mayHoldTaintRules([])).toBe(false);
    // A rule directory is read recursively, as Semgrep loads it.
    const rulesDir = makeTempDir('taint-rules-dir-');
    mkdirSync(join(rulesDir, 'nested'));
    writeFileSync(join(rulesDir, 'a.yml'), SEARCH);
    expect(mayHoldTaintRules([rulesDir])).toBe(false);
    writeFileSync(join(rulesDir, 'nested', 'b.yaml'), TAINT);
    expect(mayHoldTaintRules([rulesDir])).toBe(true);
  });

  // Round 4, A-2: Semgrep 1.176.1 runs a rule with a `taint:` block and no
  // `mode:` as a taint rule. The test is on tokens, never on a key.
  it('any file naming taint, pattern-sources or pattern-sinks may — a `taint:` block with no mode, a comment, any case', async () => {
    const { mayHoldTaintRules } = await import('../../../src/runners/semgrepRuleIds.js');
    const { makeTempDir } = await import('../../helpers/tempDir.js');
    const { writeFileSync } = await import('node:fs');
    const { join } = await import('node:path');
    const dir = makeTempDir('taint-tokens-');
    const files: Record<string, string> = {
      'block.yml':
        'rules:\n  - id: b\n    languages: [python]\n    severity: WARNING\n    message: m\n' +
        '    taint:\n      sources:\n        - pattern: input()\n      sinks:\n        - pattern: exec(...)\n',
      'comment.yml': `# TAINT is not used here\n${SEARCH}`,
      'sinks.yml': `${SEARCH}# pattern-sinks\n`,
    };
    for (const [name, text] of Object.entries(files)) {
      writeFileSync(join(dir, name), text);
      expect([name, mayHoldTaintRules([join(dir, name)])]).toEqual([name, true]);
    }
    writeFileSync(join(dir, 'search.yml'), SEARCH);
    expect(mayHoldTaintRules([join(dir, 'search.yml')])).toBe(false);
  });
});

describe('pluginPackCheckIds', () => {
  it('spells each pack rule as Semgrep does in the run — the full path natively, guardian-packs in Docker — never bare', async () => {
    const { pluginPackCheckIds, semgrepConfigPrefix } = await import('../../../src/runners/semgrepRuleIds.js');
    const { makeTempDir } = await import('../../helpers/tempDir.js');
    const { writeFileSync } = await import('node:fs');
    const { join } = await import('node:path');
    const dir = makeTempDir('pack-ids-');
    const pack = join(dir, 'llm.yml');
    writeFileSync(pack, 'rules:\n  - id: llm-a\n    pattern: x\n    message: m\n    languages: [python]\n    severity: INFO\n');
    const native = pluginPackCheckIds([pack], { cwd: makeTempDir('proj-') });
    expect([...native]).toEqual([`${semgrepConfigPrefix(pack)}.llm-a`]);
    expect(native.has('llm-a')).toBe(false);
    const docker = pluginPackCheckIds(['/guardian-packs/llm.yml'], { cwd: '/src', readAt: () => pack });
    expect([...docker]).toEqual(['guardian-packs.llm-a']);
    // A pack inside Semgrep's working directory is also spelled relative to it.
    const inside = pluginPackCheckIds([pack], { cwd: dir });
    expect(inside.has(`${semgrepConfigPrefix(pack)}.llm-a`)).toBe(true);
    expect(inside.has('llm-a')).toBe(false);
  });
});

/**
 * Whether the engine that wrote a report says anything about fixpoint
 * timeouts: 1.170.1 and 1.176.1 always carry `time.fixpoint_timeouts` (an
 * empty list on a clean run, with or without `--time`); 1.86.0, 1.95.0,
 * 1.99.0 and 1.120.1 never do (measured). Absence only counts on a report
 * that names its version and scanned files.
 */
describe('semgrepEngineOf', () => {
  it('reads the version and whether fixpoint timeouts are reported', () => {
    expect(semgrepEngineOf(report({ version: '1.176.1', time: { fixpoint_timeouts: [] } }))).toEqual({
      version: '1.176.1',
      fixpointTimeoutsReported: true,
    });
    expect(semgrepEngineOf(report({ version: '1.120.1' }))).toEqual({ version: '1.120.1', fixpointTimeoutsReported: false });
  });

  it('says nothing it cannot know: no version, nothing scanned, no report', () => {
    expect(semgrepEngineOf(report())).toEqual({});
    expect(semgrepEngineOf(report({ version: '1.120.1', paths: { scanned: [] } }))).toEqual({ version: '1.120.1' });
    expect(semgrepEngineOf(null)).toEqual({});
    expect(semgrepEngineOf('{nope')).toEqual({});
  });
});

/**
 * The one note a run carries about its engine: an engine that cannot report
 * fixpoint timeouts, and one older than the LLM pack was measured on, said
 * once — never two sentences each starting "this Semgrep (x.y.z)".
 */
describe('semgrepEngineNote', () => {
  const FIXPOINT = 'does not report taint fixpoint timeouts; incomplete taint analysis cannot be detected';

  it('an engine without the field: the named note, pack or no pack', () => {
    expect(semgrepEngineNote({ version: '1.120.1', fixpointTimeoutsReported: false }, { llmPack: false })).toBe(
      `this Semgrep (1.120.1) ${FIXPOINT}`,
    );
  });

  it('with the pack on an engine older than it was measured on: one note, the engine named once', () => {
    const both = semgrepEngineNote({ version: '1.86.0', fixpointTimeoutsReported: false }, { llmPack: true }) ?? '';
    expect(both.startsWith(`this Semgrep (1.86.0) ${FIXPOINT}; nor does it resolve`)).toBe(true);
    expect(both).toMatch(/llm\.yml was measured on Semgrep 1\.176\.1, and its child_process coverage is reduced \(160 of 184/);
    expect(both.match(/this Semgrep/g)).toHaveLength(1);
    const llmOnly = semgrepEngineNote({ version: '1.170.1', fixpointTimeoutsReported: true }, { llmPack: true }) ?? '';
    expect(llmOnly).toMatch(/^this Semgrep \(1\.170\.1\) does not resolve `import … from 'node:child_process'` in taint mode — llm\.yml/);
    expect(llmOnly).not.toMatch(/fixpoint/);
  });

  it('nothing to say: a current engine, an unknown one, or the pack not run on a new-enough engine', () => {
    expect(semgrepEngineNote({ version: '1.176.1', fixpointTimeoutsReported: true }, { llmPack: true })).toBeNull();
    expect(semgrepEngineNote({ version: '1.180.0', fixpointTimeoutsReported: true }, { llmPack: true })).toBeNull();
    expect(semgrepEngineNote({ version: '1.170.1', fixpointTimeoutsReported: true }, { llmPack: false })).toBeNull();
    expect(semgrepEngineNote({}, { llmPack: true })).toBeNull();
    // A version but no word on the field (nothing scanned): only the pack's half.
    expect(semgrepEngineNote({ version: '1.86.0' }, { llmPack: false })).toBeNull();
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
