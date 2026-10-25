/**
 * detekt's run judged, the files it is handed and its report read
 * (`runners/detektRun.ts`, `scannerParsers/detekt.ts`). The report is detekt
 * 1.23.8's own over a seeded `Demo.kt` and a `Broken.kt` that does not parse,
 * measured on 2026-10-24: exit 2 with issues and the SARIF written, every
 * level `warning`, each rule named with its rule set — and no word about the
 * file that does not parse.
 */

import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import { DETEKT_BASE_CONFIG, DETEKT_EXCLUDES, javaUtf8Env, judgeDetekt, keepListed, kotlinSources } from '../../../src/runners/detektRun.js';
import { detektParser } from '../../../src/runners/scannerParsers/detekt.js';

const ROOT = resolve('fixture-project');
const REPORT = readFileSync(
  resolve(fileURLToPath(new URL('.', import.meta.url)), '../../fixtures/scanners/detekt/seeded-1.23.8.sarif.json'),
  'utf8',
).split('{{ROOT_URI}}').join(pathToFileURL(ROOT).href);

const run = (exitCode: number | null, stdout = '', outcome: 'completed' | 'failed' | 'timed_out' | 'cancelled' = 'completed') => ({
  outcome,
  exitCode,
  stdout,
  stderr: '',
});

describe('kotlinSources', () => {
  it('.kt and .kts files, `/`-separated and sorted; nothing else', () => {
    expect(kotlinSources(['b\\B.kt', 'build.gradle.kts', 'a/A.KT', 'App.java', 'kt.txt'])).toEqual(['a/A.KT', 'b/B.kt', 'build.gradle.kts']);
  });
});

describe('judgeDetekt', () => {
  it('exit 0 and exit 2 (issues above maxIssues) with its SARIF are sound', () => {
    expect(judgeDetekt({ run: run(2, 'Analysis failed with 8 weighted issues.'), report: REPORT })).toMatchObject({ ok: true });
    expect(judgeDetekt({ run: run(0), report: REPORT }).ok).toBe(true);
  });

  it('exit 3 is an invalid configuration, exit 1 an error, with what detekt said; no report, or not detekt’s, a failure', () => {
    const invalid = judgeDetekt({ run: run(3, "Property 'style>NoSuchRule' is misspelled or does not exist."), report: null });
    expect(invalid).toMatchObject({ ok: false, reason: "the configuration is invalid: Property 'style>NoSuchRule' is misspelled or does not exist." });
    expect(judgeDetekt({ run: run(1, 'java.lang.IllegalStateException: boom'), report: null }).reason).toBe('exit 1: java.lang.IllegalStateException: boom');
    expect(judgeDetekt({ run: run(0), report: null }).reason).toBe('detekt wrote no report');
    expect(judgeDetekt({ run: run(0), report: '{"runs":[{"tool":{"driver":{"name":"other"}}}]}' }).ok).toBe(false);
    expect(judgeDetekt({ run: run(null, '', 'timed_out'), report: REPORT }).reason).toBe('did not finish (timed_out)');
  });
});

describe('DETEKT_BASE_CONFIG', () => {
  it('validation off, MagicNumber and MaxLineLength off — what a project file turns back on wins, being read after it', () => {
    expect(DETEKT_BASE_CONFIG).toMatch(/config:\n {2}validation: false/);
    expect(DETEKT_BASE_CONFIG).toMatch(/MagicNumber:\n {4}active: false/);
    expect(DETEKT_BASE_CONFIG).toMatch(/MaxLineLength:\n {4}active: false/);
  });
});

describe('keepListed and the walk', () => {
  it('the results of the files the scan lists only, counted; the rest of the report kept', () => {
    const kept = keepListed(REPORT, ROOT, ['Demo.kt']);
    expect(kept.left).toBe(2);
    const runs = (JSON.parse(kept.report) as { runs: Array<{ results: unknown[]; tool: unknown }> }).runs;
    expect(runs[0]?.results).toHaveLength(6);
    expect(runs[0]?.tool).toMatchObject({ driver: { name: 'detekt' } });
    expect(keepListed(REPORT, ROOT, []).left).toBe(8);
  });

  it('case-insensitively on Windows only', () => {
    expect(keepListed(REPORT, ROOT, ['demo.kt'], 'win32').left).toBe(2);
    expect(keepListed(REPORT, ROOT, ['demo.kt'], 'linux').left).toBe(8);
  });

  it('the walk leaves out build output, tools and dependencies', () => {
    for (const d of ['build', 'target', '.gradle', '.git', '.guardian', 'node_modules', 'vendor']) expect(DETEKT_EXCLUDES).toContain(`**/${d}/**`);
  });
});

describe('javaUtf8Env', () => {
  it('Linux with no UTF-8 locale: LC_ALL=C.UTF-8; a UTF-8 one kept; other systems as they are', () => {
    expect(javaUtf8Env({ A: '1' }, 'linux', {})).toEqual({ A: '1', LC_ALL: 'C.UTF-8' });
    expect(javaUtf8Env({}, 'linux', { LANG: 'C' })).toEqual({ LC_ALL: 'C.UTF-8' });
    expect(javaUtf8Env({}, 'linux', { LANG: 'pt_PT.UTF-8' })).toEqual({});
    expect(javaUtf8Env({ LC_ALL: 'en_US.utf8' }, 'linux', {})).toEqual({ LC_ALL: 'en_US.utf8' });
    expect(javaUtf8Env({}, 'darwin', {})).toEqual({});
    expect(javaUtf8Env({}, 'win32', {})).toEqual({});
  });
});

describe('detektParser', () => {
  const findings = detektParser.parse(REPORT, { project_path: ROOT }).findings;

  it('every result, its path project-relative, its kind and severity from its rule set', () => {
    expect(findings).toHaveLength(8);
    const byRule = (rule: string) => findings.filter((f) => f.rule_id === rule);
    expect(byRule('EmptyFunctionBlock')[0]).toMatchObject({ file_path: 'Demo.kt', line_start: 6, subcategory: 'smell', severity: 'low' });
    expect(byRule('TooGenericExceptionCaught')[0]).toMatchObject({ subcategory: 'smell', severity: 'medium', line_start: 12 });
    expect(byRule('MagicNumber')).toHaveLength(2);
    expect(byRule('MagicNumber')[0]).toMatchObject({ subcategory: 'smell', severity: 'info' });
    expect(byRule('UnusedPrivateProperty')[0]).toMatchObject({ file_path: 'Broken.kt', line_start: 4 });
    expect(findings.every((f) => f.tool === 'detekt' && f.category === 'quality')).toBe(true);
  });

  it('the rule set and the rule in the message, with its page', () => {
    expect(findings.find((f) => f.rule_id === 'EmptyFunctionBlock')?.message).toContain(
      'EmptyFunctionBlock (empty-blocks): This empty block of code can be removed. (https://detekt.dev/docs/rules/empty-blocks#emptyfunctionblock)',
    );
  });

  it('complexity and naming rule sets are their own kinds', () => {
    const sarif = (ruleId: string) =>
      JSON.stringify({
        runs: [
          {
            tool: { driver: { name: 'detekt' } },
            results: [
              {
                ruleId,
                level: 'warning',
                message: { text: 'm' },
                locations: [{ physicalLocation: { artifactLocation: { uri: pathToFileURL(join(ROOT, 'A.kt')).href }, region: { startLine: 3 } } }],
              },
            ],
          },
        ],
      });
    expect(detektParser.parse(sarif('detekt.complexity.LongMethod'), { project_path: ROOT }).findings[0]).toMatchObject({
      subcategory: 'complexity',
      severity: 'low',
      file_path: 'A.kt',
    });
    expect(detektParser.parse(sarif('detekt.naming.FunctionNaming'), { project_path: ROOT }).findings[0]?.subcategory).toBe('naming');
    expect(detektParser.parse(sarif('detekt.potential-bugs.UnsafeCast'), { project_path: ROOT }).findings[0]?.severity).toBe('medium');
  });
});
