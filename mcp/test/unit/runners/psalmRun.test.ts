/**
 * Psalm's taint pass judged, configured and parsed (`runners/psalmRun.ts`,
 * `scannerParsers/psalm.ts`). `fixtures/scanners/psalm/` holds real reports
 * of Psalm 6.20.1 (PHP 8.3, `--taint-analysis --report=<f>.json`), the
 * project mounted at `/src`, 2026-10-24:
 *
 *   - `plain-6.20.1.json`: a plain-PHP fixture — shell, include, PDO and
 *     mysqli SQL, XSS, one flow across two files (exit 2);
 *   - `wp-statistics-13.0.7-6.20.1.json`: the wp-statistics plugin with the
 *     WordPress stub — five issues on three sinks, Psalm reporting a sink once
 *     per source that reaches it.
 */

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { countedIssues, hasPhpSource, judgePsalm, phpSources, psalmConfigXml, versionOf } from '../../../src/runners/psalmRun.js';
import { psalmParser } from '../../../src/runners/scannerParsers/psalm.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): string => readFileSync(resolve(here, '../../fixtures/scanners/psalm', name), 'utf8');

/** What `--output-format=count` printed for plain-6.20.1.json's eight issues. */
const PLAIN_COUNTS = 'TaintedInclude: 1\nTaintedHtml: 1\nTaintedTextWithQuotes: 1\nTaintedSql: 3\nTaintedShell: 2\n';
const exited = (exitCode: number, stdout = '', stderr = '') => ({ outcome: exitCode === 0 ? ('completed' as const) : ('failed' as const), exitCode, stdout, stderr });

describe('phpSources and hasPhpSource', () => {
  it('.php, .phtml and .inc, never a dependency’s, sorted and /-separated', () => {
    expect(
      phpSources(['b.php', 'a\\c.PHTML', 'x.inc', 'vendor/v.php', 'lib/vendor/w.php', 'node_modules/n.php', 'vendored/ok.php', 'a.js', 'phpunit.xml']),
    ).toEqual(['a/c.PHTML', 'b.php', 'vendored/ok.php', 'x.inc']);
  });

  it('an .inc alone is no PHP project (C has them too)', () => {
    expect(hasPhpSource(['x.inc', 'y.c'])).toBe(false);
    expect(hasPhpSource(['x.inc', 'v.phtml'])).toBe(true);
    expect(hasPhpSource(['vendor/a.php'])).toBe(false);
  });
});

describe('psalmConfigXml', () => {
  it('each file listed, escaped; pdo and mysqli enabled; nothing of the project read', () => {
    const xml = psalmConfigXml(['/p/a&b.php', '/p/"q".php'], null);
    expect(xml).toContain('<file name="/p/a&amp;b.php" />');
    expect(xml).toContain('<file name="/p/&quot;q&quot;.php" />');
    expect(xml).toContain('<enableExtensions><extension name="pdo" /><extension name="mysqli" /></enableExtensions>');
    expect(xml).toContain('allFunctionsGlobal="true"');
    expect(xml).not.toMatch(/<directory|<stubs|<globals|<plugins/);
  });

  it('the WordPress stub, and $wpdb typed as the stub’s class', () => {
    const xml = psalmConfigXml(['/p/a.php'], '/plugin/configs/psalm/wordpress-taint.phpstub');
    expect(xml).toContain('<stubs><file name="/plugin/configs/psalm/wordpress-taint.phpstub" /></stubs>');
    expect(xml).toContain('<globals><var name="wpdb" type="\\wpdb" /></globals>');
  });
});

describe('versionOf and countedIssues', () => {
  it('reads PHP’s and Psalm’s versions', () => {
    expect(versionOf('8.4.4', 'php')).toEqual([8, 4]);
    expect(versionOf('Psalm 6.20.1@376425b8e67b79773add388e16b4f6be5693dc87\r\n', 'psalm')).toEqual([6, 20]);
    expect(versionOf('<?php echo 1;', 'psalm')).toBeNull();
  });

  it('sums the per-type counts; nothing counted is 0; any other line is not a count', () => {
    expect(countedIssues(PLAIN_COUNTS)).toBe(8);
    expect(countedIssues('')).toBe(0);
    expect(countedIssues('TaintedSql: 1\nPHP Warning: something\n')).toBeNull();
  });
});

describe('judgePsalm', () => {
  it('exit 2 with a report as long as the counts: ok', () => {
    const r = judgePsalm({ run: exited(2, PLAIN_COUNTS), report: fixture('plain-6.20.1.json') });
    expect(r.ok).toBe(true);
    expect(r.issues).toHaveLength(8);
  });

  it('exit 0 is no clean run unless the report says so — and findings under GITHUB_WORKFLOW (exit 0) are kept', () => {
    expect(judgePsalm({ run: exited(0, ''), report: '[]\n' })).toEqual({ ok: true, issues: [] });
    expect(judgePsalm({ run: exited(0, PLAIN_COUNTS), report: fixture('plain-6.20.1.json') }).issues).toHaveLength(8);
    expect(judgePsalm({ run: exited(0, ''), report: null }).reason).toBe('Psalm wrote no report');
  });

  it('a report cut short, not a list, or disagreeing with the counts is a failure', () => {
    const plain = fixture('plain-6.20.1.json');
    expect(judgePsalm({ run: exited(2, PLAIN_COUNTS), report: plain.slice(0, 500) }).reason).toMatch(/not JSON/);
    expect(judgePsalm({ run: exited(0, ''), report: '{"issue_counts":[]}' }).reason).toBe('the report is not a list of issues');
    expect(judgePsalm({ run: exited(2, 'TaintedSql: 3\n'), report: plain }).reason).toBe('the report holds 8 issue(s) and Psalm counted 3');
  });

  it('any other exit names what PHP or Psalm printed; a run that did not finish or start fails', () => {
    const crash =
      'Uncaught RuntimeException: PHP Error: Failed to set memory limit to 33554432 bytes (Current memory usage is 57143296 bytes)';
    expect(judgePsalm({ run: exited(1, `${crash}\n`), report: null }).reason).toBe(`exit 1: ${crash}`);
    expect(judgePsalm({ run: exited(255, '', 'PHP Fatal error:  Allowed memory size of 104857600 bytes exhausted\n'), report: null }).reason).toMatch(
      /^exit 255: PHP Fatal error: {2}Allowed memory size/,
    );
    expect(judgePsalm({ run: { outcome: 'timed_out', exitCode: null, stdout: '', stderr: '' }, report: null }).reason).toMatch(/^did not finish in 40 minutes/);
    expect(judgePsalm({ run: { outcome: 'failed', exitCode: null, stdout: '', stderr: 'spawn php ENOENT' }, report: null }).reason).toBe(
      'did not run: spawn php ENOENT',
    );
  });
});

describe('psalmParser', () => {
  it('the real report: one finding per sink, project-relative, the CWE and severity from the type, the trace source first', () => {
    const { findings } = psalmParser.parse(fixture('plain-6.20.1.json'), { project_path: '/src' });
    expect(findings.map((f) => `${f.rule_id ?? ''} ${f.file_path ?? ''}:${String(f.line_start)}`)).toEqual([
      'TaintedShell cmd.php:2',
      'TaintedInclude incl.php:2',
      'TaintedShell lib/helpers.php:6',
      'TaintedSql mysqli.php:3',
      'TaintedSql mysqli.php:4',
      'TaintedSql sqli.php:3',
      'TaintedHtml xss.php:2',
      'TaintedTextWithQuotes xss.php:2',
    ]);
    expect(findings[0]).toMatchObject({ tool: 'psalm', severity: 'critical', cwe: ['CWE-78'], category: 'security', subcategory: 'taint' });
    expect(findings.find((f) => f.rule_id === 'TaintedSql')).toMatchObject({ severity: 'high', cwe: ['CWE-89'] });
    expect(findings.find((f) => f.rule_id === 'TaintedHtml')).toMatchObject({ severity: 'medium', cwe: ['CWE-79'] });
    const crossFile = findings.find((f) => f.file_path === 'lib/helpers.php');
    expect(crossFile?.message).toMatch(/^Detected tainted shell code: \$_GET → .*\(interproc\.php:\d+\).* → call to shell_exec/);
  });

  it('a sink reported once per source is one finding', () => {
    const { findings } = psalmParser.parse(fixture('wp-statistics-13.0.7-6.20.1.json'), { project_path: '/src' });
    expect(findings.map((f) => `${f.rule_id ?? ''} ${f.file_path ?? ''}:${String(f.line_start)}`)).toEqual([
      'TaintedTextWithQuotes includes/admin/class-wp-statistics-admin-ajax.php:106',
      'TaintedExtract includes/admin/class-wp-statistics-admin-template.php:54',
      'TaintedSql includes/class-wp-statistics-visitor.php:373',
    ]);
  });

  it('a file outside the project, a type that is no taint and a report that is not JSON give nothing', () => {
    const issue = (type: string, file: string) => ({ type, file_path: file, line_from: 1, line_to: 1, column_from: 1, message: 'm' });
    expect(psalmParser.parse(JSON.stringify([issue('TaintedSql', '/elsewhere/a.php'), issue('UndefinedFunction', '/src/a.php')]), { project_path: '/src' }).findings).toEqual([]);
    expect(psalmParser.parse('not json', { project_path: '/src' }).findings).toEqual([]);
  });
});
