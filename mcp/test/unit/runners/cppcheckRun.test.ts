/**
 * cppcheck's run judged and its XML v2 parsed (`runners/cppcheckRun.ts`,
 * `scannerParsers/cppcheck.ts`). `fixtures/scanners/cppcheck/` holds real
 * output over `fixtures/cppcheck/project`, written on 2026-10-24 with
 * `cppcheck -j4 -q --enable=warning,information,missingInclude --inconclusive
 * --inline-suppr --suppress=missingIncludeSystem --cppcheck-build-dir=<bd>
 * --xml --xml-version=2 --output-file=<f> --file-list=<list>`, the list naming
 * the project's seven translation units and `src/gone.c`, which does not exist:
 *
 *   - `project-2.22.0.xml` and `files-2.22.0.txt`: cppcheck 2.22.0;
 *   - `files-2.13.txt`: cppcheck 2.13 (Ubuntu 24.04) — the older `::` form.
 */

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  cppcheckVersion,
  cppSources,
  filesRead,
  judgeCppcheck,
  parseCppcheckXml,
} from '../../../src/runners/cppcheckRun.js';
import { cppcheckParser } from '../../../src/runners/scannerParsers/cppcheck.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): string => readFileSync(resolve(here, '../../fixtures/scanners/cppcheck', name), 'utf8');

const REQUESTED = ['src/clean.cpp', 'src/configs.c', 'src/macro.cpp', 'src/missinc.c', 'src/novalid.c', 'src/syntax.c', 'src/vuln.c', 'src/gone.c'];
const done = { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '' };

describe('cppSources', () => {
  it('translation units only: never a header, a template part or another language', () => {
    expect(cppSources(['a.c', 'b.CPP', 'c.cc', 'd.cxx', 'e.c++', 'f.h', 'g.hpp', 'h.ipp', 'i.cs', 'j.cjs', 'k\\l.c'])).toEqual([
      'a.c',
      'b.CPP',
      'c.cc',
      'd.cxx',
      'e.c++',
      'k/l.c',
    ]);
  });
});

describe('parseCppcheckXml', () => {
  it('the real report: every error, its first location the defect, entities decoded, complete', () => {
    const r = parseCppcheckXml(fixture('project-2.22.0.xml'));
    expect(r.complete).toBe(true);
    const nullDeref = r.errors.find((e) => e.id === 'nullPointer' && e.locations[0]?.file === 'src/vuln.c');
    expect(nullDeref).toMatchObject({ severity: 'error', cwe: '476', inconclusive: false, file0: 'src/vuln.c' });
    expect(nullDeref?.locations).toEqual([
      { file: 'src/vuln.c', line: 8, column: 13, info: 'Null pointer dereference' },
      { file: 'src/vuln.c', line: 7, column: 14, info: "Assignment 'p=NULL', assigned value is 0" },
    ]);
    expect(r.errors.find((e) => e.id === 'missingInclude')?.msg).toBe('Include file: "missing_project_header.h" not found.');
  });

  it('a report cut short (no closing tags) is incomplete', () => {
    const xml = fixture('project-2.22.0.xml');
    expect(parseCppcheckXml(xml.slice(0, xml.indexOf('</errors>'))).complete).toBe(false);
  });
});

describe('filesRead and cppcheckVersion', () => {
  it('both forms of files.txt', () => {
    expect([...filesRead(fixture('files-2.22.0.txt'))]).toEqual(REQUESTED.filter((f) => f !== 'src/gone.c'));
    expect([...filesRead(fixture('files-2.13.txt'))]).toEqual(REQUESTED.filter((f) => f !== 'src/gone.c'));
  });

  it('the version from --version', () => {
    expect(cppcheckVersion('Cppcheck 2.22.0\n')).toEqual([2, 22]);
    expect(cppcheckVersion('Cppcheck 2.10\n')).toEqual([2, 10]);
    expect(cppcheckVersion('nope')).toBeNull();
  });
});

describe('judgeCppcheck', () => {
  it('the real run: each file not analysed or cut short named, the silent skip caught, the limits noted', () => {
    const r = judgeCppcheck({
      run: done,
      xml: fixture('project-2.22.0.xml'),
      filesTxt: fixture('files-2.22.0.txt'),
      requested: REQUESTED,
      projectPath: '/p',
    });
    expect(r.ok).toBe(true);
    expect(r.partial.map((p) => [p.file, p.type]).sort()).toEqual([
      ['src/gone.c', 'Not read'],
      ['src/macro.cpp', 'Unknown macro'],
      ['src/novalid.c', 'Not analysed'],
      ['src/syntax.c', 'Syntax error'],
    ]);
    expect(r.notes.join(' | ')).toMatch(/^1 file\(s\) checked less deeply .*src\/configs\.c/);
    expect(r.notes.join(' | ')).toMatch(/1 file\(s\) include a project header cppcheck did not find/);
  });

  // 3.6.1: `information` is enabled for coverage only, but the parser kept
  // every id off a fixed list — so an unlisted one (ConfigurationNotChecked:
  // a configuration skipped) was a low "security" finding. Hand-made in the
  // shape of the real report (cppcheck is not installed here); the message is
  // cppcheck's own for that id.
  it('ConfigurationNotChecked is a file checked less deeply; another information id is noted, never a finding', () => {
    const xml =
      '<?xml version="1.0" encoding="UTF-8"?>\n<results version="2">\n    <cppcheck version="2.22.0"/>\n    <errors>\n' +
      '        <error id="ConfigurationNotChecked" severity="information" msg="Skipping configuration &apos;HAVE_SSL&apos; since the value of &apos;HAVE_SSL&apos; is unknown. Use -D if you want to check it. You can use -U to skip it explicitly." verbose="Skipping configuration &apos;HAVE_SSL&apos; since the value of &apos;HAVE_SSL&apos; is unknown. Use -D if you want to check it. You can use -U to skip it explicitly.">\n' +
      '            <location file="src/net.c" line="12" column="0"/>\n        </error>\n' +
      '        <error id="someNewInformation" severity="information" msg="m" verbose="v">\n            <location file="src/b.c" line="1" column="0"/>\n        </error>\n' +
      '    </errors>\n</results>\n';
    const r = judgeCppcheck({ run: done, xml, filesTxt: null, requested: null, projectPath: '/p' });
    expect(r.ok).toBe(true);
    expect(r.partial).toEqual([]);
    expect(r.shallower).toEqual(['src/net.c']);
    expect(r.information).toEqual(['someNewInformation (src/b.c)']);
    expect(cppcheckParser.parse(xml, { project_path: '/p' }).findings).toEqual([]);
  });

  it('exit 1 names what cppcheck printed; no report, an incomplete one or an unfinished run fail', () => {
    expect(
      judgeCppcheck({ run: { ...done, exitCode: 1, stdout: 'cppcheck: error: could not find or open any of the paths given.\n' }, xml: null, filesTxt: null, requested: null, projectPath: '/p' }).reason,
    ).toBe('exit 1: cppcheck: error: could not find or open any of the paths given.');
    expect(judgeCppcheck({ run: done, xml: null, filesTxt: null, requested: null, projectPath: '/p' }).reason).toBe('cppcheck wrote no XML report');
    const cut = fixture('project-2.22.0.xml').slice(0, 2000);
    expect(judgeCppcheck({ run: done, xml: cut, filesTxt: null, requested: null, projectPath: '/p' }).reason).toMatch(/incomplete/);
    expect(judgeCppcheck({ run: { ...done, outcome: 'timed_out', exitCode: null }, xml: null, filesTxt: null, requested: null, projectPath: '/p' }).reason).toBe(
      'did not finish (timed_out)',
    );
  });
});

describe('cppcheckParser', () => {
  it('defects only, never a coverage result; error high, warning medium; the CWE kept', () => {
    const { findings } = cppcheckParser.parse(fixture('project-2.22.0.xml'), { project_path: '/p' });
    const ids = new Set(findings.map((f) => f.rule_id));
    for (const coverage of ['missingInclude', 'unknownMacro', 'syntaxError', 'preprocessorErrorDirective', 'toomanyconfigs', 'checkersReport']) {
      expect(ids.has(coverage), coverage).toBe(false);
    }
    const at = (id: string, file: string) => findings.find((f) => f.rule_id === id && f.file_path === file);
    expect(at('nullPointer', 'src/vuln.c')).toMatchObject({ severity: 'high', cwe: ['CWE-476'], line_start: 8, category: 'security' });
    expect(at('getsCalled', 'src/vuln.c')).toMatchObject({ severity: 'medium', cwe: ['CWE-477'] });
    expect(at('memleak', 'src/vuln.c')?.cwe).toEqual(['CWE-401']);
  });

  it('the trace goes into the message; inconclusive is one step lower; a file outside the project is dropped', () => {
    const xml =
      '<?xml version="1.0"?><results version="2"><cppcheck version="2.22.0"/><errors>' +
      '<error id="nullPointer" severity="error" msg="Null pointer dereference: p" verbose="Null pointer dereference: p" cwe="476">' +
      '<location file="a.c" line="7" column="13" info="Null pointer dereference"/><location file="a.c" line="6" column="14" info="Assignment &apos;p=NULL&apos;"/></error>' +
      '<error id="terminateStrncpy" severity="warning" msg="m" verbose="v" cwe="170" inconclusive="true"><location file="b.c" line="3"/></error>' +
      '<error id="nullPointer" severity="error" msg="m" verbose="v" cwe="476"><location file="/usr/include/x.h" line="1"/></error>' +
      '</errors></results>';
    const { findings } = cppcheckParser.parse(xml, { project_path: '/p' });
    expect(findings.map((f) => [f.rule_id, f.file_path, f.severity])).toEqual([
      ['nullPointer', 'a.c', 'high'],
      ['terminateStrncpy', 'b.c', 'low'],
    ]);
    expect(findings[0]?.message).toBe("Null pointer dereference: p — a.c:6: Assignment 'p=NULL'");
    expect(findings[1]?.message).toBe('v (inconclusive)');
  });
});
