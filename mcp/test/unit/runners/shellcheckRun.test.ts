/**
 * shellcheck's run judged, and the scripts it is handed (`runners/shellcheckRun.ts`).
 * The outputs below are shellcheck 0.11.0's own, measured on 2026-10-24:
 * `-f json1`, exit 0 clean, 1 comments, 2 a file it could not read (stderr
 * names it, the rest is still reported), SC1072/SC1073 where a parse stopped.
 */

import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { listProjectFiles } from '../../../src/runners/projectFiles.js';
import { shellcheckParser } from '../../../src/runners/scannerParsers/shellcheck.js';
import { judgeShellcheck, SHELLCHECK_SYNTAX_ERROR, shellScripts } from '../../../src/runners/shellcheckRun.js';

const PROJECT = resolve(fileURLToPath(new URL('.', import.meta.url)), '../../fixtures/shellcheck/project');

const run = (exitCode: number | null, stdout: string, stderr = '', outcome: 'completed' | 'failed' | 'timed_out' = 'completed') => ({
  outcome,
  exitCode,
  stdout,
  stderr,
});

const comment = (file: string, line: number, code: number, level: string, message: string) => ({
  file,
  line,
  endLine: line,
  column: 1,
  endColumn: 2,
  level,
  code,
  message,
  fix: null,
});

describe('shellScripts', () => {
  it('the fixture: .sh files and an extensionless bash script, never zsh, python or text', () => {
    expect(shellScripts(PROJECT, listProjectFiles(PROJECT))).toEqual([
      'bin/release',
      'scripts/broken.sh',
      'scripts/clean.sh',
      'scripts/deploy.sh',
    ]);
  });

  it('by extension without reading the file, and an extensionless file only by its shebang', () => {
    expect(shellScripts(PROJECT, ['a.bash', 'b.KSH', 'c.dash', 'd.zsh', 'e.fish', 'f.sh.txt', 'Makefile', 'missing-file'])).toEqual([
      'a.bash',
      'b.KSH',
      'c.dash',
    ]);
  });
});

describe('judgeShellcheck', () => {
  it('exit 1 with comments: ok, the report kept', () => {
    const out = JSON.stringify({ comments: [comment('a.sh', 2, 2086, 'info', 'Double quote to prevent globbing and word splitting.')] });
    expect(judgeShellcheck(run(1, out))).toEqual({ ok: true, report: out, partial: [] });
  });

  it('a script whose parse stopped is named as a syntax error; an unsupported shell as such', () => {
    const out = JSON.stringify({
      comments: [
        comment('b.sh', 2, 1046, 'error', "Couldn't find 'fi' for this 'if'."),
        comment('b.sh', 2, 1073, 'error', "Couldn't parse this if expression. Fix to allow more checks."),
        comment('b.sh', 4, 1072, 'error', "Expected 'fi'. Fix any mentioned problems and try again."),
        comment('z.sh', 1, 1071, 'error', "ShellCheck only supports sh/bash/dash/ksh/'busybox sh' scripts. Sorry!"),
      ],
    });
    expect(judgeShellcheck(run(1, out)).partial).toEqual([
      { file: 'b.sh', type: SHELLCHECK_SYNTAX_ERROR, message: "Couldn't parse this if expression. Fix to allow more checks." },
      { file: 'z.sh', type: 'Unsupported shell', message: "ShellCheck only supports sh/bash/dash/ksh/'busybox sh' scripts. Sorry!" },
    ]);
  });

  it('exit 2: the files it could not read are named, the others reported', () => {
    const r = judgeShellcheck(run(2, '{"comments":[]}', 'nope.sh: nope.sh: openBinaryFile: does not exist (No such file or directory)\n'));
    expect(r.ok).toBe(true);
    expect(r.partial).toEqual([{ file: 'nope.sh', type: 'Not read', message: 'openBinaryFile: does not exist (No such file or directory)' }]);
  });

  it('exit 2 naming no file, a bad option, no report, an unfinished run: failed', () => {
    expect(judgeShellcheck(run(2, '{"comments":[]}', 'something else')).ok).toBe(false);
    expect(judgeShellcheck(run(3, '', 'Unknown option -Q'))).toEqual({ ok: false, reason: 'exit 3: Unknown option -Q', partial: [] });
    expect(judgeShellcheck(run(1, 'not json')).reason).toBe('no readable report was written');
    expect(judgeShellcheck(run(null, '', '', 'timed_out')).reason).toBe('did not finish (timed_out)');
  });
});

describe('shellcheckParser', () => {
  it('SC codes, the level as severity, a quality smell with its wiki page', () => {
    const report = JSON.stringify({
      comments: [
        comment('/p/scripts/a.sh', 4, 2045, 'error', 'Iterating over ls output is fragile. Use globs.'),
        comment('/p/scripts/a.sh', 3, 2164, 'warning', "Use 'cd ... || exit' or 'cd ... || return' in case cd fails."),
        comment('/p/scripts/a.sh', 2, 2086, 'info', 'Double quote to prevent globbing and word splitting.'),
        comment('/p/scripts/a.sh', 5, 2006, 'style', 'Use $(...) notation instead of legacy backticks `...`.'),
      ],
    });
    const { findings } = shellcheckParser.parse(report, { project_path: '/p' });
    expect(findings.map((f) => [f.rule_id, f.severity, f.file_path, f.line_start])).toEqual([
      ['SC2045', 'medium', 'scripts/a.sh', 4],
      ['SC2164', 'low', 'scripts/a.sh', 3],
      ['SC2086', 'low', 'scripts/a.sh', 2],
      ['SC2006', 'info', 'scripts/a.sh', 5],
    ]);
    expect(findings.every((f) => f.tool === 'shellcheck' && f.category === 'quality' && f.subcategory === 'smell')).toBe(true);
    expect(findings[0]?.message).toContain('https://www.shellcheck.net/wiki/SC2045');
  });
});
