/**
 * Blinding for the LLM-scan evals (`test/evals/llmScan/blind.ts`): the
 * tell-tale names go, and NO line moves — a key's `file:line` in the original
 * is the same `file:line` in the copy the model sees.
 *
 * Synthetic inputs throughout; the one test over a real corpus (VAmPI) runs
 * only when GUARDIAN_VAMPI_SRC is set.
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  DVWA_LAYOUT,
  VAMPI_FILES,
  assertSameLineCount,
  blindBenchmarkPyText,
  blindDvwaText,
  blindJuiceText,
  blindVampiText,
  dvwaFiles,
  isJuiceFile,
  juiceAliases,
  juiceOutPath,
} from '../../evals/llmScan/blind.js';
import { buildBlindCopy } from '../../evals/llmScan/corpora.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const lines = (s: string): number => s.split('\n').length;

describe('assertSameLineCount', () => {
  it('passes on the same count and throws naming the file otherwise', () => {
    expect(() => assertSameLineCount('a\nb', 'x\ny', 'f')).not.toThrow();
    expect(() => assertSameLineCount('a\nb', 'x', 'app-v/f.py')).toThrow(/app-v\/f\.py/);
  });
});

describe('app-v (VAmPI)', () => {
  const users = [
    'from config import vuln_app',
    "vuln = int(os.getenv('vulnerable', 1))",
    '',
    'def debug():',
    '    """ debug endpoint that dumps every user, vulnerable on purpose """',
    '    return jsonify(User.get_all_users_debug())  # Excessive data exposure',
    '',
    'def get_by_title(book_title):',
    '    if vuln:  # Broken Object Level Authorization',
    '        book = Book.query.filter_by(book_title=str(book_title)).first()',
    '',
  ].join('\r\n');

  it('drops comments and flaw-describing docstring lines, renames the switch — every line in place', () => {
    const out = blindVampiText('api_views/users.py', users);
    expect(lines(out)).toBe(lines(users));
    const o = out.split('\n');
    expect(o[0]).toBe('from config import api_app\r');
    expect(o[1]).toBe("compat_mode = int(os.getenv('compat_mode', 1))\r");
    expect(o[4]).toBe('');
    expect(o[5]).toBe('    return jsonify(User.get_all_users_debug())\r');
    expect(o[8]).toBe('    if compat_mode:\r');
    expect(out).not.toMatch(/vuln|Authorization|exposure/i);
  });

  it('renames the API in the OpenAPI document, line for line', () => {
    const spec = ['openapi: 3.0.1', 'info:', '  title: VAmPI the Vulnerable API', '  description: VAmPI is a vulnerable on purpose API. It was created', '  version: "0.1"'].join('\n');
    const out = blindVampiText('openapi_specs/openapi3.yml', spec);
    expect(lines(out)).toBe(lines(spec));
    expect(out).toContain('title: Shelf API');
    expect(out).not.toMatch(/vulnerab|VAmPI/i);
  });

  it('copies exactly the spike\'s file list', () => {
    expect(VAMPI_FILES).toHaveLength(13);
    expect(VAMPI_FILES).toContain('api_views/users.py');
    expect(VAMPI_FILES).not.toContain('README.md');
  });

  const src = process.env['GUARDIAN_VAMPI_SRC'];
  it.skipIf(src === undefined || !existsSync(src))('the real blind copy keeps every line count and every key line (GUARDIAN_VAMPI_SRC)', () => {
    const root = src ?? '';
    const dest = join(makeTempDir('llmscan-blind-'), 'app-v');
    expect(buildBlindCopy('vampi', root, dest)).toBe(13);
    for (const rel of VAMPI_FILES) {
      const a = readFileSync(join(root, rel), 'utf8');
      const b = readFileSync(join(dest, rel), 'utf8');
      expect(lines(b), rel).toBe(lines(a));
      expect(b, rel).not.toMatch(/\bvuln\b|VAmPI|vulnerable/);
    }
    const line = (rel: string, n: number): string => readFileSync(join(dest, rel), 'utf8').split('\n')[n - 1] ?? '';
    expect(line('models/user_model.py', 72)).toContain('SELECT * FROM users WHERE username');
    expect(line('config.py', 13)).toContain("['SECRET_KEY']");
    expect(readdirSync(dest).sort()).toEqual(['api_views', 'app.py', 'config.py', 'database', 'models', 'openapi_specs', 'requirements.txt']);
  });
});

describe('app-j (Juice Shop)', () => {
  it('aliases the challenge identifiers consistently and strips the snippet markers, line for line', () => {
    const a = [
      "import challengeUtils = require('../lib/challengeUtils')",
      'export function login () { // vuln-code-snippet start loginAdminChallenge',
      '  challengeUtils.solveIf(challenges.loginAdminChallenge, () => true) // vuln-code-snippet vuln-line loginAdminChallenge',
      '  return insecurity.hash(x)',
      '}',
    ].join('\n');
    const b = 'solveIf(challenges.weakPasswordChallenge, () => true)\nconst y = challenges.loginAdminChallenge';
    const alias = juiceAliases(`${a}\n${b}`);
    expect([...alias.entries()]).toEqual([
      ['loginAdminChallenge', 'e001'],
      ['weakPasswordChallenge', 'e002'],
    ]);
    const outA = blindJuiceText('routes/login.ts', a, alias);
    const outB = blindJuiceText('routes/x.ts', b, alias);
    expect(lines(outA)).toBe(lines(a));
    expect(lines(outB)).toBe(lines(b));
    expect(outA).toContain('telemetry.trackIf(events.e001');
    expect(outB).toContain('events.e001');
    expect(outA).not.toMatch(/vuln|challenge|insecurity/i);
  });

  it('keeps routes/lib/models TS minus the challenge machinery, and renames the two give-away files', () => {
    expect(isJuiceFile('routes/login.ts')).toBe(true);
    expect(isJuiceFile('routes/vulnCodeSnippet.ts')).toBe(false);
    expect(isJuiceFile('lib/scripts/x.ts')).toBe(false);
    expect(isJuiceFile('models/challenge.ts')).toBe(false);
    expect(isJuiceFile('routes/login.js')).toBe(false);
    expect(juiceOutPath('lib/insecurity.ts')).toBe('lib/secutil.ts');
    expect(juiceOutPath('lib/challengeUtils.ts')).toBe('lib/telemetry.ts');
  });
});

describe('app-d (DVWA)', () => {
  it('the layout is the spike\'s blind-map: the C-items\' files hold the levels the spike gave them', () => {
    const at = (out: string): string | undefined => dvwaFiles().find((f) => f.out === out)?.source;
    expect(at('m1/variant_c.php')).toBe('vulnerabilities/exec/source/low.php');
    expect(at('m1/variant_b.php')).toBe('vulnerabilities/exec/source/high.php');
    expect(at('m1/variant_a.php')).toBe('vulnerabilities/exec/source/impossible.php');
    expect(at('m3/variant_a.php')).toBe('vulnerabilities/sqli_blind/source/medium.php');
    expect(at('m3/variant_c.php')).toBe('vulnerabilities/sqli_blind/source/high.php');
    expect(at('m4/variant_a.php')).toBe('vulnerabilities/captcha/source/impossible.php');
    expect(at('m5/variant_d.php')).toBe('vulnerabilities/upload/source/impossible.php');
    expect(dvwaFiles()).toHaveLength(28);
    for (const { variants } of Object.values(DVWA_LAYOUT)) expect(new Set(variants).size).toBe(4);
  });

  it('renames the product and the level file names, line for line', () => {
    const php = ['<?php', "if( isset( $_POST[ 'Submit' ]  ) ) {", '  dvwaMessagePush( "x" ); // see low.php', '  $html .= DVWA_WEB_PAGE_TO_ROOT . "impossible.php";', '}'].join('\n');
    const out = blindDvwaText('exec/source/low.php', php);
    expect(lines(out)).toBe(lines(php));
    expect(out).toContain('appMessagePush');
    expect(out).toContain('APP_WEB_PAGE_TO_ROOT');
    expect(out).not.toMatch(/dvwa|low\.php|impossible\.php/i);
  });
});

describe('app-b (BenchmarkPython)', () => {
  const header = ["'''", 'OWASP Benchmark for Python v0.1', '', 'This file is part of the OWASP Benchmark Project.', "'''", '', 'def init(app):', '\tpass'];

  it('blanks the benchmark\'s licence header (the quotes stay), line for line', () => {
    const text = header.join('\r\n');
    const out = blindBenchmarkPyText('testcode/BenchmarkTest00001.py', text);
    expect(lines(out)).toBe(lines(text));
    expect(out.split('\n').slice(0, 5)).toEqual(["'''\r", '\r', '\r', '\r', "'''\r"]);
    expect(out).not.toMatch(/OWASP|Benchmark Project/);
    expect(out).toContain('def init(app):');
  });

  it('leaves alone a file without that header, and every non-Python file', () => {
    const plain = 'import os\nprint(1)\n';
    expect(blindBenchmarkPyText('helpers/utils.py', plain)).toBe(plain);
    expect(blindBenchmarkPyText('testfiles/x.txt', header.join('\n'))).toBe(header.join('\n'));
    const unterminated = "'''\nOWASP\n";
    expect(blindBenchmarkPyText('a.py', unterminated)).toBe(unterminated);
  });
});
