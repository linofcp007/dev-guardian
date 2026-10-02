/**
 * Blinding for the LLM-scan evals (`test/evals/llmScan/blind.ts`): the
 * tell-tale names go, and NO line moves — a key's `file:line` in the original
 * is the same `file:line` in the copy the model sees.
 *
 * Synthetic inputs first. The tests over the real corpora run only when the
 * corpus's variable is set (GUARDIAN_LLMSCAN_SPIKE, GUARDIAN_VAMPI_SRC,
 * GUARDIAN_JUICESHOP_SRC, GUARDIAN_DVWA_SRC, GUARDIAN_BENCHMARK_PY_SRC): each
 * builds the blind copy — which itself refuses a copy with any tell left —
 * and checks the line counts and the key lines.
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  BENCHMARK_HINT_NAMES,
  DVWA_LAYOUT,
  VAMPI_FILES,
  assertSameLineCount,
  benchmarkBlindPath,
  benchmarkViewNumber,
  blindBenchmarkText,
  blindDvwaText,
  blindJuiceText,
  blindPathOf,
  blindVampiText,
  dvwaFiles,
  isJuiceFile,
  juiceAliases,
  juiceOutPath,
} from '../../evals/llmScan/blind.js';
import { CORPORA, buildBlindCopy, type CorpusId } from '../../evals/llmScan/corpora.js';
import { findTells } from '../../evals/llmScan/tells.js';
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

  it('review round 1: a comment stating the flaw is emptied before `vuln` → `item` can mangle it, and the CTF, author and tutor names go', () => {
    // lib/xml.ts and lib/startup/validateConfig.ts of Juice Shop 1618a61, abridged
    const src = [
      '/*',
      ' * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.',
      ' * SPDX-License-Identifier: MIT',
      ' */',
      '// Parses XML with entity substitution and external entity loading enabled',
      '// (intentionally vulnerable to XXE for the related challenges). The parse runs',
      '// in a vm context with a timeout.',
      'export async function parseXmlString (data: string) {',
      '  const url = "https://example.org/a//b" // not a comment start inside the string',
      "  logger.warn(`Restricted tutorial mode is enabled while Hacking Instructor is disabled`)",
      "  if (configuration.ctf?.showFlagsInNotifications) logger.warn('CTF flags are enabled')",
      "  return req.body.email === 'bjoern.kimminich@gmail.com'",
      '}',
    ].join('\n');
    const out = blindJuiceText('lib/xml.ts', src, new Map());
    expect(lines(out)).toBe(lines(src));
    const o = out.split('\n');
    expect(o.slice(0, 4)).toEqual(['/*', '', '', '*/']);
    // the whole three-line comment goes, not just the line with the tell
    expect(o.slice(4, 7)).toEqual(['', '', '']);
    expect(o[7]).toBe('export async function parseXmlString (data: string) {');
    // a `//` inside a string is not a comment, and a comment with no tell stays
    expect(o[8]).toBe('  const url = "https://example.org/a//b" // not a comment start inside the string');
    expect(out).not.toMatch(/itemerable|intentional|xxe|kimminich|hacking instructor|\bctf\b/i);
    expect(out).toContain("configuration.score?.showFlagsInNotifications) logger.warn('SCORE flags are enabled')");
    expect(out).toContain("req.body.email === 'shop.owner@gmail.com'");
    expect(findTells('lib/xml.ts', out)).toEqual([]);
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

  it('renames the product and the level file names, and empties comments naming an attack — line for line', () => {
    const php = [
      '<?php',
      "if( isset( $_POST[ 'Submit' ]  ) ) {",
      '  // Check Anti-CSRF token',
      '  dvwaMessagePush( "x" ); // see low.php',
      '  $html .= DVWA_WEB_PAGE_TO_ROOT . "impossible.php";',
      '}',
    ].join('\n');
    const out = blindDvwaText('exec/source/low.php', php);
    expect(lines(out)).toBe(lines(php));
    expect(out.split('\n')[2]).toBe('');
    expect(out).toContain('appMessagePush');
    expect(out).toContain('APP_WEB_PAGE_TO_ROOT');
    expect(out).not.toMatch(/dvwa|csrf|low\.php|impossible\.php/i);
  });
});

describe('app-b (BenchmarkPython)', () => {
  const header = ["'''", 'OWASP Benchmark for Python v0.1', '', 'This file is part of the OWASP Benchmark Project.', "'''", '', 'def init(app):', '\tpass'];

  it('blanks the benchmark\'s licence header (the quotes stay), line for line', () => {
    const text = header.join('\r\n');
    const out = blindBenchmarkText('testcode/BenchmarkTest00001.py', text);
    expect(lines(out)).toBe(lines(text));
    expect(out.split('\n').slice(0, 5)).toEqual(["'''\r", '\r', '\r', '\r', "'''\r"]);
    expect(out).not.toMatch(/OWASP|Benchmark/i);
    expect(out).toContain('def init(app):');
  });

  it('review round 1: renames the test cases, the routes and every benchmark string, file names and contents alike', () => {
    const code = [
      'def init(app):',
      "\t@app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET'])",
      '\tdef BenchmarkTest00004_get():',
      "\t\treturn render_template('web/xss-01/BenchmarkTest00004.html')",
      "\tparam = request.cookies.get('BenchmarkTest00004', 'x')",
      '\tbar = "This_should_always_happen" if 7 * 18 + num > 200 else param',
      '\tother = "This should never happen"',
      "\tlst.append('moresafe'); lst.append('safe'); bar = \"alsosafe\"; z = 'safe!'",
      "\tuser = f'SafeToby{num}'; y = param + '_SafeStuff'",
      "\tdb = f'{helpers.utils.TESTFILES_DIR}/benchmark-sqlite3.db'",
      '\t# class used in deserialization test cases as an exploit payload',
      "test_files = [f for f in os.listdir('testcode') if f.startswith('Benchmark')]",
    ].join('\n');
    const out = blindBenchmarkText('testcode/BenchmarkTest00004.py', code);
    expect(lines(out)).toBe(lines(code));
    const v = `View${benchmarkViewNumber(4)}`;
    expect(out).toContain(`@app.route('/site/pages-00/${v}', methods=['GET'])`);
    expect(out).toContain(`def ${v}_get():`);
    expect(out).toContain(`render_template('web/pages-01/${v}.html')`);
    expect(out).toContain('bar = "fixed_value_a" if 7 * 18 + num > 200 else param');
    expect(out).toContain('other = "fixed value b"');
    expect(out).toContain("lst.append('value_b'); lst.append('value_a'); bar = \"value_c\"; z = 'value_d!'");
    expect(out).toContain("user = f'Toby{num}'; y = param + '_Stuff'");
    expect(out).toContain('/site-sqlite3.db');
    expect(out).toContain(".startswith('View')]");
    expect(out.split('\n')[10]).toBe('');
    expect(out).not.toMatch(/benchmark|should[ _](never|always)|safe|exploit/i);
    expect(findTells(benchmarkBlindPath('testcode/BenchmarkTest00004.py'), out)).toEqual([]);
  });

  it('maps every path the same way, so a file opened by name is still there', () => {
    expect(benchmarkBlindPath('testcode/BenchmarkTest00004.py')).toBe(`testcode/View${benchmarkViewNumber(4)}.py`);
    expect(benchmarkBlindPath('testfiles/This should never happen')).toBe('testfiles/fixed value b');
    expect(benchmarkBlindPath('testfiles/This_should_always_happen')).toBe('testfiles/fixed_value_a');
    expect(benchmarkBlindPath('testfiles/benchmark-sqlite3.db')).toBe('testfiles/site-sqlite3.db');
    expect(benchmarkBlindPath('testfiles/moresafe')).toBe(`testfiles/${BENCHMARK_HINT_NAMES['moresafe'] ?? '?'}`);
    expect(benchmarkBlindPath('helpers/resources/xxe.txt')).toBe('helpers/resources/entity.txt');
    expect(benchmarkBlindPath('helpers/resources/insecureCmd.sh')).toBe('helpers/resources/runCmd.sh');
    expect(blindPathOf('benchmark-python', 'testcode/BenchmarkTest00432.py')).toBe(`testcode/View${benchmarkViewNumber(432)}.py`);
    expect(blindPathOf('vampi', 'config.py')).toBe('config.py');
    expect(blindPathOf('juice-shop', 'lib/insecurity.ts')).toBe('lib/secutil.ts');
  });

  it('the test-case numbers are a bijection: no two cases collide', () => {
    const all = Array.from({ length: 1230 }, (_, i) => benchmarkViewNumber(i + 1));
    expect(new Set(all).size).toBe(1230);
    expect(all).not.toContain('00004');
  });

  it('leaves alone a Python file without that header', () => {
    const plain = 'import os\nprint(1)\n';
    expect(blindBenchmarkText('helpers/utils.py', plain)).toBe(plain);
    const unterminated = "'''\nOWASP\n";
    expect(lines(blindBenchmarkText('a.py', unterminated))).toBe(lines(unterminated));
  });
});

// ---------- the real corpora (env-gated) ----------

/** A key line and what it must still say in the blind copy. */
const KEY_LINES: Readonly<Record<CorpusId, ReadonlyArray<[string, number, RegExp]>>> = {
  'app-s': [['src/repositories/shifts.ts', 64, /LIKE '%\$\{term\}%'/]],
  vampi: [
    ['models/user_model.py', 72, /SELECT \* FROM users WHERE username/],
    ['config.py', 13, /\['SECRET_KEY'\] = 'random'/],
  ],
  'juice-shop': [
    ['routes/login.ts', 34, /models\.sequelize\.query\(`SELECT \* FROM Users WHERE email/],
    ['routes/redirect.ts', 18, /redirect/],
  ],
  dvwa: [
    ['m1/variant_c.php', 10, /shell_exec/],
    ['m3/variant_a.php', 34, /\$query/],
  ],
  'benchmark-python': [[blindPathOf('benchmark-python', 'testcode/BenchmarkTest00432.py'), 53, /subprocess/]],
};

function corpusDir(id: CorpusId): string | undefined {
  const raw = process.env[CORPORA[id].env];
  if (raw === undefined || raw.trim() === '') return undefined;
  const dir = id === 'app-s' ? join(raw, 'corpus', 'app-s') : raw;
  return existsSync(dir) ? dir : undefined;
}

describe.each(Object.keys(KEY_LINES) as CorpusId[])('the real blind copy of %s (env-gated)', (id) => {
  const src = corpusDir(id);
  it.skipIf(src === undefined)(
    `has no tell left, keeps every key line in place (${CORPORA[id].env})`,
    () => {
      const dest = join(makeTempDir('llmscan-blind-'), CORPORA[id].blindName);
      const report = buildBlindCopy(id, src ?? '', dest);
      expect(report.tells_after).toEqual([]);
      expect(report.files).toBeGreaterThan(10);
      if (id !== 'app-s') expect(report.tells_before).toBeGreaterThan(0);
      for (const [rel, n, re] of KEY_LINES[id]) {
        const text = readFileSync(join(dest, ...rel.split('/')), 'utf8');
        expect(text.split('\n')[n - 1] ?? '', `${rel}:${n}`).toMatch(re);
      }
      if (id === 'vampi') {
        for (const rel of VAMPI_FILES) expect(lines(readFileSync(join(dest, rel), 'utf8')), rel).toBe(lines(readFileSync(join(src ?? '', rel), 'utf8')));
        expect(readdirSync(dest).sort()).toEqual(['api_views', 'app.py', 'config.py', 'database', 'models', 'openapi_specs', 'requirements.txt']);
      }
    },
    180_000,
  );
});
