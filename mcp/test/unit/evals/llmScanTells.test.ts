/**
 * Tells (`test/evals/llmScan/tells.ts`): the words that tell a model it is
 * looking at a deliberately vulnerable app, the scanner that finds where they
 * are, and how they go without moving a line — comments emptied (review
 * round 1), strings and identifiers renamed by one deterministic token map
 * (review round 2).
 */

import { describe, expect, it } from 'vitest';
import { renameCollisions } from '../../evals/llmScan/corpora.js';
import {
  ALLOWLIST,
  commentSpans,
  fileKindOf,
  findTells,
  neutraliseTellComments,
  newScrubLog,
  rewritePath,
  rewriteToken,
  scanSpans,
  scrubCode,
  scrubProse,
  tellsIn,
  tokenParts,
} from '../../evals/llmScan/tells.js';

const lines = (s: string): number => s.split('\n').length;

describe('the tell lists', () => {
  it('raw tells match anywhere, case-insensitively, with word boundaries where a short word needs one', () => {
    expect(tellsIn('intentionally Vulnerable vulnCode OWASP Juice benchmark DVWA VAmPI CTF pwned on purpose')).toEqual(
      expect.arrayContaining(['intention', 'Vulnerab', 'vuln', 'OWASP', 'Juice', 'benchmark', 'DVWA', 'VAmPI', 'CTF', 'pwn', 'on purpose']),
    );
    expect(tellsIn('This should never happen / This_should_always_happen').length).toBe(2);
    expect(tellsIn('Hacking Instructor hacking-instructor')).toHaveLength(2);
    // ordinary words and identifiers that only look close
    expect(tellsIn('ctfx actfind spawn insecurity xxetestbook1 purpose purposes source')).toEqual([]);
  });

  it('review round 2: the added words — cheat, hackable, unsafe, prompt injection, malicious, leaked', () => {
    for (const s of ['solved by cheating', 'hackable/uploads/', 'is unsafe', 'Chatbot Prompt Injection', 'Malicious activity', 'Leaked Unsafe Product']) {
      expect(tellsIn(s).length, s).toBeGreaterThan(0);
    }
  });

  it('review round 2: identifiers are split on case, underscore and digit boundaries', () => {
    expect(tokenParts('sqlInjectionX')).toEqual(['sql', 'Injection', 'X']);
    expect(tokenParts('is_unsafe')).toEqual(['is', '_', 'unsafe']);
    expect(tokenParts('XMLParser2')).toEqual(['XML', 'Parser', '2']);
    // a raw word inside a token is reported as the raw word (`unsafe` in `is_unsafe`); a token only when no raw word explains it
    expect(tellsIn('const xssFilter = sqlInjectionX(is_unsafe, SQLi, attackers)')).toEqual(['xssFilter', 'sqlInjectionX', 'unsafe', 'SQLi', 'attackers']);
  });

  it('the allowlist: the CSP keywords stay, and say so', () => {
    expect(ALLOWLIST.map((r) => r.source)).toEqual(['unsafe-(?:inline|eval|hashes)\\b']);
    expect(tellsIn("script-src 'self' 'unsafe-inline' 'unsafe-eval'")).toEqual([]);
    expect(tellsIn("script-src 'unsafe-inline'; is_unsafe = 1")).toEqual(['unsafe']);
  });

  it('key material is not words: a base64 run that happens to contain Rce is no tell', () => {
    expect(tellsIn("const k = 'hnIXha0atTX5AUkRRce95qSfvKFweXdJXSQ0JMGJyfuXgU6dI0TcseFRfewXAa'")).toEqual([]);
  });

  it('where a tell is: code, string, comment, prose or path', () => {
    expect(findTells('a.ts', 'const xss = "<script>"; // XXE here')).toEqual([
      { line: 1, tell: 'xss', where: 'code' },
      { line: 1, tell: 'XXE', where: 'comment' },
    ]);
    expect(findTells('a.py', 'x = "sql injection"\n')).toEqual([{ line: 1, tell: 'injection', where: 'string' }]);
    expect(findTells('notes.txt', 'XXE Attack SUCCESSFUL')).toHaveLength(2);
    expect(findTells('testcode/BenchmarkTest00001.py', '')).toEqual([{ line: 0, tell: 'Benchmark', where: 'path' }]);
    expect(findTells('helpers/resources/xxe.txt', null)).toEqual([{ line: 0, tell: 'xxe', where: 'path' }]);
    expect(findTells('lib/antiCheat.ts', '')).toEqual([{ line: 0, tell: 'Cheat', where: 'path' }]);
  });

  it('file kinds', () => {
    expect(fileKindOf('a/b.ts')).toBe('js');
    expect(fileKindOf('a/b.php')).toBe('php');
    expect(fileKindOf('a/b.py')).toBe('python');
    expect(fileKindOf('testfiles/site-sqlite3.db')).toBe('binary');
    expect(fileKindOf('testfiles/fixed value b')).toBe('prose');
  });
});

describe('the scanner skips strings, templates and regexes, and reports strings', () => {
  const text = (src: string, lang: 'js' | 'php' | 'python'): string[] => commentSpans(src, lang).map((s) => src.slice(s.start, s.end));

  it('JS/TS', () => {
    const src = [
      'const u = "http://a//b" // c1',
      "const t = `x ${'//'} y` /* c2 */",
      'const r = /\\/\\/[a/]/g // c3',
      'const d = a / b // c4',
    ].join('\n');
    expect(text(src, 'js')).toEqual(['// c1', '/* c2 */', '// c3', '// c4']);
    expect(scanSpans(src, 'js').strings.map((s) => src.slice(s.start, s.end))).toEqual(['"http://a//b"', "`x ${'//'} y`"]);
  });

  it('PHP: `#` comments, but not a `#[` attribute; strings may span lines', () => {
    const src = ['<?php', '# c1', '#[Attr]', '$s = "a # b', '// not a comment yet";', '// c2'].join('\n');
    expect(text(src, 'php')).toEqual(['# c1', '// c2']);
  });

  it('Python: `#` comments and docstrings, but not a triple-quoted string assigned or passed', () => {
    const src = ['"""Module doc."""', 'x = """SELECT', 'FROM t"""', 'def f():', '    """Doc."""', '    y = "a # b"  # c1', '    g(', '        """arg"""', '    )'].join('\n');
    expect(text(src, 'python')).toEqual(['"""Module doc."""', '"""Doc."""', '# c1']);
    expect(scanSpans(src, 'python').strings.map((s) => src.slice(s.start, s.end))).toEqual(['"""SELECT\nFROM t"""', '"a # b"', '"""arg"""']);
  });
});

describe('neutraliseTellComments: emptied, never a line added or removed', () => {
  it('a block comment keeps its delimiters and its line breaks', () => {
    const src = '/*\n * Copyright Bjoern Kimminich & the OWASP Juice Shop contributors.\n */\nconst a = 1\n';
    const out = neutraliseTellComments(src, 'js');
    expect(out.text).toBe('/*\n\n*/\nconst a = 1\n');
    expect(out.emptied).toBe(1);
  });

  it('a trailing line comment goes with the blanks before it; the code stays', () => {
    expect(neutraliseTellComments('foo() // intentionally vulnerable\r\nbar()\r\n', 'js').text).toBe('foo()\r\nbar()\r\n');
  });

  it('a run of whole-line comments is one comment: all of it goes when one line has a tell', () => {
    const src = ['// Parses XML with entities', '// (intentionally vulnerable to XXE).', '// Runs in a vm.', 'parse()', '// unrelated', 'x()'].join('\n');
    expect(neutraliseTellComments(src, 'js').text.split('\n')).toEqual(['', '', '', 'parse()', '// unrelated', 'x()']);
  });

  it('a comment naming a split identifier counts too', () => {
    expect(neutraliseTellComments('// app.use(helmet.xssFilter())\nok()\n', 'js').text).toBe('\nok()\n');
  });

  it('a comment without a tell, and code, are left alone by the comment pass', () => {
    const src = '// sums the basket\nconst challenge = 1\n';
    expect(neutraliseTellComments(src, 'js').text).toBe(src);
  });

  it('a Python docstring stating the flaw is emptied, its quotes kept', () => {
    const src = 'def debug():\n    """Debug endpoint, vulnerable on purpose.\n    Dumps users."""\n    return 1\n';
    const out = neutraliseTellComments(src, 'python').text;
    expect(lines(out)).toBe(lines(src));
    expect(out).toBe('def debug():\n    """\n"""\n    return 1\n');
  });

  it('PHP comments naming an attack', () => {
    const src = "<?php\n\t// Check Anti-CSRF token\n\tcheckToken( $_REQUEST[ 'user_token' ] );\n";
    expect(neutraliseTellComments(src, 'php').text).toBe("<?php\n\n\tcheckToken( $_REQUEST[ 'user_token' ] );\n");
  });
});

describe('review round 2: tells in strings are neutralised in place', () => {
  it('display strings: the attack words and the new words go, the quotes and the lines stay', () => {
    const src = [
      "res.status(403).json({ error: 'Malicious activity detected' })",
      "const deps = ['\"Chatbot Prompt Injection\" event', '\"Leaked Unsafe Product\" event product']",
      "const help = 'Overall probability that any hacking or coding events were solved by cheating.'",
      'const p = \'<iframe src="javascript:alert(`xss`)">\'',
      "const note = 'saved on purpose'",
    ].join('\n');
    const out = scrubCode(src, 'js');
    expect(lines(out)).toBe(lines(src));
    expect(out.split('\n')).toEqual([
      "res.status(403).json({ error: 'Unusual activity detected' })",
      "const deps = ['\"Chatbot Prompt Input\" event', '\"Shared Raw Product\" event product']",
      "const help = 'Overall probability that any testing or coding events were solved by anomaly.'",
      'const p = \'<iframe src="javascript:alert(`markup`)">\'',
      "const note = 'saved as designed'",
    ]);
    expect(findTells('a.ts', out)).toEqual([]);
  });

  it('a Python string and a PHP string, with an allowlisted CSP keyword kept', () => {
    expect(scrubCode('x = "SQLi via sql_injection_x"\n', 'python')).toBe('x = "Query via sql_input_x"\n');
    expect(scrubCode('$target_path = APP_WEB_PAGE_TO_ROOT . "hackable/uploads/";\n', 'php')).toBe('$target_path = APP_WEB_PAGE_TO_ROOT . "storage/uploads/";\n');
    const csp = "const CSP = `script-src 'self' 'unsafe-eval' 'unsafe-inline'`\n";
    expect(scrubCode(csp, 'js')).toBe(csp);
  });

  it('data files go through the same map', () => {
    expect(scrubProse("DESC 'The set of entries to inject at startup'")).toBe("DESC 'The set of entries to input at startup'");
  });
});

describe('review round 2: identifiers are renamed by one deterministic map', () => {
  it('camelCase and snake_case parts take the replacement in their own case', () => {
    expect(rewriteToken('xssFilter')).toBe('markupFilter');
    expect(rewriteToken('sqlInjectionX')).toBe('sqlInputX');
    expect(rewriteToken('is_unsafe')).toBe('is_raw');
    expect(rewriteToken('SQLI_DB')).toBe('QUERY_DB');
    expect(rewriteToken('SQLi')).toBe('Query');
    expect(rewriteToken('antiCheat')).toBe('antiAnomaly');
    expect(rewriteToken('calculateFindItCheatScore')).toBe('calculateFindItAnomalyScore');
    expect(rewriteToken('Injected')).toBe('Input');
    expect(rewriteToken('ordinaryName')).toBe('ordinaryName');
  });

  it('the same identifier gets the same name everywhere: declaration, use, import, export and the file it names', () => {
    const a = scrubCode("import * as antiCheat from './antiCheat'\nconst cheatScore = antiCheat.calculateCheatScore(event, isCheating)\nexport { cheatScore }\n", 'js');
    const b = scrubCode("import { cheatScore } from './telemetry'\nconsole.log(cheatScore)\n", 'js');
    expect(a).toBe("import * as antiAnomaly from './antiAnomaly'\nconst anomalyScore = antiAnomaly.calculateAnomalyScore(event, isAnomaly)\nexport { anomalyScore }\n");
    expect(b).toBe("import { anomalyScore } from './telemetry'\nconsole.log(anomalyScore)\n");
    expect(rewritePath('lib/antiCheat.ts')).toBe('lib/antiAnomaly.ts');
    expect(rewritePath('hackable/uploads/x.png')).toBe('storage/uploads/x.png');
    expect(findTells('a.ts', a)).toEqual([]);
  });

  it('a Python class and its uses; comments with a tell emptied in the same pass; lines never move', () => {
    const src = '# class used as an exploit payload\nclass Injected:\n    pass\n\nx = Injected()\nis_unsafe = 1\n';
    const out = scrubCode(src, 'python');
    expect(out).toBe('\nclass Input:\n    pass\n\nx = Input()\nis_raw = 1\n');
    expect(lines(out)).toBe(lines(src));
  });

  it('the scrub log keeps identifiers apart from string words, and collisions are found', () => {
    const log = newScrubLog();
    scrubCode("const xssFilter = 1\nconst m = 'xss'\n", 'js', log);
    expect([...log.code]).toEqual([['xssFilter', 'markupFilter']]);
    expect([...log.strings]).toEqual([['xss', 'markup']]);
    expect(renameCollisions(log, new Set(['markupFilter']))).toEqual(['xssFilter -> markupFilter: markupFilter is already a name in the code']);
    const twice = newScrubLog();
    scrubCode('const idor = 1\nconst bola = 2\n', 'js', twice);
    expect(renameCollisions(twice, new Set())).toEqual(['idor and bola both -> objref']);
    expect(renameCollisions(log, new Set())).toEqual([]);
  });
});
