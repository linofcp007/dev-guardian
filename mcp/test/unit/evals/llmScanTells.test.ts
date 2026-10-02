/**
 * Tells (`test/evals/llmScan/tells.ts`): the words that tell a model it is
 * looking at a deliberately vulnerable app, the comment scanner that finds
 * where they are, and the neutraliser that empties a comment without moving
 * a line. Review round 1, item 3.
 */

import { describe, expect, it } from 'vitest';
import { commentSpans, fileKindOf, findTells, neutraliseTellComments, tellsIn } from '../../evals/llmScan/tells.js';

const lines = (s: string): number => s.split('\n').length;

describe('the tell lists', () => {
  it('general tells match anywhere, case-insensitively, with word boundaries where a short word needs one', () => {
    expect(tellsIn('intentionally Vulnerable vulnCode OWASP Juice benchmark DVWA VAmPI CTF pwned on purpose')).toEqual(
      expect.arrayContaining(['intention', 'Vulnerab', 'vuln', 'OWASP', 'Juice', 'benchmark', 'DVWA', 'VAmPI', 'CTF', 'pwn', 'on purpose']),
    );
    expect(tellsIn('This should never happen / This_should_always_happen').length).toBe(2);
    expect(tellsIn('Hacking Instructor hacking-instructor')).toHaveLength(2);
    // no word boundary, no tell: these are ordinary words and identifiers
    expect(tellsIn('ctfx actfind spawn insecurity xxetestbook1 attackers')).toEqual([]);
  });

  it('attack classes are tells in prose only', () => {
    expect(findTells('a.ts', 'const xss = "<script>"; // XXE here')).toEqual([{ line: 1, tell: 'XXE', where: 'comment' }]);
    expect(findTells('notes.txt', 'XXE Attack SUCCESSFUL')).toHaveLength(2);
    expect(findTells('a.py', 'x = "sql injection"\n')).toEqual([]);
  });

  it('a path is read too', () => {
    expect(findTells('testcode/BenchmarkTest00001.py', '')).toEqual([{ line: 0, tell: 'Benchmark', where: 'path' }]);
    expect(findTells('helpers/resources/xxe.txt', null)).toEqual([{ line: 0, tell: 'xxe', where: 'path' }]);
  });

  it('file kinds', () => {
    expect(fileKindOf('a/b.ts')).toBe('js');
    expect(fileKindOf('a/b.php')).toBe('php');
    expect(fileKindOf('a/b.py')).toBe('python');
    expect(fileKindOf('testfiles/site-sqlite3.db')).toBe('binary');
    expect(fileKindOf('testfiles/fixed value b')).toBe('prose');
  });
});

describe('the comment scanner skips strings, templates and regexes', () => {
  const text = (src: string, lang: 'js' | 'php' | 'python'): string[] => commentSpans(src, lang).map((s) => src.slice(s.start, s.end));

  it('JS/TS', () => {
    const src = [
      'const u = "http://a//b" // c1',
      "const t = `x ${'//'} y` /* c2 */",
      'const r = /\\/\\/[a/]/g // c3',
      'const d = a / b // c4',
    ].join('\n');
    expect(text(src, 'js')).toEqual(['// c1', '/* c2 */', '// c3', '// c4']);
  });

  it('PHP: `#` comments, but not a `#[` attribute; strings may span lines', () => {
    const src = ['<?php', '# c1', '#[Attr]', '$s = "a # b', '// not a comment yet";', '// c2'].join('\n');
    expect(text(src, 'php')).toEqual(['# c1', '// c2']);
  });

  it('Python: `#` comments and docstrings, but not a triple-quoted string assigned or passed', () => {
    const src = ['"""Module doc."""', 'x = """SELECT', 'FROM t"""', 'def f():', '    """Doc."""', '    y = "a # b"  # c1', '    g(', '        """arg"""', '    )'].join('\n');
    expect(text(src, 'python')).toEqual(['"""Module doc."""', '"""Doc."""', '# c1']);
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
    const src = 'foo() // intentionally vulnerable\r\nbar()\r\n';
    expect(neutraliseTellComments(src, 'js').text).toBe('foo()\r\nbar()\r\n');
  });

  it('a run of whole-line comments is one comment: all of it goes when one line has a tell', () => {
    const src = ['// Parses XML with entities', '// (intentionally vulnerable to XXE).', '// Runs in a vm.', 'parse()', '// unrelated', 'x()'].join('\n');
    const out = neutraliseTellComments(src, 'js').text;
    expect(out.split('\n')).toEqual(['', '', '', 'parse()', '// unrelated', 'x()']);
  });

  it('a comment without a tell, and a tell in code, are left alone', () => {
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
