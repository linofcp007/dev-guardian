/**
 * `../../../src/skillaudit/forwardSearch.ts` — `KEYWORD[^|;&\n]*?TAIL` and
 * `KEYWORD(?![^|;&\n]*VETO)[^|;&\n]*` read forward only. Each pair below is a
 * download expression as `patterns.ts` wrote it before (the whole of it), and
 * the keyword and tail it is now read as: on every generated line they make
 * the same matches, at the same places, with the same groups.
 */

import { describe, expect, it } from 'vitest';
import { keywordThenTail, keywordWithoutVeto } from '../../../src/skillaudit/forwardSearch.js';

const PAIRS: Array<[string, RegExp, RegExp, RegExp]> = [
  [
    'curl -o',
    /\bcurl\b[^|;&\n]*?(?:\s-[A-Za-z]*o\s*|\s--output(?:\s+|=))["']?([^\s"'|;&<>]+)/g,
    /\bcurl\b/g,
    /(?:\s-[A-Za-z]*o\s*|\s--output(?:\s+|=))["']?([^\s"'|;&<>]+)/g,
  ],
  ['curl >', /\bcurl\b[^|;&\n]*?\s>\s*["']?([^\s"'|;&<>]+)/g, /\bcurl\b/g, /\s>\s*["']?([^\s"'|;&<>]+)/g],
  [
    'curl -O',
    /\bcurl\b[^|;&\n]*?\s(?:-[A-Za-z]*O[A-Za-z]*|--remote-name)(?=\s|$)[^|;&\n]*/g,
    /\bcurl\b/g,
    /\s(?:-(?=[A-Za-z]*O)[A-Za-z]+|--remote-name)(?=\s|$)[^|;&\n]*/g,
  ],
  [
    'wget -O',
    /\bwget\b[^|;&\n]*?(?:\s-[A-Za-z]*O\s*|\s--output-document(?:\s+|=))["']?([^\s"'|;&<>-][^\s"'|;&<>]*)/g,
    /\bwget\b/g,
    /(?:\s-[A-Za-z]*O\s*|\s--output-document(?:\s+|=))["']?([^\s"'|;&<>-][^\s"'|;&<>]*)/g,
  ],
  [
    'iwr -OutFile',
    /\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|;&\n]*?\s-OutFile\s+["']?([^\s"'|;&<>]+)/gi,
    /\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b/gi,
    /\s-OutFile\s+["']?([^\s"'|;&<>]+)/gi,
  ],
];

const PIECES = [
  'curl', 'wget', 'iwr', 'IRM', '-o', '-O', '-qO', '-sSLO', 'O', 'o', '--output', '--output-document', '--remote-name',
  '=', 'x.sh', '"a b"', '>', '|', ';', '&', '\n', '-OutFile', 'https://h.example/x.sh?y', 'curlx', '-', '1',
];
const SEPARATORS = [' ', ' ', '', '\t'];

// A linear congruential generator, read from its high bits (its low ones repeat).
let seed = 11;
function next(n: number): number {
  seed = (seed * 1103515245 + 12345) % 2147483648;
  return Math.floor(seed / 65536) % n;
}
function line(): string {
  let out = '';
  const count = 1 + next(10);
  for (let i = 0; i < count; i++) out += (i > 0 ? (SEPARATORS[next(SEPARATORS.length)] ?? '') : '') + (PIECES[next(PIECES.length)] ?? '');
  return out;
}

describe('keywordThenTail makes the matches the whole expression made', () => {
  it.each(PAIRS)('%s, on 5 000 generated lines', (_label, whole, keyword, tail) => {
    for (let i = 0; i < 5_000; i++) {
      const text = line();
      const expected = [...text.matchAll(whole)].map((m) => [m.index, m[0], m[1]]);
      const actual = keywordThenTail(text, keyword, tail).map((m) => [m.index, m.text, m.tail[1]]);
      expect(actual, JSON.stringify(text)).toEqual(expected);
    }
  });
});

describe('keywordWithoutVeto makes the matches the whole expression made', () => {
  it('wget saving under the URL’s name, on 5 000 generated lines', () => {
    const whole = /\bwget\b(?![^|;&\n]*\s-[A-Za-z]*O)[^|;&\n]*/g;
    for (let i = 0; i < 5_000; i++) {
      const text = line();
      const expected = [...text.matchAll(whole)].map((m) => [m.index, m[0]]);
      const actual = keywordWithoutVeto(text, /\bwget\b/g, /\s-[A-Za-z]*O/g).map((m) => [m.index, m.text]);
      expect(actual, JSON.stringify(text)).toEqual(expected);
    }
  });
});
