/**
 * `../../../src/skillaudit/markdownCode.ts`'s HTML code tags, found forward
 * only: on every generated line, the same tags removed and the same one-line
 * element bodies as the two expressions they replaced.
 */

import { describe, expect, it } from 'vitest';
import { inlineCodeBodies, withoutCodeTags } from '../../../src/skillaudit/markdownCode.js';

const TAG = /<\/?(?:pre|code|kbd|samp|tt)\b[^>]*>/gi;
const ELEMENT = /<(pre|code|kbd|samp|tt)\b[^>]*>([\s\S]*?)<\/\1\s*>/gi;

const PIECES = ['<code', '<CODE', '</code', '</Code', '<pre', '</pre', '<tt', '</tt', '<codex', '>', '/>', ' ', 'x', 'a=b', '<', '\n'];

// A linear congruential generator, read from its high bits (its low ones repeat).
let seed = 5;
function next(n: number): number {
  seed = (seed * 1103515245 + 12345) % 2147483648;
  return Math.floor(seed / 65536) % n;
}
const line = (): string => Array.from({ length: 1 + next(12) }, () => PIECES[next(PIECES.length)] ?? '').join('');

describe('HTML code tags, found forward only', () => {
  it('remove the tags the expression removed, on 5 000 generated lines', () => {
    for (let i = 0; i < 5_000; i++) {
      const text = line();
      expect(withoutCodeTags(text), JSON.stringify(text)).toBe(text.replace(TAG, ''));
    }
  });

  it('read the element bodies the expression read, on 5 000 generated lines', () => {
    for (let i = 0; i < 5_000; i++) {
      const text = line();
      expect(inlineCodeBodies(text), JSON.stringify(text)).toEqual([...text.matchAll(ELEMENT)].map((m) => m[2]));
    }
  });
});
