/**
 * `untrustedText` / `untrustedValue` — repository text made visible before
 * it reaches the model or a terminal (review of 3.0.0, item 2).
 */
import { describe, expect, it } from 'vitest';
import { untrustedText, untrustedValue } from '../../../src/platform/untrustedText.js';

describe('untrustedText', () => {
  it('escapes a right-to-left override, a zero-width space and ESC as visible \\u{XXXX}', () => {
    expect(untrustedText('invoice\u202Egpj.exe')).toBe('invoice\\u{202E}gpj.exe');
    expect(untrustedText('pass\u200Bword')).toBe('pass\\u{200B}word');
    expect(untrustedText('\u001B[31mred')).toBe('\\u{001B}[31mred');
  });

  it('escapes every bidi control, the other zero-width characters and the C1 controls', () => {
    for (const code of [0x202a, 0x202b, 0x202c, 0x202d, 0x2066, 0x2067, 0x2068, 0x2069, 0x200e, 0x200f, 0x061c]) {
      expect(untrustedText(`a${String.fromCodePoint(code)}b`)).toBe(`a\\u{${code.toString(16).toUpperCase().padStart(4, '0')}}b`);
    }
    for (const code of [0x200c, 0x2060, 0xfeff, 0x00ad, 0x034f, 0x180e, 0x3164, 0xfff9, 0x2028, 0x2029, 0x0085, 0x009b]) {
      expect(untrustedText(`a${String.fromCodePoint(code)}b`)).not.toContain(String.fromCodePoint(code));
    }
    // Tag characters and variation selectors — a smuggling alphabet.
    expect(untrustedText('x\u{E0041}\u{E0042}')).toBe('x\\u{E0041}\\u{E0042}');
    expect(untrustedText('x\u{FE01}')).toBe('x\\u{FE01}');
  });

  it('keeps \\n and \\t in a multi-line field, and escapes them in a single-line one', () => {
    expect(untrustedText('a\n\tb')).toBe('a\n\tb');
    expect(untrustedText('a\n\tb', { multiline: false })).toBe('a\\u{000A}\\u{0009}b');
    expect(untrustedText('a\r\nb')).toBe('a\\u{000D}\nb');
  });

  it('leaves legitimate non-ASCII alone: Japanese, accents, emoji', () => {
    for (const s of ['日本.py', 'Café résumé Ação', 'naïve Ñandú', 'ok 👍', 'مرحبا', 'שלום']) {
      expect(untrustedText(s)).toBe(s);
    }
  });

  it('keeps the RGI exemptions mcpaudit makes: VS16 on an emoji, ZWJ sequences, keycaps, subdivision flags', () => {
    for (const s of ['❤\uFE0F', '👨\u200D👩\u200D👧', '1\uFE0F\u20E3', '🏴\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}', '葛\u{E0100}']) {
      expect(untrustedText(s)).toBe(s);
    }
    // …but not the same code points anywhere else.
    expect(untrustedText('a\u200Db')).toBe('a\\u{200D}b');
    expect(untrustedText('a\uFE0F')).toBe('a\\u{FE0F}');
  });

  it('returns the very string when there is nothing to escape', () => {
    const s = 'plain text, line one\nline two';
    expect(untrustedText(s)).toBe(s);
  });
});

describe('untrustedValue', () => {
  it('escapes every string at any depth, keys included, and copies rather than mutates', () => {
    const input = {
      findings: [{ file_path: 'src/\u202Etxt.js', message: 'bad\u200B\nthing', line_start: 3, ok: true, n: null }],
      ['evil\u202Ekey']: 'v',
    };
    const out = untrustedValue(input);
    expect(out).toEqual({
      findings: [{ file_path: 'src/\\u{202E}txt.js', message: 'bad\\u{200B}\nthing', line_start: 3, ok: true, n: null }],
      'evil\\u{202E}key': 'v',
    });
    expect(input.findings[0]?.file_path).toBe('src/\u202Etxt.js');
  });

  it('treats a path, a name or an id as one line, and an array under such a key as a list of them', () => {
    const out = untrustedValue({ file_path: 'a\nb', files: ['c\nd'], rule_id: 'e\nf', snippet: 'g\nh' });
    expect(out).toEqual({ file_path: 'a\\u{000A}b', files: ['c\\u{000A}d'], rule_id: 'e\\u{000A}f', snippet: 'g\nh' });
  });
});
