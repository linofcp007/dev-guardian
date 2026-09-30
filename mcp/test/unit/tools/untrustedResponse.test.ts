/**
 * Repository text is escaped at the MCP response boundary (review of 3.0.0,
 * item 2): a finding whose message and file path carry a right-to-left
 * override, a zero-width space and ESC reaches the model as visible
 * `\u{XXXX}` in both the text block and `structuredContent`, while a
 * Japanese file name passes unchanged — and the stored finding keeps its
 * bytes.
 */
import { describe, expect, it } from 'vitest';
import { resourceText } from '../../../src/resources/index.js';
import { toCallToolResult } from '../../../src/tools/index.js';
import type { ToolResult } from '../../../src/types.js';

const RLO = String.fromCodePoint(0x202e);
const ZWSP = String.fromCodePoint(0x200b);
const ESC = String.fromCodePoint(0x1b);

function finding() {
  return {
    rule_id: 'demo-rule',
    file_path: `src/invoice${RLO}gpj.exe`,
    message: `hard-coded key${ZWSP} here ${ESC}[2J`,
    snippet: 'const a = 1;\nconst b = 2;',
  };
}

describe('toCallToolResult — untrusted text', () => {
  it('escapes RLO, ZWSP and ESC in the text block and in structuredContent', () => {
    const stored = finding();
    const result = { ok: true, findings: [stored, { file_path: '日本.py', message: 'ok' }] } as ToolResult<Record<string, unknown>>;
    const out = toCallToolResult(result, []);
    const text = out.content[0]?.text ?? '';

    for (const raw of [RLO, ZWSP, ESC]) {
      expect(text.includes(raw)).toBe(false);
      expect(JSON.stringify(out.structuredContent).includes(raw)).toBe(false);
    }
    const f = (out.structuredContent['findings'] as Array<Record<string, string>>)[0];
    expect(f?.['file_path']).toBe('src/invoice\\u{202E}gpj.exe');
    expect(f?.['message']).toBe('hard-coded key\\u{200B} here \\u{001B}[2J');
    // A multi-line field keeps its line breaks.
    expect(f?.['snippet']).toBe('const a = 1;\nconst b = 2;');
    // Legitimate non-ASCII is untouched.
    expect(text).toContain('日本.py');
    const second = (out.structuredContent['findings'] as Array<Record<string, string>>)[1];
    expect(second?.['file_path']).toBe('日本.py');
    // The handler's own object is not mutated: storage keeps the bytes.
    expect(stored.file_path).toBe(`src/invoice${RLO}gpj.exe`);
  });

  it('escapes a content-only key too', () => {
    const result = { ok: true, document: `x${RLO}y` } as ToolResult<Record<string, unknown>>;
    const out = toCallToolResult(result, ['document']);
    expect(out.content[0]?.text).toContain('x\\\\u{202E}y');
    expect(out.content[0]?.text.includes(RLO)).toBe(false);
  });

  it('escapes an error message, which is plain text rather than JSON', () => {
    const result: ToolResult<Record<string, unknown>> = {
      ok: false,
      error: { code: 'scanner_failed', message: `semgrep said ${ESC}]0;pwned${String.fromCodePoint(7)} in ${RLO}x` },
    };
    const out = toCallToolResult(result, []);
    const text = out.content[0]?.text ?? '';
    expect(text).toBe('Error (scanner_failed): semgrep said \\u{001B}]0;pwned\\u{0007} in \\u{202E}x');
    expect(JSON.stringify(out.structuredContent).includes(ESC)).toBe(false);
  });
});

describe('resources — untrusted text', () => {
  it('escapes every string of a resource payload', () => {
    const text = resourceText({ findings: [finding()] });
    for (const raw of [RLO, ZWSP, ESC]) expect(text.includes(raw)).toBe(false);
    expect(text).toContain('invoice\\\\u{202E}gpj.exe');
  });
});
