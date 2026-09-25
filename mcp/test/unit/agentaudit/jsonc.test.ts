import { describe, expect, it } from 'vitest';
import { parseJsonc } from '../../../src/agentaudit/jsonc.js';

describe('parseJsonc', () => {
  it('parses plain, comment-free JSON unchanged', () => {
    expect(parseJsonc('{"a": 1, "b": [1, 2, 3]}')).toEqual({ a: 1, b: [1, 2, 3] });
  });

  it('strips a line comment', () => {
    const text = ['{', '  // this is a comment', '  "a": 1', '}'].join('\n');
    expect(parseJsonc(text)).toEqual({ a: 1 });
  });

  it('strips a block comment, including one spanning multiple lines', () => {
    const text = ['{', '  /* block', '     comment */', '  "a": 1', '}'].join('\n');
    expect(parseJsonc(text)).toEqual({ a: 1 });
  });

  it('strips a trailing comma before } and ]', () => {
    expect(parseJsonc('{"a": 1, "b": [1, 2,],\n}')).toEqual({ a: 1, b: [1, 2] });
  });

  it('does NOT strip // or /* inside a string value (a URL)', () => {
    expect(parseJsonc('{"url": "http://example.com/*"}')).toEqual({ url: 'http://example.com/*' });
  });

  it('does not treat a comma inside a string as a trailing comma', () => {
    expect(parseJsonc('{"msg": "a, b, }"}')).toEqual({ msg: 'a, b, }' });
  });

  it('handles an escaped quote inside a string without ending the string early', () => {
    expect(parseJsonc(String.raw`{"a": "he said \"hi\" // not a comment"}`)).toEqual({
      a: 'he said "hi" // not a comment',
    });
  });

  it('handles a real .vscode/mcp.json-shaped document with comments and a trailing comma', () => {
    const text = [
      '{',
      '  // dev-guardian MCP server',
      '  "servers": {',
      '    "dev-guardian": {',
      '      "type": "stdio", /* stdio transport */',
      '      "command": "node",',
      '      "args": ["mcp/dist/server.js"],',
      '    },',
      '  },',
      '}',
    ].join('\n');
    expect(parseJsonc(text)).toEqual({
      servers: { 'dev-guardian': { type: 'stdio', command: 'node', args: ['mcp/dist/server.js'] } },
    });
  });

  it('throws on genuinely invalid JSON even after stripping', () => {
    expect(() => parseJsonc('{not json at all')).toThrow();
  });
});
