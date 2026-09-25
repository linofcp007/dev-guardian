/**
 * Coordinator review, round 1: the real disk-reading path in
 * `configSources.ts` (`readOne`) had no test that actually touched disk —
 * every prior test hand-built `ConfigSource` objects or wrote only valid
 * JSON. These write real files (valid, malformed, oversized, JSONC, and an
 * unreadable path) and call `readConfigSources` for real.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { MAX_CONFIG_BYTES, readConfigSources } from '../../../src/agentaudit/configSources.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

function writeMcpJson(dir: string, content: string): void {
  writeFileSync(join(dir, '.mcp.json'), content, 'utf8');
}

describe('readConfigSources — real disk I/O', () => {
  it('reads and parses a real, valid .mcp.json', () => {
    const dir = makeTempDir('agentaudit-cfg-');
    writeMcpJson(dir, JSON.stringify({ mcpServers: { x: { command: 'node' } } }));
    const [mcpJson] = readConfigSources(dir, false);
    expect(mcpJson?.exists).toBe(true);
    expect(mcpJson?.parseError).toBeUndefined();
    expect(mcpJson?.json).toEqual({ mcpServers: { x: { command: 'node' } } });
  });

  it('reports a real malformed-JSON file as a parse error, not a crash', () => {
    const dir = makeTempDir('agentaudit-cfg-');
    writeMcpJson(dir, '{ "mcpServers": { this is not valid json');
    const [mcpJson] = readConfigSources(dir, false);
    expect(mcpJson?.exists).toBe(true);
    expect(mcpJson?.parseError).toContain('invalid JSON');
    expect(mcpJson?.json).toBeUndefined();
  });

  it('parses a real JSONC .vscode/mcp.json (comments + trailing comma) off disk', () => {
    const dir = makeTempDir('agentaudit-cfg-');
    mkdirSync(join(dir, '.vscode'), { recursive: true });
    writeFileSync(
      join(dir, '.vscode', 'mcp.json'),
      [
        '{',
        '  // dev-guardian',
        '  "servers": {',
        '    "dev-guardian": { "type": "stdio", "command": "node", "args": ["x.js"] }, /* trailing */',
        '  },',
        '}',
      ].join('\n'),
      'utf8',
    );
    const sources = readConfigSources(dir, false);
    const vscode = sources.find((s) => s.label === '.vscode/mcp.json');
    expect(vscode?.exists).toBe(true);
    expect(vscode?.parseError).toBeUndefined();
    expect(vscode?.json).toEqual({
      servers: { 'dev-guardian': { type: 'stdio', command: 'node', args: ['x.js'] } },
    });
  });

  it('reports an unreadable path (a directory where a file is expected) as a parse error, not a crash', () => {
    const dir = makeTempDir('agentaudit-cfg-');
    // No permission trick (chmod is unreliable for the owner on POSIX and
    // near-meaningless on Windows, doubly so running as Administrator): a
    // directory at the expected file path makes readFileSync throw EISDIR
    // on every platform, which exercises the same catch branch.
    mkdirSync(join(dir, '.mcp.json'));
    expect(() => readConfigSources(dir, false)).not.toThrow();
    const [mcpJson] = readConfigSources(dir, false);
    expect(mcpJson?.exists).toBe(false);
    expect(mcpJson?.parseError).toContain('could not read');
  });

  it('reports a file over the size cap as a gap rather than reading it', () => {
    const dir = makeTempDir('agentaudit-cfg-');
    writeMcpJson(dir, `{"mcpServers": {"x": {"command": "${'a'.repeat(MAX_CONFIG_BYTES + 1)}"}}}`);
    const [mcpJson] = readConfigSources(dir, false);
    expect(mcpJson?.exists).toBe(true);
    expect(mcpJson?.parseError).toContain('exceeds');
    expect(mcpJson?.parseError).toContain(String(MAX_CONFIG_BYTES));
    expect(mcpJson?.json).toBeUndefined();
    expect(mcpJson?.raw).toBeUndefined();
  });

  it('reads a file right at the size cap normally (boundary, not off-by-one)', () => {
    const dir = makeTempDir('agentaudit-cfg-');
    const padLen = Math.max(0, MAX_CONFIG_BYTES - '{"mcpServers": {"x": {"command": "node"}}, "pad": ""}'.length);
    writeMcpJson(dir, `{"mcpServers": {"x": {"command": "node"}}, "pad": "${'a'.repeat(padLen)}"}`);
    const [mcpJson] = readConfigSources(dir, false);
    expect(mcpJson?.exists).toBe(true);
    expect(mcpJson?.parseError).toBeUndefined();
  });

  it('does not read user-scoped files when include_user_config is false', () => {
    const dir = makeTempDir('agentaudit-cfg-');
    const sources = readConfigSources(dir, false);
    expect(sources.some((s) => s.kind === 'user')).toBe(false);
  });
});
