/**
 * Coordinator review, round 1: the real disk-reading path in
 * `configSources.ts` (`readOne`) had no test that actually touched disk —
 * every prior test hand-built `ConfigSource` objects or wrote only valid
 * JSON. These write real files (valid, malformed, oversized, JSONC, and an
 * unreadable path) and call `readConfigSources` for real.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { afterAll, afterEach, describe, expect, it } from 'vitest';
import { MAX_CONFIG_BYTES, readConfigSources } from '../../../src/agentaudit/configSources.js';
import { claudeDesktopConfigPath } from '../../../src/hostsetup/mcpConfig.js';
import { detectOs } from '../../../src/platform/osDetect.js';
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

/**
 * Part A.1 (3.0 additions): the hosts dev-guardian itself writes configs for
 * (`hostsetup/mcpConfig.ts`) are also where an MCP server can be declared.
 * A plugin's own `.claude-plugin/plugin.json` is project-scoped; Claude
 * Desktop, Cursor, Windsurf and Gemini's user-level files are read only with
 * `include_user_config`, at the same OS paths `mcp-config --write` uses.
 */
describe('readConfigSources — the wider host set', () => {
  const saved = {
    HOME: process.env['HOME'],
    USERPROFILE: process.env['USERPROFILE'],
    APPDATA: process.env['APPDATA'],
  };

  afterEach(() => {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  function pointHomeAt(dir: string): void {
    process.env['HOME'] = dir;
    process.env['USERPROFILE'] = dir;
    process.env['APPDATA'] = join(dir, 'AppData', 'Roaming');
  }

  function writeAt(path: string, content: unknown): void {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify(content), 'utf8');
  }

  const USER_LABELS = [
    'claude_desktop_config.json',
    '~/.cursor/mcp.json',
    '~/.codeium/windsurf/mcp_config.json',
    '~/.gemini/settings.json',
  ];

  it("reads a plugin's .claude-plugin/plugin.json as a project source of mcpServers", () => {
    const dir = makeTempDir('agentaudit-cfg-');
    writeAt(join(dir, '.claude-plugin', 'plugin.json'), {
      name: 'p',
      mcpServers: { srv: { command: 'node', args: ['${CLAUDE_PLUGIN_ROOT}/server.js'] } },
    });
    const source = readConfigSources(dir, false).find((s) => s.label === '.claude-plugin/plugin.json');
    expect(source?.kind).toBe('project');
    expect(source?.exists).toBe(true);
    expect(source?.mcpServersField).toBe('mcpServers');
  });

  it('reads Claude Desktop, ~/.cursor, Windsurf and ~/.gemini configs with include_user_config', () => {
    const home = makeTempDir('agentaudit-home-');
    pointHomeAt(home);
    const desktop = claudeDesktopConfigPath({ os: detectOs(), home, appData: process.env['APPDATA'] });
    expect(desktop).not.toBeNull();
    if (desktop === null) return;
    writeAt(desktop, { mcpServers: { a: { command: 'node' } } });
    writeAt(join(home, '.cursor', 'mcp.json'), { mcpServers: { b: { command: 'node' } } });
    writeAt(join(home, '.codeium', 'windsurf', 'mcp_config.json'), { mcpServers: { c: { command: 'node' } } });
    writeAt(join(home, '.gemini', 'settings.json'), { mcpServers: { d: { command: 'node' } } });

    const dir = makeTempDir('agentaudit-cfg-');
    const sources = readConfigSources(dir, true);
    for (const label of USER_LABELS) {
      const source = sources.find((s) => s.label === label);
      expect(source, label).toBeDefined();
      expect(source?.kind, label).toBe('user');
      expect(source?.exists, label).toBe(true);
      expect(source?.mcpServersField, label).toBe('mcpServers');
    }
    expect(sources.find((s) => s.label === 'claude_desktop_config.json')?.absolutePath).toBe(desktop);
  });

  it('never reads those user-level files without include_user_config', () => {
    const home = makeTempDir('agentaudit-home-');
    pointHomeAt(home);
    writeAt(join(home, '.cursor', 'mcp.json'), { mcpServers: { b: { command: 'node' } } });
    const dir = makeTempDir('agentaudit-cfg-');
    const labels = readConfigSources(dir, false).map((s) => s.label);
    for (const label of USER_LABELS) expect(labels).not.toContain(label);
  });
});
