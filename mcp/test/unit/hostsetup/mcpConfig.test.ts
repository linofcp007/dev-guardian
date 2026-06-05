/**
 * Unit tests for the pure MCP-config helpers used by the mcp-config CLI.
 * No filesystem writes here — only string/path logic.
 */

import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

import {
  buildManualSnippet,
  buildServerEntry,
  claudeDesktopConfigPath,
  mergeJsonConfig,
  mergeTomlConfig,
  resolveMcpConfigPath,
  resolveServerJsPath,
  SERVER_ID,
} from '../../../src/hostsetup/mcpConfig.js';

const SRV = '/plugins/dev-guardian/mcp/dist/server.js';

describe('resolveServerJsPath', () => {
  it('derives <plugin>/mcp/dist/server.js from scriptsDir', () => {
    const scriptsDir = join('/plugins', 'dev-guardian', 'scripts');
    expect(resolveServerJsPath(scriptsDir)).toBe(
      resolve('/plugins', 'dev-guardian', 'mcp', 'dist', 'server.js'),
    );
  });
});

describe('buildServerEntry', () => {
  it('builds a node-launch entry without type by default', () => {
    expect(buildServerEntry(SRV, false)).toEqual({ command: 'node', args: [SRV], env: {} });
  });
  it('adds type:"stdio" first for Copilot-style hosts', () => {
    const e = buildServerEntry(SRV, true);
    expect(e).toEqual({ type: 'stdio', command: 'node', args: [SRV], env: {} });
    expect(Object.keys(e)[0]).toBe('type');
  });
});

describe('claudeDesktopConfigPath', () => {
  it('uses %APPDATA%\\Claude on Windows', () => {
    expect(
      claudeDesktopConfigPath({ os: 'win32', home: 'C:\\Users\\me', appData: 'C:\\Users\\me\\AppData\\Roaming' }),
    ).toBe(join('C:\\Users\\me\\AppData\\Roaming', 'Claude', 'claude_desktop_config.json'));
  });
  it('falls back to ~/AppData/Roaming when APPDATA is absent', () => {
    expect(claudeDesktopConfigPath({ os: 'win32', home: '/home/me' })).toBe(
      join('/home/me', 'AppData', 'Roaming', 'Claude', 'claude_desktop_config.json'),
    );
  });
  it('uses Library/Application Support on macOS', () => {
    expect(claudeDesktopConfigPath({ os: 'darwin', home: '/Users/me' })).toBe(
      join('/Users/me', 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
    );
  });
  it('uses ~/.config on Linux', () => {
    expect(claudeDesktopConfigPath({ os: 'linux', home: '/home/me' })).toBe(
      join('/home/me', '.config', 'Claude', 'claude_desktop_config.json'),
    );
  });
  it('returns null on unsupported OS', () => {
    expect(claudeDesktopConfigPath({ os: 'unsupported', home: '/home/me' })).toBeNull();
  });
});

describe('resolveMcpConfigPath', () => {
  const env = { os: 'linux' as const, home: '/home/me', projectPath: '/repo' };
  it('cursor: project vs global', () => {
    expect(resolveMcpConfigPath('cursor', 'project', env)).toBe(join('/repo', '.cursor', 'mcp.json'));
    expect(resolveMcpConfigPath('cursor', 'global', env)).toBe(join('/home/me', '.cursor', 'mcp.json'));
  });
  it('copilot: always workspace .vscode/mcp.json', () => {
    expect(resolveMcpConfigPath('copilot', 'global', env)).toBe(join('/repo', '.vscode', 'mcp.json'));
  });
  it('windsurf: global codeium path', () => {
    expect(resolveMcpConfigPath('windsurf', 'global', env)).toBe(
      join('/home/me', '.codeium', 'windsurf', 'mcp_config.json'),
    );
  });
  it('codex: project vs global toml', () => {
    expect(resolveMcpConfigPath('codex', 'project', env)).toBe(join('/repo', '.codex', 'config.toml'));
    expect(resolveMcpConfigPath('codex', 'global', env)).toBe(join('/home/me', '.codex', 'config.toml'));
  });
  it('gemini: project settings.json', () => {
    expect(resolveMcpConfigPath('gemini', 'project', env)).toBe(join('/repo', '.gemini', 'settings.json'));
  });
  it('cline: null (manual)', () => {
    expect(resolveMcpConfigPath('cline', 'global', env)).toBeNull();
  });
});

describe('mergeJsonConfig', () => {
  const entry = buildServerEntry(SRV, false);

  it('creates a fresh config when none exists', () => {
    const r = mergeJsonConfig(null, 'mcpServers', entry, false);
    expect(r.status).toBe('written');
    expect(JSON.parse(r.content as string)).toEqual({ mcpServers: { [SERVER_ID]: entry } });
  });

  it('merges without clobbering an existing server', () => {
    const existing = JSON.stringify({ mcpServers: { other: { command: 'x', args: [], env: {} } } });
    const r = mergeJsonConfig(existing, 'mcpServers', entry, false);
    expect(r.status).toBe('merged');
    const parsed = JSON.parse(r.content as string);
    expect(parsed.mcpServers.other).toEqual({ command: 'x', args: [], env: {} });
    expect(parsed.mcpServers[SERVER_ID]).toEqual(entry);
  });

  it('is idempotent when the entry already matches', () => {
    const existing = JSON.stringify({ mcpServers: { [SERVER_ID]: entry } });
    expect(mergeJsonConfig(existing, 'mcpServers', entry, false).status).toBe('already_present');
  });

  it('reports needs_update when an entry differs and force is off', () => {
    const existing = JSON.stringify({ mcpServers: { [SERVER_ID]: { command: 'node', args: ['/old.js'], env: {} } } });
    const r = mergeJsonConfig(existing, 'mcpServers', entry, false);
    expect(r.status).toBe('needs_update');
    expect(r.content).toBeUndefined();
  });

  it('updates a differing entry when force is on', () => {
    const existing = JSON.stringify({ mcpServers: { [SERVER_ID]: { command: 'node', args: ['/old.js'], env: {} } } });
    const r = mergeJsonConfig(existing, 'mcpServers', entry, true);
    expect(r.status).toBe('merged');
    expect(JSON.parse(r.content as string).mcpServers[SERVER_ID]).toEqual(entry);
  });

  it('supports the Copilot "servers" key', () => {
    const typed = buildServerEntry(SRV, true);
    const r = mergeJsonConfig(null, 'servers', typed, false);
    expect(JSON.parse(r.content as string).servers[SERVER_ID].type).toBe('stdio');
  });

  it('throws on malformed JSON instead of clobbering', () => {
    expect(() => mergeJsonConfig('{ not json', 'mcpServers', entry, false)).toThrow();
  });
});

describe('mergeTomlConfig', () => {
  const entry = buildServerEntry(SRV, false);

  it('creates a fresh TOML table', () => {
    const r = mergeTomlConfig(null, entry, false);
    expect(r.status).toBe('written');
    expect(r.content).toContain('[mcp_servers.dev-guardian]');
    expect(r.content).toContain(`'${SRV}'`); // literal string — no backslash escaping
    expect(r.content).toContain('enabled = true');
  });

  it('appends without dropping prior content', () => {
    const existing = '[mcp_servers.other]\ncommand = "x"\n';
    const r = mergeTomlConfig(existing, entry, false);
    expect(r.status).toBe('merged');
    expect(r.content).toContain('[mcp_servers.other]');
    expect(r.content).toContain('[mcp_servers.dev-guardian]');
  });

  it('is idempotent when our table already exists', () => {
    const existing = '[mcp_servers.dev-guardian]\ncommand = "node"\n';
    expect(mergeTomlConfig(existing, entry, false).status).toBe('already_present');
  });

  it('replaces our table on force, leaving one occurrence', () => {
    const existing = '[mcp_servers.dev-guardian]\ncommand = "node"\nargs = [\'/old.js\']\n\n[other]\nx = 1\n';
    const r = mergeTomlConfig(existing, entry, true);
    expect(r.status).toBe('merged');
    const occurrences = (r.content as string).match(/\[mcp_servers\.dev-guardian\]/g) ?? [];
    expect(occurrences).toHaveLength(1);
    expect(r.content).toContain('[other]'); // sibling table preserved
    expect(r.content).toContain(`'${SRV}'`);
  });

  it('escapes a path containing a single quote into a basic string', () => {
    const weird = "/plug/o'brien/server.js";
    const r = mergeTomlConfig(null, buildServerEntry(weird, false), false);
    expect(r.content).toContain('"/plug/o\'brien/server.js"');
  });
});

describe('buildManualSnippet', () => {
  it('emits an mcpServers JSON block for manual hosts', () => {
    const snippet = JSON.parse(buildManualSnippet(SRV));
    expect(snippet.mcpServers[SERVER_ID]).toEqual({ command: 'node', args: [SRV], env: {} });
  });
});
