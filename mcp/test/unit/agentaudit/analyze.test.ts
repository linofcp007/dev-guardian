import { describe, expect, it } from 'vitest';
import { analyzeAgentConfig, collectMcpEntries } from '../../../src/agentaudit/analyze.js';
import type { ConfigSource } from '../../../src/agentaudit/configSources.js';

function mcpSource(overrides: Partial<ConfigSource>): ConfigSource {
  return {
    label: '.mcp.json',
    kind: 'project',
    absolutePath: '/proj/.mcp.json',
    mcpServersField: 'mcpServers',
    exists: true,
    ...overrides,
  };
}

describe('analyzeAgentConfig', () => {
  it('runs the rule checks across every source and aggregates findings', () => {
    const sources: ConfigSource[] = [
      mcpSource({ json: { mcpServers: { x: { command: 'npx', args: ['-y', 'unpinned-pkg'] } } } }),
      {
        label: '.claude/settings.json',
        kind: 'project',
        absolutePath: '/proj/.claude/settings.json',
        mcpServersField: null,
        exists: true,
        json: { permissions: { allow: ['Bash(*)'] }, enableAllProjectMcpServers: true },
      },
    ];
    const result = analyzeAgentConfig(sources, new Map());
    const ruleIds = result.findings.map((f) => f.rule_id);
    expect(ruleIds).toContain('agent-audit-unpinned-launcher');
    expect(ruleIds).toContain('agent-audit-wildcard-permission');
    expect(ruleIds).toContain('agent-audit-enable-all-mcp-servers');
    expect(result.mcpServersFound).toBe(1);
  });

  it('records an entry hash for every MCP server entry found', () => {
    const sources: ConfigSource[] = [mcpSource({ json: { mcpServers: { x: { command: 'node' } } } })];
    const result = analyzeAgentConfig(sources, new Map());
    expect(result.entryHashes).toEqual([{ entry_key: '.mcp.json::x', hash: expect.any(String) }]);
  });

  it('flags an entry whose hash differs from the previous audit', () => {
    const sources: ConfigSource[] = [
      mcpSource({ json: { mcpServers: { x: { command: 'node', args: ['new.js'] } } } }),
    ];
    const previous = new Map([['.mcp.json::x', 'a-completely-different-hash']]);
    const result = analyzeAgentConfig(sources, previous);
    expect(result.findings.some((f) => f.rule_id === 'agent-audit-entry-changed')).toBe(true);
    expect(result.entriesChanged).toBe(1);
  });

  it('does not flag an entry with no prior hash (first-time audit)', () => {
    const sources: ConfigSource[] = [mcpSource({ json: { mcpServers: { x: { command: 'node' } } } })];
    const result = analyzeAgentConfig(sources, new Map());
    expect(result.findings.some((f) => f.rule_id === 'agent-audit-entry-changed')).toBe(false);
    expect(result.entriesChanged).toBe(0);
  });

  it('does not flag an entry whose hash matches the previous audit', () => {
    const sources: ConfigSource[] = [mcpSource({ json: { mcpServers: { x: { command: 'node' } } } })];
    const first = analyzeAgentConfig(sources, new Map());
    const previous = new Map(first.entryHashes.map((h) => [h.entry_key, h.hash]));
    const second = analyzeAgentConfig(sources, previous);
    expect(second.findings.some((f) => f.rule_id === 'agent-audit-entry-changed')).toBe(false);
  });

  // Coordinator review, round 1, cheap item: an entry the PREVIOUS audit
  // hashed but that is absent from the CURRENT scan (removed from the config
  // since) is never looked at — `analyzeAgentConfig` only walks the current
  // `entries`, never the previous-hashes map's own keys. Documented
  // behaviour (see `storage/migrations/009_agent_config_hashes.sql`'s own
  // comment: the stale row is left in place, harmless, never re-surfaced
  // unless the same entry_key reappears) rather than a bug — this pins it:
  // no crash, no finding, and the still-current entry is unaffected.
  it('does not crash and produces no finding for an entry removed since the previous audit', () => {
    const sources: ConfigSource[] = [mcpSource({ json: { mcpServers: { x: { command: 'node' } } } })];
    const first = analyzeAgentConfig(sources, new Map());
    const xHash = first.entryHashes[0]?.hash ?? '';

    // The previous audit's hashes carry an extra key no longer produced by
    // the current scan (the server was removed from .mcp.json since), plus
    // x's own hash unchanged.
    const previous = new Map([
      ['.mcp.json::x', xHash],
      ['.mcp.json::removed-server', 'some-old-hash'],
    ]);
    expect(() => analyzeAgentConfig(sources, previous)).not.toThrow();
    const result = analyzeAgentConfig(sources, previous);
    expect(result.entryHashes.map((h) => h.entry_key)).toEqual(['.mcp.json::x']);
    expect(result.findings.filter((f) => f.rule_id === 'agent-audit-entry-changed')).toEqual([]);
    expect(result.entriesChanged).toBe(0);
  });

  it('turns a parse error into a warning instead of throwing, and excludes it from sourcesRead', () => {
    const sources: ConfigSource[] = [
      { ...mcpSource({}), json: undefined, raw: '{not json', parseError: 'invalid JSON: bad' },
    ];
    const result = analyzeAgentConfig(sources, new Map());
    expect(result.warnings.some((w) => w.includes('.mcp.json'))).toBe(true);
    expect(result.sourcesRead).not.toContain('.mcp.json');
  });

  it('reports sourcesRead / sourcesMissing correctly', () => {
    const sources: ConfigSource[] = [
      mcpSource({ json: { mcpServers: {} } }),
      { ...mcpSource({}), label: '.cursor/mcp.json', exists: false, json: undefined },
    ];
    const result = analyzeAgentConfig(sources, new Map());
    expect(result.sourcesRead).toEqual(['.mcp.json']);
    expect(result.sourcesMissing).toEqual(['.cursor/mcp.json']);
  });

  it('expands ~/.claude.json nested per-project mcpServers into their own source', () => {
    const sources: ConfigSource[] = [
      {
        label: '~/.claude.json',
        kind: 'user',
        absolutePath: '/home/u/.claude.json',
        mcpServersField: 'mcpServers',
        exists: true,
        json: {
          mcpServers: { global1: { command: 'node' } },
          projects: {
            '/some/project': { mcpServers: { proj1: { command: 'npx', args: ['-y', 'unpinned'] } } },
          },
        },
      },
    ];
    const result = analyzeAgentConfig(sources, new Map());
    expect(result.mcpServersFound).toBe(2);
    const keys = result.entryHashes.map((h) => h.entry_key);
    expect(keys).toContain('~/.claude.json::global1');
    expect(keys.some((k) => k.includes('proj1'))).toBe(true);
    expect(result.findings.some((f) => f.rule_id === 'agent-audit-unpinned-launcher')).toBe(true);
  });

  // A plugin's `mcpServers` may be a PATH to another JSON file rather than
  // an inline object. Nothing here follows it, so that must be said: an
  // audit that silently skipped it would read as "no servers" — clean.
  it('warns when a source declares mcpServers as a path it does not follow', () => {
    const sources: ConfigSource[] = [
      mcpSource({
        label: '.claude-plugin/plugin.json',
        absolutePath: '/proj/.claude-plugin/plugin.json',
        json: { name: 'p', mcpServers: './servers.json' },
      }),
    ];
    const result = analyzeAgentConfig(sources, new Map());
    expect(result.mcpServersFound).toBe(0);
    expect(result.warnings.some((w) => w.includes('.claude-plugin/plugin.json') && w.includes('./servers.json'))).toBe(
      true,
    );
  });
});

describe('collectMcpEntries', () => {
  it('returns every entry across sources, nested ~/.claude.json projects included', () => {
    const sources: ConfigSource[] = [
      mcpSource({ json: { mcpServers: { a: { command: 'node' } } } }),
      {
        label: '~/.claude.json',
        kind: 'user',
        absolutePath: '/home/u/.claude.json',
        mcpServersField: 'mcpServers',
        exists: true,
        json: { projects: { '/p': { mcpServers: { b: { command: 'node' } } } } },
      },
    ];
    const collected = collectMcpEntries(sources);
    expect(collected.entries.map((e) => `${e.sourceLabel}::${e.name}`)).toEqual([
      '.mcp.json::a',
      '~/.claude.json (project: /p)::b',
    ]);
    expect(collected.sourcesRead).toEqual(['.mcp.json', '~/.claude.json']);
  });
});
