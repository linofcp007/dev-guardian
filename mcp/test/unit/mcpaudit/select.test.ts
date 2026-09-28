/**
 * `mcpaudit/select.ts` — which declared entries a requested name starts
 * (fix round 3, I1), and the server keys pins are stored under (M6).
 */

import { describe, expect, it } from 'vitest';
import type { McpServerEntry } from '../../../src/agentaudit/mcpServers.js';
import { planTargets, qualifiedName, serverNameOfPinKey, serverPinKey } from '../../../src/mcpaudit/select.js';

function entry(sourceLabel: string, name: string, args: string[] = ['s.js']): McpServerEntry {
  const raw = { command: 'node', args };
  return { sourceLabel, name, command: 'node', args, raw };
}

describe('planTargets', () => {
  it('starts exactly the entry a qualified <source>::<name> names', () => {
    const plan = planTargets(['.cursor/mcp.json::github'], [entry('.mcp.json', 'github', ['a.js']), entry('.cursor/mcp.json', 'github', ['b.js'])]);
    expect(plan).toEqual([
      expect.objectContaining({ requested: '.cursor/mcp.json::github', kind: 'start', entry: expect.objectContaining({ sourceLabel: '.cursor/mcp.json' }) }),
    ]);
  });

  it('starts a bare name once when every entry of it launches the same way, naming the others', () => {
    const plan = planTargets(['github'], [entry('.mcp.json', 'github'), entry('.cursor/mcp.json', 'github')]);
    expect(plan).toHaveLength(1);
    expect(plan[0]).toMatchObject({ kind: 'start', alsoDeclaredIn: ['.cursor/mcp.json::github'] });
  });

  it('refuses a bare name whose entries launch differently, listing the qualified names to choose from', () => {
    const plan = planTargets(['github'], [entry('.mcp.json', 'github', ['a.js']), entry('~/.claude.json', 'github', ['b.js'])]);
    expect(plan).toEqual([
      {
        requested: 'github',
        kind: 'refuse',
        reason: expect.stringContaining('.mcp.json::github, ~/.claude.json::github'),
      },
    ]);
  });

  it('reports a name no entry has', () => {
    expect(planTargets(['nope'], [entry('.mcp.json', 'github')])).toEqual([{ requested: 'nope', kind: 'missing' }]);
  });

  it('starts an entry once when two requested names both reach it', () => {
    const plan = planTargets(['github', '.mcp.json::github'], [entry('.mcp.json', 'github')]);
    expect(plan.filter((p) => p.kind === 'start')).toHaveLength(1);
    expect(plan[1]).toMatchObject({ kind: 'duplicate' });
  });
});

describe('serverPinKey (M6)', () => {
  it('is injective where "<source>::<name>" is not', () => {
    const a = serverPinKey({ sourceLabel: '~/.claude.json (project: /a)::b', name: 'c' });
    const b = serverPinKey({ sourceLabel: '~/.claude.json (project: /a)', name: 'b::c' });
    expect(qualifiedName({ sourceLabel: '~/.claude.json (project: /a)::b', name: 'c' })).toBe(qualifiedName({ sourceLabel: '~/.claude.json (project: /a)', name: 'b::c' }));
    expect(a).not.toBe(b);
  });

  it('gives back the server name, whatever the name contains', () => {
    expect(serverNameOfPinKey(serverPinKey({ sourceLabel: '.mcp.json', name: 'a::b' }))).toBe('a::b');
  });
});
