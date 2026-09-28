/**
 * Regression test for this repo's own in-repo ("dogfood") MCP host configs —
 * Task 5 of the 2026-09-25 full review, item 1.
 *
 * `.mcp.json` used `${CLAUDE_PROJECT_DIR}/mcp/dist/server.js`. Claude Code
 * does NOT expand `${CLAUDE_PROJECT_DIR}` for a project-scoped `.mcp.json`
 * server entry (only `${CLAUDE_PLUGIN_ROOT}`, used by `.claude-plugin/
 * plugin.json`, is expanded there) — reproduced directly, from this
 * project's own MCP log:
 *   `Error: Cannot find module 'c:\...\dev-guardian\${CLAUDE_PROJECT_DIR}\
 *   mcp\dist\server.js'` (MODULE_NOT_FOUND — the literal, unexpanded
 *   placeholder string became part of the path).
 * Claude Code starts a project-scoped server with cwd = the project root, so
 * a bare relative path resolves correctly with no placeholder needed at all.
 *
 * The other three dogfood configs are checked alongside it so a future edit
 * cannot reintroduce the same class of bug in a sibling file: Cursor and VS
 * Code both support `${workspaceFolder}` and use it (VS Code already did;
 * Cursor is switched here for the same robustness — it does not depend on
 * Cursor's own process cwd happening to be the project root); Gemini CLI has
 * a dedicated `cwd` field for exactly this or an explicit `"."` for cwd).
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../../..', import.meta.url)));

function readJson(relativePath: string): unknown {
  return JSON.parse(readFileSync(resolve(REPO_ROOT, relativePath), 'utf8'));
}

describe('dogfood MCP configs never rely on an unexpanded ${CLAUDE_PROJECT_DIR}', () => {
  it('.mcp.json (Claude Code) uses a bare relative path', () => {
    const cfg = readJson('.mcp.json') as { mcpServers: { 'dev-guardian': { args: string[] } } };
    expect(cfg.mcpServers['dev-guardian'].args).toEqual(['mcp/dist/server.js']);
    for (const arg of cfg.mcpServers['dev-guardian'].args) {
      expect(arg).not.toContain('${CLAUDE_PROJECT_DIR}');
    }
  });

  it('.cursor/mcp.json resolves the server path via ${workspaceFolder}, not a bare relative path', () => {
    const cfg = readJson('.cursor/mcp.json') as { mcpServers: { 'dev-guardian': { args: string[] } } };
    expect(cfg.mcpServers['dev-guardian'].args).toEqual(['${workspaceFolder}/mcp/dist/server.js']);
  });

  it('.vscode/mcp.json (Copilot) resolves the server path via ${workspaceFolder}', () => {
    const cfg = readJson('.vscode/mcp.json') as { servers: { 'dev-guardian': { args: string[] } } };
    expect(cfg.servers['dev-guardian'].args).toEqual(['${workspaceFolder}/mcp/dist/server.js']);
  });

  it('.gemini/settings.json declares an explicit cwd alongside the relative path', () => {
    const cfg = readJson('.gemini/settings.json') as {
      mcpServers: { 'dev-guardian': { args: string[]; cwd?: string } };
    };
    expect(cfg.mcpServers['dev-guardian'].args).toEqual(['mcp/dist/server.js']);
    expect(cfg.mcpServers['dev-guardian'].cwd).toBe('.');
  });

  it('no dogfood MCP config anywhere in the repo still names the unexpanded placeholder', () => {
    for (const path of ['.mcp.json', '.cursor/mcp.json', '.vscode/mcp.json', '.gemini/settings.json']) {
      const raw = readFileSync(resolve(REPO_ROOT, path), 'utf8');
      expect(raw).not.toContain('${CLAUDE_PROJECT_DIR}');
    }
  });
});
