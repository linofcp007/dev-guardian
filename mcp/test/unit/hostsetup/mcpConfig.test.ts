/**
 * Unit tests for the pure MCP-config helpers used by the mcp-config CLI.
 * No filesystem writes here — only string/path logic.
 */

import { spawnSync } from 'node:child_process';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

import {
  buildManualSnippet,
  buildServerEntry,
  claudeDesktopConfigPath,
  mergeJsonConfig,
  mergeOwnedRulesFile,
  mergeRulesBlock,
  mergeTomlConfig,
  RULES_BLOCK_BEGIN,
  RULES_BLOCK_END,
  resolveMcpConfigPath,
  resolveServerJsPath,
  SERVER_ID,
} from '../../../src/hostsetup/mcpConfig.js';

const SRV = '/plugins/dev-guardian/mcp/dist/server.js';

/**
 * Narrows `MergeResult.content` (`string | undefined`) instead of an `as
 * string` cast — fix round 1, item 6 (Global Constraint 1: narrow, never
 * assert). Every call site in this file that reaches for `.content` knows,
 * from the test's own setup, that the status it just asserted guarantees
 * content is present; this makes that guarantee explicit and throws with a
 * clear message on the one path that would otherwise silently return
 * `undefined` at runtime (a real bug, not just a type-checker satisfaction).
 */
function contentOrThrow(r: { content?: string }): string {
  const { content } = r;
  if (content === undefined) throw new Error('expected .content to be set on this MergeResult');
  return content;
}

/**
 * Shells out to Python's stdlib `tomllib` (3.11+) to prove a merged TOML
 * string is actually well-formed — item 3 (fix round 1): the previous fix
 * was verified only by string-shaped assertions (no duplicate heading, no
 * orphan sub-table text), which is exactly the kind of check that missed
 * the two non-contiguous-span regressions the reviewer found with a real
 * parser. Skips (never fails) when neither `python3` nor `python` is on
 * PATH, matching this project's own toolchain-availability skip discipline
 * elsewhere (e.g. `AVAILABLE`/`isInstalled` in the Semgrep-pack tests).
 */
function findPython(): string | null {
  for (const candidate of ['python3', 'python']) {
    const r = spawnSync(candidate, ['--version'], { encoding: 'utf8' });
    if (r.status === 0) return candidate;
  }
  return null;
}

const PYTHON = findPython();

function assertParsesAsToml(toml: string): void {
  if (PYTHON === null) return; // skip discipline — never a silent pass reported as a check
  const r = spawnSync(PYTHON, ['-c', 'import tomllib,sys; tomllib.loads(sys.stdin.read())'], {
    input: toml,
    encoding: 'utf8',
  });
  if (r.status !== 0) {
    throw new Error(`not valid TOML per python tomllib:\n${r.stderr}\n--- content ---\n${toml}`);
  }
}

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
    expect(JSON.parse(contentOrThrow(r))).toEqual({ mcpServers: { [SERVER_ID]: entry } });
  });

  it('merges without clobbering an existing server', () => {
    const existing = JSON.stringify({ mcpServers: { other: { command: 'x', args: [], env: {} } } });
    const r = mergeJsonConfig(existing, 'mcpServers', entry, false);
    expect(r.status).toBe('merged');
    const parsed = JSON.parse(contentOrThrow(r));
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
    expect(JSON.parse(contentOrThrow(r)).mcpServers[SERVER_ID]).toEqual(entry);
  });

  it('supports the Copilot "servers" key', () => {
    const typed = buildServerEntry(SRV, true);
    const r = mergeJsonConfig(null, 'servers', typed, false);
    expect(JSON.parse(contentOrThrow(r)).servers[SERVER_ID].type).toBe('stdio');
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
    assertParsesAsToml(contentOrThrow(r));
  });

  it('appends without dropping prior content', () => {
    const existing = '[mcp_servers.other]\ncommand = "x"\n';
    const r = mergeTomlConfig(existing, entry, false);
    expect(r.status).toBe('merged');
    expect(r.content).toContain('[mcp_servers.other]');
    expect(r.content).toContain('[mcp_servers.dev-guardian]');
    assertParsesAsToml(contentOrThrow(r));
  });

  it('a heading alone is not enough for already_present — a partial/stale table reports needs_update (item 6c)', () => {
    // Deliberately incomplete (no args/env/enabled) — the PRE-fix behaviour
    // treated any existing heading as already_present regardless of content,
    // which is exactly the bug item 6c fixes: see the dedicated
    // needs_update/already_present/sub-table tests below for the full
    // content-aware contract.
    const existing = '[mcp_servers.dev-guardian]\ncommand = "node"\n';
    expect(mergeTomlConfig(existing, entry, false).status).toBe('needs_update');
  });

  it('replaces our table on force, leaving one occurrence', () => {
    const existing = '[mcp_servers.dev-guardian]\ncommand = "node"\nargs = [\'/old.js\']\n\n[other]\nx = 1\n';
    const r = mergeTomlConfig(existing, entry, true);
    expect(r.status).toBe('merged');
    const content = contentOrThrow(r);
    const occurrences = content.match(/\[mcp_servers\.dev-guardian\]/g) ?? [];
    expect(occurrences).toHaveLength(1);
    expect(content).toContain('[other]'); // sibling table preserved
    expect(content).toContain(`'${SRV}'`);
    assertParsesAsToml(content);
  });

  it('escapes a path containing a single quote into a basic string', () => {
    const weird = "/plug/o'brien/server.js";
    const r = mergeTomlConfig(null, buildServerEntry(weird, false), false);
    expect(r.content).toContain('"/plug/o\'brien/server.js"');
    assertParsesAsToml(contentOrThrow(r));
  });

  // Item 6c (2026-09-25 full review): a stale TOML entry used to always read
  // `already_present` regardless of force — `mergeTomlConfig` only checked
  // whether the HEADING existed, never whether its content matched what we'd
  // actually write, so `mcp-config codex` never noticed (or offered to fix)
  // a Codex config pointing at an old server path. JSON hosts already got
  // this right via `mergeJsonConfig`'s `deepEqual` check.
  it('reports needs_update (not already_present) when the existing table differs and force is off', () => {
    const stale = '[mcp_servers.dev-guardian]\ncommand = \'node\'\nargs = [\'/old.js\']\nenv = {}\nenabled = true\n';
    const r = mergeTomlConfig(stale, entry, false);
    expect(r.status).toBe('needs_update');
    expect(r.content).toBeUndefined();
  });

  it('is idempotent (already_present) when the existing table already matches byte-for-byte', () => {
    const fresh = contentOrThrow(mergeTomlConfig(null, entry, false));
    expect(mergeTomlConfig(fresh, entry, false).status).toBe('already_present');
  });

  it('updates a stale entry when force is on', () => {
    const stale = '[mcp_servers.dev-guardian]\ncommand = \'node\'\nargs = [\'/old.js\']\nenv = {}\nenabled = true\n';
    const r = mergeTomlConfig(stale, entry, true);
    expect(r.status).toBe('merged');
    const content = contentOrThrow(r);
    expect(content).toContain(`'${SRV}'`);
    expect(content).not.toContain('/old.js');
    assertParsesAsToml(content);
  });

  // The exact regression reported: a hand-edited config with a
  // `[mcp_servers.dev-guardian.env]` sub-table survives a force-update next
  // to a freshly-written `env = {}` scalar — two conflicting definitions of
  // the same key, which is invalid TOML.
  it('force replaces the WHOLE dev-guardian block, including its own sub-tables, leaving valid TOML', () => {
    const withSubTable =
      '[mcp_servers.dev-guardian]\n' +
      "command = 'node'\n" +
      "args = ['/old.js']\n" +
      'enabled = true\n\n' +
      '[mcp_servers.dev-guardian.env]\n' +
      'FOO = "bar"\n\n' +
      '[other]\n' +
      'x = 1\n';
    const r = mergeTomlConfig(withSubTable, entry, true);
    expect(r.status).toBe('merged');
    const content = contentOrThrow(r);
    // The invalid shape this regression produced: an `env = {}` scalar
    // co-existing with a `[mcp_servers.dev-guardian.env]` table for the same
    // key. Neither may appear once force has replaced the block.
    expect(content).not.toMatch(/\[mcp_servers\.dev-guardian\.env\]/);
    expect(content).not.toContain('FOO = "bar"');
    expect(content).toContain('env = {}');
    // Exactly one dev-guardian heading, and the sibling table survives.
    expect((content.match(/\[mcp_servers\.dev-guardian\]/g) ?? [])).toHaveLength(1);
    expect(content).toContain('[other]');
    expect(content).toContain('x = 1');
    assertParsesAsToml(content);
  });

  // Fix round 1, item 3: `findOwnTomlSpan` (the fix's own first version)
  // stopped scanning at the FIRST heading that was not ours, so a
  // NON-CONTIGUOUS dev-guardian span — one that reappears AFTER an
  // unrelated table sits between it and the main heading — was left only
  // partially removed. Verified directly against the reported failure mode:
  // `python -c "import tomllib..."` raised
  // "Cannot declare ('mcp_servers','dev-guardian','env') twice" on the old
  // fix's own output for exactly this shape.
  it('removes a NON-CONTIGUOUS dev-guardian span — a sub-table reappearing after an unrelated table', () => {
    const nonContiguous =
      '[mcp_servers.dev-guardian]\n' +
      "command = 'node'\n" +
      "args = ['/old.js']\n" +
      'enabled = true\n\n' +
      '[other]\n' +
      'x = 1\n\n' +
      '[mcp_servers.dev-guardian.env]\n' +
      'FOO = "bar"\n';
    const r = mergeTomlConfig(nonContiguous, entry, true);
    expect(r.status).toBe('merged');
    const content = contentOrThrow(r);
    expect(content).not.toMatch(/\[mcp_servers\.dev-guardian\.env\]/);
    expect(content).not.toContain('FOO = "bar"');
    expect((content.match(/\[mcp_servers\.dev-guardian\]/g) ?? [])).toHaveLength(1);
    expect(content).toContain('[other]');
    expect(content).toContain('x = 1');
    assertParsesAsToml(content);
  });

  // Fix round 1, item 3: an orphan `mcp_servers.dev-guardian.env` sub-table
  // with NO main `[mcp_servers.dev-guardian]` heading at all used to be
  // invisible to the old `TOML_HEADING`-only presence check, so
  // `mergeTomlConfig` took the "no existing entry" branch and APPENDED a
  // fresh block — landing a second, conflicting definition of the same
  // implicit table. Verified directly: `python -c "import tomllib..."`
  // raised "Cannot overwrite a value" on the old fix's own output for this
  // shape.
  it('treats an orphan dev-guardian.env sub-table (no main heading) as an existing entry, not "none"', () => {
    const orphanEnvOnly = '[mcp_servers.dev-guardian.env]\nFOO = "bar"\n';

    const withoutForce = mergeTomlConfig(orphanEnvOnly, entry, false);
    expect(withoutForce.status).toBe('needs_update');
    expect(withoutForce.content).toBeUndefined();

    const withForce = mergeTomlConfig(orphanEnvOnly, entry, true);
    expect(withForce.status).toBe('merged');
    const content = contentOrThrow(withForce);
    expect(content).not.toMatch(/\[mcp_servers\.dev-guardian\.env\]/);
    expect(content).not.toContain('FOO = "bar"');
    expect((content.match(/\[mcp_servers\.dev-guardian\]/g) ?? [])).toHaveLength(1);
    assertParsesAsToml(content);
  });
});

// Item 6b (2026-09-25 full review): `--force` used to `copyFileSync` over
// the user's WHOLE rules file (AGENTS.md / GEMINI.md / the copilot
// instructions file), destroying any unrelated content already there —
// reproduced directly: a project's own "Never touch prod" instruction in
// AGENTS.md was gone after a `--force` run. `mergeRulesBlock` manages a
// delimited block instead, so dev-guardian's own content is always
// confined between two HTML-comment markers and the rest of the file is
// never read, let alone replaced.
describe('mergeRulesBlock', () => {
  const rendered = 'dev-guardian rules body';

  it('creates a fresh file (just the wrapped block) when none exists', () => {
    const r = mergeRulesBlock(null, rendered, false);
    expect(r.status).toBe('written');
    expect(r.content).toBe(`${RULES_BLOCK_BEGIN}\n${rendered}\n${RULES_BLOCK_END}\n`);
  });

  it('APPENDS the block to an existing file with no markers, force off — never touches existing content', () => {
    const existing = '# My project\n\nNever touch prod.\n';
    const r = mergeRulesBlock(existing, rendered, false);
    expect(r.status).toBe('merged');
    // Every byte of the user's original content survives, verbatim.
    expect(r.content).toContain(existing);
    expect(r.content).toContain('Never touch prod.');
    expect(r.content).toContain(RULES_BLOCK_BEGIN);
    expect(r.content).toContain(rendered);
  });

  it('is idempotent (already_present) when the existing block already matches', () => {
    const existing = `# My project\n\n${RULES_BLOCK_BEGIN}\n${rendered}\n${RULES_BLOCK_END}\n`;
    const r = mergeRulesBlock(existing, rendered, false);
    expect(r.status).toBe('already_present');
    expect(r.content).toBeUndefined();
  });

  it('reports needs_update (not already_present) when an existing block differs and force is off', () => {
    const existing = `# My project\n\n${RULES_BLOCK_BEGIN}\nold body\n${RULES_BLOCK_END}\n`;
    const r = mergeRulesBlock(existing, rendered, false);
    expect(r.status).toBe('needs_update');
    expect(r.content).toBeUndefined();
  });

  it('never touches surrounding content when force updates a stale block', () => {
    const existing =
      `# My project\n\nNever touch prod.\n\n${RULES_BLOCK_BEGIN}\nold body\n${RULES_BLOCK_END}\n\nMore user content after.\n`;
    const r = mergeRulesBlock(existing, rendered, true);
    expect(r.status).toBe('merged');
    const content = contentOrThrow(r);
    expect(content).toContain('Never touch prod.');
    expect(content).toContain('More user content after.');
    expect(content).toContain(rendered);
    expect(content).not.toContain('old body');
    // Exactly one pair of markers.
    expect((content.match(new RegExp(RULES_BLOCK_BEGIN.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) ?? [])).toHaveLength(1);
  });

  it('appending to an existing file with no markers works regardless of force (non-destructive by construction)', () => {
    const existing = '# My project\n';
    const r = mergeRulesBlock(existing, rendered, true);
    expect(r.status).toBe('merged');
    expect(r.content).toContain('# My project');
    expect(r.content).toContain(rendered);
  });

  // Fix round 2, item 1 (CRITICAL data-loss regression from fix round 1's
  // own item-2 fix): the round-1 version treated ANY file containing the
  // substring "dev-guardian MCP server" ANYWHERE as "this whole file IS an
  // old dev-guardian install" and, on force, discarded the ENTIRE existing
  // content. Reproduced directly with the CLI: (A) the pre-Task-5
  // host-rules/AGENTS.md with a user's own "## Team rules / Never touch
  // prod." appended below it, and (B) a user's own AGENTS.md that merely
  // says "We use the dev-guardian MCP server…" in passing — both reported
  // needs_update ("pass --update-mcp to refresh it"), and --update-mcp then
  // deleted "Never touch prod" / the user's own text. `mergeRulesBlock` now
  // takes an explicit list of KNOWN, byte-exact legacy template bodies
  // (`knownLegacyTemplates`) and only ever rewrites a region it can prove
  // is ONE of them — exact, prefix, or suffix match. A file that merely
  // CONTAINS the phrase without matching a known template gets a new,
  // force-INDEPENDENT `manual_merge_required` status instead: never
  // written, ever, by this function.
  describe('legacy dev-guardian copy — known-template matching only (fix round 2, item 1)', () => {
    const legacyAgentsMd =
      'This repository has the **dev-guardian MCP server** registered. It exposes\n' +
      '54 tools and 18 resources for security...\n';
    const knownTemplates = [legacyAgentsMd];

    describe('exact match — the whole file IS the known template', () => {
      it('needs_update, not written, when force is off', () => {
        const r = mergeRulesBlock(legacyAgentsMd, rendered, false, knownTemplates);
        expect(r.status).toBe('needs_update');
        expect(r.content).toBeUndefined();
      });

      it('replaced by the managed block when force is on', () => {
        const r = mergeRulesBlock(legacyAgentsMd, rendered, true, knownTemplates);
        expect(r.status).toBe('merged');
        const content = contentOrThrow(r);
        expect(content).toContain(rendered);
        expect(content).not.toContain('54 tools and 18 resources');
        expect(content).toContain(RULES_BLOCK_BEGIN);
      });
    });

    // The exact regression reported: case A.
    describe('PREFIX match — the known template with user content appended after it', () => {
      const withUserContentAfter = `${legacyAgentsMd}\n## Team rules\nNever touch prod.\n`;

      it('needs_update when force is off — and the file is completely untouched', () => {
        const r = mergeRulesBlock(withUserContentAfter, rendered, false, knownTemplates);
        expect(r.status).toBe('needs_update');
        expect(r.content).toBeUndefined();
      });

      it('--update-mcp (force) preserves "Never touch prod" BYTE-FOR-BYTE, replacing only the matched region', () => {
        const r = mergeRulesBlock(withUserContentAfter, rendered, true, knownTemplates);
        expect(r.status).toBe('merged');
        const content = contentOrThrow(r);
        // The exact text the regression deleted, verbatim.
        expect(content).toContain('## Team rules\nNever touch prod.\n');
        expect(content).toContain(rendered);
        expect(content).not.toContain('54 tools and 18 resources');
        expect((content.match(/Never touch prod\./g) ?? [])).toHaveLength(1);
      });
    });

    describe('SUFFIX match — user content followed by the known template', () => {
      const withUserContentBefore = `## Team rules\nNever touch prod.\n\n${legacyAgentsMd}`;

      it('needs_update when force is off — and the file is completely untouched', () => {
        const r = mergeRulesBlock(withUserContentBefore, rendered, false, knownTemplates);
        expect(r.status).toBe('needs_update');
        expect(r.content).toBeUndefined();
      });

      it('--update-mcp (force) preserves "Never touch prod" BYTE-FOR-BYTE, replacing only the matched region', () => {
        const r = mergeRulesBlock(withUserContentBefore, rendered, true, knownTemplates);
        expect(r.status).toBe('merged');
        const content = contentOrThrow(r);
        expect(content).toContain('## Team rules\nNever touch prod.');
        expect(content).toContain(rendered);
        expect(content).not.toContain('54 tools and 18 resources');
      });
    });

    // The exact regression reported: case B. Mentions the phrase in passing
    // but matches no known template exactly, as a prefix, or as a suffix —
    // must never be auto-merged, with or without force.
    describe('substring-only match — mentions dev-guardian but matches no known template (case B)', () => {
      const usersOwnFile = 'This is our internal wiki page.\n\nWe use the dev-guardian MCP server for security scans.\n\nMore notes here.\n';

      it('reports manual_merge_required, not needs_update, when force is off', () => {
        const r = mergeRulesBlock(usersOwnFile, rendered, false, knownTemplates);
        expect(r.status).toBe('manual_merge_required');
        expect(r.content).toBeUndefined();
      });

      it('force does NOT override manual_merge_required — the file is never written, byte-for-byte preserved', () => {
        const r = mergeRulesBlock(usersOwnFile, rendered, true, knownTemplates);
        expect(r.status).toBe('manual_merge_required');
        expect(r.content).toBeUndefined();
      });

      it('a different legacy phrasing that still matches no known template is caught the same way', () => {
        const legacyCopilotStyle = 'This project uses the **dev-guardian MCP server** — 54 tools and 18\n';
        const r = mergeRulesBlock(legacyCopilotStyle, rendered, true, knownTemplates);
        expect(r.status).toBe('manual_merge_required');
      });
    });

    it('genuinely foreign content (no dev-guardian mention at all) still safely appends, never needs_update or manual_merge_required', () => {
      const foreign = '# Totally unrelated project\n\nSome other tool wrote this.\n';
      const r = mergeRulesBlock(foreign, rendered, false, knownTemplates);
      expect(r.status).toBe('merged');
      expect(contentOrThrow(r)).toContain('Some other tool wrote this.');
    });

    it('with no knownLegacyTemplates supplied at all (defensive default), a substring match still refuses rather than replacing the whole file', () => {
      const r = mergeRulesBlock(legacyAgentsMd, rendered, true);
      // No known templates means nothing can be an exact/prefix/suffix
      // match, so this degrades to the safe manual_merge_required path —
      // NEVER the old, unsafe "replace everything" behaviour.
      expect(r.status).toBe('manual_merge_required');
    });
  });
});

// Fix round 1, items 1 and 2 (2026-09-25 full review, review round 1):
// `mergeRulesBlock`'s delimited-block scheme is wrong for a file
// dev-guardian owns exclusively — wrapping Cursor's `.mdc` / Windsurf's
// rules file in `<!-- dev-guardian:begin -->` put that marker BEFORE the
// YAML frontmatter both hosts require as the file's literal first bytes,
// silently disabling `alwaysApply`/`trigger` on every new install.
// `mergeOwnedRulesFile` writes these two files whole instead — no markers,
// no legacy-signature detection needed (nothing else is ever expected to
// write here), always safe to overwrite outright.
describe('mergeOwnedRulesFile', () => {
  const rendered = '---\ntrigger: always_on\n---\n\n# dev-guardian\n\nbody text';

  it('writes a fresh file when none exists', () => {
    const r = mergeOwnedRulesFile(null, rendered);
    expect(r.status).toBe('written');
    expect(r.content).toBe(rendered);
  });

  it('starts with the frontmatter, not a delimiter marker — the exact CRITICAL regression', () => {
    const r = mergeOwnedRulesFile(null, rendered);
    expect(contentOrThrow(r).startsWith('---\n')).toBe(true);
    expect(contentOrThrow(r)).not.toContain(RULES_BLOCK_BEGIN);
  });

  it('is idempotent when the existing file already matches exactly', () => {
    expect(mergeOwnedRulesFile(rendered, rendered).status).toBe('already_present');
  });

  it('overwrites a differing existing file WHOLE, unconditionally (no force flag involved)', () => {
    const old = '---\ntrigger: always_on\n---\n\n# dev-guardian\n\nOLD body text';
    const r = mergeOwnedRulesFile(old, rendered);
    expect(r.status).toBe('merged');
    expect(r.content).toBe(rendered);
    expect(r.content).not.toContain('OLD body text');
  });
});

describe('buildManualSnippet', () => {
  it('emits an mcpServers JSON block for manual hosts', () => {
    const snippet = JSON.parse(buildManualSnippet(SRV));
    expect(snippet.mcpServers[SERVER_ID]).toEqual({ command: 'node', args: [SRV], env: {} });
  });
});
