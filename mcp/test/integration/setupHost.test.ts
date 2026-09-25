/**
 * Integration tests for the host-setup core (hostsetup/setup.ts), which backs
 * the `dev-guardian mcp-config` CLI. No PluginContext / DB — the core is
 * context-free, so we just feed it a fake host-rules dir + a temp project.
 *
 * Global-only hosts (windsurf, claude-desktop) resolve to real user paths, so
 * those cases run with apply:false to avoid touching the dev machine.
 */

import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';

import { previewMcpConfig, setupHost, type SetupOptions } from '../../src/hostsetup/setup.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

const SRV = '/plugins/dev-guardian/mcp/dist/server.js';
const CLI = '/plugins/dev-guardian/cli/dev-guardian.mjs';

function makeHostRules(): string {
  const dir = makeTempDir('hostrules-');
  writeFileSync(join(dir, 'cursor.mdc'), '---\nfor: cursor\n---\nbody: run {{DEV_GUARDIAN_CLI}} status', 'utf8');
  // Frontmatter here too — Windsurf requires it as the file's literal first
  // bytes exactly like Cursor does (fix round 1, item 1), so the fixture
  // needs one for the "starts with the frontmatter" test to mean anything.
  writeFileSync(join(dir, 'windsurf.md'), '---\ntrigger: always_on\n---\nbody: run {{DEV_GUARDIAN_CLI}} status', 'utf8');
  writeFileSync(join(dir, 'copilot-instructions.md'), '# copilot', 'utf8');
  writeFileSync(join(dir, 'clinerules'), '# cline', 'utf8');
  writeFileSync(join(dir, 'AGENTS.md'), '# codex', 'utf8');
  writeFileSync(join(dir, 'GEMINI.md'), '# gemini', 'utf8');
  return dir;
}

let hostsDir: string;
let project: string;

beforeEach(() => {
  hostsDir = makeHostRules();
  project = makeTempDir('proj-');
});

afterAll(cleanupTempDirs);

function run(over: Partial<SetupOptions> & Pick<SetupOptions, 'hosts'>) {
  return setupHost({
    projectPath: project,
    hostsDir,
    serverJsPath: SRV,
    cliPath: CLI,
    env: { os: 'linux', home: '/home/me', projectPath: project },
    scope: 'project',
    registerMcp: true,
    installRules: true,
    apply: true,
    force: false,
    ...over,
  });
}

describe('setupHost — rules files', () => {
  // Fix round 1, item 1 (CRITICAL): Cursor and Windsurf are OWNED files —
  // dev-guardian writes them whole, never wrapped in the
  // `<!-- dev-guardian:begin -->` delimited block the SHARED hosts use.
  // Wrapping them (this describe block's own ORIGINAL, pre-fix assertions
  // below, kept only as a comment for context) put that marker BEFORE the
  // required YAML frontmatter, so `.cursor/rules/dev-guardian.mdc` and
  // `.windsurf/rules/dev-guardian.md` silently stopped being valid rule
  // files on every new install: `content.startsWith('---\n')` is the
  // property that actually matters here, and the old version of this test
  // never checked it — it asserted `content.toContain('<!-- dev-guardian:
  // begin -->')`, which the BROKEN shape also satisfies, so the bug shipped
  // green.
  it('writes the cursor rules file WHOLE — frontmatter first, no delimited-block markers, CLI placeholder substituted', () => {
    const r = run({ hosts: ['cursor'], registerMcp: false })[0];
    expect(r?.status).toBe('written');
    const content = readFileSync(join(project, '.cursor/rules/dev-guardian.mdc'), 'utf8');
    expect(content.startsWith('---\n')).toBe(true);
    expect(content).toContain('for: cursor');
    expect(content).toContain(`run ${CLI} status`);
    expect(content).not.toContain('{{DEV_GUARDIAN_CLI}}');
    expect(content).not.toContain('<!-- dev-guardian:begin -->');
    expect(content).not.toContain('<!-- dev-guardian:end -->');
  });

  it('writes the windsurf rules file WHOLE — frontmatter first, no delimited-block markers, CLI placeholder substituted', () => {
    const r = run({ hosts: ['windsurf'], registerMcp: false })[0];
    expect(r?.status).toBe('written');
    const content = readFileSync(join(project, '.windsurf/rules/dev-guardian.md'), 'utf8');
    expect(content.startsWith('---\n')).toBe(true);
    expect(content).toContain('trigger: always_on');
    expect(content).toContain(`run ${CLI} status`);
    expect(content).not.toContain('{{DEV_GUARDIAN_CLI}}');
    expect(content).not.toContain('<!-- dev-guardian:begin -->');
    expect(content).not.toContain('<!-- dev-guardian:end -->');
  });

  it('cursor: a differing existing file is overwritten WHOLE, unconditionally — no force needed (nothing else ever writes here)', () => {
    mkdirSync(join(project, '.cursor', 'rules'), { recursive: true });
    writeFileSync(join(project, '.cursor/rules/dev-guardian.mdc'), '---\nfor: OLD\n---\nold body', 'utf8');
    const r = run({ hosts: ['cursor'], registerMcp: false, force: false })[0];
    expect(r?.status).toBe('merged');
    const content = readFileSync(join(project, '.cursor/rules/dev-guardian.mdc'), 'utf8');
    expect(content.startsWith('---\n')).toBe(true);
    expect(content).toContain('for: cursor');
    expect(content).not.toContain('old body');
  });

  it('cursor: is idempotent (already_present) once the exact rendered content is already there', () => {
    run({ hosts: ['cursor'], registerMcp: false });
    const r = run({ hosts: ['cursor'], registerMcp: false })[0];
    expect(r?.status).toBe('already_present');
  });

  it('marks claude-desktop rules unsupported', () => {
    const r = run({ hosts: ['claude-desktop'], registerMcp: false, apply: false })[0];
    expect(r?.status).toBe('unsupported');
  });

  // Item 6b (2026-09-25 full review): an existing rules file with no
  // dev-guardian markers is APPENDED to, never clobbered — every byte of
  // the user's own content survives, regardless of `force`. This replaces
  // the old all-or-nothing "leave it alone unless --force" contract, which
  // is exactly what let `--force` destroy unrelated content in the first
  // place (a whole-file `copyFileSync`).
  it('appends the block to an existing rules file with no markers — never touches existing content, force or not', () => {
    writeFileSync(join(project, '.clinerules'), 'Never touch prod.\n', 'utf8');
    const r = run({ hosts: ['cline'], registerMcp: false })[0];
    expect(r?.status).toBe('merged');
    const content = readFileSync(join(project, '.clinerules'), 'utf8');
    expect(content).toContain('Never touch prod.');
    expect(content).toContain('# cline');
    expect(content).toContain('<!-- dev-guardian:begin -->');
  });

  it('is idempotent (already_present) on a second run once the block is installed', () => {
    run({ hosts: ['codex'], registerMcp: false });
    const r = run({ hosts: ['codex'], registerMcp: false })[0];
    expect(r?.status).toBe('already_present');
  });

  it('reports needs_update (not a silent rewrite) when the template changed since install, force off', () => {
    run({ hosts: ['codex'], registerMcp: false });
    writeFileSync(join(hostsDir, 'AGENTS.md'), '# codex v2', 'utf8');
    const r = run({ hosts: ['codex'], registerMcp: false })[0];
    expect(r?.status).toBe('needs_update');
    // Untouched — the stale block is left exactly as it was until --update-mcp/--force.
    expect(readFileSync(join(project, 'AGENTS.md'), 'utf8')).toContain('# codex\n');
  });

  it('--force (still honoured as a deprecated alias) refreshes a stale block without touching surrounding content', () => {
    writeFileSync(join(project, 'AGENTS.md'), 'Never touch prod.\n', 'utf8');
    run({ hosts: ['codex'], registerMcp: false });
    writeFileSync(join(hostsDir, 'AGENTS.md'), '# codex v2', 'utf8');
    const r = run({ hosts: ['codex'], registerMcp: false, force: true })[0];
    expect(r?.status).toBe('merged');
    const content = readFileSync(join(project, 'AGENTS.md'), 'utf8');
    expect(content).toContain('Never touch prod.');
    expect(content).toContain('# codex v2');
    expect(content).not.toContain('# codex\n');
  });

  // Fix round 1, item 2: a project that ran an OLDER `mcp-config --write`
  // (back when it still `copyFileSync`d the whole file) has an AGENTS.md
  // that is ENTIRELY unmarked dev-guardian text, no markers at all. Without
  // legacy detection, the "no markers found" branch would append a second,
  // freshly-wrapped copy underneath it on every future --write.
  it('a legacy unmarked dev-guardian copy is never duplicated — needs_update without force, replaced (not doubled) with it', () => {
    writeFileSync(
      join(project, 'AGENTS.md'),
      'This repository has the **dev-guardian MCP server** registered. Some old body.\n',
      'utf8',
    );
    const blocked = run({ hosts: ['codex'], registerMcp: false })[0];
    expect(blocked?.status).toBe('needs_update');
    expect(readFileSync(join(project, 'AGENTS.md'), 'utf8')).not.toContain('<!-- dev-guardian:begin -->');

    const updated = run({ hosts: ['codex'], registerMcp: false, force: true })[0];
    expect(updated?.status).toBe('merged');
    const content = readFileSync(join(project, 'AGENTS.md'), 'utf8');
    expect(content).toContain('# codex');
    // The exact regression: the OLD unmarked copy must be GONE, not sitting
    // beside the new one.
    expect(content).not.toContain('Some old body.');
    expect((content.match(/<!-- dev-guardian:begin -->/g) ?? [])).toHaveLength(1);
  });

  it('host="all" covers 7 hosts', () => {
    expect(run({ hosts: ['all'], registerMcp: false, apply: false })).toHaveLength(7);
  });

  it('reports template_missing when a template is absent', () => {
    rmSync(join(hostsDir, 'cursor.mdc'));
    expect(run({ hosts: ['cursor'], registerMcp: false })[0]?.status).toBe('template_missing');
  });
});

describe('setupHost — MCP registration', () => {
  it('writes .cursor/mcp.json with the node entry', () => {
    const r = run({ hosts: ['cursor'], installRules: false })[0];
    expect(r?.mcp.status).toBe('written');
    const cfg = JSON.parse(readFileSync(join(project, '.cursor/mcp.json'), 'utf8'));
    expect(cfg.mcpServers['dev-guardian'].args[0]).toBe(SRV);
  });

  it('is idempotent on a second run', () => {
    run({ hosts: ['cursor'], installRules: false });
    expect(run({ hosts: ['cursor'], installRules: false })[0]?.mcp.status).toBe('already_present');
  });

  it('merges without clobbering another server', () => {
    mkdirSync(join(project, '.cursor'), { recursive: true });
    writeFileSync(
      join(project, '.cursor/mcp.json'),
      JSON.stringify({ mcpServers: { other: { command: 'x', args: [], env: {} } } }),
      'utf8',
    );
    run({ hosts: ['cursor'], installRules: false });
    const cfg = JSON.parse(readFileSync(join(project, '.cursor/mcp.json'), 'utf8'));
    expect(cfg.mcpServers.other).toBeDefined();
    expect(cfg.mcpServers['dev-guardian']).toBeDefined();
  });

  it('reports needs_update then merges with force', () => {
    mkdirSync(join(project, '.cursor'), { recursive: true });
    writeFileSync(
      join(project, '.cursor/mcp.json'),
      JSON.stringify({ mcpServers: { 'dev-guardian': { command: 'node', args: ['/old.js'], env: {} } } }),
      'utf8',
    );
    expect(run({ hosts: ['cursor'], installRules: false })[0]?.mcp.status).toBe('needs_update');
    expect(run({ hosts: ['cursor'], installRules: false, force: true })[0]?.mcp.status).toBe('merged');
  });

  it('copilot uses the "servers" key with type:"stdio"', () => {
    run({ hosts: ['copilot'], installRules: false });
    const cfg = JSON.parse(readFileSync(join(project, '.vscode/mcp.json'), 'utf8'));
    expect(cfg.servers['dev-guardian'].type).toBe('stdio');
  });

  it('codex writes a TOML table', () => {
    run({ hosts: ['codex'], installRules: false });
    expect(readFileSync(join(project, '.codex/config.toml'), 'utf8')).toContain('[mcp_servers.dev-guardian]');
  });

  it('windsurf is global-only and planned under apply:false', () => {
    const r = run({ hosts: ['windsurf'], scope: 'project', installRules: false, apply: false })[0];
    expect(r?.mcp.scope).toBe('global');
    expect(r?.mcp.status).toBe('would_write');
  });

  it('windsurf named explicitly (not "all") still registers globally at project scope — the user asked for it by name', () => {
    const r = run({ hosts: ['windsurf'], scope: 'project', installRules: false, apply: false })[0];
    expect(r?.mcp.status).not.toBe('skipped');
  });

  // Item 6d (2026-09-25 full review): `mcp-config all --write` at the
  // default project scope used to silently write the GLOBAL Windsurf and
  // Claude Desktop configs — a surprising, cross-project side effect. Now
  // it skips them (with a stated reason) unless global scope was explicitly
  // requested.
  describe("'all' at project scope skips global-only hosts (item 6d)", () => {
    it('windsurf and claude-desktop are reported skipped, not silently written', () => {
      const results = run({ hosts: ['all'], scope: 'project', installRules: false, apply: false });
      const windsurf = results.find((r) => r.host === 'windsurf');
      const claudeDesktop = results.find((r) => r.host === 'claude-desktop');
      expect(windsurf?.mcp.status).toBe('skipped');
      expect(windsurf?.mcp.reason).toMatch(/global/i);
      expect(claudeDesktop?.mcp.status).toBe('skipped');
      expect(claudeDesktop?.mcp.reason).toMatch(/global/i);
    });

    it('every other host in "all" is unaffected at project scope', () => {
      const results = run({ hosts: ['all'], scope: 'project', installRules: false, apply: false });
      const cursor = results.find((r) => r.host === 'cursor');
      expect(cursor?.mcp.status).not.toBe('skipped');
    });

    it('scope: global includes them', () => {
      const results = run({ hosts: ['all'], scope: 'global', installRules: false, apply: false });
      const windsurf = results.find((r) => r.host === 'windsurf');
      expect(windsurf?.mcp.status).not.toBe('skipped');
    });
  });

  it('cline registration is manual and returns a snippet', () => {
    const r = run({ hosts: ['cline'], installRules: false, apply: false })[0];
    expect(r?.mcp.status).toBe('manual');
    expect(r?.mcp.snippet).toContain('dev-guardian');
  });

  it('apply:false writes nothing', () => {
    run({ hosts: ['cursor'], apply: false });
    expect(existsSync(join(project, '.cursor/mcp.json'))).toBe(false);
    expect(existsSync(join(project, '.cursor/rules/dev-guardian.mdc'))).toBe(false);
  });
});

describe('previewMcpConfig — paste-ready blocks (CLI print mode)', () => {
  const env = { os: 'linux' as const, home: '/home/me', projectPath: '/repo' };

  it('cursor: mcpServers block at the project path with the absolute server path', () => {
    const p = previewMcpConfig('cursor', 'project', SRV, env);
    expect(p.config_path).toBe(join('/repo', '.cursor', 'mcp.json'));
    expect(p.manual).toBe(false);
    expect(JSON.parse(p.block).mcpServers['dev-guardian'].args[0]).toBe(SRV);
    expect(p.rules_target).toBe('.cursor/rules/dev-guardian.mdc');
  });

  it('copilot: servers key + type', () => {
    const p = previewMcpConfig('copilot', 'project', SRV, env);
    expect(JSON.parse(p.block).servers['dev-guardian'].type).toBe('stdio');
  });

  it('codex: TOML table', () => {
    expect(previewMcpConfig('codex', 'project', SRV, env).block).toContain('[mcp_servers.dev-guardian]');
  });

  it('cline: manual snippet', () => {
    const p = previewMcpConfig('cline', 'global', SRV, env);
    expect(p.manual).toBe(true);
    expect(p.config_path).toBeUndefined();
  });

  it('claude-desktop: OS-specific path, no rules file', () => {
    const p = previewMcpConfig('claude-desktop', 'global', SRV, env);
    expect(p.config_path).toContain('Claude');
    expect(p.rules_target).toBeUndefined();
  });
});
