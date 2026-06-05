/**
 * Integration tests for the host-setup core (hostsetup/setup.ts), which backs
 * the `dev-guardian mcp-config` CLI. No PluginContext / DB — the core is
 * context-free, so we just feed it a fake host-rules dir + a temp project.
 *
 * Global-only hosts (windsurf, claude-desktop) resolve to real user paths, so
 * those cases run with apply:false to avoid touching the dev machine.
 */

import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';

import { previewMcpConfig, setupHost, type SetupOptions } from '../../src/hostsetup/setup.js';

const SRV = '/plugins/dev-guardian/mcp/dist/server.js';

function makeHostRules(): string {
  const dir = mkdtempSync(join(tmpdir(), 'hostrules-'));
  writeFileSync(join(dir, 'cursor.mdc'), '---\nfor: cursor\n---\nbody', 'utf8');
  writeFileSync(join(dir, 'windsurfrules'), '# windsurf', 'utf8');
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
  project = mkdtempSync(join(tmpdir(), 'proj-'));
});

function run(over: Partial<SetupOptions> & Pick<SetupOptions, 'hosts'>) {
  return setupHost({
    projectPath: project,
    hostsDir,
    serverJsPath: SRV,
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
  it('writes the cursor rules file', () => {
    const r = run({ hosts: ['cursor'], registerMcp: false })[0];
    expect(r?.status).toBe('written');
    expect(readFileSync(join(project, '.cursor/rules/dev-guardian.mdc'), 'utf8')).toContain('for: cursor');
  });

  it('marks claude-desktop rules unsupported', () => {
    const r = run({ hosts: ['claude-desktop'], registerMcp: false, apply: false })[0];
    expect(r?.status).toBe('unsupported');
  });

  it('does not overwrite an existing rules file without force', () => {
    writeFileSync(join(project, '.clinerules'), 'old', 'utf8');
    expect(run({ hosts: ['cline'], registerMcp: false })[0]?.status).toBe('already_exists');
    expect(readFileSync(join(project, '.clinerules'), 'utf8')).toBe('old');
  });

  it('overwrites with force', () => {
    writeFileSync(join(project, 'AGENTS.md'), 'old', 'utf8');
    expect(run({ hosts: ['codex'], registerMcp: false, force: true })[0]?.status).toBe('written');
    expect(readFileSync(join(project, 'AGENTS.md'), 'utf8')).toContain('# codex');
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
