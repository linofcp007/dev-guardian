/**
 * Integration tests for install_host_context.
 *
 * The tool now does two things per host: copy a rules file AND register the
 * MCP server in the host's config. We construct a fake plugin layout
 * (scriptsDir + host-rules/) in tmpdir so we don't depend on the real
 * host-rules/ shipped with the repo.
 *
 * Global-only hosts (windsurf, claude-desktop) resolve to real user paths, so
 * those cases are exercised with apply:false to avoid touching the dev machine.
 */

import Database from 'better-sqlite3';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { PluginContext } from '../../src/context.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';

beforeAll(async () => {
  await import('../../src/tools/installHostContext.js');
});

function getTool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

function makeFakePluginLayout(): { scriptsDir: string; hostRulesDir: string } {
  const root = mkdtempSync(join(tmpdir(), 'plugin-'));
  const scriptsDir = join(root, 'scripts');
  const hostRulesDir = join(root, 'host-rules');
  mkdirSync(scriptsDir, { recursive: true });
  mkdirSync(hostRulesDir, { recursive: true });
  // Seed the rules templates with distinctive markers so we can assert routing.
  writeFileSync(join(hostRulesDir, 'cursor.mdc'), '---\nfor: cursor\n---\nbody', 'utf8');
  writeFileSync(join(hostRulesDir, 'windsurfrules'), '# windsurf template', 'utf8');
  writeFileSync(join(hostRulesDir, 'copilot-instructions.md'), '# copilot template', 'utf8');
  writeFileSync(join(hostRulesDir, 'clinerules'), '# cline template', 'utf8');
  writeFileSync(join(hostRulesDir, 'AGENTS.md'), '# codex template', 'utf8');
  writeFileSync(join(hostRulesDir, 'GEMINI.md'), '# gemini template', 'utf8');
  return { scriptsDir, hostRulesDir };
}

function makePlugin(scriptsDir: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: null,
    scriptsDir,
    progressNotifier: { send: () => {} },
  };
}

interface RuleEntry {
  host: string;
  status: string;
  target_path?: string;
  bytes?: number;
  reason?: string;
  mcp: { status: string; config_path?: string; key?: string; scope?: string; snippet?: string };
}

let project: string;
let plugin: PluginContext;
let scriptsDir: string;

beforeEach(() => {
  const layout = makeFakePluginLayout();
  scriptsDir = layout.scriptsDir;
  project = mkdtempSync(join(tmpdir(), 'host-target-'));
  plugin = makePlugin(scriptsDir);
});

afterEach(() => {
  // tmp cleanup is OS-handled; no explicit teardown needed.
});

async function run(args: Record<string, unknown>) {
  return (await getTool('install_host_context').handler({ project_path: project, ...args }, plugin)) as {
    ok: boolean;
    applied?: boolean;
    server_js?: string;
    results?: RuleEntry[];
    error?: { code: string };
  };
}

describe('install_host_context — rules files', () => {
  it('writes the cursor template to .cursor/rules/dev-guardian.mdc', async () => {
    const r = await run({ host: 'cursor', register_mcp: false });
    expect(r.ok).toBe(true);
    expect(r.results?.[0]?.status).toBe('written');
    expect(r.results?.[0]?.target_path).toBe(join(project, '.cursor/rules/dev-guardian.mdc'));
    expect(readFileSync(join(project, '.cursor/rules/dev-guardian.mdc'), 'utf8')).toContain('for: cursor');
  });

  it('writes the windsurf template at the project root', async () => {
    const r = await run({ host: 'windsurf', register_mcp: false });
    expect(existsSync(join(project, '.windsurfrules'))).toBe(true);
    expect(r.results?.[0]?.target_path).toBe(join(project, '.windsurfrules'));
  });

  it('writes .github/copilot-instructions.md (and creates .github/ if missing)', async () => {
    expect(existsSync(join(project, '.github'))).toBe(false);
    await run({ host: 'copilot', register_mcp: false });
    expect(existsSync(join(project, '.github/copilot-instructions.md'))).toBe(true);
  });

  it('writes GEMINI.md for the gemini host', async () => {
    await run({ host: 'gemini', register_mcp: false });
    expect(readFileSync(join(project, 'GEMINI.md'), 'utf8')).toContain('gemini template');
  });

  it('refuses to overwrite an existing rules file by default', async () => {
    writeFileSync(join(project, '.clinerules'), 'pre-existing content', 'utf8');
    const r = await run({ host: 'cline', register_mcp: false });
    expect(r.results?.[0]?.status).toBe('already_exists');
    expect(readFileSync(join(project, '.clinerules'), 'utf8')).toBe('pre-existing content');
  });

  it('overwrites a rules file when force=true', async () => {
    writeFileSync(join(project, 'AGENTS.md'), 'old', 'utf8');
    const r = await run({ host: 'codex', register_mcp: false, force: true });
    expect(r.results?.[0]?.status).toBe('written');
    expect(readFileSync(join(project, 'AGENTS.md'), 'utf8')).toContain('codex template');
  });

  it('marks claude-desktop rules as unsupported (no rules-file mechanism)', async () => {
    const r = await run({ host: 'claude-desktop', register_mcp: false });
    expect(r.results?.[0]?.status).toBe('unsupported');
  });

  it('host="all" covers every supported host', async () => {
    const r = await run({ host: 'all', register_mcp: false });
    expect(r.results).toHaveLength(7);
    expect(r.results?.map((x) => x.host).sort()).toEqual([
      'claude-desktop',
      'cline',
      'codex',
      'copilot',
      'cursor',
      'gemini',
      'windsurf',
    ]);
    for (const f of ['.cursor/rules/dev-guardian.mdc', '.windsurfrules', '.github/copilot-instructions.md', '.clinerules', 'AGENTS.md', 'GEMINI.md']) {
      expect(existsSync(join(project, f))).toBe(true);
    }
  });
});

describe('install_host_context — MCP registration', () => {
  it('writes .cursor/mcp.json with a node-launch entry', async () => {
    const r = await run({ host: 'cursor', install_rules: false });
    const mcp = r.results?.[0]?.mcp;
    expect(mcp?.status).toBe('written');
    expect(mcp?.config_path).toBe(join(project, '.cursor/mcp.json'));
    const cfg = JSON.parse(readFileSync(join(project, '.cursor/mcp.json'), 'utf8'));
    expect(cfg.mcpServers['dev-guardian'].command).toBe('node');
    expect(cfg.mcpServers['dev-guardian'].args[0]).toBe(r.server_js);
    expect(cfg.mcpServers['dev-guardian'].args[0].endsWith(join('mcp', 'dist', 'server.js'))).toBe(true);
  });

  it('is idempotent on a second run', async () => {
    await run({ host: 'cursor', install_rules: false });
    const r2 = await run({ host: 'cursor', install_rules: false });
    expect(r2.results?.[0]?.mcp.status).toBe('already_present');
  });

  it('merges without clobbering an existing server', async () => {
    mkdirSync(join(project, '.cursor'), { recursive: true });
    writeFileSync(
      join(project, '.cursor/mcp.json'),
      JSON.stringify({ mcpServers: { other: { command: 'x', args: [], env: {} } } }, null, 2),
      'utf8',
    );
    await run({ host: 'cursor', install_rules: false });
    const cfg = JSON.parse(readFileSync(join(project, '.cursor/mcp.json'), 'utf8'));
    expect(cfg.mcpServers.other).toBeDefined();
    expect(cfg.mcpServers['dev-guardian']).toBeDefined();
  });

  it('reports needs_update for a differing entry, then merges with force', async () => {
    mkdirSync(join(project, '.cursor'), { recursive: true });
    writeFileSync(
      join(project, '.cursor/mcp.json'),
      JSON.stringify({ mcpServers: { 'dev-guardian': { command: 'node', args: ['/old.js'], env: {} } } }),
      'utf8',
    );
    const r1 = await run({ host: 'cursor', install_rules: false });
    expect(r1.results?.[0]?.mcp.status).toBe('needs_update');
    const r2 = await run({ host: 'cursor', install_rules: false, force: true });
    expect(r2.results?.[0]?.mcp.status).toBe('merged');
    const cfg = JSON.parse(readFileSync(join(project, '.cursor/mcp.json'), 'utf8'));
    expect(cfg.mcpServers['dev-guardian'].args[0]).toBe(r2.server_js);
  });

  it('copilot uses the "servers" key with type:"stdio"', async () => {
    const r = await run({ host: 'copilot', install_rules: false });
    expect(r.results?.[0]?.mcp.key).toBe('servers');
    const cfg = JSON.parse(readFileSync(join(project, '.vscode/mcp.json'), 'utf8'));
    expect(cfg.servers['dev-guardian'].type).toBe('stdio');
    expect(cfg.servers['dev-guardian'].command).toBe('node');
  });

  it('codex writes a TOML table with a single-quoted path', async () => {
    const r = await run({ host: 'codex', install_rules: false });
    expect(r.results?.[0]?.mcp.config_path).toBe(join(project, '.codex/config.toml'));
    const toml = readFileSync(join(project, '.codex/config.toml'), 'utf8');
    expect(toml).toContain('[mcp_servers.dev-guardian]');
    expect(toml).toContain(`'${r.server_js}'`);
    // second run is idempotent
    const r2 = await run({ host: 'codex', install_rules: false });
    expect(r2.results?.[0]?.mcp.status).toBe('already_present');
  });

  it('cline registration is manual and returns a snippet', async () => {
    const r = await run({ host: 'cline', install_rules: false });
    expect(r.results?.[0]?.mcp.status).toBe('manual');
    expect(r.results?.[0]?.mcp.snippet).toContain('dev-guardian');
  });

  it('windsurf is global-only and planned (not written) under apply:false', async () => {
    const r = await run({ host: 'windsurf', scope: 'project', install_rules: false, apply: false });
    const mcp = r.results?.[0]?.mcp;
    expect(mcp?.scope).toBe('global'); // forced global despite scope:project
    expect(mcp?.status).toBe('would_write');
    expect(mcp?.config_path?.endsWith(join('.codeium', 'windsurf', 'mcp_config.json'))).toBe(true);
  });

  it('claude-desktop plans an OS-specific config path under apply:false', async () => {
    const r = await run({ host: 'claude-desktop', apply: false });
    const entry = r.results?.[0];
    expect(entry?.status).toBe('unsupported'); // rules
    expect(entry?.mcp.status).toBe('would_write');
    expect(entry?.mcp.config_path).toContain('Claude');
  });
});

describe('install_host_context — plan & error handling', () => {
  it('apply=false writes nothing to disk', async () => {
    const r = await run({ host: 'cursor', apply: false });
    expect(r.applied).toBe(false);
    expect(r.results?.[0]?.status).toBe('would_write'); // rules
    expect(r.results?.[0]?.mcp.status).toBe('would_write'); // mcp
    expect(existsSync(join(project, '.cursor/rules/dev-guardian.mdc'))).toBe(false);
    expect(existsSync(join(project, '.cursor/mcp.json'))).toBe(false);
  });

  it('returns template_missing when the rules template is absent', async () => {
    const broken = makeFakePluginLayout();
    require('node:fs').unlinkSync(join(broken.hostRulesDir, 'cursor.mdc'));
    const plug = makePlugin(broken.scriptsDir);
    const r = (await getTool('install_host_context').handler(
      { project_path: project, host: 'cursor', register_mcp: false },
      plug,
    )) as { ok: true; results: Array<{ status: string }> };
    expect(r.results[0]?.status).toBe('template_missing');
  });

  it('emits scanner_failed when the host-rules dir is gone entirely', async () => {
    const orphanScripts = mkdtempSync(join(tmpdir(), 'orphan-scripts-'));
    const plug = makePlugin(orphanScripts);
    const r = (await getTool('install_host_context').handler(
      { project_path: project, host: 'cursor' },
      plug,
    )) as { ok: boolean; error?: { code: string } };
    expect(r.ok).toBe(false);
    expect(r.error?.code).toBe('scanner_failed');
  });
});
