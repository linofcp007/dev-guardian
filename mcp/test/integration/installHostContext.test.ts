/**
 * Integration tests for install_host_context.
 *
 * We construct a fake plugin layout (scriptsDir + host-rules/) in tmpdir so
 * we don't depend on the real host-rules/ shipped with the repo.
 */

import Database from 'better-sqlite3';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
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
  // Seed the 5 templates with distinctive markers so we can assert routing.
  writeFileSync(join(hostRulesDir, 'cursor.mdc'), '---\nfor: cursor\n---\nbody', 'utf8');
  writeFileSync(join(hostRulesDir, 'windsurfrules'), '# windsurf template', 'utf8');
  writeFileSync(
    join(hostRulesDir, 'copilot-instructions.md'),
    '# copilot template',
    'utf8',
  );
  writeFileSync(join(hostRulesDir, 'clinerules'), '# cline template', 'utf8');
  writeFileSync(join(hostRulesDir, 'AGENTS.md'), '# codex template', 'utf8');
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

describe('install_host_context', () => {
  it('writes the cursor template to .cursor/rules/dev-guardian.mdc', async () => {
    const tool = getTool('install_host_context');
    const r = (await tool.handler({ project_path: project, host: 'cursor' }, plugin)) as {
      ok: true;
      results: Array<{ status: string; target_path: string; bytes?: number }>;
    };
    expect(r.ok).toBe(true);
    expect(r.results[0]?.status).toBe('written');
    expect(r.results[0]?.target_path).toBe(
      join(project, '.cursor/rules/dev-guardian.mdc'),
    );
    const written = readFileSync(join(project, '.cursor/rules/dev-guardian.mdc'), 'utf8');
    expect(written).toContain('for: cursor');
  });

  it('writes the windsurf template at the project root', async () => {
    const r = (await getTool('install_host_context').handler(
      { project_path: project, host: 'windsurf' },
      plugin,
    )) as { ok: true; results: Array<{ target_path: string }> };
    expect(existsSync(join(project, '.windsurfrules'))).toBe(true);
    expect(r.results[0]?.target_path).toBe(join(project, '.windsurfrules'));
  });

  it('writes .github/copilot-instructions.md (and creates .github/ if missing)', async () => {
    expect(existsSync(join(project, '.github'))).toBe(false);
    await getTool('install_host_context').handler(
      { project_path: project, host: 'copilot' },
      plugin,
    );
    expect(existsSync(join(project, '.github/copilot-instructions.md'))).toBe(true);
  });

  it('refuses to overwrite an existing file by default', async () => {
    writeFileSync(join(project, '.clinerules'), 'pre-existing content', 'utf8');
    const r = (await getTool('install_host_context').handler(
      { project_path: project, host: 'cline' },
      plugin,
    )) as { ok: true; results: Array<{ status: string; reason?: string }> };
    expect(r.results[0]?.status).toBe('already_exists');
    expect(readFileSync(join(project, '.clinerules'), 'utf8')).toBe('pre-existing content');
  });

  it('overwrites when force=true', async () => {
    writeFileSync(join(project, 'AGENTS.md'), 'old', 'utf8');
    const r = (await getTool('install_host_context').handler(
      { project_path: project, host: 'codex', force: true },
      plugin,
    )) as { ok: true; results: Array<{ status: string }> };
    expect(r.results[0]?.status).toBe('written');
    expect(readFileSync(join(project, 'AGENTS.md'), 'utf8')).toContain('codex template');
  });

  it('apply=false returns the plan without writing', async () => {
    const r = (await getTool('install_host_context').handler(
      { project_path: project, host: 'cursor', apply: false },
      plugin,
    )) as { ok: true; applied: boolean; results: Array<{ status: string; bytes?: number }> };
    expect(r.applied).toBe(false);
    expect(r.results[0]?.status).toBe('would_write');
    expect(r.results[0]?.bytes).toBeGreaterThan(0);
    expect(existsSync(join(project, '.cursor/rules/dev-guardian.mdc'))).toBe(false);
  });

  it('host="all" writes one file per host', async () => {
    const r = (await getTool('install_host_context').handler(
      { project_path: project, host: 'all' },
      plugin,
    )) as { ok: true; results: Array<{ host: string; status: string }> };
    expect(r.results).toHaveLength(5);
    expect(r.results.map((x) => x.host).sort()).toEqual([
      'cline',
      'codex',
      'copilot',
      'cursor',
      'windsurf',
    ]);
    expect(existsSync(join(project, '.cursor/rules/dev-guardian.mdc'))).toBe(true);
    expect(existsSync(join(project, '.windsurfrules'))).toBe(true);
    expect(existsSync(join(project, '.github/copilot-instructions.md'))).toBe(true);
    expect(existsSync(join(project, '.clinerules'))).toBe(true);
    expect(existsSync(join(project, 'AGENTS.md'))).toBe(true);
  });

  it('returns template_missing when the template file is absent', async () => {
    // Sabotage the cursor template.
    const broken = makeFakePluginLayout();
    require('node:fs').unlinkSync(join(broken.hostRulesDir, 'cursor.mdc'));
    const plug = makePlugin(broken.scriptsDir);
    const r = (await getTool('install_host_context').handler(
      { project_path: project, host: 'cursor' },
      plug,
    )) as { ok: true; results: Array<{ status: string }> };
    expect(r.results[0]?.status).toBe('template_missing');
  });

  it('emits a scanner_failed error when host-rules dir is gone entirely', async () => {
    const orphanScripts = mkdtempSync(join(tmpdir(), 'orphan-scripts-'));
    const plug = makePlugin(orphanScripts);
    const r = (await getTool('install_host_context').handler(
      { project_path: project, host: 'cursor' },
      plug,
    )) as { ok: true } | { ok: false; error: { code: string } };
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('scanner_failed');
  });
});

// Suppress unused-import warning when not all imports are used in every test.
void dirname;
