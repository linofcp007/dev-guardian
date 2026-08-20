/**
 * Config drift end to end: `init_project` stamps provenance, `init_project`
 * with `refresh` acts on it, and the scan path reports it without ever
 * becoming a finding.
 *
 * The bug this exists for: `init_project` copies four baseline configs into a
 * project and then never looks at them again, so `configs/semgrep/base.yml`'s
 * `wp-unescaped-output` rule — which could not match anything, and was fixed
 * in b51a2dc — is still running dead in every project initialised before that
 * commit, with no way for the project to find out.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { okResult } from '../helpers/toolResult.js';

afterAll(cleanupTempDirs);

vi.mock('../../src/runners/shellRunner.js', () => ({
  runShellScript: vi.fn(),
}));

import type { PluginContext } from '../../src/context.js';
import { MANIFEST_RELATIVE_PATH, readManifest } from '../../src/configdrift/manifest.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { makeScanTool } from '../../src/tools/scanToolFactory.js';

beforeAll(async () => {
  await import('../../src/tools/initProject.js');
});

const BASE_V1 = 'rules:\n  - id: wp-unescaped-output\n    pattern: echo $_GET[$X]\n';
const BASE_V2 = 'rules:\n  - id: wp-unescaped-output\n    pattern: echo $_GET[...]\n';
const GITLEAKS = '# gitleaks baseline\n[[rules]]\nid = "aws"\n';
const RENOVATE = '{\n  "extends": ["config:recommended"]\n}\n';
const PRECOMMIT = 'repos: []\n';

interface Harness {
  project: string;
  scriptsDir: string;
  configsDir: string;
  plugin: PluginContext;
}

function harness(): Harness {
  const project = makeTempDir('drift-int-project-');
  const scriptsDir = join(makeTempDir('drift-int-plugin-'), 'scripts');
  const configsDir = join(scriptsDir, '..', 'configs');
  mkdirSync(scriptsDir, { recursive: true });
  for (const d of ['gitleaks', 'renovate', 'semgrep', 'pre-commit']) {
    mkdirSync(join(configsDir, d), { recursive: true });
  }
  writeFileSync(join(configsDir, 'gitleaks', 'gitleaks.toml'), GITLEAKS, 'utf8');
  writeFileSync(join(configsDir, 'renovate', 'renovate.json'), RENOVATE, 'utf8');
  writeFileSync(join(configsDir, 'semgrep', 'base.yml'), BASE_V1, 'utf8');
  writeFileSync(join(configsDir, 'pre-commit', 'pre-commit-config.yaml'), PRECOMMIT, 'utf8');

  const db = new Database(':memory:');
  runMigrations(db);
  const plugin: PluginContext = {
    storage: new Storage(db),
    shell: { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' },
    scriptsDir,
    progressNotifier: { send: () => {} },
  };
  return { project, scriptsDir, configsDir, plugin };
}

function getTool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

interface InitPayload {
  files_written: Array<{ target: string }>;
  files_skipped: Array<{ target: string; reason_skipped: string }>;
  refresh?: {
    applied: boolean;
    plan: Array<{ target: string; action: string; reason: string; alongside_path?: string }>;
  };
}

async function init(
  h: Harness,
  extra: Record<string, unknown> = {},
): Promise<{ ok: true } & InitPayload> {
  return okResult<InitPayload>(
    await getTool('init_project').handler(
      { project_path: h.project, profile: 'standard', ...extra },
      h.plugin,
    ),
  );
}

function planFor(r: { refresh?: InitPayload['refresh'] }, target: string) {
  const item = r.refresh?.plan.find((p) => p.target === target);
  if (item === undefined) throw new Error(`no refresh plan item for ${target}`);
  return item;
}

/** Ship a newer `base.yml`, i.e. what b51a2dc did to a real user's project. */
function shipNewerBaseYml(h: Harness): void {
  writeFileSync(join(h.configsDir, 'semgrep', 'base.yml'), BASE_V2, 'utf8');
}

beforeEach(() => {
  vi.resetModules();
});

describe('init_project provenance stamp', () => {
  it('writes a manifest recording target, source, plugin version and content hash', async () => {
    const h = harness();
    await init(h);

    expect(existsSync(join(h.project, MANIFEST_RELATIVE_PATH))).toBe(true);
    const manifest = readManifest(h.project);
    if (manifest === null) throw new Error('expected a manifest');
    expect(manifest.entries.map((e) => e.target).sort()).toEqual([
      '.gitleaks.toml',
      '.pre-commit-config.yaml',
      '.semgrep.yml',
      'renovate.json',
    ]);
    const semgrep = manifest.entries.find((e) => e.target === '.semgrep.yml');
    if (semgrep === undefined) throw new Error('expected a .semgrep.yml entry');
    expect(semgrep.source).toBe('semgrep/base.yml');
    expect(semgrep.plugin_version).toMatch(/^\d+\.\d+\.\d+/);
    expect(semgrep.source_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(semgrep.provenance).toBe('copied');
  });

  it('stamps a comment header where the format allows one', async () => {
    const h = harness();
    await init(h);
    const yml = readFileSync(join(h.project, '.semgrep.yml'), 'utf8');
    expect(yml).toContain('dev-guardian:managed');
    expect(yml).toContain('semgrep/base.yml');
    // The body survives intact underneath the header.
    expect(yml).toContain('id: wp-unescaped-output');
  });

  it('leaves renovate.json byte-identical, because JSON has no comment syntax', async () => {
    const h = harness();
    await init(h);
    expect(readFileSync(join(h.project, 'renovate.json'), 'utf8')).toBe(RENOVATE);
    // ...which is exactly why the manifest, not the header, is the mechanism.
    const manifest = readManifest(h.project);
    expect(manifest?.entries.some((e) => e.target === 'renovate.json')).toBe(true);
  });

  it('adopts an untracked file that is byte-identical to what we ship', async () => {
    const h = harness();
    writeFileSync(join(h.project, '.semgrep.yml'), BASE_V1, 'utf8');
    const r = await init(h);
    expect(r.files_skipped.some((s) => s.target === '.semgrep.yml')).toBe(true);
    const entry = readManifest(h.project)?.entries.find((e) => e.target === '.semgrep.yml');
    expect(entry?.provenance).toBe('adopted');
  });

  it('does not claim provenance over a same-named file it did not write', async () => {
    const h = harness();
    writeFileSync(join(h.project, '.semgrep.yml'), 'rules: []  # mine, not yours\n', 'utf8');
    await init(h);
    const entry = readManifest(h.project)?.entries.find((e) => e.target === '.semgrep.yml');
    expect(entry).toBeUndefined();
  });

  it('writes no manifest on a dry run', async () => {
    const h = harness();
    await init(h, { apply: false });
    expect(existsSync(join(h.project, MANIFEST_RELATIVE_PATH))).toBe(false);
  });
});

describe('init_project refresh mode', () => {
  it('is opt-in — a plain call reports no refresh at all', async () => {
    const h = harness();
    const r = await init(h);
    expect(r.refresh).toBeUndefined();
  });

  it('reports what would change without writing when apply=false', async () => {
    const h = harness();
    await init(h);
    shipNewerBaseYml(h);

    const r = await init(h, { refresh: true, apply: false });
    expect(r.refresh?.applied).toBe(false);
    expect(planFor(r, '.semgrep.yml').action).toBe('update_in_place');
    expect(planFor(r, '.gitleaks.toml').action).toBe('up_to_date');
    // Nothing on disk moved.
    expect(readFileSync(join(h.project, '.semgrep.yml'), 'utf8')).toContain('echo $_GET[$X]');
  });

  it('updates a file the user never touched, in place', async () => {
    const h = harness();
    await init(h);
    shipNewerBaseYml(h);

    const r = await init(h, { refresh: true, apply: true });
    expect(planFor(r, '.semgrep.yml').action).toBe('update_in_place');
    expect(readFileSync(join(h.project, '.semgrep.yml'), 'utf8')).toContain('echo $_GET[...]');
    expect(existsSync(join(h.project, '.semgrep.yml.new'))).toBe(false);
  });

  it('never clobbers a customised file — it writes alongside and says so', async () => {
    const h = harness();
    await init(h);
    const mine = `${readFileSync(join(h.project, '.semgrep.yml'), 'utf8')}  - id: my-own-rule\n`;
    writeFileSync(join(h.project, '.semgrep.yml'), mine, 'utf8');
    shipNewerBaseYml(h);

    const r = await init(h, { refresh: true, apply: true });
    const item = planFor(r, '.semgrep.yml');
    expect(item.action).toBe('write_alongside');
    expect(item.alongside_path).toBe('.semgrep.yml.new');
    // Their file is exactly as they left it.
    expect(readFileSync(join(h.project, '.semgrep.yml'), 'utf8')).toBe(mine);
    expect(readFileSync(join(h.project, '.semgrep.yml.new'), 'utf8')).toContain('echo $_GET[...]');
  });

  it('degrades gracefully on a project with no manifest, and adopts one', async () => {
    const h = harness();
    // A project initialised before any of this existed: the copy is on disk,
    // it is an OLD copy, and nothing records where it came from.
    writeFileSync(join(h.project, '.semgrep.yml'), BASE_V1, 'utf8');
    shipNewerBaseYml(h);

    const r = await init(h, { refresh: true, apply: true });
    // Provenance is genuinely unknown — an old copy and a hand-written file
    // are indistinguishable — so the safe action is the non-destructive one.
    const item = planFor(r, '.semgrep.yml');
    expect(item.action).toBe('write_alongside');
    expect(readFileSync(join(h.project, '.semgrep.yml'), 'utf8')).toBe(BASE_V1);
    expect(existsSync(join(h.project, '.semgrep.yml.new'))).toBe(true);
    // From here on, drift is detectable.
    const entry = readManifest(h.project)?.entries.find((e) => e.target === '.semgrep.yml');
    expect(entry?.provenance).toBe('adopted');
  });

  it('creates files that are missing entirely', async () => {
    const h = harness();
    const r = await init(h, { refresh: true, apply: true });
    expect(planFor(r, '.semgrep.yml').action).toBe('create');
    expect(existsSync(join(h.project, '.semgrep.yml'))).toBe(true);
  });
});

describe('the drift advisory on the scan path', () => {
  const tinySchema = {
    project_path: z.string().optional(),
    severity_min: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional(),
    force: z.boolean().optional(),
  };

  function mockScanTool() {
    return makeScanTool({
      name: 'drift_mock_scan',
      scan_type: 'sast',
      category: 'security',
      description: 'mock',
      inputSchema: tinySchema,
      invoke: async () => ({
        outcome: 'completed' as const,
        tools_run: [{ name: 'semgrep', status: 'ok' as const }],
        missing_tools: [],
        parser_inputs: [],
        report_paths: [],
      }),
    });
  }

  interface ScanPayload {
    status: string;
    warnings: string[];
    findings_count_by_severity: Record<string, number>;
    top_findings: unknown[];
  }

  async function scan(h: Harness): Promise<{ ok: true } & ScanPayload> {
    return okResult<ScanPayload>(
      await mockScanTool().handler({ project_path: h.project, force: true }, h.plugin),
    );
  }

  it('stays silent for a project in sync', async () => {
    const h = harness();
    await init(h);
    const r = await scan(h);
    expect(r.warnings.some((w) => w.includes('config drift'))).toBe(false);
  });

  it('stays silent for a project with no manifest', async () => {
    const h = harness();
    writeFileSync(join(h.project, '.semgrep.yml'), BASE_V1, 'utf8');
    shipNewerBaseYml(h);
    const r = await scan(h);
    expect(r.warnings.some((w) => w.includes('config drift'))).toBe(false);
  });

  it('stays silent when the user merely edited their own copy', async () => {
    const h = harness();
    await init(h);
    const mine = `${readFileSync(join(h.project, '.semgrep.yml'), 'utf8')}  - id: mine\n`;
    writeFileSync(join(h.project, '.semgrep.yml'), mine, 'utf8');
    const r = await scan(h);
    expect(r.warnings.some((w) => w.includes('config drift'))).toBe(false);
  });

  it('emits exactly one advisory line when we shipped a newer baseline', async () => {
    const h = harness();
    await init(h);
    shipNewerBaseYml(h);
    const r = await scan(h);
    const lines = r.warnings.filter((w) => w.includes('config drift'));
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain('.semgrep.yml');
    expect(lines[0]).toContain('init_project');
  });

  it('never turns the advisory into a finding, a failure, or a non-clean status', async () => {
    const h = harness();
    await init(h);
    shipNewerBaseYml(h);
    const r = await scan(h);
    expect(r.ok).toBe(true);
    expect(r.status).toBe('completed');
    expect(r.top_findings).toEqual([]);
    expect(Object.values(r.findings_count_by_severity).every((n) => n === 0)).toBe(true);
  });

  it('survives an unreadable manifest without failing the scan', async () => {
    const h = harness();
    mkdirSync(join(h.project, '.dev-guardian'), { recursive: true });
    writeFileSync(join(h.project, MANIFEST_RELATIVE_PATH), 'not json at all', 'utf8');
    const r = await scan(h);
    expect(r.ok).toBe(true);
    expect(r.status).toBe('completed');
  });

  it('goes quiet once a refresh has delivered the update', async () => {
    const h = harness();
    await init(h);
    shipNewerBaseYml(h);
    expect((await scan(h)).warnings.some((w) => w.includes('config drift'))).toBe(true);

    await init(h, { refresh: true, apply: true });
    expect((await scan(h)).warnings.some((w) => w.includes('config drift'))).toBe(false);
  });
});
