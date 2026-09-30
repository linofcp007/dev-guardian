/**
 * Every tool that writes into the scanned project, against a project whose
 * files are links out of it. The measured defect was the server's startup
 * `.gitignore` upkeep (`gitignoreGuard.ts`); the same `existsSync` +
 * `writeFileSync` shape sat in `observability_setup`, `init_project`'s config
 * install and refresh, and `mcp-config --write`. `existsSync` is false for a
 * dangling link and `writeFileSync` follows one, so each of them could be
 * made to create or rewrite a file anywhere the user can write.
 */
import { mkdirSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { CAN_SYMLINK, POSIX } from '../helpers/fsCapabilities.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { okResult } from '../helpers/toolResult.js';

vi.mock('../../src/runners/shellRunner.js', () => ({ runShellScript: vi.fn() }));
vi.mock('../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));
vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual = await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>('../../src/tools/scanHelpers.js');
  return { ...actual, scannerAvailable: vi.fn() };
});

import type { PluginContext } from '../../src/context.js';
import { MANIFEST_RELATIVE_PATH } from '../../src/configdrift/manifest.js';
import { hashConfigText } from '../../src/configdrift/hash.js';
import { setupHost } from '../../src/hostsetup/setup.js';
import { runProcess } from '../../src/runners/processRunner.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';

afterAll(cleanupTempDirs);

beforeAll(async () => {
  await import('../../src/tools/initProject.js');
  await import('../../src/tools/observabilitySetup.js');
  await import('../../src/tools/precommitInstall.js');
});

beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});

const DIR_LINK = POSIX ? 'dir' : 'junction';

function getTool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

const BASE_V1 = 'rules:\n  - id: a\n    pattern: f($X)\n';
const BASE_V2 = 'rules:\n  - id: a\n    pattern: f(...)\n';

function plugin(): { ctx: PluginContext; configsDir: string } {
  const scriptsDir = join(makeTempDir('pwh-plugin-'), 'scripts');
  const configsDir = join(scriptsDir, '..', 'configs');
  mkdirSync(scriptsDir, { recursive: true });
  for (const d of ['gitleaks', 'renovate', 'semgrep', 'pre-commit']) mkdirSync(join(configsDir, d), { recursive: true });
  writeFileSync(join(configsDir, 'gitleaks', 'gitleaks.toml'), '[[rules]]\nid = "x"\n', 'utf8');
  writeFileSync(join(configsDir, 'renovate', 'renovate.json'), '{}\n', 'utf8');
  writeFileSync(join(configsDir, 'semgrep', 'base.yml'), BASE_V1, 'utf8');
  writeFileSync(join(configsDir, 'pre-commit', 'pre-commit-config.yaml'), 'repos: []\n', 'utf8');
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    ctx: {
      storage: new Storage(db),
      shell: null,
      scriptsDir,
      progressNotifier: { send: () => {} },
    },
    configsDir,
  };
}

interface ObsPayload {
  files_written: string[];
  files_skipped: Array<{ target: string; reason_skipped: string }>;
  files_failed: Array<{ target: string; error: string }>;
}

describe('observability_setup — hostile project', () => {
  it.skipIf(!CAN_SYMLINK)('never writes through a src/ directory that links out of the project', async () => {
    const project = makeTempDir('pwh-obs-');
    const outside = makeTempDir('pwh-outside-');
    writeFileSync(join(project, 'package.json'), '{"name":"x"}', 'utf8');
    symlinkSync(outside, join(project, 'src'), DIR_LINK);

    const r = okResult<ObsPayload>(
      await getTool('observability_setup').handler({ project_path: project, apply: true }, plugin().ctx),
    );

    expect(readdirSync(outside)).toEqual([]);
    expect(r.files_written).toEqual([]);
    expect(r.files_failed.map((f) => f.target).sort()).toEqual(['src/logger.ts', 'src/metrics.ts']);
  });

  it.skipIf(!CAN_SYMLINK)('never creates the target of a dangling link at a proposed path', async () => {
    const project = makeTempDir('pwh-obs-');
    const outside = makeTempDir('pwh-outside-');
    writeFileSync(join(project, 'package.json'), '{"name":"x"}', 'utf8');
    mkdirSync(join(project, 'src'));
    symlinkSync(join(outside, 'planted.ts'), join(project, 'src', 'logger.ts'), 'file');

    const r = okResult<ObsPayload>(
      await getTool('observability_setup').handler({ project_path: project, apply: true }, plugin().ctx),
    );

    expect(existsSync(join(outside, 'planted.ts'))).toBe(false);
    expect(r.files_written).toEqual(['src/metrics.ts']);
    expect(r.files_skipped.concat(r.files_failed as never[]).map((f) => f.target)).toContain('src/logger.ts');
  });
});

interface InitPayload {
  files_written: Array<{ target: string }>;
  files_skipped: Array<{ target: string; reason_skipped: string }>;
  files_failed: Array<{ target: string; error: string }>;
  refresh?: { plan: Array<{ target: string; action: string; reason: string }> };
}

describe('init_project — hostile project', () => {
  it.skipIf(!CAN_SYMLINK)('never creates the target of a dangling config link', async () => {
    const project = makeTempDir('pwh-init-');
    const outside = makeTempDir('pwh-outside-');
    symlinkSync(join(outside, 'planted.toml'), join(project, '.gitleaks.toml'), 'file');
    const { ctx } = plugin();

    const r = okResult<InitPayload>(
      await getTool('init_project').handler({ project_path: project, profile: 'minimal' }, ctx),
    );

    expect(existsSync(join(outside, 'planted.toml'))).toBe(false);
    expect(r.files_written.map((f) => f.target)).toEqual(['renovate.json']);
  });

  it.skipIf(!CAN_SYMLINK)('never writes its manifest through a .dev-guardian directory that links out', async () => {
    const project = makeTempDir('pwh-init-');
    const outside = makeTempDir('pwh-outside-');
    symlinkSync(outside, join(project, '.dev-guardian'), DIR_LINK);
    const { ctx } = plugin();

    await getTool('init_project').handler({ project_path: project, profile: 'minimal' }, ctx);

    expect(readdirSync(outside)).toEqual([]);
  });

  it.skipIf(!CAN_SYMLINK)('refresh never updates in place through a link to a file outside the project', async () => {
    const project = makeTempDir('pwh-init-');
    const outside = makeTempDir('pwh-outside-');
    const { ctx, configsDir } = plugin();
    // An "untouched since install" .semgrep.yml — except that it is a link,
    // and the manifest (the project's own file) says it is ours.
    const victim = join(outside, 'victim.yml');
    writeFileSync(victim, BASE_V1, 'utf8');
    symlinkSync(victim, join(project, '.semgrep.yml'), 'file');
    const h = hashConfigText(BASE_V1);
    mkdirSync(join(project, '.dev-guardian'));
    writeFileSync(
      join(project, MANIFEST_RELATIVE_PATH),
      JSON.stringify({
        schema_version: 1,
        entries: [
          {
            target: '.semgrep.yml',
            source: 'semgrep/base.yml',
            plugin_version: '0.0.1',
            source_sha256: h,
            target_sha256: h,
            recorded_at: '2026-01-01T00:00:00.000Z',
            provenance: 'copied',
          },
        ],
      }),
      'utf8',
    );
    writeFileSync(join(configsDir, 'semgrep', 'base.yml'), BASE_V2, 'utf8');

    const r = okResult<InitPayload>(
      await getTool('init_project').handler(
        { project_path: project, profile: 'standard', refresh: true, apply: true },
        ctx,
      ),
    );

    expect(readFileSync(victim, 'utf8')).toBe(BASE_V1);
    const item = r.refresh?.plan.find((p) => p.target === '.semgrep.yml');
    expect(item?.action).toBe('refused');
    expect(readdirSync(outside)).toEqual(['victim.yml']);
  });
});

describe('precommit_install — hostile project', () => {
  it.skipIf(!CAN_SYMLINK)('refuses a .git/hooks directory that links out of the project, before pre-commit runs', async () => {
    const project = makeTempDir('pwh-pc-');
    const outside = makeTempDir('pwh-outside-');
    writeFileSync(join(project, '.pre-commit-config.yaml'), 'repos: []\n', 'utf8');
    mkdirSync(join(project, '.git'));
    symlinkSync(outside, join(project, '.git', 'hooks'), DIR_LINK);
    vi.mocked(scannerAvailable).mockResolvedValue('pre-commit');

    const r = await getTool('precommit_install').handler({ project_path: project }, plugin().ctx);

    expect(r.ok).toBe(false);
    expect(vi.mocked(runProcess)).not.toHaveBeenCalled();
  });

  it.skipIf(!CAN_SYMLINK)('refuses a hook file that is a link, before pre-commit runs', async () => {
    const project = makeTempDir('pwh-pc-');
    const outside = makeTempDir('pwh-outside-');
    writeFileSync(join(project, '.pre-commit-config.yaml'), 'repos: []\n', 'utf8');
    mkdirSync(join(project, '.git', 'hooks'), { recursive: true });
    symlinkSync(join(outside, 'bashrc'), join(project, '.git', 'hooks', 'pre-push'), 'file');
    vi.mocked(scannerAvailable).mockResolvedValue('pre-commit');

    const r = await getTool('precommit_install').handler({ project_path: project }, plugin().ctx);

    expect(r.ok).toBe(false);
    expect(vi.mocked(runProcess)).not.toHaveBeenCalled();
  });

  it.skipIf(!CAN_SYMLINK)('refuses a .pre-commit-config.yaml that is a link out of the project', async () => {
    const project = makeTempDir('pwh-pc-');
    const outside = makeTempDir('pwh-outside-');
    writeFileSync(join(outside, 'cfg.yaml'), 'repos: []\n', 'utf8');
    symlinkSync(join(outside, 'cfg.yaml'), join(project, '.pre-commit-config.yaml'), 'file');
    mkdirSync(join(project, '.git'));
    vi.mocked(scannerAvailable).mockResolvedValue('pre-commit');

    const r = await getTool('precommit_install').handler({ project_path: project }, plugin().ctx);

    expect(r.ok).toBe(false);
    expect(vi.mocked(runProcess)).not.toHaveBeenCalled();
  });
});

describe('mcp-config --write (setupHost) — hostile project', () => {
  function hostRules(): string {
    const dir = makeTempDir('pwh-hostrules-');
    writeFileSync(join(dir, 'AGENTS.md'), '# codex', 'utf8');
    writeFileSync(join(dir, 'cursor.mdc'), '---\nfor: cursor\n---\nbody', 'utf8');
    return dir;
  }

  function run(project: string, host: 'codex' | 'cursor') {
    return setupHost({
      hosts: [host],
      projectPath: project,
      hostsDir: hostRules(),
      serverJsPath: '/plugins/dev-guardian/mcp/dist/server.js',
      cliPath: '/plugins/dev-guardian/cli/dev-guardian.mjs',
      env: { os: 'linux', home: '/home/me', projectPath: project },
      scope: 'project',
      registerMcp: true,
      installRules: true,
      apply: true,
      force: false,
    });
  }

  it.skipIf(!CAN_SYMLINK)('never creates the target of a dangling AGENTS.md link', () => {
    const project = makeTempDir('pwh-host-');
    const outside = makeTempDir('pwh-outside-');
    symlinkSync(join(outside, 'planted.md'), join(project, 'AGENTS.md'), 'file');

    const [r] = run(project, 'codex');

    expect(existsSync(join(outside, 'planted.md'))).toBe(false);
    expect(r?.status).toBe('failed');
  });

  it.skipIf(!CAN_SYMLINK)('never writes a project-scope MCP config through a .codex directory that links out', () => {
    const project = makeTempDir('pwh-host-');
    const outside = makeTempDir('pwh-outside-');
    symlinkSync(outside, join(project, '.codex'), DIR_LINK);

    const [r] = run(project, 'codex');

    expect(readdirSync(outside)).toEqual([]);
    expect(r?.mcp.status).toBe('failed');
  });

  it.skipIf(!CAN_SYMLINK)('never writes the Cursor rules file through a .cursor directory that links out', () => {
    const project = makeTempDir('pwh-host-');
    const outside = makeTempDir('pwh-outside-');
    symlinkSync(outside, join(project, '.cursor'), DIR_LINK);

    const [r] = run(project, 'cursor');

    expect(readdirSync(outside)).toEqual([]);
    expect(r?.status).toBe('failed');
    expect(r?.mcp.status).toBe('failed');
  });
});
