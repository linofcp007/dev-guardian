/**
 * `scan_containers` (task 15, brief item 3): the image scan only ran
 * `--scanners vuln` (secret scanning explicitly off), and nothing checked
 * hadolint or compose files even though `/guardian-docker` promised both.
 *
 *   - image scan now asks Trivy for vuln, secret AND misconfig — trivyParser
 *     already handles all three JSON shapes (Vulnerabilities/Secrets/
 *     Misconfigurations), so this is purely the CLI flag.
 *   - hadolint lints a Dockerfile when it is installed (a named gap, never
 *     silence, when it is not).
 *   - a compose file (docker-compose.yml / compose.yml / docker-compose.yaml)
 *     is checked for privileged/host-network/docker.sock/`:latest` — see
 *     runners/composeChecks.ts for the checks themselves (unit-tested there;
 *     this file only proves scan_containers actually calls it).
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));
vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual = await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>(
    '../../src/tools/scanHelpers.js',
  );
  return { ...actual, scannerAvailable: vi.fn() };
});

import { runProcess } from '../../src/runners/processRunner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import type { PluginContext } from '../../src/context.js';
import { TOOLS } from '../../src/tools/index.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

// The file's first test pays for loading the tool's module graph: 1.5-1.7 s
// ordinarily, 10.0 s — past the 10 s default — with the CPU at 100% (other
// suites running; review 3.0, R7). Scanners are mocked here: nothing can hang.
vi.setConfig({ testTimeout: 30_000 });
beforeAll(async () => {
  await import('../../src/tools/scanContainers.js');
});

function tool() {
  const t = TOOLS.find((x) => x.name === 'scan_containers');
  if (!t) throw new Error('scan_containers not registered');
  return t;
}

function plugin(projectPath: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' },
    scriptsDir: projectPath,
    progressNotifier: { send: () => {} },
  };
}

const ok = { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };

beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});

type Result = Record<string, unknown> & { ok: boolean };

describe('scan_containers: trivy image scanners', () => {
  it('asks trivy for vuln, secret AND misconfig — not vuln alone', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/trivy');
    vi.mocked(runProcess).mockResolvedValue(ok);
    const project = makeTempDir('containers-');
    const r = (await tool().handler({ project_path: project, image: 'alpine:3.20' }, plugin(project))) as Result;
    expect(r.ok).toBe(true);
    const call = vi.mocked(runProcess).mock.calls.find((c) => c[0].args?.[0] === 'image');
    const scannersIdx = call?.[0].args?.indexOf('--scanners') ?? -1;
    expect(scannersIdx).toBeGreaterThanOrEqual(0);
    expect(call?.[0].args?.[scannersIdx + 1]).toBe('vuln,secret,misconfig');
  });

  // Follow-up X5: the image reference is recorded on the run, so a later
  // comparison can tell image A's findings from image B's (runCompare.ts).
  it('records which image it scanned on the trivy-image run, ok or failed, and stores it', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/trivy');
    for (const [result, status] of [
      [ok, 'ok'],
      [{ ...ok, outcome: 'failed' as const, exitCode: 1 }, 'failed'],
    ] as const) {
      vi.mocked(runProcess).mockResolvedValue(result);
      const project = makeTempDir('containers-');
      const ctx = plugin(project);
      const r = (await tool().handler({ project_path: project, image: 'ghcr.io/org/app:1.2.3' }, ctx)) as Result & {
        scan_id: string;
        tools_run: { name: string; status: string; target?: string; reason?: string }[];
      };
      const run = r.tools_run.find((t) => t.name === 'trivy-image');
      expect(run).toMatchObject({ status, target: 'ghcr.io/org/app:1.2.3' });
      expect(run?.reason).toMatch(/ghcr\.io\/org\/app:1\.2\.3/);
      const stored = ctx.storage.scans.getById(r.scan_id)?.tools_run.find((t) => t.name === 'trivy-image');
      expect(stored?.target).toBe('ghcr.io/org/app:1.2.3');
    }
  });
});

describe('scan_containers: hadolint', () => {
  it('lints the Dockerfile when hadolint is installed, and its findings count', async () => {
    vi.mocked(scannerAvailable).mockImplementation(async (name) =>
      name === 'trivy' || name === 'hadolint' ? `/fake/bin/${name}` : null,
    );
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      if (opts.command === 'hadolint') {
        return {
          outcome: 'completed',
          exitCode: 1,
          stdout: JSON.stringify([
            { file: 'Dockerfile', line: 3, column: 1, level: 'warning', code: 'DL3006', message: 'Always tag the version of an image explicitly' },
          ]),
          stderr: '',
          truncated: false,
        };
      }
      return ok;
    });
    const project = makeTempDir('containers-');
    writeFileSync(join(project, 'Dockerfile'), 'FROM alpine\nRUN echo hi\n', 'utf8');

    const r = (await tool().handler({ project_path: project }, plugin(project))) as Result & {
      tools_run: { name: string; status: string }[];
      findings_count_by_severity: Record<string, number>;
    };
    expect(r.ok).toBe(true);
    expect(r.tools_run.find((t) => t.name === 'hadolint')?.status).toBe('ok');
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBeGreaterThan(0);
  });

  /**
   * Round 4, item 3: hadolint reads `.hadolint.yaml` from its working
   * directory (`ignored:` rules, `trustedRegistries`, severity overrides), and
   * it ran in the project. It runs in the report directory now; the
   * project's own root config is passed with `--config`, and named.
   */
  it("runs outside the project; the project's .hadolint.yaml is passed explicitly and named", async () => {
    vi.mocked(scannerAvailable).mockImplementation(async (name) => (name === 'hadolint' ? '/fake/bin/hadolint' : null));
    vi.mocked(runProcess).mockImplementation(async () => ({ ...ok, stdout: '[]' }));
    const bare = makeTempDir('containers-');
    writeFileSync(join(bare, 'Dockerfile'), 'FROM alpine\n', 'utf8');
    const plain = (await tool().handler({ project_path: bare }, plugin(bare))) as Result & {
      tools_run: { name: string; honoured_config?: string[] }[];
    };
    const first = vi.mocked(runProcess).mock.calls.find((c) => c[0].command === 'hadolint')?.[0];
    expect(first?.cwd).not.toBe(bare);
    expect(first?.args).not.toContain('--config');
    expect(plain.tools_run.find((t) => t.name === 'hadolint')?.honoured_config).toBeUndefined();

    vi.mocked(runProcess).mockClear();
    const own = makeTempDir('containers-');
    writeFileSync(join(own, 'Dockerfile'), 'FROM alpine\n', 'utf8');
    writeFileSync(join(own, '.hadolint.yaml'), 'ignored:\n  - DL3006\n', 'utf8');
    const r = (await tool().handler({ project_path: own }, plugin(own))) as Result & {
      tools_run: { name: string; status: string; reason?: string; honoured_config?: string[] }[];
    };
    const call = vi.mocked(runProcess).mock.calls.find((c) => c[0].command === 'hadolint')?.[0];
    expect(call?.cwd).not.toBe(own);
    expect(call?.args).toEqual(expect.arrayContaining(['--config', join(own, '.hadolint.yaml')]));
    const hadolint = r.tools_run.find((t) => t.name === 'hadolint');
    expect(hadolint?.status).toBe('ok');
    expect(hadolint?.honoured_config).toEqual(['.hadolint.yaml']);
    expect(hadolint?.reason).toMatch(/honoured the project's \.hadolint\.yaml/);
  });

  it('is a named gap (skipped, missing_tools) when hadolint is not installed', async () => {
    vi.mocked(scannerAvailable).mockImplementation(async (name) => (name === 'trivy' ? '/fake/bin/trivy' : null));
    vi.mocked(runProcess).mockResolvedValue(ok);
    const project = makeTempDir('containers-');
    writeFileSync(join(project, 'Dockerfile'), 'FROM alpine\n', 'utf8');

    const r = (await tool().handler({ project_path: project }, plugin(project))) as Result & {
      tools_run: { name: string; status: string; reason?: string }[];
      missing_tools: string[];
    };
    expect(r.ok).toBe(true);
    expect(r.tools_run.find((t) => t.name === 'hadolint')).toMatchObject({
      status: 'skipped',
      reason: 'not_installed',
    });
    expect(r.missing_tools).toContain('hadolint');
  });

  it('never runs hadolint when there is no Dockerfile to lint', async () => {
    vi.mocked(scannerAvailable).mockImplementation(async (name) => (name === 'trivy' ? '/fake/bin/trivy' : '/fake/bin/hadolint'));
    vi.mocked(runProcess).mockResolvedValue(ok);
    const project = makeTempDir('containers-');
    const r = (await tool().handler({ project_path: project, image: 'alpine:3.20' }, plugin(project))) as Result & {
      tools_run: { name: string }[];
    };
    expect(r.ok).toBe(true);
    expect(r.tools_run.some((t) => t.name === 'hadolint')).toBe(false);
    expect(vi.mocked(runProcess).mock.calls.some((c) => c[0].command === 'hadolint')).toBe(false);
  });
});

describe('scan_containers: compose files', () => {
  it('checks docker-compose.yml and reports a privileged-service finding', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue(null); // trivy absent — irrelevant to this check
    vi.mocked(runProcess).mockResolvedValue(ok);
    const project = makeTempDir('containers-');
    writeFileSync(
      join(project, 'docker-compose.yml'),
      'services:\n  app:\n    image: myapp:latest\n    privileged: true\n',
      'utf8',
    );

    const r = (await tool().handler({ project_path: project }, plugin(project))) as Result & {
      tools_run: { name: string; status: string }[];
      findings_count_by_severity: Record<string, number>;
    };
    expect(r.ok).toBe(true);
    expect(r.tools_run.find((t) => t.name === 'docker-compose')?.status).toBe('ok');
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    // privileged + :latest tag == at least 2 findings from this one file.
    expect(total).toBeGreaterThanOrEqual(2);
  });

  it('also checks compose.yml (the newer canonical name)', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue(null);
    vi.mocked(runProcess).mockResolvedValue(ok);
    const project = makeTempDir('containers-');
    writeFileSync(join(project, 'compose.yml'), 'services:\n  app:\n    network_mode: host\n', 'utf8');

    const r = (await tool().handler({ project_path: project }, plugin(project))) as Result & {
      findings_count_by_severity: Record<string, number>;
    };
    expect(r.ok).toBe(true);
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBeGreaterThan(0);
  });

  it('does nothing extra when no compose file exists', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/trivy');
    vi.mocked(runProcess).mockResolvedValue(ok);
    const project = makeTempDir('containers-');
    const r = (await tool().handler({ project_path: project, image: 'alpine:3.20' }, plugin(project))) as Result & {
      tools_run: { name: string }[];
    };
    expect(r.ok).toBe(true);
    expect(r.tools_run.some((t) => t.name === 'docker-compose')).toBe(false);
  });

  it('mounting docker.sock in compose is scanned even when nothing else is (no Dockerfile, no image, trivy absent)', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue(null);
    vi.mocked(runProcess).mockResolvedValue(ok);
    const project = makeTempDir('containers-');
    mkdirSync(project, { recursive: true });
    writeFileSync(
      join(project, 'docker-compose.yaml'),
      'services:\n  app:\n    image: myapp:1.0\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n',
      'utf8',
    );

    const r = (await tool().handler({ project_path: project }, plugin(project))) as Result & {
      findings_count_by_severity: Record<string, number>;
    };
    expect(r.ok).toBe(true);
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBeGreaterThan(0);
  });
});
