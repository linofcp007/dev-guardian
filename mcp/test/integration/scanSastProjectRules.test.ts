/**
 * What `scan_sast` actually asks Semgrep to run.
 *
 * ---- The defect these tests exist for --------------------------------
 *
 * `init_project` writes 13 security rules into a project as `.semgrep.yml`,
 * and `scan_sast` ran `--config=auto` — which does not load it. Measured
 * against semgrep 1.164.0 on a project containing `<?php echo $_GET['name'];`
 * and a copy of `configs/semgrep/base.yml`:
 *
 *   --config=<that file>  → 1 finding (wp-unescaped-output), scanned 2
 *   --config=auto         → 0 findings,                      scanned 2
 *
 * So the rule pack this plugin ships had no consumer at all. The
 * `wp-unescaped-output` rule fixed in b51a2dc was dead twice over, for
 * independent reasons, and the second reason only surfaced because someone
 * went looking for who read the file.
 *
 * These are argv-level tests against a mocked runner; the end-to-end proof
 * with the real binary is `test/e2e/projectRulesFixture.test.ts`.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { okResult } from '../helpers/toolResult.js';

vi.mock('../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));
vi.mock('../../src/runners/shellRunner.js', () => ({ runShellScript: vi.fn() }));
vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual =
    await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>(
      '../../src/tools/scanHelpers.js',
    );
  return { ...actual, scannerAvailable: vi.fn() };
});

import type { PluginContext } from '../../src/context.js';
import { runProcess } from '../../src/runners/processRunner.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';

afterAll(cleanupTempDirs);

beforeAll(async () => {
  await import('../../src/tools/scanSast.js');
});

const RULES =
  'rules:\n  - id: x\n    pattern: foo(...)\n    message: m\n    languages: [python]\n    severity: WARNING\n';

function getTool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

function makePlugin(projectPath: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' },
    scriptsDir: projectPath,
    progressNotifier: { send: () => {} },
  };
}

/** Captured argv of the last `runProcess` call, per command. */
const captured: Array<{ command: string; args: string[] }> = [];

function mockSemgrepOnPath(exitCode = 0): void {
  vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
    name === 'semgrep' ? '/fake/bin/semgrep' : null,
  );
  vi.mocked(runProcess).mockImplementation(async (opts) => {
    captured.push({ command: opts.command, args: [...(opts.args ?? [])] });
    const out = opts.args?.find((_a, i) => opts.args?.[i - 1] === '--output');
    if (out) {
      writeFileSync(
        out,
        JSON.stringify({ results: [], errors: [], paths: { scanned: ['a.py'] } }),
        'utf8',
      );
    }
    return { outcome: 'completed' as const, exitCode, stdout: '', stderr: '', truncated: false };
  });
}

function semgrepArgs(): string[] {
  const call = captured.find((c) => c.command === 'semgrep');
  if (call === undefined) throw new Error('semgrep was never invoked');
  return call.args;
}

interface SastPayload {
  tools_run: Array<{ name: string; status: string; reason?: string }>;
  missing_tools: string[];
  status: string;
}

async function runSast(
  project: string,
  plugin: PluginContext,
  extra: Record<string, unknown> = {},
): Promise<{ ok: true } & SastPayload> {
  return okResult<SastPayload>(
    await getTool('scan_sast').handler({ project_path: project, force: true, ...extra }, plugin),
  );
}

beforeEach(() => {
  captured.length = 0;
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});
afterEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});

describe('scan_sast loads the project’s own Semgrep rules', () => {
  it('passes .semgrep.yml to Semgrep alongside --config=auto', async () => {
    const project = makeTempDir('sast-rules-');
    writeFileSync(join(project, '.semgrep.yml'), RULES, 'utf8');
    mockSemgrepOnPath();

    await runSast(project, makePlugin(project));

    const args = semgrepArgs();
    expect(args).toContain('--config=auto');
    expect(args).toContain(`--config=${join(project, '.semgrep.yml')}`);
  });

  it('follows the manifest to a config that is not called .semgrep.yml', async () => {
    const project = makeTempDir('sast-rules-');
    mkdirSync(join(project, 'ci'), { recursive: true });
    writeFileSync(join(project, 'ci', 'rules.yml'), RULES, 'utf8');
    mkdirSync(join(project, '.dev-guardian'), { recursive: true });
    writeFileSync(
      join(project, '.dev-guardian', 'configs.json'),
      JSON.stringify({
        schema_version: 1,
        entries: [
          {
            target: 'ci/rules.yml',
            source: 'semgrep/base.yml',
            plugin_version: '1.8.0',
            source_sha256: 'a'.repeat(64),
            target_sha256: 'a'.repeat(64),
            recorded_at: '2026-01-01T00:00:00.000Z',
            provenance: 'copied',
          },
        ],
      }),
      'utf8',
    );
    mockSemgrepOnPath();

    await runSast(project, makePlugin(project));
    expect(semgrepArgs()).toContain(`--config=${join(project, 'ci', 'rules.yml')}`);
  });

  it('refuses to pass a config that would abort the whole scan', async () => {
    // Measured: a malformed --config gives `paths.scanned: []` and exit 7, so
    // one stray character in a file the user owns would turn every SAST scan
    // into a silent "0 findings".
    const project = makeTempDir('sast-rules-');
    writeFileSync(join(project, '.semgrep.yml'), 'rules: [ broken', 'utf8');
    mockSemgrepOnPath();

    await runSast(project, makePlugin(project));
    const args = semgrepArgs();
    expect(args).toContain('--config=auto');
    expect(args.some((a) => a.includes('.semgrep.yml'))).toBe(false);
  });

  it('says so, rather than silently dropping it', async () => {
    const project = makeTempDir('sast-rules-');
    writeFileSync(join(project, '.semgrep.yml'), 'rules: [ broken', 'utf8');
    mockSemgrepOnPath();

    const r = await runSast(project, makePlugin(project));
    const run = r.tools_run.find((t) => t.name === 'semgrep');
    expect(run?.reason ?? '').toContain('.semgrep.yml');
  });

  it('reaches the Docker fallback too, expressed inside the mount', async () => {
    const project = makeTempDir('sast-rules-');
    writeFileSync(join(project, '.semgrep.yml'), RULES, 'utf8');
    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'docker' ? '/usr/bin/docker' : null,
    );
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      captured.push({ command: opts.command, args: [...(opts.args ?? [])] });
      const i = opts.args?.findIndex((a) => a === '--output') ?? -1;
      const containerOut = i >= 0 ? opts.args?.[i + 1] : undefined;
      if (containerOut !== undefined) {
        // Container path back to a host path, without assuming a separator.
        const host = join(project, ...containerOut.replace('/src/', '').split('/'));
        writeFileSync(host, JSON.stringify({ results: [], errors: [] }), 'utf8');
      }
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    await runSast(project, makePlugin(project));
    const call = captured.find((c) => c.command === 'docker');
    if (call === undefined) throw new Error('docker was never invoked');
    // The container cannot see host paths — it must be the /src form.
    expect(call.args).toContain('--config=/src/.semgrep.yml');
    expect(call.args.some((a) => a.startsWith(`--config=${project}`))).toBe(false);
  });
});

describe('scan_sast exit-code tolerance for a rule that cannot compile', () => {
  it('still counts as a real scan when Semgrep exits 2 but scanned files', async () => {
    // Loading the user's own config makes this reachable: one bad rule in a
    // file they own must not flip the whole scan to `failed` and drag coverage
    // down with it. Measured: exit 2 with `paths.scanned` non-empty.
    const project = makeTempDir('sast-rules-');
    writeFileSync(join(project, '.semgrep.yml'), RULES, 'utf8');
    mockSemgrepOnPath(2);

    const r = await runSast(project, makePlugin(project));
    const run = r.tools_run.find((t) => t.name === 'semgrep');
    expect(run?.status).toBe('ok');
    expect(r.status).toBe('completed');
  });
});

describe('scan_sast local_only mode', () => {
  it('drops --config=auto and turns Semgrep telemetry off', async () => {
    // `--config=auto` REFUSES to run with metrics off ("Cannot create auto
    // config when metrics are off"), which is why every scan today sends
    // telemetry. With the project's own rules actually loaded there is finally
    // a coherent local-only alternative.
    const project = makeTempDir('sast-rules-');
    writeFileSync(join(project, '.semgrep.yml'), RULES, 'utf8');
    mockSemgrepOnPath();

    await runSast(project, makePlugin(project), { local_only: true });
    const args = semgrepArgs();
    expect(args).toContain('--metrics=off');
    expect(args).not.toContain('--config=auto');
    expect(args).toContain(`--config=${join(project, '.semgrep.yml')}`);
  });

  it('never pairs --metrics=off with --config=auto, in either mode', async () => {
    // Semgrep refuses the combination outright, so this is not style — getting
    // it wrong makes the scan exit 7 and report nothing.
    const project = makeTempDir('sast-rules-');
    writeFileSync(join(project, '.semgrep.yml'), RULES, 'utf8');
    for (const local_only of [false, true]) {
      captured.length = 0;
      mockSemgrepOnPath();
      await runSast(project, makePlugin(project), { local_only });
      const args = semgrepArgs();
      expect(args.includes('--metrics=off')).toBe(!args.includes('--config=auto'));
    }
  });

  it('still scans a project that has no rules of its own', async () => {
    // The mirror image of the change: making the project's config load must
    // not make its absence fatal. Asserted here rather than in the e2e file
    // because it needs no real binary — and a second registry-backed pass in
    // the e2e was measured breaking createFixPr.test.ts under suite load.
    const project = makeTempDir('sast-rules-bare-');
    mockSemgrepOnPath();

    const r = await runSast(project, makePlugin(project));
    const args = semgrepArgs();
    expect(args).toContain('--config=auto');
    expect(args.some((a) => a.startsWith('--config=') && a.includes('semgrep.y'))).toBe(false);
    expect(r.tools_run.find((t) => t.name === 'semgrep')?.status).toBe('ok');
    expect(r.status).toBe('completed');
  });

  it('refuses to pretend it scanned when there are no local rules at all', async () => {
    const project = makeTempDir('sast-rules-');
    mockSemgrepOnPath();

    const r = await runSast(project, makePlugin(project), { local_only: true });
    expect(captured.some((c) => c.command === 'semgrep')).toBe(false);
    const run = r.tools_run.find((t) => t.name === 'semgrep');
    expect(run?.status).toBe('skipped');
    expect(run?.reason ?? '').toContain('local_only');
    expect(r.missing_tools).toContain('semgrep');
  });
});
