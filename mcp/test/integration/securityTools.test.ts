/**
 * Integration tests for the 6 security tools.
 *
 * Strategy:
 *   - mock `runProcess` and `runShellScript` to drop canned scanner reports
 *     into the expected output paths and return `outcome=completed`;
 *   - mock `scannerAvailable` so it answers "yes" for every probed scanner;
 *   - import each tool module, invoke its handler through the registry, and
 *     assert the ScanResult shape, finding counts, and missing_tools logic.
 *
 * The factory's edge-case behaviour (cache, cancel, error finalisation) is
 * covered in `test/unit/tools/scanToolFactory.test.ts`. These tests focus
 * on wiring: does the tool call the right command, route reports to the
 * right parser, and surface tools_run / missing_tools correctly?
 */

import { execa } from 'execa';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/runners/processRunner.js', () => ({
  runProcess: vi.fn(),
}));
vi.mock('../../src/runners/shellRunner.js', () => ({
  runShellScript: vi.fn(),
}));
vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual =
    await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>(
      '../../src/tools/scanHelpers.js',
    );
  return {
    ...actual,
    scannerAvailable: vi.fn(),
  };
});

// Re-import the mocked symbols + the source-of-truth `scanHelpers` so we can
// drive the mocks from each test.
import { runProcess } from '../../src/runners/processRunner.js';
import { runShellScript } from '../../src/runners/shellRunner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';

import type { PluginContext } from '../../src/context.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { makeTempDir, cleanupTempDirs } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

// Side-effect imports populate the TOOLS registry — once per file.
beforeAll(async () => {
  await import('../../src/tools/securityScanFull.js');
  await import('../../src/tools/scanSast.js');
  await import('../../src/tools/scanSecrets.js');
  await import('../../src/tools/scanDeps.js');
  await import('../../src/tools/scanContainers.js');
  await import('../../src/tools/scanIac.js');
});

const here = dirname(fileURLToPath(import.meta.url));
const FIX = resolve(here, '..', 'fixtures', 'scanners');

function getTool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

function makePlugin(projectPath: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  const storage = new Storage(db);
  return {
    storage,
    shell: {
      command: 'bash',
      args_prefix: [],
      needs_wsl_path_translate: false,
      label: 'fake',
    },
    scriptsDir: projectPath,
    progressNotifier: { send: () => {} },
  };
}

function tempProject(): string {
  return makeTempDir('sec-tools-');
}

const semgrepFixture = () => readFileSync(join(FIX, 'semgrep.json'), 'utf8');
const trivyFsFixture = () => readFileSync(join(FIX, 'trivy-fs.json'), 'utf8');
const trivyDockerFixture = () =>
  readFileSync(join(FIX, 'trivy-dockerfile.json'), 'utf8');
const gitleaksFixture = () => readFileSync(join(FIX, 'gitleaks.json'), 'utf8');

beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(runShellScript).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});

afterEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(runShellScript).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});

interface SuccessOpts {
  ok?: boolean;
  exitCode?: number;
}

function fakeRunSuccess(opts: SuccessOpts = {}) {
  return {
    outcome: 'completed' as const,
    exitCode: opts.exitCode ?? 0,
    stdout: '',
    stderr: '',
    truncated: false,
  };
}

describe('scan_sast (Semgrep)', () => {
  it('drops semgrep.json into the report dir and persists findings', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const out = opts.args?.find((_a, i) => opts.args?.[i - 1] === '--output');
      if (out) writeFileSync(out, semgrepFixture(), 'utf8');
      return fakeRunSuccess();
    });

    const tool = getTool('scan_sast');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      findings_count_by_severity: Record<string, number>;
      tools_run: { name: string; status: string }[];
    };

    expect(r.ok).toBe(true);
    // Semgrep fixture has 3 results → 3 findings.
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBe(3);
    expect(r.tools_run.some((t) => t.name === 'semgrep' && t.status === 'ok')).toBe(true);
  });

  it('marks semgrep as missing when scannerAvailable returns null', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue(null);

    const tool = getTool('scan_sast');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      tools_run: { name: string; status: string }[];
      missing_tools: string[];
    };

    expect(r.ok).toBe(true);
    expect(r.missing_tools).toContain('semgrep');
    expect(r.tools_run.find((t) => t.name === 'semgrep')?.status).toBe('skipped');
  });

  it('falls back to Docker when semgrep is absent but a daemon is available', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    // semgrep not on PATH, docker is.
    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'docker' ? '/usr/bin/docker' : null,
    );
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      expect(opts.command).toBe('docker');
      expect(opts.args).toContain('--mount');
      expect(opts.args).toContain('semgrep/semgrep');
      // Simulate the bind mount: the container writes /src/... which lands on
      // the host project. Reconstruct the host path from the container path.
      const outIdx = opts.args?.findIndex((a) => a === '--output') ?? -1;
      const containerOut = outIdx >= 0 ? opts.args?.[outIdx + 1] : undefined;
      if (containerOut?.startsWith('/src/')) {
        const hostOut = join(project, containerOut.slice('/src/'.length));
        mkdirSync(dirname(hostOut), { recursive: true });
        writeFileSync(hostOut, semgrepFixture(), 'utf8');
      }
      return fakeRunSuccess({ exitCode: 1 }); // semgrep exits 1 when it finds issues
    });

    const tool = getTool('scan_sast');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      coverage: string;
      findings_count_by_severity: Record<string, number>;
      tools_run: { name: string; status: string; reason?: string }[];
      missing_tools: string[];
    };

    expect(r.ok).toBe(true);
    const semgrep = r.tools_run.find((t) => t.name === 'semgrep');
    expect(semgrep?.status).toBe('ok');
    expect(semgrep?.reason).toMatch(/docker/i);
    expect(r.missing_tools).not.toContain('semgrep');
    expect(r.coverage).toBe('full');
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBe(3);
  });

  // Review M2, round 2: the Docker fallback gets the submodule note too. Which
  // listing Semgrep uses inside the container cannot be checked from here, so
  // an initialised submodule is named — the safe direction.
  it('the Docker fallback names an initialised submodule as a gap', async () => {
    const git = (cwd: string, ...args: string[]) =>
      execa('git', ['-c', 'protocol.file.allow=always', '-c', 'user.email=t@example.com', '-c', 'user.name=T', '-c', 'commit.gpgsign=false', ...args], { cwd });
    const lib = tempProject();
    await git(lib, 'init', '-q');
    writeFileSync(join(lib, 'lib.py'), 'x = 1\n', 'utf8');
    await git(lib, 'add', '-A');
    await git(lib, 'commit', '-q', '-m', 'lib');
    const project = tempProject();
    await git(project, 'init', '-q');
    writeFileSync(join(project, 'app.py'), 'x = 1\n', 'utf8');
    await git(project, 'add', '-A');
    await git(project, 'commit', '-q', '-m', 'app');
    await git(project, 'submodule', 'add', '-q', `file://${lib.replace(/\\/g, '/')}`, 'vendor/lib');
    const plugin = makePlugin(project);
    vi.mocked(scannerAvailable).mockImplementation(async (name: string) => (name === 'docker' ? '/usr/bin/docker' : null));
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const outIdx = opts.args?.findIndex((a) => a === '--output') ?? -1;
      const containerOut = outIdx >= 0 ? opts.args?.[outIdx + 1] : undefined;
      if (containerOut?.startsWith('/src/')) {
        const hostOut = join(project, containerOut.slice('/src/'.length));
        mkdirSync(dirname(hostOut), { recursive: true });
        writeFileSync(hostOut, semgrepFixture(), 'utf8');
      }
      return fakeRunSuccess({ exitCode: 1 });
    });
    const r = (await getTool('scan_sast').handler({ project_path: project }, plugin)) as {
      ok: true;
      coverage: string;
      tools_run: { name: string; status: string; reason?: string }[];
      missing_tools: string[];
    };
    const semgrep = r.tools_run.find((t) => t.name === 'semgrep');
    expect(semgrep?.reason).toMatch(/docker.*submodule contents not scanned: vendor\/lib/i);
    expect(r.missing_tools).toContain('semgrep');
    expect(r.coverage).toBe('partial');
  }, 60_000);

  it('reports coverage=none with a loud warning when neither semgrep nor docker exist', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue(null);

    const tool = getTool('scan_sast');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      coverage: string;
      warnings: string[];
      missing_tools: string[];
    };

    expect(r.ok).toBe(true);
    expect(r.coverage).toBe('none');
    expect(r.missing_tools).toContain('semgrep');
    // The headline must not let "0 findings" read as clean.
    expect(r.warnings.some((w) => /not a clean bill of health/i.test(w))).toBe(true);
  });
});

describe('scan_secrets (gitleaks)', () => {
  it('runs with --redact and persists secret findings', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'settings.ini'), 'x=1\n', 'utf8');
    const plugin = makePlugin(project);

    let scannedFrom: string | undefined;
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/gitleaks');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const reportArg = opts.args?.find((a) => a.startsWith('--report-path='));
      if (reportArg) {
        const path = reportArg.replace('--report-path=', '');
        writeFileSync(path, gitleaksFixture(), 'utf8');
      }
      // Verify gitleaks is invoked with --redact.
      expect(opts.args).toContain('--redact');
      // Not a git repository: the directory is scanned in place, never
      // through `gitleaks detect` on git history ("0 commits scanned").
      expect(opts.args).toContain('--no-git');
      expect(opts.args?.slice(opts.args.indexOf('-s'), opts.args.indexOf('-s') + 2)).toEqual(['-s', '.']);
      scannedFrom = opts.cwd;
      return fakeRunSuccess({ exitCode: 1 }); // gitleaks exits 1 when leaks found
    });

    const tool = getTool('scan_secrets');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      findings_count_by_severity: Record<string, number>;
    };
    expect(r.ok).toBe(true);
    expect(r.findings_count_by_severity.high).toBe(2); // 2 secret findings in fixture
    expect(scannedFrom).toBe(project);
  });

  it('scans uncommitted files from a temporary copy that is gone once the scan is', async () => {
    const project = tempProject();
    await execa('git', ['init', '-q'], { cwd: project });
    writeFileSync(join(project, '.gitignore'), '.guardian/\n', 'utf8');
    await execa('git', ['add', '.gitignore'], { cwd: project });
    await execa(
      'git',
      ['-c', 'user.email=t@example.com', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'x'],
      { cwd: project },
    );
    writeFileSync(join(project, 'settings.ini'), 'x=1\n', 'utf8');
    const plugin = makePlugin(project);
    let copy: string | undefined;
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/gitleaks');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const reportArg = opts.args?.find((a) => a.startsWith('--report-path='));
      if (reportArg) writeFileSync(reportArg.replace('--report-path=', ''), '[]', 'utf8');
      if (opts.args?.includes('--no-git')) {
        copy = opts.cwd;
        expect(existsSync(join(opts.cwd, 'settings.ini'))).toBe(true);
      }
      return { ...fakeRunSuccess(), stderr: 'INF 1 commits scanned.' };
    });
    const r = await getTool('scan_secrets').handler({ project_path: project }, plugin);
    expect(r.ok).toBe(true);
    expect(copy).toBeDefined();
    expect(copy).not.toBe(project);
    expect(existsSync(copy ?? project)).toBe(false);
  });

  it('a history pass that reports "0 commits scanned" in a repository with commits is failed, never clean', async () => {
    const project = tempProject();
    await execa('git', ['init', '-q'], { cwd: project });
    writeFileSync(join(project, 'a.txt'), 'a\n', 'utf8');
    await execa('git', ['add', 'a.txt'], { cwd: project });
    await execa(
      'git',
      ['-c', 'user.email=t@example.com', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'x'],
      { cwd: project },
    );
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/gitleaks');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const reportArg = opts.args?.find((a) => a.startsWith('--report-path='));
      if (reportArg) writeFileSync(reportArg.replace('--report-path=', ''), '[]', 'utf8');
      // What gitleaks prints when git could not be read — and it exits 0.
      return { ...fakeRunSuccess(), stderr: '\u001b[32mINF\u001b[0m 0 commits scanned.\nINF no leaks found\n' };
    });

    const r = (await getTool('scan_secrets').handler({ project_path: project }, plugin)) as {
      ok: true;
      coverage: string;
      tools_run: { name: string; status: string; reason?: string }[];
    };
    expect(r.ok).toBe(true);
    const history = r.tools_run.find((t) => t.name === 'gitleaks');
    expect(history?.status).toBe('failed');
    expect(history?.reason).toMatch(/0 commits scanned/);
    expect(r.coverage).not.toBe('full');
  });

  it('a commit or a moved ref that changes no file is a new scan, never a stale cache hit', async () => {
    const project = tempProject();
    const git = (...a: string[]) =>
      execa('git', ['-c', 'user.email=t@example.com', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', ...a], {
        cwd: project,
      });
    await git('init', '-q');
    writeFileSync(join(project, '.gitignore'), '.guardian/\n', 'utf8');
    await git('add', '.gitignore');
    await git('commit', '-q', '-m', 'x');
    const plugin = makePlugin(project);
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/gitleaks');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const reportArg = opts.args?.find((a) => a.startsWith('--report-path='));
      if (reportArg) writeFileSync(reportArg.replace('--report-path=', ''), '[]', 'utf8');
      return { ...fakeRunSuccess(), stderr: 'INF 1 commits scanned.' };
    });
    const tool = getTool('scan_secrets');
    const run = async () =>
      (await tool.handler({ project_path: project }, plugin)) as { ok: true; coverage: string; cached?: boolean };

    const first = await run();
    expect(first.coverage).toBe('full');
    expect((await run()).cached).toBe(true);

    // History grew; the tree did not.
    await git('commit', '-q', '--allow-empty', '-m', 'empty');
    expect((await run()).cached).toBeUndefined();
    expect((await run()).cached).toBe(true);

    // A ref moved (what a fetch does), HEAD and tree untouched.
    const tree = (await execa('git', ['rev-parse', 'HEAD^{tree}'], { cwd: project })).stdout.trim();
    const commit = (await git('commit-tree', tree, '-m', 'fetched')).stdout.trim();
    await git('update-ref', 'refs/remotes/origin/main', commit);
    expect((await run()).cached).toBeUndefined();
  }, 30_000); // Measured in full-suite runs (review 3.0, R7): real git and three scans, 8.7 s under coverage, past 10 s under load.

  it('a history pass whose report was never written is failed even on exit 0', async () => {
    const project = tempProject();
    await execa('git', ['init', '-q'], { cwd: project });
    writeFileSync(join(project, 'a.txt'), 'a\n', 'utf8');
    await execa('git', ['add', 'a.txt'], { cwd: project });
    await execa(
      'git',
      ['-c', 'user.email=t@example.com', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'x'],
      { cwd: project },
    );
    const plugin = makePlugin(project);
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/gitleaks');
    vi.mocked(runProcess).mockResolvedValue({ ...fakeRunSuccess(), stderr: 'INF 1 commits scanned.' });

    const r = (await getTool('scan_secrets').handler({ project_path: project }, plugin)) as {
      ok: true;
      coverage: string;
      tools_run: { name: string; status: string; reason?: string }[];
    };
    expect(r.tools_run.find((t) => t.name === 'gitleaks')?.status).toBe('failed');
    expect(r.tools_run.find((t) => t.name === 'gitleaks')?.reason).toMatch(/no report/);
    expect(r.coverage).toBe('none');
  });
});

describe('scan_wordpress secrets pass', () => {
  it('scans the files of a site that is not a git repository instead of reporting "0 commits" clean', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'wp-config.php'), "<?php define('DB_PASSWORD', 'x');\n", 'utf8');
    const plugin = makePlugin(project);
    await import('../../src/tools/scanWordpress.js');

    const gitleaksCalls: string[][] = [];
    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'gitleaks' ? '/fake/bin/gitleaks' : null,
    );
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      if (opts.command === 'gitleaks') {
        gitleaksCalls.push(opts.args ?? []);
        const reportArg = opts.args?.find((a) => a.startsWith('--report-path='));
        if (reportArg) writeFileSync(reportArg.replace('--report-path=', ''), gitleaksFixture(), 'utf8');
        return fakeRunSuccess({ exitCode: 1 });
      }
      return fakeRunSuccess();
    });

    const r = (await getTool('scan_wordpress').handler({ project_path: project }, plugin)) as {
      ok: true;
      scan_id: string;
      tools_run: { name: string; status: string; reason?: string }[];
    };
    expect(r.ok).toBe(true);
    expect(gitleaksCalls).toHaveLength(1);
    expect(gitleaksCalls[0]).toContain('--no-git');
    const secrets = plugin.storage.findings.listByScan(r.scan_id).filter((f) => f.tool === 'gitleaks');
    expect(secrets).toHaveLength(2);
    expect(secrets.every((f) => /location: directory/.test(f.message ?? ''))).toBe(true);
    expect(r.tools_run.find((t) => t.name === 'gitleaks')?.status).toBe('ok');
  });
});

describe('scan_deps (Trivy fs)', () => {
  it('runs trivy fs with vuln+license scanners and indexes CVEs', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/trivy');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      expect(opts.args?.[0]).toBe('fs');
      expect(opts.args).toContain('vuln,license');
      const outIdx = opts.args?.findIndex((a) => a === '--output');
      const path = outIdx !== undefined && outIdx >= 0 ? opts.args?.[outIdx + 1] : undefined;
      if (path) writeFileSync(path, trivyFsFixture(), 'utf8');
      return fakeRunSuccess();
    });

    const tool = getTool('scan_deps');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      scan_id: string;
      findings_count_by_severity: Record<string, number>;
    };
    expect(r.ok).toBe(true);
    // Fixture: 2 vulns + 1 risky license → 3 findings; 2 CVEs indexed.
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBe(3);
    const cves = plugin.storage.cves.listActive(r.scan_id);
    expect(cves).toHaveLength(2);
  });
});

describe('scan_containers (Trivy Dockerfile)', () => {
  it('scans the project Dockerfile when present', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'Dockerfile'), 'FROM node:20\n', 'utf8');
    const plugin = makePlugin(project);

    // Only trivy — hadolint sits behind the same `dockerfile !== undefined`
    // gate and would otherwise also run (task 15), tripping the `args?.[0]
    // === 'config'` assertion below with its own, differently-shaped call.
    vi.mocked(scannerAvailable).mockImplementation(async (name) => (name === 'trivy' ? '/fake/bin/trivy' : null));
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      expect(opts.args?.[0]).toBe('config');
      const outIdx = opts.args?.findIndex((a) => a === '--output');
      const path = outIdx !== undefined && outIdx >= 0 ? opts.args?.[outIdx + 1] : undefined;
      if (path) writeFileSync(path, trivyDockerFixture(), 'utf8');
      return fakeRunSuccess();
    });

    const tool = getTool('scan_containers');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      findings_count_by_severity: Record<string, number>;
      tools_run: { name: string; status: string }[];
    };
    expect(r.ok).toBe(true);
    expect(r.findings_count_by_severity.high).toBe(1);
    expect(r.tools_run.some((t) => t.name === 'trivy-dockerfile')).toBe(true);
    expect(r.tools_run.find((t) => t.name === 'hadolint')).toMatchObject({ status: 'skipped' });
  });

  it('reports skipped when neither Dockerfile nor image is provided', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/trivy');

    const tool = getTool('scan_containers');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      tools_run: { name: string; status: string; reason?: string }[];
    };
    expect(r.ok).toBe(true);
    expect(r.tools_run[0]?.status).toBe('skipped');
    expect(r.tools_run[0]?.reason).toBe('no_dockerfile_or_image');
  });
});

describe('scan_iac (Trivy config)', () => {
  it('runs trivy config on the project root', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/trivy');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      expect(opts.args?.[0]).toBe('config');
      const outIdx = opts.args?.findIndex((a) => a === '--output');
      const path = outIdx !== undefined && outIdx >= 0 ? opts.args?.[outIdx + 1] : undefined;
      if (path) writeFileSync(path, trivyDockerFixture(), 'utf8');
      return fakeRunSuccess();
    });

    const tool = getTool('scan_iac');
    const r = (await tool.handler({ project_path: project }, plugin)) as { ok: true };
    expect(r.ok).toBe(true);
  });
});

// security_scan_full: see securityScanFull.test.ts.

// Suppress an unused-import warning when the helpers aren't used.
void cpSync;
void existsSync;
