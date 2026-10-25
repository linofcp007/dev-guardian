/**
 * `init_project`'s first-pass status (review 3.6.1).
 *
 * Finding 4: its "Secrets:" line, computed with `runGitleaksScan`, treated
 * only a `failed` pass as a gap. A pass that ran with reduced coverage (a
 * shallow clone's missing history, an oversized or unreadable file, a
 * submodule — `ok` in `tools_run`, its name in `missing_tools`) and a scan
 * whose every pass was skipped both read "Secrets: 0 findings", the line of
 * a clean, fully scanned project.
 *
 * Finding 5: `initial-scan.sh` ran under WSL when that was the only shell.
 * WSL's processes see none of the Windows environment's git hardening
 * (`GIT_CONFIG_COUNT`, …) unless WSLENV names it, and the repository's
 * configuration is read by the Windows git, which evaluates its `includeIf`
 * conditions for the Windows path — so the script's gitleaks (`git log -p`,
 * textconv) and Semgrep (`git ls-files`, fsmonitor) ran the repository's git
 * configuration unhardened. Under WSL the script is not run, and the status
 * says so.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/runners/gitleaksScan.js', () => ({ runGitleaksScan: vi.fn() }));
vi.mock('../../src/runners/shellRunner.js', () => ({ runShellScript: vi.fn() }));
vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual = await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>('../../src/tools/scanHelpers.js');
  return { ...actual, scannerAvailable: vi.fn() };
});

import { runGitleaksScan, type GitleaksScanResult } from '../../src/runners/gitleaksScan.js';
import { runShellScript } from '../../src/runners/shellRunner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import type { PluginContext } from '../../src/context.js';
import { WSL_SHELL, type ShellChoice } from '../../src/platform/shellProbe.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/initProject.js');
});
beforeEach(() => {
  vi.mocked(runGitleaksScan).mockReset();
  vi.mocked(runShellScript).mockReset();
  vi.mocked(runShellScript).mockResolvedValue({
    outcome: 'completed',
    exitCode: 0,
    stdout: 'Estado inicial do projeto:\n\n  SAST (Semgrep): 0 findings\n',
    stderr: '',
    truncated: false,
  });
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(scannerAvailable).mockResolvedValue('/usr/bin/gitleaks');
});

const GIT_BASH: ShellChoice = { command: 'C:\\Program Files\\Git\\bin\\bash.exe', args_prefix: [], needs_wsl_path_translate: false, label: 'Git Bash' };

function setup(shell: ShellChoice | null): { project: string; ctx: PluginContext } {
  const project = resolveProjectPath(makeTempDir('init-status-')).path;
  const scriptsDir = join(makeTempDir('init-status-plugin-'), 'scripts');
  mkdirSync(join(scriptsDir, 'scan'), { recursive: true });
  writeFileSync(join(scriptsDir, 'scan', 'initial-scan.sh'), '#!/bin/sh\necho ok\n');
  const configs = join(scriptsDir, '..', 'configs');
  mkdirSync(join(configs, 'gitleaks'), { recursive: true });
  mkdirSync(join(configs, 'renovate'), { recursive: true });
  writeFileSync(join(configs, 'gitleaks', 'gitleaks.toml'), '# gl\n');
  writeFileSync(join(configs, 'renovate', 'renovate.json'), '{}');
  const db = new Database(':memory:');
  runMigrations(db);
  return { project, ctx: { storage: new Storage(db), shell, scriptsDir, progressNotifier: { send: () => {} } } };
}

async function initialState(shell: ShellChoice | null, scan: GitleaksScanResult): Promise<string[]> {
  vi.mocked(runGitleaksScan).mockResolvedValue(scan);
  const { project, ctx } = setup(shell);
  const tool = TOOLS.find((t) => t.name === 'init_project');
  if (!tool) throw new Error('init_project is not registered');
  const r = (await tool.handler({ project_path: project, profile: 'minimal' }, ctx)) as { ok: boolean; initial_state: string[] };
  expect(r.ok).toBe(true);
  return r.initial_state;
}

const scanOf = (tools_run: GitleaksScanResult['tools_run'], missing_tools: string[] = []): GitleaksScanResult => ({
  tools_run,
  missing_tools,
  parser_inputs: [],
  cancelled: false,
});

const secrets = (lines: string[]): string => lines.find((l) => /Secrets:/.test(l)) ?? '';

describe('init_project — the Secrets line says what the scan covered (finding 4)', () => {
  it('the control: every pass ran fully — "0 findings"', async () => {
    const lines = await initialState(null, scanOf([
      { name: 'gitleaks', status: 'ok', reason: '3 commit(s) scanned' },
      { name: 'gitleaks-working-tree', status: 'ok', reason: '2 uncommitted file(s) scanned' },
    ]));
    expect(secrets(lines)).toBe('  Secrets: 0 findings');
  });

  it('a pass with reduced coverage: partial, the gap named — never a bare "0 findings"', async () => {
    const lines = await initialState(null, scanOf(
      [
        { name: 'gitleaks', status: 'ok', reason: '3 commit(s) scanned; shallow clone: history before abc1234 not scanned' },
        { name: 'gitleaks-working-tree', status: 'ok', reason: '1 file(s) not scanned: big.bin (over 25 MiB)' },
      ],
      ['gitleaks', 'gitleaks-working-tree'],
    ));
    const line = secrets(lines);
    expect(line).not.toBe('  Secrets: 0 findings');
    expect(line).toMatch(/^ {2}Secrets: 0 findings, partial/);
    expect(line).toContain('shallow clone: history before abc1234 not scanned');
    expect(line).toContain('big.bin (over 25 MiB)');
  });

  it('every pass skipped: nothing was scanned, said so — not "0 findings"', async () => {
    const lines = await initialState(null, scanOf([
      { name: 'gitleaks', status: 'skipped', reason: 'the repository has no commits yet — no history to scan' },
      { name: 'gitleaks-working-tree', status: 'skipped', reason: 'no uncommitted files' },
    ]));
    const line = secrets(lines);
    expect(line).not.toMatch(/0 findings/);
    expect(line).toMatch(/^ {2}Secrets: not scanned/);
    expect(line).toContain('no commits yet');
  });

  it('a failed pass is still "failed", with its reason', async () => {
    const lines = await initialState(null, scanOf([{ name: 'gitleaks', status: 'failed', reason: 'git could not read the repository' }]));
    expect(secrets(lines)).toMatch(/^ {2}Secrets: failed \(git could not read the repository\)/);
  });
});

describe('init_project — initial-scan.sh never runs under WSL (finding 5)', () => {
  const FULL = scanOf([{ name: 'gitleaks', status: 'ok', reason: '1 commit(s) scanned' }]);

  it('the control: Git Bash runs the script', async () => {
    const lines = await initialState(GIT_BASH, FULL);
    expect(vi.mocked(runShellScript)).toHaveBeenCalledTimes(1);
    expect(lines).toContain('  SAST (Semgrep): 0 findings');
  });

  it('WSL: the script is not run, and the status names the gap', async () => {
    const lines = await initialState({ ...WSL_SHELL }, FULL);
    expect(vi.mocked(runShellScript)).not.toHaveBeenCalled();
    expect(lines.some((l) => /not run.*WSL.*git hardening/i.test(l)), lines.join('\n')).toBe(true);
    // The Secrets line does not need the shell: it is still there.
    expect(secrets(lines)).toBe('  Secrets: 0 findings');
  });
});
