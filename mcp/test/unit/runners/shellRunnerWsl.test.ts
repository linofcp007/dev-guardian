/**
 * WSL path translation in `runShellScript`.
 *
 * Under WSL, bash lives in the Linux filesystem view: `C:\proj` means nothing
 * there, `/mnt/c/proj` does. Only the script path used to be translated, so
 * every script tool received its project path as `C:\…` and scanned nothing.
 * `runProcess` is mocked so the test reads exactly the argv WSL is handed.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/runners/processRunner.js', () => ({
  runProcess: vi.fn(),
}));

import { runProcess } from '../../../src/runners/processRunner.js';
import { runShellScript } from '../../../src/runners/shellRunner.js';
import type { ShellChoice } from '../../../src/platform/shellProbe.js';

const WSL: ShellChoice = {
  command: 'wsl',
  args_prefix: ['bash'],
  needs_wsl_path_translate: true,
  label: 'WSL bash',
};

beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(runProcess).mockResolvedValue({
    outcome: 'completed',
    exitCode: 0,
    stdout: '',
    stderr: '',
    truncated: false,
  });
});

describe('runShellScript under WSL', () => {
  it('translates the script AND every absolute Windows path argument', async () => {
    await runShellScript({
      shell: WSL,
      scriptPath: 'C:\\Users\\me\\CLAUDE SKILLS\\dev-guardian\\scripts\\scan\\x.sh',
      args: ['D:\\Code\\my proj', '--no-sudo', 'relative\\file.txt', 'c:/lower/case'],
      cwd: 'C:\\Users\\me',
    });
    expect(vi.mocked(runProcess).mock.calls[0]?.[0].args).toEqual([
      'bash',
      '/mnt/c/Users/me/CLAUDE SKILLS/dev-guardian/scripts/scan/x.sh',
      '/mnt/d/Code/my proj',
      '--no-sudo',
      'relative\\file.txt',
      '/mnt/c/lower/case',
    ]);
  });

  it('leaves arguments alone for a shell that needs no translation', async () => {
    await runShellScript({
      shell: { ...WSL, command: 'bash', args_prefix: [], needs_wsl_path_translate: false },
      scriptPath: 'C:\\s\\x.sh',
      args: ['C:\\proj'],
      cwd: 'C:\\',
    });
    expect(vi.mocked(runProcess).mock.calls[0]?.[0].args).toEqual(['C:\\s\\x.sh', 'C:\\proj']);
  });
});
