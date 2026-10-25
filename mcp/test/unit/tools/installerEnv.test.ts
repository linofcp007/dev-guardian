/**
 * The environment install_toolchain runs an install step in
 * (`tools/installToolchain.ts#installerEnv`). Measured 2026-10-24: a server
 * whose PSModulePath came from a PowerShell 7 session made Windows
 * PowerShell 5.1 load PowerShell 7's modules, and every pinned Windows
 * installer stopped at `Get-FileHash` ("not recognized").
 */
import { describe, expect, it } from 'vitest';
import { installerEnv } from '../../../src/tools/installToolchain.js';

describe('installerEnv', () => {
  it('Windows PowerShell: the whole environment, PSModulePath left out whatever its case, never merged back', () => {
    const env = {
      PSModulePath: 'C:\\Program Files\\PowerShell\\7\\Modules;C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\Modules',
      psmodulepath: 'x',
      PATH: 'C:\\bin',
      USERPROFILE: 'C:\\Users\\u',
    };
    expect(installerEnv('powershell', env)).toEqual({ env: { PATH: 'C:\\bin', USERPROFILE: 'C:\\Users\\u' }, extendEnv: false });
    expect(installerEnv('PowerShell', env).extendEnv).toBe(false);
  });

  it('any other installer: the server environment as it is', () => {
    for (const command of ['bash', 'ruby', 'winget', 'scoop', 'go', 'pwsh']) expect(installerEnv(command, { PSModulePath: 'x' })).toEqual({});
  });
});
