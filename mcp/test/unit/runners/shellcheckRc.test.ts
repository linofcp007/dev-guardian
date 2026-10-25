/**
 * The project's root `.shellcheckrc` reaches shellcheck as a filtered copy
 * (`runners/shellcheckRun.ts`, 3.6.1). Passed as it was with `--rcfile`, its
 * `external-sources=true` made shellcheck follow every `source` — measured on
 * shellcheck 0.11.0 (Windows, 2026-10-25): a script's `. ../outside/lib.sh`
 * was read (its variable no longer SC2154), and with `source-path=` too a
 * `# shellcheck source=` name was looked for in any directory. The directive
 * counts anywhere on a line, a trailing comment or CRLF included; `EXTERNAL-
 * SOURCES=` and `external-sources = true` do not.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));

import { runProcess } from '../../../src/runners/processRunner.js';
import { neutralShellcheckRc, shellcheckScripts } from '../../../src/runners/shellcheckRun.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const mockedRun = vi.mocked(runProcess);
/** The rc each run was handed, read while it ran. */
let seen: Array<{ args: string[]; rc: string | null }> = [];

beforeEach(() => {
  seen = [];
  mockedRun.mockReset();
  mockedRun.mockImplementation(async (opts) => {
    const args = opts.args ?? [];
    const i = args.indexOf('--rcfile');
    const rcPath = i >= 0 ? args[i + 1] : undefined;
    seen.push({ args, rc: rcPath === undefined ? null : readFileSync(rcPath, 'utf8') });
    return { outcome: 'completed', exitCode: 0, stdout: '{"comments":[]}', stderr: '', truncated: false };
  });
});

describe('neutralShellcheckRc', () => {
  it('keeps disable, enable, shell and extended-analysis; drops what reads other files, wherever it is on a line', () => {
    const { text, dropped } = neutralShellcheckRc(
      '# the team config\r\n' +
        'disable=SC2035,SC2086 external-sources=true\r\n' +
        'source-path=SCRIPTDIR/../outside # look there\n' +
        'enable=require-variable-braces\n' +
        'shell=bash\n' +
        'extended-analysis=false\n' +
        'source=/etc/profile\n' +
        'external-sources=true # trailing\n',
    );
    expect(text.split('\n')).toEqual([
      '',
      'disable=SC2035,SC2086',
      '',
      'enable=require-variable-braces',
      'shell=bash',
      'extended-analysis=false',
      '',
      '',
      '',
    ]);
    expect(dropped).toEqual(['external-sources=true', 'source-path=SCRIPTDIR/../outside', 'source=/etc/profile']);
  });
});

describe('shellcheckScripts: the root .shellcheckrc', () => {
  const runIt = (projectPath: string) =>
    shellcheckScripts({ projectPath, scripts: ['a.sh'], env: {}, signal: new AbortController().signal });

  it('a copy without external-sources is passed, never the project file; the reason says what was left out', async () => {
    const dir = makeTempDir('shellcheckrc-');
    writeFileSync(join(dir, '.shellcheckrc'), 'disable=SC2035\nexternal-sources=true\n');
    writeFileSync(join(dir, 'a.sh'), '#!/bin/sh\n. ../outside/lib.sh\n');
    const pass = await runIt(dir);
    expect(seen).toHaveLength(1);
    const call = seen[0];
    const i = call?.args.indexOf('--rcfile') ?? -1;
    expect(call?.args[i + 1]).not.toBe(join(dir, '.shellcheckrc'));
    expect(call?.rc).toBe('disable=SC2035\n\n');
    expect(pass.toolRun.status).toBe('ok');
    expect(pass.toolRun.reason).toMatch(/external-sources=true/);
    expect(pass.toolRun.honoured_config).toEqual(['.shellcheckrc']);
    expect(pass.missing).toBe(false);
  });

  it('no root .shellcheckrc: --norc, as before', async () => {
    const dir = makeTempDir('shellcheckrc-none-');
    writeFileSync(join(dir, 'a.sh'), '#!/bin/sh\n');
    await runIt(dir);
    expect(seen[0]?.args).toContain('--norc');
    expect(seen[0]?.rc).toBeNull();
  });
});
