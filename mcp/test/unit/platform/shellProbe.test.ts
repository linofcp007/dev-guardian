import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { describe, expect, it } from 'vitest';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { RuntimeMetaRepo } from '../../../src/storage/runtimeMetaRepo.js';
import { candidatesFor, probeShell } from '../../../src/platform/shellProbe.js';

function freshRuntimeMeta() {
  const db = new Database(':memory:');
  runMigrations(db);
  return new RuntimeMetaRepo(db);
}

describe('candidatesFor', () => {
  it('orders Windows as Git Bash, then WSL bash, then bash on PATH', () => {
    // Git Bash first: it sees the Windows-native scanners on PATH and takes
    // Windows paths as they are; WSL sees neither without translation.
    const c = candidatesFor('win32');
    expect(c.map((x) => x.label)).toEqual(['Git Bash', 'WSL bash', 'bash on PATH']);
    expect(c[0]?.command).toBe('C:\\Program Files\\Git\\bin\\bash.exe');
    expect(c[0]?.needs_wsl_path_translate).toBe(false);
    expect(c[1]?.command).toBe('wsl');
    expect(c[1]?.needs_wsl_path_translate).toBe(true);
    expect(c.at(-1)?.command).toBe('bash.exe');
  });

  it('does not enable WSL translation on POSIX hosts', () => {
    expect(candidatesFor('linux').every((c) => c.needs_wsl_path_translate === false)).toBe(true);
    expect(candidatesFor('darwin').every((c) => c.needs_wsl_path_translate === false)).toBe(true);
  });
});

describe('probeShell', () => {
  it('caches the first successful candidate to runtime_meta', async () => {
    const meta = freshRuntimeMeta();
    let calls = 0;
    const result = await probeShell(
      meta,
      {
        testShell: async (cmd) => {
          calls += 1;
          if (cmd === '/bin/bash') return 'GNU bash, version 5.2';
          return null;
        },
      },
      'linux',
    );
    expect(result?.command).toBe('/bin/bash');
    expect(calls).toBeGreaterThan(0);

    const cached = meta.getJson<{ command: string }>('shell_choice');
    expect(cached?.command).toBe('/bin/bash');
  });

  it('reuses the cached choice without re-probing every candidate', async () => {
    const meta = freshRuntimeMeta();
    // Seed the cache.
    meta.setJson('shell_choice', {
      command: '/bin/bash',
      args_prefix: [],
      needs_wsl_path_translate: false,
      label: 'cached',
    });

    let calls = 0;
    const result = await probeShell(
      meta,
      {
        testShell: async () => {
          calls += 1;
          return 'GNU bash 5.2';
        },
      },
      'linux',
    );
    expect(result?.command).toBe('/bin/bash');
    // Only one call: validating the cached choice.
    expect(calls).toBe(1);
  });

  it('falls back to probing when the cached choice no longer works', async () => {
    const meta = freshRuntimeMeta();
    meta.setJson('shell_choice', {
      command: '/old/bash',
      args_prefix: [],
      needs_wsl_path_translate: false,
      label: 'stale',
    });

    const result = await probeShell(
      meta,
      {
        testShell: async (cmd) => {
          if (cmd === '/old/bash') return null;
          if (cmd === '/bin/bash') return 'GNU bash 5.2';
          return null;
        },
      },
      'linux',
    );
    expect(result?.command).toBe('/bin/bash');
  });

  it('replaces a cached WSL choice once Git Bash is usable (the order changed)', async () => {
    // A host that cached WSL under the old order must not stay on it: the
    // cache only saves re-probing what the choice already outranks.
    const meta = freshRuntimeMeta();
    meta.setJson('shell_choice', {
      command: 'wsl',
      args_prefix: ['bash'],
      needs_wsl_path_translate: true,
      label: 'WSL bash (cached)',
    });
    const result = await probeShell(
      meta,
      { testShell: async () => 'GNU bash, version 5.2' },
      'win32',
    );
    expect(result?.command).toBe('C:\\Program Files\\Git\\bin\\bash.exe');
    expect(meta.getJson<{ command: string }>('shell_choice')?.command).toBe(
      'C:\\Program Files\\Git\\bin\\bash.exe',
    );
  });

  it('keeps a cached WSL choice when nothing outranks it', async () => {
    const meta = freshRuntimeMeta();
    meta.setJson('shell_choice', {
      command: 'wsl',
      args_prefix: ['bash'],
      needs_wsl_path_translate: true,
      label: 'WSL bash (cached)',
    });
    const probed: string[] = [];
    const result = await probeShell(
      meta,
      {
        testShell: async (cmd) => {
          probed.push(cmd);
          return cmd === 'wsl' ? 'GNU bash, version 5.2' : null;
        },
      },
      'win32',
    );
    expect(result?.label).toBe('WSL bash (cached)');
    // Git Bash (the one candidate that outranks it) and the cached choice.
    expect(probed).toEqual(['C:\\Program Files\\Git\\bin\\bash.exe', 'wsl']);
  });

  it('returns null when no candidate is usable', async () => {
    const meta = freshRuntimeMeta();
    const result = await probeShell(
      meta,
      { testShell: async () => null },
      'linux',
    );
    expect(result).toBeNull();
  });
});
