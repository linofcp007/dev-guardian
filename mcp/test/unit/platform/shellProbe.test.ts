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
  it('starts Windows with WSL bash and ends with bash on PATH', () => {
    const c = candidatesFor('win32');
    expect(c[0]?.command).toBe('wsl');
    expect(c[0]?.needs_wsl_path_translate).toBe(true);
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
