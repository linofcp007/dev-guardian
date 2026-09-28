/**
 * scan_containers argument validation.
 *
 * `image` goes to `trivy image` as a positional argument, so a value starting
 * with `-` is parsed as an option (`--config=…`, `--output=…`) and a value
 * with whitespace is not an image reference at all. `dockerfile_path` must
 * name a file INSIDE the project: the tool scans the project, and a path
 * outside it (`../../etc/…`, an absolute path elsewhere) reads files the
 * caller never scoped. Both are rejected before any scan row is written or
 * any process is started.
 */
import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
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
  vi.mocked(runProcess).mockResolvedValue(ok);
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/trivy');
});

type Result = { ok: true; tools_run: { name: string }[] } | { ok: false; error: { code: string; message: string } };

describe('scan_containers image validation', () => {
  it.each(['--config=/tmp/evil.yaml', '-o', 'alpine latest', 'alpine\tlatest', ' alpine'])(
    'rejects image %j before running anything',
    async (image) => {
      const project = makeTempDir('containers-');
      const c = plugin(project);
      const r = (await tool().handler({ project_path: project, image }, c)) as Result;
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error.message).toMatch(/image/);
      expect(vi.mocked(runProcess)).not.toHaveBeenCalled();
      expect(c.storage.scans.listHistory(10)).toHaveLength(0);
    },
  );

  it('the schema itself rejects them too (protocol-level validation)', () => {
    const schema = z.object(tool().inputSchema);
    expect(schema.safeParse({ image: '--help' }).success).toBe(false);
    expect(schema.safeParse({ image: 'a b' }).success).toBe(false);
    expect(schema.safeParse({ image: 'ghcr.io/org/app:1.2.3' }).success).toBe(true);
  });

  it.each(['alpine:3.20', 'ghcr.io/org/app@sha256:0123abcd', 'localhost:5000/team/app:dev'])(
    'accepts image %j and passes it to trivy as-is',
    async (image) => {
      const project = makeTempDir('containers-');
      const r = (await tool().handler({ project_path: project, image }, plugin(project))) as Result;
      expect(r.ok).toBe(true);
      const call = vi.mocked(runProcess).mock.calls.find((x) => x[0].args?.[0] === 'image');
      expect(call?.[0].args?.at(-1)).toBe(image);
    },
  );
});

describe('scan_containers dockerfile_path validation', () => {
  it.each([
    ['a parent-relative path', (outside: string) => join('..', outside.split(/[\\/]/).at(-1) ?? '', 'Dockerfile')],
    ['an absolute path outside the project', (outside: string) => join(outside, 'Dockerfile')],
  ])('rejects %s', async (_label, pathFor) => {
    const project = makeTempDir('containers-');
    const outside = makeTempDir('containers-outside-');
    writeFileSync(join(outside, 'Dockerfile'), 'FROM alpine\n');
    const c = plugin(project);
    const r = (await tool().handler(
      { project_path: project, dockerfile_path: pathFor(outside) },
      c,
    )) as Result;
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.message).toMatch(/dockerfile_path/);
    expect(vi.mocked(runProcess)).not.toHaveBeenCalled();
    expect(c.storage.scans.listHistory(10)).toHaveLength(0);
  });

  it('rejects a symlink inside the project that points outside it', async (t) => {
    const project = makeTempDir('containers-');
    const outside = makeTempDir('containers-outside-');
    writeFileSync(join(outside, 'Dockerfile'), 'FROM alpine\n');
    try {
      symlinkSync(join(outside, 'Dockerfile'), join(project, 'Dockerfile.link'));
    } catch {
      t.skip(); // no symlink privilege on this host
      return;
    }
    const c = plugin(project);
    const r = (await tool().handler(
      { project_path: project, dockerfile_path: 'Dockerfile.link' },
      c,
    )) as Result;
    expect(r.ok).toBe(false);
    expect(vi.mocked(runProcess)).not.toHaveBeenCalled();
  });

  it('accepts a relative path inside the project and hands trivy the resolved file', async () => {
    const project = makeTempDir('containers-');
    mkdirSync(join(project, 'docker'));
    writeFileSync(join(project, 'docker', 'Dockerfile.api'), 'FROM alpine\n');
    const r = (await tool().handler(
      { project_path: project, dockerfile_path: join('docker', 'Dockerfile.api') },
      plugin(project),
    )) as Result;
    expect(r.ok).toBe(true);
    const call = vi.mocked(runProcess).mock.calls.find((x) => x[0].args?.[0] === 'config');
    expect(call?.[0].args?.at(-1)).toBe(join(project, 'docker', 'Dockerfile.api'));
  });
});
