/**
 * `create_fix_pr` runs the project's own test command — the project's code —
 * on a dry run too. It ran with the server's full environment: a
 * `scripts.test` that dumps `process.env` read every token the server was
 * started with (review of 3.0.0, item 3).
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';
import { testCommandEnv, testEnvAllows } from '../../../src/fixpr/testCommandEnv.js';
import { judgeTests } from '../../../src/fixpr/verify.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);
afterEach(() => {
  vi.unstubAllEnvs();
});

const SECRETS: Record<string, string> = {
  GITHUB_TOKEN: 'ghp_dev_guardian_test_secret_0001',
  GH_TOKEN: 'gho_dev_guardian_test_secret_0002',
  NPM_TOKEN: 'npm_dev_guardian_test_secret_0003',
  NODE_AUTH_TOKEN: 'npm_dev_guardian_test_secret_0004',
  AWS_ACCESS_KEY_ID: 'AKIADEVGUARDIANTEST05',
  AWS_SECRET_ACCESS_KEY: 'dev_guardian_test_secret_0006',
  AZURE_CLIENT_SECRET: 'dev_guardian_test_secret_0007',
  GOOGLE_APPLICATION_CREDENTIALS: '/secret/dev_guardian_test_0008.json',
  ANTHROPIC_API_KEY: 'sk-ant-dev_guardian_test_secret_0009',
  OPENAI_API_KEY: 'sk-dev_guardian_test_secret_0010',
  DATABASE_URL: 'postgres://user:dev_guardian_test_secret_0011@db/app',
  GUARDIAN_DATA_DIR: '/secret/dev_guardian_test_0012',
  PYTHON_KEYRING_PASSWORD: 'dev_guardian_test_secret_0013',
  npm_config__authToken: 'dev_guardian_test_secret_0014',
};

describe('testCommandEnv', () => {
  it('keeps what a test runner needs and drops tokens, cloud credentials and GUARDIAN_*', () => {
    const env = testCommandEnv({
      PATH: '/usr/bin',
      Path: 'C:\\Windows',
      HOME: '/home/u',
      TMPDIR: '/tmp',
      LANG: 'C.UTF-8',
      LC_ALL: 'C.UTF-8',
      CI: 'true',
      NODE_OPTIONS: '--max-old-space-size=4096',
      PYTHONPATH: '/p',
      CARGO_HOME: '/c',
      GOPATH: '/g',
      SystemRoot: 'C:\\Windows',
      ...SECRETS,
    });
    for (const name of Object.keys(SECRETS)) expect(env, name).not.toHaveProperty(name);
    expect(env).toMatchObject({
      PATH: '/usr/bin',
      Path: 'C:\\Windows',
      HOME: '/home/u',
      TMPDIR: '/tmp',
      LANG: 'C.UTF-8',
      LC_ALL: 'C.UTF-8',
      CI: 'true',
      NODE_OPTIONS: '--max-old-space-size=4096',
      PYTHONPATH: '/p',
      CARGO_HOME: '/c',
      GOPATH: '/g',
      SystemRoot: 'C:\\Windows',
    });
  });

  it('judges names case-insensitively, as Windows does', () => {
    expect(testEnvAllows('Path')).toBe(true);
    expect(testEnvAllows('comspec')).toBe(true);
    expect(testEnvAllows('guardian_offline')).toBe(false);
    expect(testEnvAllows('node_auth_token')).toBe(false);
  });
});

describe('judgeTests — the project test command sees no secret', () => {
  it('a test script that dumps its environment finds none of the server\'s secrets', async () => {
    for (const [k, v] of Object.entries(SECRETS)) vi.stubEnv(k, v);
    const tree = makeTempDir('fixpr-env-');
    const dump = join(tree, 'env.json');
    // What a hostile `scripts.test` / conftest.py / build.rs does.
    writeFileSync(
      join(tree, 'dump.cjs'),
      `require('fs').writeFileSync(${JSON.stringify(dump)}, JSON.stringify(process.env)); process.exit(0);\n`,
    );

    const verdict = await judgeTests({
      derived: { command: process.execPath, args: ['dump.cjs'], origin: 'test' },
      worktreePath: tree,
      baseTree: async () => ({ ok: false, reason: 'not needed' }),
      timeoutMs: 30_000,
    });

    expect(verdict.outcome).toBe('passed');
    const seen = JSON.parse(readFileSync(dump, 'utf8')) as Record<string, string>;
    const leaked = Object.entries(seen).filter(([, v]) => Object.values(SECRETS).some((s) => v.includes(s)));
    expect(leaked).toEqual([]);
    for (const name of Object.keys(SECRETS)) expect(seen, name).not.toHaveProperty(name);
    // …and it still found its toolchain.
    expect(Object.keys(seen).some((k) => k.toUpperCase() === 'PATH')).toBe(true);
  });

  it('the base-commit run gets the same environment', async () => {
    for (const [k, v] of Object.entries(SECRETS)) vi.stubEnv(k, v);
    const tree = makeTempDir('fixpr-env-');
    const base = makeTempDir('fixpr-env-base-');
    const dump = join(base, 'env.json');
    writeFileSync(join(tree, 'dump.cjs'), 'process.exit(1);\n');
    writeFileSync(
      join(base, 'dump.cjs'),
      `require('fs').writeFileSync(${JSON.stringify(dump)}, JSON.stringify(process.env)); process.exit(1);\n`,
    );

    await judgeTests({
      derived: { command: process.execPath, args: ['dump.cjs'], origin: 'test' },
      worktreePath: tree,
      baseTree: async () => ({ ok: true, path: base, dispose: async () => {} }),
      timeoutMs: 30_000,
    });

    const seen = JSON.parse(readFileSync(dump, 'utf8')) as Record<string, string>;
    for (const name of Object.keys(SECRETS)) expect(seen, name).not.toHaveProperty(name);
  });
});

describe('create_fix_pr — what its description promises', () => {
  it('says a dry run executes the project\'s test command, and never that it "never leaves the machine"', async () => {
    const { TOOLS } = await import('../../../src/tools/index.js');
    await import('../../../src/tools/createFixPr.js');
    const tool = TOOLS.find((t) => t.name === 'create_fix_pr');
    if (tool === undefined) throw new Error('create_fix_pr not registered');
    expect(tool.description.length).toBeLessThanOrEqual(1500);
    expect(tool.description).toMatch(/dry run[^.]*runs the project's own test command/i);
    expect(tool.description).toMatch(/project's (own )?code/i);
    // Round 2: the repository's package-manager configuration, and what refuses a fix.
    expect(tool.description).toMatch(/\.npmrc\/\.yarnrc[^;]*set aside/);
    // W2E: a requirement that names its own host (a direct, bare or VCS URL) refuses it too.
    expect(tool.description).toMatch(/pip index or URL\/VCS requirement or Composer repository refuses the fix/);
    const apply = tool.inputSchema['apply']?.description ?? '';
    expect(apply).not.toMatch(/never leaves the machine/);
    expect(apply).toMatch(/test command/);
  });
});
