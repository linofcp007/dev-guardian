/**
 * `--project` with an empty value, and `mcp-config --write` in the home
 * directory — the CLI as a real subprocess.
 *
 * `resolve('')` is the working directory: `scan --project ""` and
 * `--project=` (a CI variable that expanded to nothing) scanned — and
 * `baseline update` rewrote the baseline of — wherever the command ran,
 * while `import-sarif`, `db adopt` and the ref flags refused an empty value.
 * And `mcp-config` never judged its project at all: `mcp-config all --write`
 * run from the home directory wrote AGENTS.md, GEMINI.md, `.vscode/mcp.json`
 * and the rest into it, where every other command refuses a filesystem root
 * or the home directory.
 */

import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { spawnSyncCapped, timeoutAbove } from '../helpers/spawnCap.js';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const CLI = resolve(REPO_ROOT, 'cli', 'dev-guardian.mjs');
const TIMEOUT_MS = 30_000;
vi.setConfig({ testTimeout: timeoutAbove(TIMEOUT_MS) });

// Every spawn runs in a throwaway home — its own working directory — so a
// regression writes into the sandbox, never into the home of whoever runs this.
const HOME = mkdtempSync(join(tmpdir(), 'guardian-project-arg-home-'));
afterAll(() => rmSync(HOME, { recursive: true, force: true }));

function run(args: string[]): { status: number | null; stderr: string } {
  const r = spawnSyncCapped(process.execPath, [CLI, ...args], {
    cwd: HOME,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1', HOME, USERPROFILE: HOME, APPDATA: join(HOME, 'AppData', 'Roaming') },
    timeout: TIMEOUT_MS,
  });
  return { status: r.status, stderr: r.stderr ?? '' };
}

describe('--project with an empty value is a usage error, for every command that takes it', () => {
  const commands: Array<[string, string[]]> = [
    ['scan', ['scan']],
    ['baseline update', ['baseline', 'update']],
    ['status', ['status']],
    ['dashboard', ['dashboard', '--no-open']],
    ['ci-init', ['ci-init', 'github']],
    ['mcp-config', ['mcp-config', 'cursor', '--write']],
    ['import-sarif', ['import-sarif', 'x.sarif']],
    ['db adopt', ['db', 'adopt']],
  ];
  it.each(commands.flatMap(([name, args]) => [[`${name} --project ""`, [...args, '--project', '']], [`${name} --project=`, [...args, '--project=']]]))(
    '%s',
    (_label, args) => {
      const r = run(args as string[]);
      expect(r.stderr).toMatch(/--project requires a value/);
      expect(r.status).toBe(3);
    },
  );
  it('and nothing was written where they ran', () => {
    expect(readdirSync(HOME)).toEqual([]);
  });
});

describe('mcp-config --write judges its project like every other command', () => {
  it('in the home directory (no --project): refused, exit 3, nothing written', () => {
    const r = run(['mcp-config', 'all', '--write']);
    expect(r.stderr).toMatch(/--project must not be a filesystem root or the user's home directory/);
    expect(r.status).toBe(3);
    expect(readdirSync(HOME)).toEqual([]);
  });

  it('a --project that does not exist: refused, never created', () => {
    const missing = join(HOME, 'no-such-project');
    const r = run(['mcp-config', 'cursor', '--write', '--project', missing]);
    expect(r.stderr).toMatch(/--project does not exist or is not a directory/);
    expect(r.status).toBe(3);
    expect(existsSync(missing)).toBe(false);
  });

  it('a preview writes nothing, so it still runs anywhere — the home directory included', () => {
    expect(run(['mcp-config', 'cursor']).status).toBe(0);
  });
});
