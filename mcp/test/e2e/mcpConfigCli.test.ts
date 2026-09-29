/**
 * End-to-end tests of `cli/dev-guardian.mjs mcp-config`, invoked as a REAL
 * SUBPROCESS — Task 5 of the 2026-09-25 full review, item 4 (and friends).
 *
 * `mcp-config`'s own arg parser (`parseArgs`, separate from the
 * `takeOperand`-based parsers `scan`/`baseline`/`status`/`dashboard` use) did
 * not check whether `--project`/`--scope` had a value at all: `--project`
 * as the LAST token left `args.project === undefined`, and the very next
 * line, `resolve(args.project)`, threw an UNCAUGHT
 * `TypeError [ERR_INVALID_ARG_TYPE]` — a raw Node stack trace and exit code
 * 1 (Node's default for an uncaught exception), not a clean, flag-naming
 * usage error. Reproduced directly before this fix.
 */

import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { spawnSyncCapped, testTimeoutAbove } from '../helpers/spawnCap.js';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const CLI = resolve(REPO_ROOT, 'cli', 'dev-guardian.mjs');
const TIMEOUT_MS = 15_000;
// Above the cap: a hung CLI is reported by the cap, naming it (R7-I1).
vi.setConfig({ testTimeout: testTimeoutAbove(TIMEOUT_MS) });

/**
 * Fix round 1, item 7 (escalated from minor by the controller, review round
 * 1): `mcp-config all --write` legitimately reaches for the GLOBAL
 * Windsurf/Claude Desktop config paths whenever the item-6d gate that is
 * supposed to skip them under "all" regresses — `resolveMcpConfigPath`
 * derives those paths from `env.home`/`env.appData`, which
 * `cmdMcpConfig` fills straight from `homedir()`/`process.env.APPDATA`. A
 * subprocess test that inherits the real developer machine's `HOME`/
 * `USERPROFILE`/`APPDATA` would, on exactly that regression, silently
 * overwrite the person running this suite's own
 * `~/.codeium/windsurf/mcp_config.json` and Claude Desktop config — a
 * destructive side effect on the machine running tests, not just a failed
 * assertion. Every subprocess this file spawns is sandboxed into a
 * throwaway HOME regardless of what it's expected to do, so a regression
 * here fails LOUDLY (a written file inside the sandbox, or a missing one)
 * rather than QUIETLY on someone's real machine.
 */
const SANDBOX_HOME = mkdtempSync(join(tmpdir(), 'guardian-mcpconfig-home-'));
afterAll(() => {
  rmSync(SANDBOX_HOME, { recursive: true, force: true });
});

function sandboxedEnv(): NodeJS.ProcessEnv {
  return {
    ...process.env,
    NO_COLOR: '1',
    HOME: SANDBOX_HOME,
    USERPROFILE: SANDBOX_HOME,
    APPDATA: join(SANDBOX_HOME, 'AppData', 'Roaming'),
  };
}

function runCliSpawn(args: string[], timeout = TIMEOUT_MS) {
  return spawnSyncCapped(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: sandboxedEnv(),
    timeout,
  });
}

function runCli(args: string[]) {
  const r = runCliSpawn(args);
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

describe('mcp-config — --project with no value', () => {
  it('exits 2 with a clean usage error, never an uncaught TypeError stack trace', () => {
    const r = runCli(['mcp-config', 'cursor', '--project']);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/--project requires a value/);
    expect(r.stderr).not.toMatch(/TypeError|ERR_INVALID_ARG_TYPE|at Object|at async/);
  });

  it('--scope with no value also exits 2 cleanly', () => {
    const r = runCli(['mcp-config', 'cursor', '--scope']);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/--scope requires a value/);
    expect(r.stderr).not.toMatch(/TypeError|at Object|at async/);
  });

  it('a well-formed preview call is unaffected', () => {
    const r = runCli(['mcp-config', 'cursor']);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/dev-guardian/);
  });
});

describe('mcp-config --write — CLI path substitution + delimited rules block (items 6a/6b)', () => {
  let project: string;

  beforeEach(() => {
    project = mkdtempSync(join(tmpdir(), 'guardian-mcpconfig-'));
  });
  afterEach(() => {
    rmSync(project, { recursive: true, force: true });
  });

  it('the installed codex rules file names an absolute CLI path, never the repo-relative one', () => {
    const r = runCliSpawn(['mcp-config', 'codex', '--write', '--project', project]);
    expect(r.status).toBe(0);
    const agentsMd = join(project, 'AGENTS.md');
    expect(existsSync(agentsMd)).toBe(true);
    const content = readFileSync(agentsMd, 'utf8');
    expect(content).not.toContain('{{DEV_GUARDIAN_CLI}}');
    // Never the literal repo-relative form a template shipped with — that
    // path does not exist inside `project`.
    expect(content).not.toMatch(/node cli\/dev-guardian\.mjs/);
    expect(content).toContain(resolve(REPO_ROOT, 'cli', 'dev-guardian.mjs'));
  });

  it('installing over an existing AGENTS.md never destroys the user\'s own content', () => {
    writeFileSync(join(project, 'AGENTS.md'), '# My project\n\nNever touch prod.\n', 'utf8');
    const r = runCliSpawn(['mcp-config', 'codex', '--write', '--project', project]);
    expect(r.status).toBe(0);
    const content = readFileSync(join(project, 'AGENTS.md'), 'utf8');
    expect(content).toContain('Never touch prod.');
    expect(content).toContain('<!-- dev-guardian:begin -->');
  });
});

describe('mcp-config all --write — global-only hosts require explicit --global (item 6d)', () => {
  it('windsurf/claude-desktop report skipped at the default project scope, and nothing is written to the (sandboxed) global config locations', () => {
    const project = mkdtempSync(join(tmpdir(), 'guardian-mcpconfig-all-'));
    try {
      const r = runCliSpawn(['mcp-config', 'all', '--write', '--project', project]);
      expect(r.status).toBe(0);
      expect(r.stdout).toMatch(/## windsurf[\s\S]*?skipped/);
      expect(r.stdout).toMatch(/## claude-desktop[\s\S]*?skipped/);
      // Belt-and-braces beyond the stdout assertions above: prove nothing
      // landed at either global path INSIDE the sandbox either — if item
      // 6d's gate ever regresses, this fails on a file inside SANDBOX_HOME,
      // never on the developer's own machine (see SANDBOX_HOME's own doc
      // comment above for why that distinction matters).
      expect(existsSync(join(SANDBOX_HOME, '.codeium', 'windsurf', 'mcp_config.json'))).toBe(false);
      expect(existsSync(join(SANDBOX_HOME, 'AppData', 'Roaming', 'Claude', 'claude_desktop_config.json'))).toBe(
        false,
      );
    } finally {
      rmSync(project, { recursive: true, force: true });
    }
  });

  it('scope: global explicitly DOES reach the (sandboxed) global Windsurf config — proves the sandbox itself is live, not just silent', () => {
    const project = mkdtempSync(join(tmpdir(), 'guardian-mcpconfig-all-global-'));
    try {
      const r = runCliSpawn(['mcp-config', 'windsurf', '--write', '--global', '--project', project]);
      expect(r.status).toBe(0);
      expect(existsSync(join(SANDBOX_HOME, '.codeium', 'windsurf', 'mcp_config.json'))).toBe(true);
    } finally {
      rmSync(project, { recursive: true, force: true });
    }
  });
});

describe('check --help documents exit code 2', () => {
  it('the usage screen names exit code 2 in the check section', () => {
    const r = runCli(['check', '--help']);
    expect(r.status).toBe(0);
    // The check section documents its own exit codes, including 2 (usage
    // error / file not found) alongside the existing 0/1 documentation.
    const checkSection = r.stdout.slice(r.stdout.indexOf('check — run the guardrail detectors'));
    expect(checkSection).toMatch(/2 = /);
  });
});
