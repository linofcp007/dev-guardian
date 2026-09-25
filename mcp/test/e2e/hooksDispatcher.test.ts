/**
 * End-to-end test of `hooks/guardian-hook.mjs`, invoked as a REAL SUBPROCESS
 * fed the JSON stdin payload Claude Code actually sends — the only way to
 * exercise the dispatcher's own routing (`hooks.json`'s matcher, the
 * `tool_name` switch in `main()`) and its filesystem-facing config
 * resolution (project vs. user-level config, the env var override), none of
 * which `bashGuard.test.ts`/`secretScan.test.ts` can see since those call the
 * pure detector functions directly.
 *
 * Requires a built `mcp/dist/hooks/*` (the dispatcher dynamic-imports it —
 * see `loadDetectors` in guardian-hook.mjs); run `npm run build` in `mcp/`
 * first. Every case here is deliberately fast (no real scanner involved), so
 * no skip-when-toolchain-missing discipline is needed, unlike
 * `rulePackFixture.test.ts`/`ciCliFixture.test.ts`.
 */

import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

const here = dirname(fileURLToPath(import.meta.url));
// mcp/test/e2e -> mcp/test -> mcp -> repo root
const REPO_ROOT = resolve(here, '..', '..', '..');
const HOOK = resolve(REPO_ROOT, 'hooks', 'guardian-hook.mjs');

/** Hang-breaker only; nothing here asserts by reaching it — every case is a
 *  fast, dependency-free regex pass with no real scanner involved. */
const TIMEOUT_MS = 15_000;

interface HookResult {
  status: number | null;
  stdout: unknown;
  stderr: string;
}

function runHook(
  payload: Record<string, unknown>,
  opts: { cwd: string; env?: Record<string, string>; homeDir?: string } = { cwd: process.cwd() },
): HookResult {
  const home = opts.homeDir ?? opts.cwd;
  const r = spawnSync(process.execPath, [HOOK], {
    cwd: opts.cwd,
    input: JSON.stringify(payload),
    encoding: 'utf8',
    timeout: TIMEOUT_MS,
    env: {
      ...process.env,
      // Isolates the user-level config lookup (~/.config/dev-guardian/…)
      // from whatever the machine actually running this suite has.
      HOME: home,
      USERPROFILE: home,
      GUARDIAN_HOOKS_BASH_BLOCK: '',
      GUARDIAN_HOOKS: '',
      ...opts.env,
    },
  });
  let stdout: unknown = undefined;
  const trimmed = (r.stdout ?? '').trim();
  if (trimmed) {
    try {
      stdout = JSON.parse(trimmed);
    } catch {
      stdout = trimmed;
    }
  }
  return { status: r.status, stdout, stderr: r.stderr ?? '' };
}

function preToolUse(toolName: string, toolInput: Record<string, unknown>, cwd: string) {
  return { hook_event_name: 'PreToolUse', tool_name: toolName, tool_input: toolInput, cwd };
}

describe('hooks/guardian-hook.mjs — task-1 (real subprocess)', () => {
  let projectDir: string;
  let homeDir: string;

  beforeEach(() => {
    projectDir = mkdtempSync(join(tmpdir(), 'guardian-hook-project-'));
    homeDir = mkdtempSync(join(tmpdir(), 'guardian-hook-home-'));
  });

  afterEach(() => {
    rmSync(projectDir, { recursive: true, force: true });
    rmSync(homeDir, { recursive: true, force: true });
  });

  describe('finding 1 — the PowerShell tool is matched, not just Bash', () => {
    it('blocks a catastrophic command sent as the PowerShell tool', () => {
      const r = runHook(
        preToolUse('PowerShell', { command: 'Remove-Item -Recurse -Force C:\\' }, projectDir),
        { cwd: projectDir, homeDir },
      );
      expect(r.status).toBe(0);
      expect(r.stdout).toMatchObject({
        hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny' },
      });
    });

    it('warns (does not deny) an ordinary PowerShell command', () => {
      const r = runHook(preToolUse('PowerShell', { command: 'Get-ChildItem' }, projectDir), {
        cwd: projectDir,
        homeDir,
      });
      expect(r.status).toBe(0);
      expect(r.stdout).toBeUndefined();
    });
  });

  describe('finding 6 — the deny message and the downgrade switch', () => {
    it('the deny reason does not tell the model how to disable the guard', () => {
      const r = runHook(preToolUse('Bash', { command: 'rm -rf /' }, projectDir), {
        cwd: projectDir,
        homeDir,
      });
      const reason = (r.stdout as { hookSpecificOutput: { permissionDecisionReason: string } })
        .hookSpecificOutput.permissionDecisionReason;
      expect(reason).not.toMatch(/hooks\.config\.json/);
      expect(reason).not.toMatch(/"block"\s*:\s*false/);
    });

    it('a project-level "bash":{"block":false} no longer downgrades the block', () => {
      mkdirSync(join(projectDir, '.guardian'), { recursive: true });
      writeFileSync(
        join(projectDir, '.guardian', 'hooks.config.json'),
        JSON.stringify({ bash: { block: false } }),
      );
      const r = runHook(preToolUse('Bash', { command: 'rm -rf /' }, projectDir), {
        cwd: projectDir,
        homeDir,
      });
      expect(r.stdout).toMatchObject({
        hookSpecificOutput: { permissionDecision: 'deny' },
      });
    });

    it('the ignored project downgrade logs a debug-only note, silent otherwise', () => {
      mkdirSync(join(projectDir, '.guardian'), { recursive: true });
      writeFileSync(
        join(projectDir, '.guardian', 'hooks.config.json'),
        JSON.stringify({ bash: { block: false } }),
      );
      const quiet = runHook(preToolUse('Bash', { command: 'rm -rf /' }, projectDir), {
        cwd: projectDir,
        homeDir,
      });
      expect(quiet.stderr).toBe('');

      const loud = runHook(preToolUse('Bash', { command: 'rm -rf /' }, projectDir), {
        cwd: projectDir,
        homeDir,
        env: { GUARDIAN_HOOKS_DEBUG: '1' },
      });
      expect(loud.stderr).toMatch(/ignoring "bash":\{"block":false\}/);
    });

    it('a user-level config CAN downgrade the block', () => {
      mkdirSync(join(homeDir, '.config', 'dev-guardian'), { recursive: true });
      writeFileSync(
        join(homeDir, '.config', 'dev-guardian', 'hooks.json'),
        JSON.stringify({ bash: { block: false } }),
      );
      const r = runHook(preToolUse('Bash', { command: 'rm -rf /' }, projectDir), {
        cwd: projectDir,
        homeDir,
      });
      // No longer denied — downgraded to a non-blocking warning instead.
      expect(r.stdout).toMatchObject({
        hookSpecificOutput: { hookEventName: 'PreToolUse' },
      });
      expect((r.stdout as { hookSpecificOutput: Record<string, unknown> }).hookSpecificOutput)
        .not.toHaveProperty('permissionDecision');
    });

    it('GUARDIAN_HOOKS_BASH_BLOCK=0 CAN downgrade the block', () => {
      const r = runHook(preToolUse('Bash', { command: 'rm -rf /' }, projectDir), {
        cwd: projectDir,
        homeDir,
        env: { GUARDIAN_HOOKS_BASH_BLOCK: '0' },
      });
      expect((r.stdout as { hookSpecificOutput: Record<string, unknown> } | undefined)?.hookSpecificOutput)
        .not.toHaveProperty('permissionDecision');
    });

    it('Write/Edit targeting the project hooks config is denied — "ask the user"', () => {
      const target = join(projectDir, '.guardian', 'hooks.config.json');
      const r = runHook(
        preToolUse('Write', { file_path: target, content: '{"bash":{"block":false}}' }, projectDir),
        { cwd: projectDir, homeDir },
      );
      expect(r.stdout).toMatchObject({
        hookSpecificOutput: { permissionDecision: 'deny' },
      });
      const reason = (r.stdout as { hookSpecificOutput: { permissionDecisionReason: string } })
        .hookSpecificOutput.permissionDecisionReason;
      expect(reason.toLowerCase()).toMatch(/ask the user/);
    });

    it('Write targeting the project hooks-allowlist is also denied', () => {
      const target = join(projectDir, '.guardian', 'hooks-allowlist.json');
      const r = runHook(preToolUse('Write', { file_path: target, content: '[]' }, projectDir), {
        cwd: projectDir,
        homeDir,
      });
      expect(r.stdout).toMatchObject({ hookSpecificOutput: { permissionDecision: 'deny' } });
    });

    it('Write targeting the user-level hooks config is denied', () => {
      const target = join(homeDir, '.config', 'dev-guardian', 'hooks.json');
      const r = runHook(preToolUse('Write', { file_path: target, content: '{}' }, projectDir), {
        cwd: projectDir,
        homeDir,
      });
      expect(r.stdout).toMatchObject({ hookSpecificOutput: { permissionDecision: 'deny' } });
    });

    it('an ordinary project file is NOT denied', () => {
      const target = join(projectDir, 'src', 'config.ts');
      const r = runHook(preToolUse('Write', { file_path: target, content: 'export const x = 1;' }, projectDir), {
        cwd: projectDir,
        homeDir,
      });
      expect(r.stdout).toBeUndefined();
    });

    // Fix round 1 — reviewer finding: this deny reason used to tell the
    // model exactly how to disable the guard ("add it to
    // .guardian/hooks-allowlist.json or set \"secrets\":{\"block\":false}"),
    // which is doubly wrong now — item 6 removes model-facing disable
    // instructions everywhere, and both of those specific actions are
    // themselves denied outright by guardianConfigWriteGuard.
    it('the secrets-block deny reason does not tell the model how to disable the guard either', () => {
      mkdirSync(join(projectDir, '.guardian'), { recursive: true });
      writeFileSync(
        join(projectDir, '.guardian', 'hooks.config.json'),
        JSON.stringify({ secrets: { block: true } }),
      );
      const target = join(projectDir, 'src', 'config.ts');
      const r = runHook(
        preToolUse(
          'Write',
          { file_path: target, content: 'const key = "AKIAIOSFODNN7EXAMPLE";' },
          projectDir,
        ),
        { cwd: projectDir, homeDir },
      );
      expect(r.stdout).toMatchObject({ hookSpecificOutput: { permissionDecision: 'deny' } });
      const reason = (r.stdout as { hookSpecificOutput: { permissionDecisionReason: string } })
        .hookSpecificOutput.permissionDecisionReason;
      expect(reason).not.toMatch(/hooks-allowlist\.json/);
      expect(reason).not.toMatch(/"block"\s*:\s*false/);
      expect(reason.toLowerCase()).toMatch(/the user can/);
    });
  });

  describe('finding 10 — the ignore list is project-relative, not a raw substring', () => {
    it('a React-style src/hooks/ file is still secret-scanned, not silently skipped', () => {
      const target = join(projectDir, 'src', 'hooks', 'useAuth.ts');
      const r = runHook(
        preToolUse(
          'Write',
          { file_path: target, content: 'const stripeSecretKey = "Gx7$kPq2zVw9MtRbQeLpXo";' },
          projectDir,
        ),
        { cwd: projectDir, homeDir },
      );
      // PreToolUse write-blocking is opt-in (secrets.block defaults false),
      // so this must fall through with no output here — the real assertion
      // is the PostToolUse warn below, which fires unconditionally on the
      // default config.
      expect(r.stdout).toBeUndefined();

      const post = runHook(
        {
          hook_event_name: 'PostToolUse',
          tool_name: 'Write',
          tool_input: { file_path: target, content: 'const stripeSecretKey = "Gx7$kPq2zVw9MtRbQeLpXo";' },
          cwd: projectDir,
        },
        { cwd: projectDir, homeDir },
      );
      expect(post.stdout).toMatchObject({ hookSpecificOutput: { hookEventName: 'PostToolUse' } });
    });

    it('the plugin repo\'s own hooks/ directory is still skipped, by absolute prefix', () => {
      // cwd is an unrelated temp project; the target is the real, absolute
      // path to this repo's own hooks/guardian-hook.mjs — simulating an edit
      // to the plugin's own file regardless of which project is open.
      const post = runHook(
        {
          hook_event_name: 'PostToolUse',
          tool_name: 'Write',
          tool_input: {
            file_path: HOOK,
            content: 'const stripeSecretKey = "Gx7$kPq2zVw9MtRbQeLpXo";',
          },
          cwd: projectDir,
        },
        { cwd: projectDir, homeDir },
      );
      expect(post.stdout).toBeUndefined();
    });

    it('NotebookEdit is matched on notebook_path, not file_path', () => {
      const target = join(projectDir, 'analysis.ipynb');
      const post = runHook(
        {
          hook_event_name: 'PostToolUse',
          tool_name: 'NotebookEdit',
          tool_input: {
            notebook_path: target,
            new_source: 'stripe_secret_key = "Gx7$kPq2zVw9MtRbQeLpXo"',
          },
          cwd: projectDir,
        },
        { cwd: projectDir, homeDir },
      );
      expect(post.stdout).toMatchObject({ hookSpecificOutput: { hookEventName: 'PostToolUse' } });
      const ctx = (post.stdout as { hookSpecificOutput: { additionalContext: string } })
        .hookSpecificOutput.additionalContext;
      expect(ctx).toContain('analysis.ipynb');
    });
  });

  it('fails open on malformed stdin (finding: preserved existing behaviour)', () => {
    const r = spawnSync(process.execPath, [HOOK], {
      cwd: projectDir,
      input: 'not json at all {{{',
      encoding: 'utf8',
      timeout: TIMEOUT_MS,
      env: { ...process.env, HOME: homeDir, USERPROFILE: homeDir },
    });
    expect(r.status).toBe(0);
    expect((r.stdout ?? '').trim()).toBe('');
  });
});
