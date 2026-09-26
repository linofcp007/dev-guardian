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
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
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

/** Whether this account may create symlinks (Windows needs admin or Developer Mode). */
const CAN_SYMLINK = ((): boolean => {
  const probe = mkdtempSync(join(tmpdir(), 'guardian-hook-symlink-probe-'));
  try {
    writeFileSync(join(probe, 't'), 'x');
    symlinkSync(join(probe, 't'), join(probe, 'l'));
    return true;
  } catch {
    return false;
  } finally {
    rmSync(probe, { recursive: true, force: true });
  }
})();

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

  // Task 23 fix round 1, C1: `{"enabled": false}` in a PROJECT file switched
  // off every hook — the shell guard, install vetting, the config write guard —
  // and even beat GUARDIAN_HOOKS_BASH_BLOCK=1. An assistant can write that file
  // through Bash, which the Write/Edit guard does not cover. A project file may
  // only make the protective hooks stricter; the advisory settings stay its own.
  describe('a project hooks config may only make the protective hooks stricter', () => {
    function projectConfig(config: Record<string, unknown>): void {
      mkdirSync(join(projectDir, '.guardian'), { recursive: true });
      writeFileSync(join(projectDir, '.guardian', 'hooks.config.json'), JSON.stringify(config));
    }
    function userConfig(config: Record<string, unknown>): void {
      mkdirSync(join(homeDir, '.config', 'dev-guardian'), { recursive: true });
      writeFileSync(join(homeDir, '.config', 'dev-guardian', 'hooks.json'), JSON.stringify(config));
    }
    const decision = (r: HookResult): unknown =>
      (r.stdout as { hookSpecificOutput?: { permissionDecision?: string } } | undefined)?.hookSpecificOutput
        ?.permissionDecision;
    const context = (r: HookResult): string =>
      (r.stdout as { hookSpecificOutput?: { additionalContext?: string } } | undefined)?.hookSpecificOutput
        ?.additionalContext ?? '';
    const sessionStart = (): HookResult =>
      runHook({ hook_event_name: 'SessionStart', cwd: projectDir }, { cwd: projectDir, homeDir });

    it('project "enabled": false does not switch off the shell guard', () => {
      projectConfig({ enabled: false });
      const r = runHook(preToolUse('Bash', { command: 'rm -rf /' }, projectDir), { cwd: projectDir, homeDir });
      expect(decision(r)).toBe('deny');
    });

    it('project "enabled": false no longer beats GUARDIAN_HOOKS_BASH_BLOCK=1', () => {
      projectConfig({ enabled: false });
      const r = runHook(preToolUse('PowerShell', { command: 'Remove-Item -Recurse -Force C:\\' }, projectDir), {
        cwd: projectDir,
        homeDir,
        env: { GUARDIAN_HOOKS_BASH_BLOCK: '1' },
      });
      expect(decision(r)).toBe('deny');
    });

    it('project "enabled": false does not switch off the config write guard', () => {
      projectConfig({ enabled: false });
      const target = join(projectDir, '.guardian', 'hooks.config.json');
      const r = runHook(preToolUse('Write', { file_path: target, content: '{}' }, projectDir), {
        cwd: projectDir,
        homeDir,
      });
      expect(decision(r)).toBe('deny');
    });

    it('project "bash": { "warn": false } does not silence the risky-command warning', () => {
      projectConfig({ bash: { warn: false } });
      const r = runHook(preToolUse('Bash', { command: 'git reset --hard HEAD~3' }, projectDir), {
        cwd: projectDir,
        homeDir,
      });
      expect(context(r)).toMatch(/risky shell command/);
    });

    it('a project file can still make the guard stricter ("secrets": { "block": true })', () => {
      projectConfig({ enabled: false, secrets: { block: true } });
      const target = join(projectDir, 'src', 'config.ts');
      const r = runHook(preToolUse('Write', { file_path: target, content: 'const k = "AKIAIOSFODNN7EXAMPLE";' }, projectDir), {
        cwd: projectDir,
        homeDir,
      });
      expect(decision(r)).toBe('deny');
    });

    it('project "secrets": { "warn": false } still silences the advisory secret warning', () => {
      projectConfig({ secrets: { warn: false } });
      const r = runHook(
        {
          hook_event_name: 'PostToolUse',
          tool_name: 'Write',
          tool_input: { file_path: join(projectDir, 'src', 'a.ts'), content: 'const k = "AKIAIOSFODNN7EXAMPLE";' },
          cwd: projectDir,
        },
        { cwd: projectDir, homeDir },
      );
      expect(r.stdout).toBeUndefined();
    });

    it('the user-level "enabled": false still switches every hook off', () => {
      userConfig({ enabled: false });
      const r = runHook(preToolUse('Bash', { command: 'rm -rf /' }, projectDir), { cwd: projectDir, homeDir });
      expect(r.stdout).toBeUndefined();
    });

    it('GUARDIAN_HOOKS=off still switches every hook off', () => {
      const r = runHook(preToolUse('Bash', { command: 'rm -rf /' }, projectDir), {
        cwd: projectDir,
        homeDir,
        env: { GUARDIAN_HOOKS: 'off' },
      });
      expect(r.stdout).toBeUndefined();
    });

    it('SessionStart says, once, which project settings were ignored — without naming the off switch', () => {
      projectConfig({ enabled: false, bash: { block: false, warn: false } });
      const ctx = context(sessionStart());
      expect(ctx).toMatch(/ignored/i);
      expect(ctx).toContain('"enabled": false');
      expect(ctx).toContain('"bash.block": false');
      expect(ctx).toContain('"bash.warn": false');
      expect(ctx.match(/ignored/gi)?.length).toBe(1);
      expect(ctx).not.toMatch(/GUARDIAN_HOOKS|hooks\.json/);
    });

    it('SessionStart still carries that notice when the project also turns the briefing off', () => {
      projectConfig({ enabled: false, sessionStart: false });
      const ctx = context(sessionStart());
      expect(ctx).toContain('"enabled": false');
    });

    it('SessionStart says nothing of the kind for a project file that loosens nothing', () => {
      projectConfig({ secrets: { warn: false, block: true }, ignorePaths: ['/vendor/'] });
      expect(context(sessionStart())).not.toMatch(/ignored/i);
    });

    // Final review M4: `ignorePaths` is advisory, but it also exempted a path
    // from the opt-in secret BLOCK — so a project file with
    // `"ignorePaths": ["/"]` switched off a block the USER had enabled. It now
    // narrows the warning only; a user-enabled block honours the user's own
    // ignore list (or the defaults), never the project's.
    const tokenWriteTo = (rel: string): HookResult =>
      runHook(preToolUse('Write', { file_path: join(projectDir, rel), content: 'const k = "AKIAIOSFODNN7EXAMPLE";' }, projectDir), {
        cwd: projectDir,
        homeDir,
      });

    it('a project "ignorePaths" cannot exempt a path from a user-enabled secret block', () => {
      userConfig({ secrets: { block: true } });
      projectConfig({ ignorePaths: ['/'] });
      expect(decision(tokenWriteTo('src/k.ts'))).toBe('deny');
    });

    it('…while the same project "ignorePaths" still silences the advisory warning', () => {
      userConfig({ secrets: { block: true } });
      projectConfig({ ignorePaths: ['/'] });
      const r = runHook(
        {
          hook_event_name: 'PostToolUse',
          tool_name: 'Write',
          tool_input: { file_path: join(projectDir, 'src', 'k.ts'), content: 'const k = "AKIAIOSFODNN7EXAMPLE";' },
          cwd: projectDir,
        },
        { cwd: projectDir, homeDir },
      );
      expect(r.stdout).toBeUndefined();
    });

    it('the user-level "ignorePaths" still exempts a path from the user-enabled block', () => {
      userConfig({ secrets: { block: true }, ignorePaths: ['/generated/'] });
      expect(decision(tokenWriteTo('generated/k.ts'))).toBeUndefined();
      expect(decision(tokenWriteTo('src/k.ts'))).toBe('deny');
    });

    it('a user-enabled block keeps the default ignore list when neither file narrows it', () => {
      userConfig({ secrets: { block: true } });
      projectConfig({ ignorePaths: ['/'] });
      expect(decision(tokenWriteTo('test/fixtures/k.ts'))).toBeUndefined();
    });

    it('a block the PROJECT enabled may still be narrowed by the project\'s own ignorePaths', () => {
      projectConfig({ secrets: { block: true }, ignorePaths: ['/vendor/'] });
      expect(decision(tokenWriteTo('vendor/k.ts'))).toBeUndefined();
      expect(decision(tokenWriteTo('src/k.ts'))).toBe('deny');
    });
  });

  // Task 23 fix round 2, N1: the config reader did existsSync + readFileSync
  // with no check on what the path was. A FIFO (or a link to /dev/zero) at
  // .guardian/hooks.config.json or the allowlist blocked the hook until Claude
  // Code killed it at 15 s — and the tool call then ran unguarded.
  describe('a hook config that is not a small regular file is not read', () => {
    const POSIX = process.platform !== 'win32';
    const guardianDir = (): string => {
      const d = join(projectDir, '.guardian');
      mkdirSync(d, { recursive: true });
      return d;
    };
    const decision = (r: HookResult): unknown =>
      (r.stdout as { hookSpecificOutput?: { permissionDecision?: string } } | undefined)?.hookSpecificOutput
        ?.permissionDecision;
    const context = (r: HookResult): string =>
      (r.stdout as { hookSpecificOutput?: { additionalContext?: string } } | undefined)?.hookSpecificOutput
        ?.additionalContext ?? '';
    const timedRmRf = (): { r: HookResult; ms: number } => {
      const t0 = Date.now();
      const r = runHook(preToolUse('Bash', { command: 'rm -rf /' }, projectDir), { cwd: projectDir, homeDir });
      return { r, ms: Date.now() - t0 };
    };
    const tokenWrite = (): HookResult =>
      runHook(
        preToolUse('Write', { file_path: join(projectDir, 'src', 'k.ts'), content: 'const k = "AKIAIOSFODNN7EXAMPLE";' }, projectDir),
        { cwd: projectDir, homeDir },
      );

    it.skipIf(!POSIX)('a FIFO hooks.config.json: rm -rf / is still denied, at once (POSIX only: Windows has no FIFOs)', () => {
      expect(spawnSync('mkfifo', [join(guardianDir(), 'hooks.config.json')]).status).toBe(0);
      const { r, ms } = timedRmRf();
      expect(decision(r)).toBe('deny');
      expect(ms).toBeLessThan(5000);
    });

    it.skipIf(!POSIX)('a hooks.config.json linked to /dev/zero: denied at once (POSIX only: Windows has no /dev/zero)', () => {
      symlinkSync('/dev/zero', join(guardianDir(), 'hooks.config.json'));
      const { r, ms } = timedRmRf();
      expect(decision(r)).toBe('deny');
      expect(ms).toBeLessThan(5000);
    });

    it.skipIf(!POSIX)('a FIFO or /dev/zero allowlist: denied at once, and SessionStart names both (POSIX only)', () => {
      expect(spawnSync('mkfifo', [join(guardianDir(), 'hooks-allowlist.json')]).status).toBe(0);
      symlinkSync('/dev/zero', join(guardianDir(), 'hooks.config.json'));
      const { r, ms } = timedRmRf();
      expect(decision(r)).toBe('deny');
      expect(ms).toBeLessThan(5000);
      const ctx = context(runHook({ hook_event_name: 'SessionStart', cwd: projectDir }, { cwd: projectDir, homeDir }));
      expect(ctx).toContain('.guardian/hooks.config.json');
      expect(ctx).toContain('.guardian/hooks-allowlist.json');
      expect(ctx).toMatch(/not a regular file/);
    });

    it('a directory in place of hooks.config.json: denied, and SessionStart names it', () => {
      mkdirSync(join(guardianDir(), 'hooks.config.json'));
      expect(decision(timedRmRf().r)).toBe('deny');
      const ctx = context(runHook({ hook_event_name: 'SessionStart', cwd: projectDir }, { cwd: projectDir, homeDir }));
      expect(ctx).toMatch(/\.guardian\/hooks\.config\.json was not read \(not a regular file\)/);
    });

    it('a project config over 64 KiB is not read: its settings do not apply', () => {
      writeFileSync(
        join(guardianDir(), 'hooks.config.json'),
        JSON.stringify({ secrets: { block: true }, pad: 'x'.repeat(70 * 1024) }),
      );
      expect(decision(tokenWrite())).toBeUndefined();
      const ctx = context(runHook({ hook_event_name: 'SessionStart', cwd: projectDir }, { cwd: projectDir, homeDir }));
      expect(ctx).toMatch(/\.guardian\/hooks\.config\.json was not read \(larger than 64 KiB\)/);
    });

    it('a user-level config over 64 KiB is not read either: its "enabled": false does not apply', () => {
      mkdirSync(join(homeDir, '.config', 'dev-guardian'), { recursive: true });
      writeFileSync(
        join(homeDir, '.config', 'dev-guardian', 'hooks.json'),
        JSON.stringify({ enabled: false, pad: 'x'.repeat(70 * 1024) }),
      );
      expect(decision(timedRmRf().r)).toBe('deny');
    });

    it('a UTF-8 byte-order mark does not make a project config unreadable (PowerShell 5 writes one)', () => {
      writeFileSync(join(guardianDir(), 'hooks.config.json'), '\uFEFF' + JSON.stringify({ secrets: { block: true } }), 'utf8');
      expect(decision(tokenWrite())).toBe('deny');
    });

    // Final review I12: a link to an unreachable `\\host\share` made the
    // config read (and SessionStart's look at `.guardian`) wait ~136 s on
    // Windows \u2014 past the hook's 15 s, after which the call ran unguarded.
    // 192.0.2.1 is TEST-NET-1: never routed, and never contacted when the
    // walk works.
    const UNC = POSIX ? '//192.0.2.1/share' : '\\\\192.0.2.1\\share';
    it.skipIf(!CAN_SYMLINK)(
      '.guardian linked to a UNC share: rm -rf / is still denied at once, and SessionStart names the file (needs symlink rights; skipped without them)',
      () => {
        symlinkSync(UNC, join(projectDir, '.guardian'), 'dir');
        const { r, ms } = timedRmRf();
        expect(decision(r)).toBe('deny');
        expect(ms).toBeLessThan(5000);
        const t0 = Date.now();
        const ctx = context(runHook({ hook_event_name: 'SessionStart', cwd: projectDir }, { cwd: projectDir, homeDir }));
        expect(Date.now() - t0).toBeLessThan(5000);
        expect(ctx).toMatch(
          /\.guardian\/hooks\.config\.json was not read \(reached through a link to a network or device path\)/,
        );
      },
      30_000,
    );

    it.skipIf(!CAN_SYMLINK)(
      'a user-level config dir linked to a UNC share: rm -rf / is still denied at once (needs symlink rights; skipped without them)',
      () => {
        mkdirSync(join(homeDir, '.config'), { recursive: true });
        symlinkSync(UNC, join(homeDir, '.config', 'dev-guardian'), 'dir');
        const { r, ms } = timedRmRf();
        expect(decision(r)).toBe('deny');
        expect(ms).toBeLessThan(5000);
      },
      30_000,
    );
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
