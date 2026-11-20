/**
 * The hook dispatcher, as a real subprocess, with the session's folder or the
 * project's on the network (bugfix `hook-unc-cwd-hang`): a `\\host\share` whose
 * host does not answer held every event 21 s on Windows — past the 15 s Claude
 * Code gives a hook, so no guard answered in time.
 *
 * T-04 is the regression, Windows only: each case names a host of its own in
 * 198.51.100.0/24 (TEST-NET-2, routed nowhere) because Windows remembers for
 * about half a minute that a host did not answer — a second ask of the same host
 * returns at once and proves nothing. T-05 to T-08 keep what already works.
 *
 * Requires a built `mcp/dist/` (the dispatcher loads its bundle).
 */
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { HEARTBEAT_DIR } from '../../src/hooks/heartbeat.js';
import { HOOK } from '../helpers/runHook.js';
import { spawnSyncCapped, timeoutAbove } from '../helpers/spawnCap.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { hangBound } from '../helpers/timing.js';

/** The dispatcher is started with this limit: more than the 21 s the defect costs, so that it is measured, not killed. */
const DISPATCH_CAP_MS = 40_000;
vi.setConfig({ testTimeout: timeoutAbove(DISPATCH_CAP_MS) });
afterAll(cleanupTempDirs);

const REPO_ROOT = resolve(fileURLToPath(new URL('.', import.meta.url)), '..', '..', '..');
const BS = String.fromCharCode(92);
/** A fake AWS key the scan reports (assembled: AWS's own documented placeholder is skipped). */
const FAKE_AWS_KEY = ['AKIA', 'Q7XZ2M9KDP4RWT3B'].join('');

interface Said {
  permissionDecision?: string;
  additionalContext?: string;
}
interface Run {
  status: number | null;
  ms: number;
  stdout: unknown;
  said: Said;
  text: string;
}

/** `hooks/guardian-hook.mjs` as Claude Code starts it, with a limit of 40 s (`runHook` fixes 15). */
function dispatch(
  payload: Record<string, unknown>,
  o: { cwd: string; home: string; projectDir?: string; env?: Record<string, string>; hook?: string; nodeArgs?: readonly string[] },
): Run {
  const t0 = Date.now();
  const r = spawnSyncCapped(process.execPath, [...(o.nodeArgs ?? []), o.hook ?? HOOK], {
    cwd: o.cwd,
    input: JSON.stringify(payload),
    encoding: 'utf8',
    timeout: DISPATCH_CAP_MS,
    env: {
      ...process.env,
      HOME: o.home,
      USERPROFILE: o.home,
      CLAUDE_CONFIG_DIR: '',
      GUARDIAN_HOOKS_BASH_BLOCK: '',
      GUARDIAN_HOOKS: '',
      GUARDIAN_OFFLINE: '1',
      CLAUDE_PROJECT_DIR: o.projectDir ?? o.cwd,
      ...o.env,
    },
  });
  const ms = Date.now() - t0;
  const trimmed = (r.stdout ?? '').trim();
  let stdout: unknown = undefined;
  if (trimmed !== '') {
    try {
      stdout = JSON.parse(trimmed);
    } catch {
      stdout = trimmed;
    }
  }
  const said = (stdout as { hookSpecificOutput?: Said } | undefined)?.hookSpecificOutput ?? {};
  return { status: r.status, ms, stdout, said, text: JSON.stringify(stdout ?? '') };
}

const bash = (command: string, cwd: string) => ({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, cwd });
const sessionStart = (cwd: string) => ({ hook_event_name: 'SessionStart', source: 'startup', session_id: 'unc-test', cwd });

describe('hook-unc-cwd-hang', () => {
  describe('T-04 a session or project folder on a host that does not answer (Windows)', () => {
    const WINDOWS = process.platform === 'win32';
    // A counter that starts at a new place every minute, a step wider than the hosts a run uses (this file's
    // cases, and the check), so that two runs close in time never meet a host Windows still remembers.
    const STEP = 16;
    const first = (Math.floor(Date.now() / 60_000) % 15) * STEP + 1;
    const host = (n: number): string => `198.51.100.${String(first + n)}`;
    const unc = (n: number): string => `${BS}${BS}${host(n)}${BS}share${BS}proj`;
    let home: string;
    let local: string;
    let skipReason: string | undefined;

    beforeAll(() => {
      home = makeTempDir('dg-unc-home-');
      local = makeTempDir('dg-unc-local-');
      if (!WINDOWS) return;
      // A host no case uses: when the network refuses these addresses at once, there is no wait to reproduce.
      const t0 = Date.now();
      const asked = spawnSync(
        process.execPath,
        ['-e', 'process.stdout.write(String(require("node:fs").existsSync(process.argv[1])))', `${BS}${BS}198.51.100.${String(first + STEP - 1)}${BS}share${BS}proj`],
        { cwd: tmpdir(), encoding: 'utf8', timeout: DISPATCH_CAP_MS },
      );
      if (asked.status === 0 && Date.now() - t0 < 5000) {
        skipReason = `this network answers "does not exist" for 198.51.100.0/24 in ${String(Date.now() - t0)} ms (it refuses those addresses): there is no wait to reproduce`;
      }
    }, 60_000);

    const only = (name: string, run: () => void) =>
      it(`T-04 ${WINDOWS ? '' : '(Windows only: skipped here) '}${name}`, (ctx) => {
        if (!WINDOWS) ctx.skip();
        if (skipReason !== undefined) ctx.skip(skipReason);
        run();
      });

    only('(a) CLAUDE_PROJECT_DIR on the network, `rm -rf /`: denied, within the bound', () => {
      const r = dispatch(bash('rm -rf /', local), { cwd: local, home, projectDir: unc(0) });
      expect(r.ms).toBeLessThan(hangBound(5000));
      expect(r.said.permissionDecision).toBe('deny');
    });

    only('(b) the session folder on the network, `rm -rf /`: denied, within the bound', () => {
      const r = dispatch(bash('rm -rf /', unc(1)), { cwd: local, home, projectDir: local });
      expect(r.ms).toBeLessThan(hangBound(5000));
      expect(r.said.permissionDecision).toBe('deny');
    });

    only('(c) the session folder on the network, `ls`: the context says which share, and "session"', () => {
      const r = dispatch(bash('ls', unc(2)), { cwd: local, home, projectDir: local });
      expect(r.ms).toBeLessThan(hangBound(5000));
      expect(r.said.additionalContext ?? '').toContain(`${BS}${BS}${host(2)}${BS}share`);
      expect(r.said.additionalContext ?? '').toMatch(/session/);
    });

    only('(d) SessionStart with CLAUDE_PROJECT_DIR on the network: the briefing with the line, and the session mark written', () => {
      const dataDir = join(makeTempDir('dg-unc-data-'), 'dev-guardian');
      const r = dispatch(sessionStart(local), { cwd: local, home, projectDir: unc(3), env: { GUARDIAN_DATA_DIR: dataDir, CLAUDE_PID: '' } });
      expect(r.ms).toBeLessThan(hangBound(5000));
      expect(r.said.additionalContext ?? '').toMatch(/dev-guardian active/);
      expect(r.said.additionalContext ?? '').toContain(`${BS}${BS}${host(3)}${BS}share`);
      const marks = existsSync(join(dataDir, HEARTBEAT_DIR)) ? readdirSync(join(dataDir, HEARTBEAT_DIR)) : [];
      expect(marks).toHaveLength(1);
    });

    only('(d) the same with `sessionStart: false` in the user configuration: only the notice, with the line', () => {
      const userHome = makeTempDir('dg-unc-home-off-');
      mkdirSync(join(userHome, '.config', 'dev-guardian'), { recursive: true });
      writeFileSync(join(userHome, '.config', 'dev-guardian', 'hooks.json'), JSON.stringify({ sessionStart: false }));
      const r = dispatch(sessionStart(local), { cwd: local, home: userHome, projectDir: unc(4) });
      expect(r.ms).toBeLessThan(hangBound(5000));
      expect(r.said.additionalContext ?? '').toContain(`${BS}${BS}${host(4)}${BS}share`);
      expect(r.said.additionalContext ?? '').not.toMatch(/dev-guardian active/);
    });

    only('(e) PostToolUse with the session folder on the network: ends with code 0, within the bound', () => {
      const payload = {
        hook_event_name: 'PostToolUse',
        tool_name: 'Write',
        tool_input: { file_path: join(local, 'notes.txt'), content: 'x' },
        tool_response: { success: true },
        cwd: unc(5),
      };
      const r = dispatch(payload, { cwd: local, home, projectDir: local });
      expect(r.ms).toBeLessThan(hangBound(5000));
      expect(r.status).toBe(0);
    });
  });

  describe('T-05 local folders: nothing new, no process started', () => {
    /** A module for Node's `--import`: logs every start of a process through `node:child_process`, one line each. */
    const countingPreload = (): { preload: string; log: string } => {
      const dir = makeTempDir('dg-spawn-count-');
      const log = join(dir, 'starts.txt');
      const file = join(dir, 'count-starts.mjs');
      writeFileSync(
        file,
        [
          "import { createRequire } from 'node:module';",
          "import { appendFileSync } from 'node:fs';",
          "const require = createRequire(import.meta.url);",
          "const cp = require('node:child_process');",
          "for (const name of ['spawn', 'spawnSync', 'execFile', 'execFileSync', 'exec', 'execSync', 'fork']) {",
          '  const original = cp[name];',
          '  cp[name] = function counted(...args) {',
          "    appendFileSync(process.env.DG_SPAWN_LOG, name + '\\n');",
          '    return original.apply(this, args);',
          '  };',
          '}',
          "require('node:module').syncBuiltinESMExports();",
          '',
        ].join('\n'),
      );
      return { preload: pathToFileURL(file).href, log };
    };
    const starts = (log: string): number => (existsSync(log) ? readFileSync(log, 'utf8').split('\n').filter(Boolean).length : 0);
    let home: string;
    let project: string;
    beforeAll(() => {
      home = makeTempDir('dg-local-home-');
      project = makeTempDir('dg-local-proj-');
    });

    it('T-05 `ls` and SessionStart with local folders carry no line, and `ls` starts no process', () => {
      const { preload, log } = countingPreload();
      const nodeArgs = ['--import', preload];
      const env = { DG_SPAWN_LOG: log };
      const ls = dispatch(bash('ls', project), { cwd: project, home, nodeArgs, env });
      expect(ls.status).toBe(0);
      expect(ls.text).not.toMatch(/network share/);
      expect(starts(log)).toBe(0);
      const session = dispatch(sessionStart(project), { cwd: project, home, nodeArgs, env: { ...env, GUARDIAN_DATA_DIR: join(home, 'data') } });
      expect(session.said.additionalContext ?? '').toMatch(/dev-guardian active/);
      expect(session.text).not.toMatch(/network share/);
    });

    it.runIf(spawnSync('git', ['--version']).status === 0)('T-05 the counting module does count: SessionStart in a git repository starts at least one process', () => {
      const repo = makeTempDir('dg-local-repo-');
      expect(spawnSync('git', ['init', '-q', repo]).status).toBe(0);
      const { preload, log } = countingPreload();
      dispatch(sessionStart(repo), { cwd: repo, home, nodeArgs: ['--import', preload], env: { DG_SPAWN_LOG: log, GUARDIAN_DATA_DIR: join(home, 'data') } });
      expect(starts(log)).toBeGreaterThanOrEqual(1);
    });

    it('T-05 a local session folder that does not exist gives the answer of a call from the hook\'s own folder', () => {
      const gone = join(project, 'does-not-exist');
      for (const command of ['ls', 'rm -rf /']) {
        const without = dispatch(bash(command, gone), { cwd: project, home, projectDir: project });
        const own = dispatch(bash(command, project), { cwd: project, home, projectDir: project });
        expect(without.status).toBe(0);
        expect(without.stdout, command).toEqual(own.stdout);
      }
    });
  });

  describe('T-06 a share that answers is read as today (Windows)', () => {
    const WINDOWS = process.platform === 'win32';
    let home: string;
    let dir: string;
    let share: string;
    let skipReason: string | undefined;
    beforeAll(() => {
      home = makeTempDir('dg-share-home-');
      dir = makeTempDir('dg-share-proj-');
      if (!WINDOWS) return;
      // `C:\Users\x\Temp\p` as `\\localhost\C$\Users\x\Temp\p`: the administrative share of this machine.
      const m = /^([A-Za-z]):[\\/](.*)$/.exec(dir);
      share = m === null ? '' : `${BS}${BS}localhost${BS}${(m[1] ?? '').toUpperCase()}$${BS}${(m[2] ?? '').replace(/\//g, BS)}`;
      mkdirSync(join(dir, '.guardian'), { recursive: true });
      writeFileSync(join(dir, '.guardian', 'hooks.config.json'), JSON.stringify({ secrets: { block: true } }));
      if (share === '' || !existsSync(share)) skipReason = 'the administrative share \\\\localhost\\C$ is not reachable from this account';
    });

    const onShare = (name: string, run: () => void) =>
      it(`T-06 ${WINDOWS ? '' : '(Windows only: skipped here) '}${name}`, (ctx) => {
        if (!WINDOWS) ctx.skip();
        if (skipReason !== undefined) ctx.skip(skipReason);
        run();
      });

    onShare('the project configuration on the share is read: a write with a secret is denied', () => {
      const write = {
        hook_event_name: 'PreToolUse',
        tool_name: 'Write',
        tool_input: { file_path: join(dir, 'src', 'config.ts'), content: `const k = "${FAKE_AWS_KEY}";` },
        cwd: share,
      };
      const r = dispatch(write, { cwd: tmpdir(), home, projectDir: share });
      expect(r.said.permissionDecision).toBe('deny');
    });

    onShare('`ls` and SessionStart answer without the line', () => {
      const ls = dispatch(bash('ls', share), { cwd: tmpdir(), home, projectDir: share });
      expect(ls.text).not.toMatch(/network share/);
      const session = dispatch(sessionStart(share), { cwd: tmpdir(), home, projectDir: share, env: { GUARDIAN_DATA_DIR: join(home, 'data') } });
      expect(session.said.additionalContext ?? '').toMatch(/dev-guardian active/);
      expect(session.text).not.toMatch(/network share/);
    });
  });

  describe('T-07 a `//host/share/dir` that is a local path that does not exist (Linux and macOS)', () => {
    it.runIf(process.platform !== 'win32')('T-07 `ls` answers within the bound with the line, and the guards decide as with a folder that does not exist', () => {
      const home = makeTempDir('dg-posix-home-');
      const local = makeTempDir('dg-posix-local-');
      const net = '//h/s/p';
      const ls = dispatch(bash('ls', net), { cwd: local, home, projectDir: local });
      expect(ls.ms).toBeLessThan(hangBound(5000));
      expect(ls.said.additionalContext ?? '').toMatch(/network share/);
      expect(ls.status).toBe(0);
      expect(ls.said.permissionDecision).toBeUndefined();
      const rm = dispatch(bash('rm -rf /', net), { cwd: local, home, projectDir: local });
      expect(rm.said.permissionDecision).toBe('deny');
      // As with a local folder that does not exist: the same refusal, word for word (a refusal carries no context).
      const gone = dispatch(bash('rm -rf /', join(local, 'does-not-exist')), { cwd: local, home, projectDir: local });
      expect(rm.stdout).toEqual(gone.stdout);
    });
  });

  describe('T-08 without the main bundle file', () => {
    it('T-08 SessionStart with local folders says the guards are off, with code 0', () => {
      const bare = makeTempDir('dg-no-bundle-');
      for (const part of ['hooks', '.claude-plugin']) cpSync(join(REPO_ROOT, part), join(bare, part), { recursive: true });
      expect(existsSync(join(bare, 'mcp', 'dist', 'hooks.js'))).toBe(false);
      const home = makeTempDir('dg-no-bundle-home-');
      const project = makeTempDir('dg-no-bundle-proj-');
      const r = dispatch(sessionStart(project), { cwd: project, home, hook: join(bare, 'hooks', 'guardian-hook.mjs') });
      expect(r.status).toBe(0);
      expect(r.said.additionalContext ?? '').toMatch(/running with guards OFF/);
      expect(r.said.additionalContext ?? '').toMatch(/could not be loaded/);
    });
  });
});

