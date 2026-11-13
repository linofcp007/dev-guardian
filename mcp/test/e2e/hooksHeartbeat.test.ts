/**
 * The session mark, through the real dispatcher: `hooks/guardian-hook.mjs` run
 * as a subprocess on a SessionStart payload, with a data directory, a home and
 * a project of the test's own. `test/unit/hooks/heartbeat.test.ts` holds the
 * module to its contract; this file holds the dispatcher to calling it — first,
 * in every state the hooks can be in, and without ever costing the session its
 * briefing.
 *
 * Requires a built `mcp/dist/` (the dispatcher loads its bundle).
 */

import { execFileSync } from 'node:child_process';
import { chmodSync, cpSync, existsSync, mkdirSync, readdirSync, readFileSync, truncateSync, utimesSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it, vi } from 'vitest';

import {
  HEARTBEAT_DIR,
  hooksStatus,
  markFileName,
  MAX_AGE_MS,
  projectKey,
  type HeartbeatMark,
} from '../../src/hooks/heartbeat.js';
import { POSIX } from '../helpers/fsCapabilities.js';
import { HOOK_TIMEOUT_MS, runHook, type HookResult } from '../helpers/runHook.js';
import { timeoutAbove } from '../helpers/spawnCap.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { hangBound } from '../helpers/timing.js';

vi.setConfig({ testTimeout: timeoutAbove(HOOK_TIMEOUT_MS) });

afterAll(cleanupTempDirs);

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const PLUGIN_VERSION = (JSON.parse(readFileSync(join(REPO_ROOT, '.claude-plugin', 'plugin.json'), 'utf8')) as { version: string }).version;

interface Session {
  project: string;
  home: string;
  dataDir: string;
}

function session(): Session {
  return {
    project: makeTempDir('guardian-hb-project-'),
    home: makeTempDir('guardian-hb-home-'),
    dataDir: join(makeTempDir('guardian-hb-data-'), 'dev-guardian'),
  };
}

function sessionStart(s: Session, opts: { env?: Record<string, string>; source?: string; hook?: string } = {}): HookResult {
  return runHook(
    { hook_event_name: 'SessionStart', source: opts.source ?? 'startup', session_id: 'test-session', cwd: s.project },
    {
      cwd: s.project,
      homeDir: s.home,
      env: { GUARDIAN_DATA_DIR: s.dataDir, CLAUDE_PID: '', ...opts.env },
      ...(opts.hook !== undefined ? { hook: opts.hook } : {}),
    },
  );
}

/** The marks in a session's data directory: their file names and contents. */
function marks(s: Session): Array<{ name: string; text: string; mark: HeartbeatMark }> {
  const dir = join(s.dataDir, HEARTBEAT_DIR);
  if (!existsSync(dir)) return [];
  return readdirSync(dir).map((name) => {
    const text = readFileSync(join(dir, name), 'utf8');
    return { name, text, mark: JSON.parse(text) as HeartbeatMark };
  });
}

/** The briefing a hook emitted, or undefined when it emitted nothing. */
function briefing(r: HookResult): string | undefined {
  return (r.stdout as { hookSpecificOutput?: { additionalContext?: string } } | undefined)?.hookSpecificOutput?.additionalContext;
}

describe('SessionStart leaves the session mark', () => {
  it('T-01 the mark is in the data directory, with the date, the version, the event\'s source, the host process and the project\'s key', () => {
    const s = session();
    const before = Date.now();
    const r = sessionStart(s, { source: 'resume' });
    expect(r.status, r.stderr).toBe(0);
    expect(briefing(r)).toMatch(/dev-guardian active/);

    const written = marks(s);
    expect(written).toHaveLength(1);
    const [only] = written;
    if (only === undefined) throw new Error('no mark');
    expect(only.mark.v).toBe(1);
    expect(only.mark.plugin_version).toBe(PLUGIN_VERSION);
    expect(only.mark.source).toBe('resume');
    expect(only.mark.state).toBe('active');
    // The hook's parent is this process: that is the "host" of this test.
    expect(only.mark.host_pids).toContain(process.pid);
    expect(only.mark.project).toBe(projectKey(s.project));
    expect(only.name).toBe(markFileName(only.mark.project, only.mark.host_pids[0] ?? 0));
    expect(only.mark.at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    const at = Date.parse(only.mark.at);
    expect(at).toBeGreaterThanOrEqual(before - 1_000);
    expect(at).toBeLessThanOrEqual(Date.now() + 1_000);

    // CLAUDE_PID, when Claude Code sets it, is the host as well.
    const withPid = session();
    sessionStart(withPid, { env: { CLAUDE_PID: '424242' } });
    expect(marks(withPid)[0]?.mark.host_pids).toEqual([424242, process.pid]);

    // A source the hook does not know stays out of the mark, and the mark is still written.
    const odd = session();
    sessionStart(odd, { source: 'teleport' });
    expect(marks(odd)).toHaveLength(1);
    expect(marks(odd)[0]?.mark).not.toHaveProperty('source');
  });

  it('T-02 the mark is started before git and the session checks', () => {
    const s = session();
    execFileSync('git', ['init', '-q'], { cwd: s.project });
    const r = sessionStart(s, { env: { GUARDIAN_HOOKS_DEBUG: '1' } });
    const lines = r.stderr.split(/\r?\n/);
    const mark = lines.findIndex((l) => /heartbeat/.test(l));
    const git = lines.findIndex((l) => /git status/.test(l));
    expect(mark, r.stderr).toBeGreaterThan(-1);
    expect(git, r.stderr).toBeGreaterThan(-1);
    expect(mark).toBeLessThan(git);
    expect(marks(s)).toHaveLength(1);
  });

  it('T-09 with the hooks switched off by the user, the mark says so and health_status reads disabled_by_user', () => {
    const byEnv = session();
    const off = sessionStart(byEnv, { env: { GUARDIAN_HOOKS: 'off' } });
    expect(off.status).toBe(0);
    expect(off.stdout).toBeUndefined();
    expect(marks(byEnv)[0]?.mark).toMatchObject({ state: 'disabled', disabled_by: 'GUARDIAN_HOOKS' });

    const byFile = session();
    mkdirSync(join(byFile.home, '.config', 'dev-guardian'), { recursive: true });
    writeFileSync(join(byFile.home, '.config', 'dev-guardian', 'hooks.json'), '{ "enabled": false }\n');
    const quiet = sessionStart(byFile);
    expect(quiet.stdout).toBeUndefined();
    expect(marks(byFile)[0]?.mark).toMatchObject({ state: 'disabled', disabled_by: 'user-config' });

    for (const s of [byEnv, byFile]) {
      const r = hooksStatus({
        expected: { expected: true, reason: "started as the plugin's server" },
        dataDir: s.dataDir,
        projectRoot: s.project,
        hostPids: [process.pid],
        serverStartedAt: Date.now() - 60_000,
      });
      expect(r.hooks.state).toBe('disabled_by_user');
      expect(r.hooks.disabled_by ?? '').not.toBe('');
      expect(r.warning).toBeNull();
    }

    // Switched off, no other event writes anything: the mark is SessionStart's alone.
    const other = session();
    const bash = runHook(
      { hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'git status' }, cwd: other.project },
      { cwd: other.project, homeDir: other.home, env: { GUARDIAN_DATA_DIR: other.dataDir, GUARDIAN_HOOKS: 'off' } },
    );
    expect(bash.stdout).toBeUndefined();
    expect(existsSync(other.dataDir)).toBe(false);
  });

  it('T-10 a project that turned the briefing off still gets its mark', () => {
    const s = session();
    mkdirSync(join(s.project, '.guardian'), { recursive: true });
    writeFileSync(join(s.project, '.guardian', 'hooks.config.json'), '{ "sessionStart": false }\n');
    const r = sessionStart(s);
    expect(r.status).toBe(0);
    expect(r.stdout).toBeUndefined();
    expect(marks(s)).toHaveLength(1);
    expect(marks(s)[0]?.mark.state).toBe('active');
  });

  it('T-13 the mark holds its own fields and nothing of the project, the environment or the session', () => {
    const s = session();
    writeFileSync(join(s.project, 'quarterly-forecast.txt'), 'confidential');
    sessionStart(s, { env: { GUARDIAN_TEST_MARKER: 'zz-marker-91f3-zz' } });
    expect(marks(s)).toHaveLength(1);
    const [only] = marks(s);
    if (only === undefined) throw new Error('no mark');
    const allowed = ['v', 'at', 'plugin_version', 'source', 'host_pids', 'project', 'state', 'disabled_by'];
    expect(Object.keys(only.mark).filter((k) => !allowed.includes(k))).toEqual([]);
    const text = only.text.toLowerCase();
    for (const secret of [s.project, s.home, 'quarterly-forecast', 'confidential', 'zz-marker-91f3-zz', 'test-session']) {
      expect(text, secret).not.toContain(secret.toLowerCase());
      expect(text, secret).not.toContain(secret.toLowerCase().replace(/\\/g, '/'));
      expect(text, secret).not.toContain(JSON.stringify(secret).slice(1, -1).toLowerCase());
    }
    expect(Buffer.byteLength(only.text, 'utf8')).toBeLessThanOrEqual(1024);
  });

  it('T-14 a mark that cannot be written costs the session nothing: the same briefing, exit 0, nothing on stderr', () => {
    const fine = session();
    const control = sessionStart(fine);

    // The data directory is a file: nothing can be created in it.
    const broken = { ...session(), project: fine.project, home: fine.home };
    const parent = makeTempDir('guardian-hb-data-');
    broken.dataDir = join(parent, 'not-a-directory');
    writeFileSync(broken.dataDir, 'x');
    const r = sessionStart(broken);
    expect(r.status).toBe(0);
    expect(r.stderr).toBe('');
    expect(r.stdout).toEqual(control.stdout);
    expect(readFileSync(broken.dataDir, 'utf8')).toBe('x');

    // Only the debug switch says why.
    const debugged = sessionStart(broken, { env: { GUARDIAN_HOOKS_DEBUG: '1' } });
    expect(debugged.stdout).toEqual(control.stdout);
    expect(debugged.stderr).toMatch(/heartbeat.*not written/i);
  });

  it('T-15 a data directory on an unreachable share does not hold the session', () => {
    const s = session();
    s.dataDir = process.platform === 'win32' ? '\\\\10.255.255.1\\share\\dev-guardian' : '//10.255.255.1/share/dev-guardian';
    const started = Date.now();
    const r = sessionStart(s);
    expect(Date.now() - started).toBeLessThan(hangBound(3_000));
    expect(r.status).toBe(0);
    expect(briefing(r)).toMatch(/dev-guardian/);
  });

  it('T-23 an old mark that cannot be removed changes neither the briefing nor the exit code', () => {
    const fine = session();
    const control = sessionStart(fine);

    const s = { ...session(), project: fine.project, home: fine.home };
    const dir = join(s.dataDir, HEARTBEAT_DIR);
    mkdirSync(dir, { recursive: true });
    const old = join(dir, markFileName(projectKey(s.project), 999_001));
    const longAgo = new Date(Date.now() - MAX_AGE_MS - 24 * 60 * 60 * 1000);
    writeFileSync(old, JSON.stringify({ v: 1, at: longAgo.toISOString(), plugin_version: '3.0.0', host_pids: [999_001], project: projectKey(s.project), state: 'active' }));
    utimesSync(old, longAgo, longAgo);
    // What makes a removal fail here: a directory nothing can be removed from (not for root, which may).
    // Windows has no portable equivalent — libuv clears a read-only attribute before it unlinks — so
    // there the old mark is simply removed; the failing removal itself is the unit file's T-24.
    if (POSIX) chmodSync(dir, 0o555);
    try {
      const r = sessionStart(s);
      expect(r.status).toBe(0);
      expect(r.stderr).toBe('');
      expect(r.stdout).toEqual(control.stdout);
      if (POSIX && process.getuid?.() !== 0) expect(existsSync(old)).toBe(true);
    } finally {
      if (POSIX) chmodSync(dir, 0o755);
    }
  });

  it('T-27 the mark says a hook started, not that every guard loaded; and it adds no wait a session would notice', () => {
    // EC-7: a damaged shell-guard part. The briefing names it; the mark still says the hook ran.
    const plug = join(makeTempDir('guardian-hb-plug-'), 'plugin');
    for (const part of ['hooks', '.claude-plugin', join('mcp', 'dist')]) {
      cpSync(join(REPO_ROOT, part), join(plug, part), { recursive: true });
    }
    truncateSync(join(plug, 'mcp', 'dist', 'hooksBash.js'), 10);
    const s = session();
    const r = sessionStart(s, { hook: join(plug, 'hooks', 'guardian-hook.mjs') });
    expect(briefing(r)).toMatch(/guards OFF/);
    expect(marks(s)[0]?.mark.state).toBe('active');

    // SC-003, as a shape: with the mark, SessionStart still answers inside the bound it had without it.
    const timed = session();
    const started = Date.now();
    sessionStart(timed);
    expect(Date.now() - started).toBeLessThan(hangBound(3_000));
    expect(marks(timed)).toHaveLength(1);
  });
});
