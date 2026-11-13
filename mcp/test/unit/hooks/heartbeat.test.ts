/**
 * The session mark (`src/hooks/heartbeat.ts`): what SessionStart writes, and
 * what `health_status` concludes from it.
 *
 * A Claude Code older than 2.1.139 starts no hook at all and none can say so,
 * while the MCP server keeps answering. The mark is how the server tells: it
 * looks for the mark of the host process that started it.
 *
 * Two failures matter, and the tests below are split between them. A FALSE
 * WARNING ("no hook started" when they did) teaches the user to ignore the
 * warning: the grace period, the tolerance and `not_applicable` guard against
 * it. A FALSE CALM (a stale, forged or unreadable mark taken for this
 * session's) hides an unguarded session: every abuse case here must read as
 * "no mark".
 *
 * Nothing touches the real data directory: every test has its own. Time is
 * injected; the tests that guard against a hang use `hangBound`, never a
 * number of milliseconds of their own.
 */

import { execFileSync } from 'node:child_process';
import { lstatSync, mkdirSync, readdirSync, readFileSync, statSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs';
import * as fsp from 'node:fs/promises';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';

import {
  GRACE_MS,
  HEARTBEAT_DIR,
  hooksStatus,
  hostPidsOf,
  MARK_MAX_BYTES,
  markFileName,
  MAX_AGE_MS,
  pluginServerExpected,
  projectKey,
  PRUNE_MAX,
  pruneHeartbeats,
  serializeMark,
  TOLERANCE_MS,
  writeHeartbeat,
  type HeartbeatFs,
  type HeartbeatMark,
  type HooksStatusOptions,
  type WriteHeartbeatOptions,
} from '../../../src/hooks/heartbeat.js';
import { CAN_SYMLINK, POSIX } from '../../helpers/fsCapabilities.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';
import { hangBound } from '../../helpers/timing.js';

afterAll(cleanupTempDirs);

const NOW = Date.parse('2026-11-13T12:00:00.000Z');
const iso = (ms: number): string => new Date(ms).toISOString();

/** A project the tests never create: the key is arithmetic on the path. */
const ROOT = process.platform === 'win32' ? 'C:\\work\\shop' : '/work/shop';
const OTHER_ROOT = process.platform === 'win32' ? 'C:\\work\\blog' : '/work/blog';

/** The host process of "this session", as the server sees it. */
const HOST = 4242;

function mark(over: Partial<HeartbeatMark> = {}): HeartbeatMark {
  return {
    v: 1,
    at: iso(NOW - 5_000),
    plugin_version: '3.9.0',
    source: 'startup',
    host_pids: [HOST],
    project: projectKey(ROOT),
    state: 'active',
    ...over,
  };
}

/** Writes `content` as the mark file of (`project`, `pid`) — by hand, never through the module under test. */
function seed(dataDir: string, m: HeartbeatMark, opts: { content?: string; pid?: number; project?: string } = {}): string {
  const dir = join(dataDir, HEARTBEAT_DIR);
  mkdirSync(dir, { recursive: true });
  const file = join(dir, markFileName(opts.project ?? m.project, opts.pid ?? m.host_pids[0] ?? 0));
  writeFileSync(file, opts.content ?? JSON.stringify(m), 'utf8');
  return file;
}

function status(dataDir: string, over: Partial<HooksStatusOptions> = {}): ReturnType<typeof hooksStatus> {
  return hooksStatus({
    expected: { expected: true, reason: "started as the plugin's server" },
    dataDir,
    projectRoot: ROOT,
    hostPids: [HOST],
    serverStartedAt: NOW - 60_000,
    now: NOW,
    writable: () => null,
    ...over,
  });
}

/** `node:fs/promises`, with every call recorded. */
function spyFs(): { fs: HeartbeatFs; calls: Array<{ op: string; args: unknown[] }> } {
  const calls: Array<{ op: string; args: unknown[] }> = [];
  const record =
    <A extends unknown[], R>(op: string, fn: (...args: A) => Promise<R>) =>
    (...args: A): Promise<R> => {
      calls.push({ op, args });
      return fn(...args);
    };
  const fs: HeartbeatFs = {
    mkdir: record('mkdir', (p: string, o: { recursive: true; mode: number }) => fsp.mkdir(p, o)),
    writeFile: record('writeFile', (p: string, d: string, o: { flag: 'wx'; mode: number }) => fsp.writeFile(p, d, o)),
    rename: record('rename', (a: string, b: string) => fsp.rename(a, b)),
    rm: record('rm', (p: string, o: { force: true }) => fsp.rm(p, o)),
    readdir: record('readdir', (p: string) => fsp.readdir(p)),
    lstat: record('lstat', (p: string) => fsp.lstat(p)),
    unlink: record('unlink', (p: string) => fsp.unlink(p)),
  };
  return { fs, calls };
}

function writeOptions(dataDir: string, over: Partial<WriteHeartbeatOptions> = {}): WriteHeartbeatOptions {
  return {
    dataDir,
    home: dirname(dataDir),
    projectRoot: ROOT,
    pluginVersion: '3.9.0',
    source: 'startup',
    state: 'active',
    env: {},
    ppid: HOST,
    now: NOW,
    ...over,
  };
}

/** Everything `health_status` would show, as text: what a warning or a field could leak. */
const shown = (r: ReturnType<typeof hooksStatus>): string => JSON.stringify(r);

describe('the session mark: what health_status concludes', () => {
  it('T-03 a mark of the host process that started the server is this session: running, matched by the process', () => {
    const dataDir = makeTempDir('guardian-hb-');
    seed(dataDir, mark());
    const r = status(dataDir);
    expect(r.hooks).toMatchObject({
      state: 'running',
      matched_by: 'host_process',
      last_seen_at: iso(NOW - 5_000),
      age_seconds: 5,
      plugin_version: '3.9.0',
    });
    expect(r.warning).toBeNull();

    // EC-2: the server was restarted mid-session — the mark is older than the server, and still this session's.
    const restarted = makeTempDir('guardian-hb-');
    seed(restarted, mark({ at: iso(NOW - 2 * 60 * 60 * 1000) }));
    expect(status(restarted, { serverStartedAt: NOW - 60_000 }).hooks).toMatchObject({ state: 'running', matched_by: 'host_process' });

    // Either of the host's two identifiers is enough: CLAUDE_PID on one side, the parent on the other.
    const either = makeTempDir('guardian-hb-');
    seed(either, mark({ host_pids: [9001, HOST] }), { pid: 9001 });
    expect(status(either, { hostPids: [HOST, 7] }).hooks).toMatchObject({ state: 'running', matched_by: 'host_process' });
  });

  it('T-04 with no process match, a mark of the same project counts only within the tolerance, and says so', () => {
    const started = NOW - 60_000;
    const within = makeTempDir('guardian-hb-');
    seed(within, mark({ host_pids: [777], at: iso(started - (TOLERANCE_MS - 1_000)) }));
    expect(status(within, { serverStartedAt: started }).hooks).toMatchObject({ state: 'running', matched_by: 'time' });

    const tooOld = makeTempDir('guardian-hb-');
    seed(tooOld, mark({ host_pids: [777], at: iso(started - (TOLERANCE_MS + 1_000)) }));
    expect(status(tooOld, { serverStartedAt: started }).hooks.state).toBe('not_observed');

    const otherProject = makeTempDir('guardian-hb-');
    seed(otherProject, mark({ host_pids: [777], project: projectKey(OTHER_ROOT) }));
    expect(status(otherProject, { serverStartedAt: started }).hooks.state).toBe('not_observed');
  });

  it('T-05 hooks expected, no mark, past the grace period: not_observed, with a warning that says what is unguarded and what to check', () => {
    const r = status(makeTempDir('guardian-hb-'), { serverStartedAt: NOW - (GRACE_MS + 1_000) });
    expect(r.hooks.state).toBe('not_observed');
    expect(r.hooks.matched_by).toBeUndefined();
    const warning = r.warning ?? '';
    expect(warning).toMatch(/no dev-guardian hook/i);
    expect(warning).toMatch(/not (?:being )?assessed/i);
    // What the user can check: the Claude Code version, the node the hooks find, Claude Code's hook settings.
    expect(warning).toMatch(/Claude Code version/i);
    expect(warning).toMatch(/\bnode\b/);
    expect(warning).toMatch(/settings/i);
  });

  it('T-06 inside the grace period there is no warning yet: pending', () => {
    const young = status(makeTempDir('guardian-hb-'), { serverStartedAt: NOW - (GRACE_MS - 1_000) });
    expect(young.hooks.state).toBe('pending');
    expect(young.warning).toBeNull();
    // At the limit itself the grace is over.
    expect(status(makeTempDir('guardian-hb-'), { serverStartedAt: NOW - GRACE_MS }).hooks.state).toBe('not_observed');
  });

  it("T-07 a server that was not started as the plugin's own expects no hooks: not_applicable, whatever marks exist", () => {
    const dataDir = makeTempDir('guardian-hb-');
    seed(dataDir, mark());
    const r = status(dataDir, {
      expected: { expected: false, reason: "not started as a Claude Code plugin's server" },
      client: { name: 'cursor-vscode', version: '1.9.0' },
    });
    expect(r.hooks.state).toBe('not_applicable');
    expect(r.hooks.reason).toMatch(/plugin/);
    expect(r.hooks.host).toBe('cursor-vscode 1.9.0');
    expect(r.warning).toBeNull();

    // What makes them expected: CLAUDE_PLUGIN_ROOT naming the root this server runs from.
    const here = process.platform === 'win32' ? 'C:\\plugins\\dev-guardian' : '/plugins/dev-guardian';
    expect(pluginServerExpected({}, here).expected).toBe(false);
    expect(pluginServerExpected({ CLAUDE_PLUGIN_ROOT: process.platform === 'win32' ? 'C:\\plugins\\other' : '/plugins/other' }, here).expected).toBe(false);
    expect(pluginServerExpected({ CLAUDE_PLUGIN_ROOT: here }, here).expected).toBe(true);
    expect(pluginServerExpected({ CLAUDE_PLUGIN_ROOT: `${here}${process.platform === 'win32' ? '\\' : '/'}` }, here).expected).toBe(true);
    expect(pluginServerExpected({ CLAUDE_PLUGIN_ROOT: 'c:/PLUGINS/dev-guardian' }, 'C:\\plugins\\dev-guardian', 'win32').expected).toBe(true);
    expect(pluginServerExpected({ CLAUDE_PLUGIN_ROOT: '/Plugins/Dev-Guardian' }, '/plugins/dev-guardian', 'linux').expected).toBe(false);
  });

  it('T-08 a Claude Code older than 2.1.139 is named as the likely cause, and no other version is', () => {
    const at = { serverStartedAt: NOW - 60_000 };
    const unknown = status(makeTempDir('guardian-hb-'), at).warning ?? '';
    const old = status(makeTempDir('guardian-hb-'), { ...at, client: { name: 'claude-code', version: '2.1.138' } }).warning ?? '';
    expect(old).toContain('2.1.138');
    expect(old).not.toBe(unknown);
    for (const version of ['2.1.139', '2.1.322', '3.0.0', 'not-a-version']) {
      const r = status(makeTempDir('guardian-hb-'), { ...at, client: { name: 'claude-code', version } });
      expect(r.warning, version).toBe(unknown);
      expect(r.hooks.host, version).toBe(`claude-code ${version}`);
    }
  });

  it('T-11 a data directory no mark could be written to, and no mark: unknown, never "not observed"', () => {
    const r = status(makeTempDir('guardian-hb-'), { writable: () => 'it is not writable (EACCES)' });
    expect(r.hooks.state).toBe('unknown');
    expect(r.hooks.reason).toMatch(/not writable/);
    expect(r.warning).toBeNull();

    // A mark that is there still counts: the directory was writable when the hook ran.
    const dataDir = makeTempDir('guardian-hb-');
    seed(dataDir, mark());
    expect(status(dataDir, { writable: () => 'it is not writable (EACCES)' }).hooks.state).toBe('running');

    // The real probe: a data directory that is a file.
    const file = join(makeTempDir('guardian-hb-'), 'not-a-directory');
    writeFileSync(file, 'x');
    const probed = hooksStatus({
      expected: { expected: true, reason: "started as the plugin's server" },
      dataDir: file,
      projectRoot: ROOT,
      hostPids: [HOST],
      serverStartedAt: NOW - 60_000,
      now: NOW,
    });
    expect(probed.hooks.state).toBe('unknown');
    expect(probed.warning).toBeNull();
  });

  it('T-12 nothing health_status shows says how a hook or a guard is switched off', () => {
    const switches = /disableAllHooks|GUARDIAN_HOOKS|GUARDIAN_PKG_VET|bash\.block|"enabled"|hooks\.json|hooks\.config/;
    const versions = [undefined, '2.1.0', '2.1.138', '2.1.139', '9.9.9'];
    const uptimes = [1_000, GRACE_MS - 1, GRACE_MS, 10 * 60_000];
    const expectations = [true, false];
    const marks: Array<HeartbeatMark | null> = [
      null,
      mark(),
      mark({ host_pids: [777] }),
      mark({ host_pids: [777], at: iso(NOW - 3 * 60 * 60 * 1000) }),
      mark({ at: iso(NOW + 10 * 60_000) }),
    ];
    let seen = 0;
    for (const version of versions) {
      for (const uptime of uptimes) {
        for (const expected of expectations) {
          for (const m of marks) {
            for (const writable of [null, 'it is not writable (EACCES)']) {
              const dataDir = makeTempDir('guardian-hb-');
              if (m !== null) seed(dataDir, m);
              const r = status(dataDir, {
                expected: { expected, reason: expected ? "started as the plugin's server" : 'not a plugin server' },
                serverStartedAt: NOW - uptime,
                writable: () => writable,
                ...(version !== undefined ? { client: { name: 'claude-code', version } } : {}),
              });
              expect(r.hooks.state).not.toBe('disabled_by_user');
              expect(shown(r), `${String(version)} ${String(uptime)} ${String(expected)}`).not.toMatch(switches);
              seen += 1;
            }
          }
        }
      }
    }
    expect(seen).toBe(versions.length * uptimes.length * expectations.length * marks.length * 2);

    // The one state that names a setting names the one in force, and still not how to change it.
    const off = makeTempDir('guardian-hb-');
    seed(off, mark({ state: 'disabled', disabled_by: 'GUARDIAN_HOOKS' }));
    const r = status(off);
    expect(r.hooks).toMatchObject({ state: 'disabled_by_user', matched_by: 'host_process' });
    expect(r.hooks.disabled_by).toMatch(/GUARDIAN_HOOKS/);
    expect(r.warning).toBeNull();
    expect(shown(r)).not.toMatch(/=\s*off|set it|unset|export /i);
    const byFile = makeTempDir('guardian-hb-');
    seed(byFile, mark({ state: 'disabled', disabled_by: 'user-config' }));
    expect(status(byFile).hooks.disabled_by).toMatch(/user/i);
  });

  it('T-16 a mark that cannot be read or validated counts as absent, never as proof', () => {
    const absent = (prepare: (dataDir: string) => void): string => {
      const dataDir = makeTempDir('guardian-hb-');
      prepare(dataDir);
      return status(dataDir).hooks.state;
    };
    const name = markFileName(projectKey(ROOT), HOST);

    expect(absent((d) => mkdirSync(join(d, HEARTBEAT_DIR, name), { recursive: true })), 'a directory named as the mark').toBe('not_observed');
    expect(absent((d) => seed(d, mark(), { content: 'not json {' })), 'not JSON').toBe('not_observed');
    expect(absent((d) => seed(d, mark(), { content: JSON.stringify({ ...mark(), host_pids: 'x' }) })), 'host_pids of the wrong type').toBe('not_observed');
    expect(absent((d) => seed(d, mark(), { content: JSON.stringify({ ...mark(), at: 12345 }) })), 'at of the wrong type').toBe('not_observed');
    expect(absent((d) => seed(d, mark(), { content: JSON.stringify({ ...mark(), v: 2 }) })), 'another version of the mark').toBe('not_observed');
    expect(absent((d) => seed(d, mark({ at: iso(NOW + TOLERANCE_MS + 1_000) }))), 'a date past the tolerance').toBe('not_observed');
    expect(absent((d) => seed(d, mark({ at: iso(NOW + TOLERANCE_MS - 1_000) }))), 'a date within the tolerance').toBe('running');
    expect(absent((d) => seed(d, mark(), { content: JSON.stringify({ ...mark(), pad: 'x'.repeat(64 * 1024) }) })), 'over the read cap').toBe('not_observed');
    // The name says host 4242, the content another: a file renamed into place.
    expect(absent((d) => seed(d, mark({ host_pids: [1] }), { pid: HOST })), 'a name that is not its content').toBe('not_observed');
    expect(absent((d) => seed(d, mark({ project: projectKey(OTHER_ROOT) }), { project: projectKey(ROOT) })), 'a project that is not its name').toBe('not_observed');
  });

  it('T-18 only health_status reads the mark, and nothing else in src/ names it', () => {
    const src = fileURLToPath(new URL('../../../src', import.meta.url));
    const mentions: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const path = join(dir, entry.name);
        if (entry.isDirectory()) walk(path);
        else if (entry.name.endsWith('.ts') && /hooksStatus|pluginServerExpected|HEARTBEAT_DIR|hooks-heartbeat/.test(readFileSync(path, 'utf8'))) {
          mentions.push(relative(src, path).replace(/\\/g, '/'));
        }
      }
    };
    walk(src);
    expect(mentions.sort()).toEqual(['hooks/heartbeat.ts', 'tools/healthStatus.ts']);
  });

  it('T-19 a mark that is not this session\'s is refused as proof: copied from another process, shipped with the project, or waiting in a redirected data directory', () => {
    // Copied in: another host process, an old date.
    const copied = makeTempDir('guardian-hb-');
    seed(copied, mark({ host_pids: [777], at: iso(NOW - 2 * 60 * 60 * 1000) }));
    expect(status(copied).hooks.state).toBe('not_observed');
    expect(status(copied).warning).not.toBeNull();

    // Shipped with the project: nothing under the project is a mark, however well it is named.
    const project = makeTempDir('guardian-hb-project-');
    const shipped = join(project, '.guardian');
    seed(shipped, mark({ project: projectKey(project) }));
    expect(status(makeTempDir('guardian-hb-'), { projectRoot: project }).hooks.state).toBe('not_observed');

    // The data directory redirected INTO the project, where marks were waiting — one of them, written a
    // moment ago, even names this session's host process (a repository can ship one for every plausible
    // id). Nothing inside the project is proof: the state is what it would be with no mark, warning included.
    seed(shipped, mark({ project: projectKey(project), host_pids: [777], at: iso(NOW - 24 * 60 * 60 * 1000) }));
    const redirected = status(shipped, { projectRoot: project });
    expect(redirected.hooks.state).toBe('not_observed');
    expect(redirected.hooks.matched_by).toBeUndefined();
    expect(redirected.warning).toMatch(/inside the project/);
    // Nor can what the project put in the data directory's place change the answer: pointed at a FILE of
    // the project it is not even probed — "unknown" would be the quiet state, and this one must warn.
    const decoy = join(project, 'not-a-directory');
    writeFileSync(decoy, 'x');
    const probed = hooksStatus({
      expected: { expected: true, reason: "started as the plugin's server" },
      dataDir: decoy,
      projectRoot: project,
      hostPids: [HOST],
      serverStartedAt: NOW - 60_000,
      now: NOW,
    });
    expect(probed.hooks.state).toBe('not_observed');
    expect(probed.warning).toMatch(/inside the project/);
    // The same marks in a data directory outside the project do count: the refusal is about where they are.
    const outside = makeTempDir('guardian-hb-');
    seed(outside, mark({ project: projectKey(project) }));
    expect(status(outside, { projectRoot: project }).hooks.state).toBe('running');
  });
});

describe('the session mark: writing it', () => {
  it('T-15 nothing is asked of the filesystem about a data directory on the network', async () => {
    for (const dataDir of ['\\\\10.255.255.1\\share\\dev-guardian', '//10.255.255.1/share/dev-guardian', '\\\\?\\UNC\\10.255.255.1\\share\\dg']) {
      const { fs, calls } = spyFs();
      const started = Date.now();
      const r = await writeHeartbeat(writeOptions(dataDir, { home: ROOT, fs }));
      expect(r.written, dataDir).toBe(false);
      expect(r.reason, dataDir).toMatch(/network/);
      expect(calls, dataDir).toEqual([]);
      expect(Date.now() - started, dataDir).toBeLessThan(hangBound(1_000));
    }
  });

  it.skipIf(!CAN_SYMLINK)('T-15 a link on the way to the data directory that leaves for the network: no write is tried', async () => {
    const home = makeTempDir('guardian-hb-home-');
    symlinkSync(process.platform === 'win32' ? '\\\\10.255.255.1\\share' : '//10.255.255.1/share', join(home, 'data'), 'dir');
    const { fs, calls } = spyFs();
    const started = Date.now();
    const r = await writeHeartbeat(writeOptions(join(home, 'data', 'dev-guardian'), { home, fs }));
    expect(r.written).toBe(false);
    expect(calls.filter((c) => ['mkdir', 'writeFile', 'rename'].includes(c.op))).toEqual([]);
    expect(Date.now() - started).toBeLessThan(hangBound(1_000));
  });

  it('T-17 the mark is written to a temporary file opened exclusively and renamed into place; what is already there is replaced, never opened', async () => {
    const dataDir = join(makeTempDir('guardian-hb-'), 'dev-guardian');
    const { fs, calls } = spyFs();
    const r = await writeHeartbeat(writeOptions(dataDir, { fs }));
    expect(r.written, r.reason).toBe(true);
    const dir = join(dataDir, HEARTBEAT_DIR);
    const final = join(dir, markFileName(projectKey(ROOT), HOST));
    expect(r.file).toBe(final);

    const write = calls.find((c) => c.op === 'writeFile');
    const rename = calls.find((c) => c.op === 'rename');
    expect(write, 'one exclusive write').toBeDefined();
    expect(rename, 'one rename').toBeDefined();
    const temp = String(write?.args[0]);
    expect(dirname(temp)).toBe(dir);
    expect(temp).not.toBe(final);
    expect(write?.args[2]).toMatchObject({ flag: 'wx', mode: 0o600 });
    expect(rename?.args).toEqual([temp, final]);
    expect(calls.findIndex((c) => c.op === 'writeFile')).toBeLessThan(calls.findIndex((c) => c.op === 'rename'));
    // Nothing writes the final name directly, and no temporary is left behind.
    expect(calls.filter((c) => c.op === 'writeFile' && c.args[0] === final)).toEqual([]);
    expect(readdirSync(dir)).toEqual([markFileName(projectKey(ROOT), HOST)]);

    const written = JSON.parse(readFileSync(final, 'utf8')) as HeartbeatMark;
    expect(written).toEqual({ v: 1, at: iso(NOW), plugin_version: '3.9.0', source: 'startup', host_pids: [HOST], project: projectKey(ROOT), state: 'active' });
    if (POSIX) {
      expect(statSync(final).mode & 0o777).toBe(0o600);
      expect(statSync(dir).mode & 0o777).toBe(0o700);
    }

    // CLAUDE_PID, when it is a number, comes first; the parent stays.
    expect(hostPidsOf({ CLAUDE_PID: '9001' }, HOST)).toEqual([9001, HOST]);
    expect(hostPidsOf({ CLAUDE_PID: String(HOST) }, HOST)).toEqual([HOST]);
    expect(hostPidsOf({ CLAUDE_PID: 'x; rm' }, HOST)).toEqual([HOST]);
    expect(hostPidsOf({}, HOST)).toEqual([HOST]);
  });

  it.skipIf(!CAN_SYMLINK)('T-17 a symbolic link named as the mark is replaced, and what it pointed at is left alone', async () => {
    const base = makeTempDir('guardian-hb-');
    const dataDir = join(base, 'dev-guardian');
    const dir = join(dataDir, HEARTBEAT_DIR);
    mkdirSync(dir, { recursive: true });
    const target = join(base, 'elsewhere.txt');
    writeFileSync(target, 'keep me');
    const final = join(dir, markFileName(projectKey(ROOT), HOST));
    symlinkSync(target, final);

    expect((await writeHeartbeat(writeOptions(dataDir))).written).toBe(true);
    expect(lstatSync(final).isSymbolicLink()).toBe(false);
    expect(lstatSync(final).isFile()).toBe(true);
    expect(readFileSync(target, 'utf8')).toBe('keep me');
  });

  it.skipIf(!POSIX)('T-17 a FIFO named as the mark is replaced at once (POSIX only: Windows has no FIFOs)', async () => {
    const dataDir = join(makeTempDir('guardian-hb-'), 'dev-guardian');
    const dir = join(dataDir, HEARTBEAT_DIR);
    mkdirSync(dir, { recursive: true });
    const final = join(dir, markFileName(projectKey(ROOT), HOST));
    execFileSync('mkfifo', [final]);
    const started = Date.now();
    expect((await writeHeartbeat(writeOptions(dataDir))).written).toBe(true);
    expect(Date.now() - started).toBeLessThan(hangBound(1_000));
    expect(lstatSync(final).isFile()).toBe(true);
  });

  it('T-22 whatever its fields, a mark is at most 1 KiB', () => {
    const sources = [undefined, 'startup', 'resume', 'clear', 'compact', 'fork'] as const;
    const pids = [[1], [4294967295], [4294967295, 4294967294]];
    const versions = ['3.9.0', '3.10.0-rc.1+build.20261113', 'v'.repeat(40), 'v'.repeat(500)];
    const states = [{ state: 'active' as const }, { state: 'disabled' as const, disabled_by: 'GUARDIAN_HOOKS' as const }, { state: 'disabled' as const, disabled_by: 'user-config' as const }];
    let checked = 0;
    for (const source of sources) {
      for (const host_pids of pids) {
        for (const plugin_version of versions) {
          for (const s of states) {
            const text = serializeMark(mark({ host_pids, plugin_version, ...s, ...(source !== undefined ? { source } : {}) }));
            expect(Buffer.byteLength(text, 'utf8'), `${String(source)} ${plugin_version.length}`).toBeLessThanOrEqual(MARK_MAX_BYTES);
            expect(() => JSON.parse(text) as unknown).not.toThrow();
            checked += 1;
          }
        }
      }
    }
    expect(checked).toBe(sources.length * pids.length * versions.length * states.length);
  });
});

describe('the session mark: cleaning up', () => {
  const DAY = 24 * 60 * 60 * 1000;

  /** A mark of host `pid`, last written `age` ms before NOW. */
  function aged(dataDir: string, pid: number, age: number): string {
    const file = seed(dataDir, mark({ host_pids: [pid], at: iso(NOW - age) }));
    utimesSync(file, new Date(NOW - age), new Date(NOW - age));
    return file;
  }

  it('T-21 marks over 30 days old go, at most 64 a run, and so do those of host processes that no longer exist', async () => {
    const dataDir = makeTempDir('guardian-hb-');
    const dir = join(dataDir, HEARTBEAT_DIR);
    const old = aged(dataDir, 1001, MAX_AGE_MS + DAY);
    const recent = aged(dataDir, 1002, MAX_AGE_MS - DAY);
    expect(await pruneHeartbeats(dir, { now: NOW, isAlive: () => true })).toBe(1);
    expect(readdirSync(dir)).toEqual([markFileName(projectKey(ROOT), 1002)]);
    expect(old).not.toBe(recent);

    // EC-4: a host process that is gone leaves a mark a recycled id could match — it goes at once.
    const dead = makeTempDir('guardian-hb-');
    aged(dead, 2001, 60_000);
    aged(dead, 2002, 60_000);
    expect(await pruneHeartbeats(join(dead, HEARTBEAT_DIR), { now: NOW, isAlive: (pid) => pid !== 2001 })).toBe(1);
    expect(readdirSync(join(dead, HEARTBEAT_DIR))).toEqual([markFileName(projectKey(ROOT), 2002)]);

    // The mark just written is kept whatever is said of its process.
    const kept = makeTempDir('guardian-hb-');
    const mine = aged(kept, 3001, 1_000);
    expect(await pruneHeartbeats(join(kept, HEARTBEAT_DIR), { now: NOW, isAlive: () => false, keep: mine })).toBe(0);

    const many = makeTempDir('guardian-hb-');
    for (let pid = 5000; pid < 5100; pid += 1) aged(many, pid, MAX_AGE_MS + DAY);
    expect(await pruneHeartbeats(join(many, HEARTBEAT_DIR), { now: NOW, isAlive: () => true })).toBe(PRUNE_MAX);
    expect(readdirSync(join(many, HEARTBEAT_DIR))).toHaveLength(100 - PRUNE_MAX);
  });

  it('T-24 the cleanup removes its own marks and nothing else', async () => {
    const dataDir = makeTempDir('guardian-hb-');
    const dir = join(dataDir, HEARTBEAT_DIR);
    mkdirSync(dir, { recursive: true });
    const longAgo = new Date(NOW - MAX_AGE_MS - DAY);
    const outside = join(dataDir, markFileName(projectKey(ROOT), 6001));
    const others = [
      join(dir, 'notes.txt'),
      join(dir, 'p0123456789abcdef.h12.json.bak'),
      join(dir, 'P0123456789ABCDEF.H12.JSON'),
      join(dir, 'p0123.h12.json'),
      outside,
    ];
    for (const file of others) {
      writeFileSync(file, 'x');
      utimesSync(file, longAgo, longAgo);
    }
    const asDirectory = join(dir, markFileName(projectKey(ROOT), 6002));
    mkdirSync(asDirectory);
    utimesSync(asDirectory, longAgo, longAgo);
    const linked = join(dir, markFileName(projectKey(ROOT), 6003));
    const target = join(dataDir, 'target.txt');
    writeFileSync(target, 'keep me');
    if (CAN_SYMLINK) symlinkSync(target, linked);

    const { fs, calls } = spyFs();
    expect(await pruneHeartbeats(dir, { now: NOW, isAlive: () => false, fs })).toBe(0);
    for (const file of others) expect(statSync(file).isFile(), file).toBe(true);
    expect(statSync(asDirectory).isDirectory()).toBe(true);
    expect(readFileSync(target, 'utf8')).toBe('keep me');
    if (CAN_SYMLINK) expect(lstatSync(linked).isSymbolicLink()).toBe(true);
    // Nothing outside its own directory is even looked at.
    for (const call of calls) {
      const path = String(call.args[0]);
      expect(path === dir || dirname(path) === dir, `${call.op} ${path}`).toBe(true);
    }

    // A removal that fails does not stop the others, and does not throw.
    const failing = makeTempDir('guardian-hb-');
    const a = seed(failing, mark({ host_pids: [7001] }));
    const b = seed(failing, mark({ host_pids: [7002] }));
    for (const f of [a, b]) utimesSync(f, longAgo, longAgo);
    const stubborn = spyFs();
    const unlink = stubborn.fs.unlink;
    stubborn.fs.unlink = (path: string) => (path === a ? Promise.reject(Object.assign(new Error('EPERM'), { code: 'EPERM' })) : unlink(path));
    expect(await pruneHeartbeats(join(failing, HEARTBEAT_DIR), { now: NOW, isAlive: () => true, fs: stubborn.fs })).toBe(1);
    expect(readdirSync(join(failing, HEARTBEAT_DIR))).toEqual([markFileName(projectKey(ROOT), 7001)]);
  });
});
