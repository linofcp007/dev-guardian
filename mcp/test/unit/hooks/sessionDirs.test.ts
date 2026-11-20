/**
 * `hooks/sessionDirs.ts` and `hooks/folderProbe.ts` — which folders a hook call
 * works in, and the question "does this network folder answer?" that a child
 * process asks within a deadline (bugfix `hook-unc-cwd-hang`: a session or
 * project folder on a host that is down held the dispatcher 21 s).
 *
 * The disk and the probe are stand-ins here; the one real question (T-03) is
 * asked of local folders and of children that answer late or never. No path of
 * a network share is touched.
 */
import { join, sep } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { isNetworkPath } from '../../../src/hooks/configFile.js';
import { probeFolders } from '../../../src/hooks/folderProbe.js';
import {
  chooseSessionDirs,
  unreachableLines,
  type FolderAnswer,
  type FolderProbe,
  type UnreachableFolder,
} from '../../../src/hooks/sessionDirs.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';
import { hangBound } from '../../helpers/timing.js';

afterAll(cleanupTempDirs);

const BS = String.fromCharCode(92);
const LOCAL = join('work', 'local', 'project');
const PROCESS_DIR = join('work', 'hook', 'own');

/** The three spellings of a network path, `share` and `leaf` apart. */
const spelled = (leaf: string): string[] => [
  `${BS}${BS}h${BS}s${BS}${leaf}`,
  `//h/s/${leaf}`,
  `${BS}${BS}?${BS}UNC${BS}h${BS}s${BS}${leaf}`,
];

/** A disk that has nothing but `present`, and a probe that answers `answers` (a path not in it: `'silent'`). */
function stand(answers: Record<string, FolderAnswer>, present: readonly string[] = [LOCAL, PROCESS_DIR]) {
  const exists = vi.fn((path: string) => present.includes(path));
  const probe = vi.fn<FolderProbe>(async (paths) => new Map(paths.map((p): [string, FolderAnswer] => [p, answers[p] ?? 'silent'])));
  return { exists, probe, deps: { exists, probe, isNetworkPath } };
}

describe('hook-unc-cwd-hang', () => {
  describe('T-01 chooseSessionDirs asks about a network folder in a process of its own, and never opens it', () => {
    it.each(spelled('p'))('T-01 %s: a session and a project folder on the network go to one probe call, `exists` never sees them', async (cwdPath) => {
      const projectPath = cwdPath.slice(0, -1) + 'q';
      const { exists, probe, deps } = stand({ [cwdPath]: 'there', [projectPath]: 'there' });
      await chooseSessionDirs({ payloadCwd: cwdPath, envProjectDir: projectPath, processCwd: PROCESS_DIR }, deps);
      expect(exists.mock.calls.map(([p]) => p)).not.toContain(cwdPath);
      expect(exists.mock.calls.map(([p]) => p)).not.toContain(projectPath);
      expect(probe).toHaveBeenCalledTimes(1);
      const [asked, deadline] = probe.mock.calls[0] ?? [[], 0];
      expect([...asked].sort()).toEqual([cwdPath, projectPath].sort());
      expect(deadline).toBe(2000);
    });

    it('T-01 the same network path for both: one path in the question', async () => {
      const net = `${BS}${BS}h${BS}s${BS}p`;
      const { exists, probe, deps } = stand({ [net]: 'there' });
      await chooseSessionDirs({ payloadCwd: net, envProjectDir: net, processCwd: PROCESS_DIR }, deps);
      expect(probe).toHaveBeenCalledTimes(1);
      expect(probe.mock.calls[0]?.[0]).toEqual([net]);
      expect(exists.mock.calls.map(([p]) => p)).not.toContain(net);
    });

    it('T-01 only the project on the network: `exists` for the local session folder, the probe for the project', async () => {
      const net = `//h/s/p`;
      const { exists, probe, deps } = stand({ [net]: 'there' });
      await chooseSessionDirs({ payloadCwd: LOCAL, envProjectDir: net, processCwd: PROCESS_DIR }, deps);
      expect(exists.mock.calls.map(([p]) => p)).toContain(LOCAL);
      expect(exists.mock.calls.map(([p]) => p)).not.toContain(net);
      expect(probe).toHaveBeenCalledTimes(1);
      expect(probe.mock.calls[0]?.[0]).toEqual([net]);
    });

    it('T-01 only the session on the network: `exists` for the local project, the probe for the session folder', async () => {
      const net = `${BS}${BS}?${BS}UNC${BS}h${BS}s${BS}p`;
      const { exists, probe, deps } = stand({ [net]: 'there' });
      await chooseSessionDirs({ payloadCwd: net, envProjectDir: LOCAL, processCwd: PROCESS_DIR }, deps);
      expect(exists.mock.calls.map(([p]) => p)).toContain(LOCAL);
      expect(exists.mock.calls.map(([p]) => p)).not.toContain(net);
      expect(probe).toHaveBeenCalledTimes(1);
      expect(probe.mock.calls[0]?.[0]).toEqual([net]);
    });

    it('T-01 two local folders: no probe, `exists` as always', async () => {
      const { exists, probe, deps } = stand({});
      const dirs = await chooseSessionDirs({ payloadCwd: LOCAL, envProjectDir: PROCESS_DIR, processCwd: PROCESS_DIR }, deps);
      expect(probe).not.toHaveBeenCalled();
      expect(exists).toHaveBeenCalled();
      expect(dirs).toEqual({ cwd: LOCAL, projectDir: PROCESS_DIR, unreachable: [] });
    });
  });

  describe('T-02 chooseSessionDirs treats an answer per folder', () => {
    const SESSION = `${BS}${BS}h${BS}s${BS}p`;
    const PROJECT = `${BS}${BS}h2${BS}s2${BS}q`;

    it('T-02 "there": the folders are used as today, nothing is unreachable', async () => {
      const { probe, deps } = stand({ [SESSION]: 'there', [PROJECT]: 'there' });
      const dirs = await chooseSessionDirs({ payloadCwd: SESSION, envProjectDir: PROJECT, processCwd: PROCESS_DIR }, deps);
      expect(probe).toHaveBeenCalledTimes(1);
      expect(dirs).toEqual({ cwd: SESSION, projectDir: PROJECT, unreachable: [] });
    });

    const ways: Array<[string, FolderProbe | undefined]> = [
      ['"absent"', async (paths) => new Map(paths.map((p): [string, FolderAnswer] => [p, 'absent']))],
      ['"silent"', async (paths) => new Map(paths.map((p): [string, FolderAnswer] => [p, 'silent']))],
      ['no answer for the path', async () => new Map()],
      [
        'a probe that rejects',
        async () => {
          throw new Error('the child did not start');
        },
      ],
      [
        'a probe that throws before it returns a promise',
        (() => {
          throw new Error('permission model');
        }) as unknown as FolderProbe,
      ],
      ['a probe that is missing (its part did not load)', undefined],
    ];
    it.each(ways)('T-02 %s: the hook\'s own folder is the session, the project is ignored, both are reported with their role', async (_name, probe) => {
      const exists = vi.fn((p: string) => p === PROCESS_DIR);
      const dirs = await chooseSessionDirs(
        { payloadCwd: SESSION, envProjectDir: PROJECT, processCwd: PROCESS_DIR },
        { exists, isNetworkPath, probe },
      );
      expect(dirs.cwd).toBe(PROCESS_DIR);
      expect(dirs.projectDir).toBeUndefined();
      expect([...dirs.unreachable].sort((a, b) => a.path.localeCompare(b.path))).toEqual(
        [
          { path: SESSION, role: 'session' },
          { path: PROJECT, role: 'project' },
        ].sort((a, b) => a.path.localeCompare(b.path)),
      );
      expect(exists.mock.calls.map(([p]) => p)).not.toContain(SESSION);
      expect(exists.mock.calls.map(([p]) => p)).not.toContain(PROJECT);
    });

    it('T-02 the same unreachable path for both folders is one entry, with the role "both"', async () => {
      const { deps } = stand({ [SESSION]: 'silent' });
      const dirs = await chooseSessionDirs({ payloadCwd: SESSION, envProjectDir: SESSION, processCwd: PROCESS_DIR }, deps);
      expect(dirs.cwd).toBe(PROCESS_DIR);
      expect(dirs.projectDir).toBeUndefined();
      expect(dirs.unreachable).toEqual([{ path: SESSION, role: 'both' }]);
    });

    it('T-02 the session folder "absent" and the project "there" on the same share: the project is used', async () => {
      const session = `${BS}${BS}h${BS}s${BS}gone`;
      const project = `${BS}${BS}h${BS}s${BS}proj`;
      const { deps } = stand({ [session]: 'absent', [project]: 'there' });
      const dirs = await chooseSessionDirs({ payloadCwd: session, envProjectDir: project, processCwd: PROCESS_DIR }, deps);
      expect(dirs).toEqual({ cwd: PROCESS_DIR, projectDir: project, unreachable: [{ path: session, role: 'session' }] });
    });

    it('T-02 the session folder "silent" and the project "there" on another share: the project is used', async () => {
      const { deps } = stand({ [SESSION]: 'silent', [PROJECT]: 'there' });
      const dirs = await chooseSessionDirs({ payloadCwd: SESSION, envProjectDir: PROJECT, processCwd: PROCESS_DIR }, deps);
      expect(dirs).toEqual({ cwd: PROCESS_DIR, projectDir: PROJECT, unreachable: [{ path: SESSION, role: 'session' }] });
    });

    it('T-02 no CLAUDE_PROJECT_DIR and a session folder that is silent: the root is looked for from the hook\'s own folder', async () => {
      const { deps } = stand({ [SESSION]: 'silent' });
      const dirs = await chooseSessionDirs({ payloadCwd: SESSION, envProjectDir: undefined, processCwd: PROCESS_DIR }, deps);
      expect(dirs).toEqual({ cwd: PROCESS_DIR, projectDir: undefined, unreachable: [{ path: SESSION, role: 'session' }] });
    });

    it('T-02 a hook folder that is itself on the network is returned without a probe or `exists`', async () => {
      const own = `${BS}${BS}own${BS}s${BS}hook`;
      const { exists, probe, deps } = stand({ [SESSION]: 'silent' });
      const dirs = await chooseSessionDirs({ payloadCwd: SESSION, envProjectDir: undefined, processCwd: own }, deps);
      expect(dirs.cwd).toBe(own);
      expect(probe.mock.calls.flatMap(([paths]) => [...paths])).not.toContain(own);
      expect(exists.mock.calls.map(([p]) => p)).not.toContain(own);
    });
  });

  describe('T-03 probeFolders asks a child, within a deadline', () => {
    const wait = 'setTimeout(() => {}, 30000);';
    const answersFirstThenWaits = "require('node:fs').writeSync(1, '0 there\\n'); " + wait;

    it('T-03 a folder that exists (a space, a non-ASCII letter, a trailing separator), one that does not, and two in one call', async () => {
      const dir = makeTempDir('dg probe é ');
      const withSeparator = `${dir}${sep}`;
      const missing = join(dir, 'nope');
      expect((await probeFolders([withSeparator], 2000)).get(withSeparator)).toBe('there');
      expect((await probeFolders([missing], 2000)).get(missing)).toBe('absent');
      const both = await probeFolders([dir, missing], 2000);
      expect([...both.entries()]).toEqual([
        [dir, 'there'],
        [missing, 'absent'],
      ]);
    });

    it('T-03 a child that answers the first folder and then waits past the deadline: "there" for the first, "silent" for the second', async () => {
      const first = join('x', 'first');
      const second = join('x', 'second');
      const got = await probeFolders([first, second], 2000, { command: process.execPath, args: ['-e', answersFirstThenWaits] });
      expect(got.get(first)).toBe('there');
      expect(got.get(second)).toBe('silent');
    });

    it('T-03 a child that waits 30 s, with a deadline of 300 ms: "silent" for all, back within the hang bound', async () => {
      const paths = [join('x', 'a'), join('x', 'b')];
      const t0 = Date.now();
      const got = await probeFolders(paths, 300, { command: process.execPath, args: ['-e', wait] });
      expect(Date.now() - t0).toBeLessThan(hangBound(2000));
      expect(paths.map((p) => got.get(p))).toEqual(['silent', 'silent']);
    });

    it('T-03 a program that does not exist, and a path with a NUL character: "silent", no throw', async () => {
      const gone = join('x', 'a');
      const missingProgram = await probeFolders([gone], 2000, { command: join(makeTempDir('dg probe '), 'no-such-program'), args: [] });
      expect(missingProgram.get(gone)).toBe('silent');
      const nul = `a${String.fromCharCode(0)}b`;
      const withNul = await probeFolders([nul], 2000);
      expect(withNul.get(nul)).toBe('silent');
    });
  });

  describe('T-10 unreachableLines names the share and the role, and nothing the payload could smuggle in', () => {
    const one = (path: string, role: UnreachableFolder['role']): string => {
      const lines = unreachableLines([{ path, role }]);
      expect(lines).toHaveLength(1);
      return lines[0] ?? '';
    };
    const share = `${BS}${BS}fileserver${BS}docs`;
    /** What the line puts in parentheses as the share. */
    const named = (line: string): string => /\((\\\\[^)]*)\)/.exec(line)?.[1] ?? '';

    it('T-10 the role "session", "project" and "both"', () => {
      const session = one(`${share}${BS}p`, 'session');
      expect(session).toContain(share);
      expect(session).toMatch(/session's folder/);
      expect(session).not.toMatch(/project folder/);
      expect(session).toMatch(/not read/);
      const project = one(`${share}${BS}p`, 'project');
      expect(project).toContain(share);
      expect(project).toMatch(/project folder \(CLAUDE_PROJECT_DIR\)/);
      expect(project).not.toMatch(/session's folder/);
      expect(project).toMatch(/not read/);
      const both = one(`${share}${BS}p`, 'both');
      expect(both).toContain(share);
      expect(both).toMatch(/session's folder and the project folder/);
      expect(both).toMatch(/not read/);
    });

    it('T-10 two different shares: two lines', () => {
      const lines = unreachableLines([
        { path: `${BS}${BS}a${BS}one${BS}p`, role: 'session' },
        { path: `${BS}${BS}b${BS}two${BS}p`, role: 'project' },
      ]);
      expect(lines).toHaveLength(2);
      expect(lines[0]).toContain(`${BS}${BS}a${BS}one`);
      expect(lines[1]).toContain(`${BS}${BS}b${BS}two`);
    });

    it('T-10 a `\\\\?\\UNC\\h\\s\\p` path is named `\\\\h\\s`', () => {
      const line = one(`${BS}${BS}?${BS}UNC${BS}h${BS}s${BS}p`, 'session');
      expect(named(line)).toBe(`${BS}${BS}h${BS}s`);
      expect(line).not.toContain('UNC');
    });

    it('T-10 a host with a line break, a backtick or a space: those characters are not in the line', () => {
      const line = one(`${BS}${BS}ho\nst\`x y${BS}sh\nare${BS}p`, 'session');
      expect(line).not.toContain('\n');
      expect(line).not.toContain('`');
      expect(named(line)).toMatch(/^\\\\[A-Za-z0-9._$-]+\\[A-Za-z0-9._$-]+$/);
    });

    it('T-10 a host of 300 characters is cut to 64', () => {
      const line = one(`${BS}${BS}${'h'.repeat(300)}${BS}${'s'.repeat(300)}${BS}p`, 'session');
      const [host = '', shareName = ''] = named(line).slice(2).split(BS);
      expect(host).toBe('h'.repeat(64));
      expect(shareName).toBe('s'.repeat(64));
    });
  });
});
