/**
 * The pure half of the Windows tree kill: reading Git's `ps` and `grep`, and
 * choosing which MSYS processes are ours. The end-to-end half (a real Git
 * Bash `sleep` grandchild) is `processRunner.test.ts`.
 */
import { describe, expect, it } from 'vitest';
import {
  parseEnvironMatches,
  parseMsysPs,
  selectOwnMsysProcesses,
} from '../../../src/runners/windowsTreeKill.js';

// Real `ps` output from Git for Windows (trimmed), plus a stopped (`S`)
// process and a date-form STIME, the two shapes a naive split gets wrong.
const PS = [
  '      PID    PPID    PGID     WINPID   TTY         UID    STIME COMMAND',
  '   286088  285889  285887      97600  ?         197108 00:40:59 /c/Program Files/nodejs/node',
  '   291284       1  291284      70180  ?         197108 00:54:54 /usr/bin/bash',
  '   291285  291284  291284      75080  ?         197108 00:54:54 /usr/bin/sleep',
  '   291290  291284  291284      75099  ?         197108 00:54:55 /c/Program Files/semgrep/semgrep',
  '   291291  291284  291284      75100  ?         197108 00:54:55 /usr/bin/env',
  'S  291299  288721  288721     114604  ?         197108 00:54:56 /usr/bin/sleep',
  '      219       1     219      25708  ?         197108   Sep 23 /usr/bin/bash',
  '   285887       1  285887      74148  ?         197108 00:40:39 /usr/bin/bash',
].join('\n');

describe('parseMsysPs', () => {
  it('reads pid, group, Windows pid and command from every process line', () => {
    const rows = parseMsysPs(PS);
    expect(rows).toHaveLength(8);
    expect(rows.find((r) => r.winpid === 75080)).toEqual({
      pid: 291285,
      ppid: 291284,
      pgid: 291284,
      winpid: 75080,
      command: '/usr/bin/sleep',
    });
    expect(rows.find((r) => r.winpid === 114604)?.pgid).toBe(288721);
    expect(rows.find((r) => r.winpid === 25708)?.command).toBe('/usr/bin/bash');
    expect(rows.find((r) => r.winpid === 97600)?.command).toBe('/c/Program Files/nodejs/node');
  });
});

describe('parseEnvironMatches', () => {
  it('reads the MSYS pid out of each /proc/<pid>/environ match', () => {
    const out = '/proc/291284/environ\n/proc/291285/environ\r\n\n';
    expect([...parseEnvironMatches(out)]).toEqual([291284, 291285]);
  });
});

describe('selectOwnMsysProcesses', () => {
  const snapshot = parseMsysPs(PS);
  const self = { pid: 1, ppid: 2 };

  it('takes every token carrier and every member of its MSYS group', () => {
    // bash and sleep carry the token; semgrep (native) and an `env -i`
    // descendant do not, but share bash's group.
    const own = selectOwnMsysProcesses(snapshot, new Set([291284, 291285]), self);
    expect(own.msys.sort()).toEqual([70180, 75080, 75100].sort());
    expect(own.native).toEqual([75099]);
  });

  it('never touches a process that is neither a carrier nor in a carrier group', () => {
    const own = selectOwnMsysProcesses(snapshot, new Set([291285]), self);
    expect(own.msys).not.toContain(114604);
    expect(own.msys).not.toContain(25708);
    expect(own.msys).not.toContain(74148);
  });

  it('returns nothing when no process carries the token', () => {
    expect(selectOwnMsysProcesses(snapshot, new Set(), self)).toEqual({ msys: [], native: [] });
  });

  it("never touches the caller's own group, even if a member carried the token", () => {
    // node (97600) started from a Git Bash terminal is a member of that
    // terminal's group 285887; that group is off limits whatever happens.
    const own = selectOwnMsysProcesses(snapshot, new Set([285887]), { pid: 97600, ppid: 3 });
    expect(own).toEqual({ msys: [], native: [] });
  });
});
