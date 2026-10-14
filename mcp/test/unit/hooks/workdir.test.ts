/**
 * `hooks/shell/workdir.ts` — where each command of a line runs, as the `cd`s
 * before it moved it (review of 3.4.0, findings 5 and 9): `may` for what a
 * deny must assume, `sure` for what the install vetting may skip on.
 */

import { describe, expect, it } from 'vitest';
import { splitShell } from '../../../src/hooks/shell/split.js';
import { cdOperand } from '../../../src/hooks/shell/paths.js';
import { workdirs, type Workdir } from '../../../src/hooks/shell/workdir.js';
import { expectLinear } from '../../helpers/timing.js';

/** Where the last command of `command` runs. */
function last(command: string, opts: { cdpath?: boolean } = {}): Workdir {
  const rows = workdirs(splitShell(command).statements, opts);
  const row = rows[rows.length - 1] ?? [];
  return row[row.length - 1] ?? { may: null, sure: null };
}

describe('workdirs — where a command runs', () => {
  it.each([
    ['npx x', [], []],
    ['cd web && npx x', ['web'], ['web']],
    ['cd web; npx x', ['web'], ['web']],
    ['cd web && cd src; npx x', ['web', 'src'], ['web', 'src']],
    ['cd -- web && npx x', ['web'], ['web']],
    ['cd -P ../web && npx x', ['../web'], ['../web']],
    ['cd /tmp/x && npx x', ['/tmp/x'], ['/tmp/x']],
    ['cd web; cd /abs; npx x', ['/abs'], ['/abs']],
    ['pushd web; popd; npx x', [], []],
    ['cd web; cd -; npx x', [], []],
    ['cd.. && npx x', ['..'], ['..']],
  ] as const)('%s → may %j, sure %j', (command, may, sure) => {
    expect(last(command)).toEqual({ may, sure });
  });

  it.each([
    'false && cd web; npx x',
    '[ -d nope ] && cd web; npx x',
    'true || cd web; npx x',
    'if false; then cd web; fi; npx x',
    'while false; do cd web; done; npx x',
    'for d in web; do cd $d; done; npx x',
    'f() { cd web; }; npx x',
    'function f { cd web; }; npx x',
    '{ cd web; } & npx x',
    '{ cd web; } | cat; npx x',
    'cd web | cat; npx x',
    'cd web && true & npx x',
    'cd web & npx x',
    'CDPATH=other cd web && npx x',
    'export CDPATH=other; cd web; npx x',
    'CDPATH=other; cd web; npx x',
  ])('%s → not surely moved there', (command) => {
    expect(last(command).sure === null || last(command).sure?.length === 0).toBe(true);
  });

  it('the command after `||` runs because the `cd` failed: not surely there', () => {
    expect(last('cd web || npx x').sure).toBeNull();
  });

  it('a subshell’s moves end with it; inside it they count', () => {
    const rows = workdirs(splitShell('echo $(cd web && pwd); npx x').statements);
    expect(rows[rows.length - 1]?.[0]).toEqual({ may: [], sure: [] });
    // A `(` at a statement's start is seen now (review 12, finding 5): its moves end with it.
    expect(last('(cd web && npm ci) && npx x')).toEqual({ may: [], sure: [] });
    const inside = workdirs(splitShell('x; (cd web && npx y)').statements);
    expect(inside[2]?.[0]).toEqual({ may: ['web'], sure: ['web'] });
  });

  // Review 12, finding 5: a statement-leading subshell, a `case` pattern and
  // PowerShell's `(1);` lost track of where the line was.
  it.each([
    ['(true); npx x', [], []],
    ['(cd web; ); npx x', [], []],
    ['case x in x) ;; esac; npx x', [], []],
    ['(1); npx x', [], []],
    ['(cd /; npx x)', ['/'], ['/']],
  ] as const)('%s → may %j, sure %j', (command, may, sure) => {
    expect(last(command)).toEqual({ may, sure });
  });

  it('splitShell marks the subshells a statement opens and closes, and a case pattern', () => {
    const fields = (command: string): unknown[] =>
      splitShell(command).statements.map((s) => [s.masked, s.opens, s.closes, s.casePattern]);
    const none = undefined;
    expect(fields('(true); x')).toEqual([['true', 1, none, none], ['x', none, none, none]]);
    expect(fields('(cd web; ); x')).toEqual([['cd web', 1, 1, none], ['x', none, none, none]]);
    expect(fields('x; (cd /tmp); y')).toEqual([['x', none, none, none], ['cd /tmp', 1, none, none], ['y', none, none, none]]);
    expect(fields('case x in x) ;; esac')).toEqual([['case x in x', none, none, true], ['esac', none, none, none]]);
  });

  it('a `)` whose `(` was never seen keeps the moves for a deny, and drops them for the vetting', () => {
    expect(last('cd web; x ) ; npx y')).toEqual({ may: ['web'], sure: null });
  });

  it('a target this cannot read is not known; a bare cd goes home — what a deny assumes', () => {
    for (const command of ['cd `pwd` && npx x', 'cd $(pwd) && npx x', 'cd ~bob && npx x', 'cd a b && npx x', 'popd && npx x']) {
      expect(last(command), command).toEqual({ may: null, sure: null });
    }
    // One variable and a plain path is kept for the shell guard to read (review 12, finding 16); never surely.
    for (const [command, step] of [['cd "$DIR" && npx x', '$DIR'], ['cd %TEMP% && npx x', '%TEMP%'], ['cd "$TEMP/../.." && npx x', '$TEMP/../..']] as const) {
      expect(last(command), command).toEqual({ may: [step], sure: null });
    }
    expect(last('eval cd / && npx x')).toEqual({ may: ['/'], sure: ['/'] });
    expect(last('cd && rm -rf *')).toEqual({ may: ['~'], sure: null });
    expect(last('cd - && npx x')).toEqual({ may: null, sure: null });
  });

  it('CDPATH in the environment: a bare name is not surely where it says, ./name and absolute paths are', () => {
    expect(last('cd web && npx x', { cdpath: true }).sure).toBeNull();
    expect(last('cd ./web && npx x', { cdpath: true }).sure).toEqual(['./web']);
    expect(last('cd /srv/web && npx x', { cdpath: true }).sure).toEqual(['/srv/web']);
  });

  it('PowerShell: Set-Location, sl and -Path move it the same way', () => {
    expect(last('Set-Location -Path web; npx x')).toEqual({ may: ['web'], sure: ['web'] });
    expect(last('sl web; npx x')).toEqual({ may: ['web'], sure: ['web'] });
    expect(last("cd /d 'C:\\work' && npx x")).toEqual({ may: ['C:\\work'], sure: ['C:\\work'] });
  });

  it('cdOperand reads the one operand past cd’s own flags', () => {
    expect(cdOperand(['-P', '--', 'web'])).toBe('web');
    expect(cdOperand(['/d', 'C:\\x'])).toBe('C:\\x');
    expect(cdOperand(['-Path', 'web'])).toBe('web');
    expect(cdOperand([])).toBeUndefined();
    expect(cdOperand(['a', 'b'])).toBeNull();
  });

  it.each([
    ['cd cd cd …', (n: number): string => 'cd a; '.repeat(n / 6)],
    ['pushd pushd …', (n: number): string => 'pushd a; '.repeat(n / 9)],
    ['( ( ( …', (n: number): string => `${'(cd a; '.repeat(n / 7)}x`],
    ['if if if …', (n: number): string => 'if x; then cd a; '.repeat(n / 17)],
  ])('%s: eight times the line costs well under 22.6 times as much', (label, make) => {
    expectLinear(label, (n) => workdirs(splitShell(make(n)).statements), 4_000);
  }, 120_000);
});
