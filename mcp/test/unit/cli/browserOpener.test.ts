/**
 * Unit test for `resolveOpenerCommand`, exported from `cli/dev-guardian.mjs`
 * — fix-round-1 addition (coordinator review of Task 6).
 *
 * Every OTHER test that touches this file invokes it as a real subprocess
 * (see `test/e2e/dashboardCli.test.ts`, `test/e2e/ciCliFixture.test.ts`),
 * deliberately — the file's own top-level code calls `main()` unconditionally
 * unless it detects it is being imported rather than run directly (see the
 * "entry-point guard" at the bottom of `cli/dev-guardian.mjs`), so importing
 * it here relies on that guard: without it, this import alone would run the
 * whole CLI against THIS TEST RUNNER's own argv/exit lifecycle.
 *
 * What a subprocess/e2e test structurally CANNOT prove is the shape of an
 * argv array that is never observed from outside the process (`dashboard`'s
 * browser opener only fires when stdout is a TTY, which `spawnSync`-driven
 * tests never are — see that file's own "never launches a browser" test).
 * This file exists for exactly that gap: it asserts on `resolveOpenerCommand`'s
 * pure, no-I/O return value directly, without ever spawning a process itself.
 *
 * Context (coordinator review, Important 1): the ORIGINAL implementation
 * spawned the literal string `'start'` on win32. `start` is a `cmd.exe`
 * BUILT-IN, not a standalone executable, so that spawn failed ENOENT on
 * every real Windows machine — confirmed directly, and separately reconfirmed
 * here structurally: a wrong implementation that reverts to `command: 'start'`
 * fails the win32 test below on the command name alone.
 */

import { describe, expect, it } from 'vitest';

// A plain relative specifier, not a hand-built `file://` URL: Vitest routes
// dynamic imports through Vite's own resolver (Vitest runs on Vite), and a
// manually constructed `pathToFileURL(...).href` for a path outside `mcp/`
// containing a space (this repo's own directory name has one) fails to
// resolve there even though the identical URL loads correctly under plain
// Node — confirmed directly. A relative specifier is what Vite's resolver
// is built around, and resolves correctly the same way `ciCliFixture.test.ts`
// and `dashboardCli.test.ts` already reach `cli/dev-guardian.mjs` (as a
// subprocess path, computed via `resolve`) without incident.
// mcp/test/unit/cli -> ../../../.. -> repo root -> cli/dev-guardian.mjs
const { resolveOpenerCommand } = await import('../../../../cli/dev-guardian.mjs');

describe('resolveOpenerCommand', () => {
  it('win32: spawns cmd.exe (a real executable), not the bare "start" builtin', () => {
    // The exact defect this test exists to catch: `start` alone is not
    // spawnable with shell:false (no start.exe on PATH). cmd.exe IS a real,
    // standalone executable.
    const { command } = resolveOpenerCommand('win32', 'C:\\p\\dashboard.html');
    expect(command).toBe('cmd.exe');
    expect(command).not.toBe('start');
  });

  it('win32: argv is exactly ["/c", "start", the empty-title placeholder, target] — four elements, in order', () => {
    const target = 'C:\\Users\\dev\\.guardian\\dashboard.html';
    const { args } = resolveOpenerCommand('win32', target);
    // The FULL shape, not a loose "contains" check — a wrong implementation
    // that drops the '""' empty-title argument (start would then treat
    // `target` itself as the window title and open nothing) or that joins
    // '/c start' into one combined string both fail this exact-array check.
    expect(args).toEqual(['/c', 'start', '""', target]);
  });

  it('darwin: spawns "open" with target as its sole argument', () => {
    const target = '/Users/dev/.guardian/dashboard.html';
    expect(resolveOpenerCommand('darwin', target)).toEqual({
      command: 'open',
      args: [target],
    });
  });

  it('linux (and any other platform value): spawns "xdg-open" with target as its sole argument', () => {
    const target = '/home/dev/.guardian/dashboard.html';
    expect(resolveOpenerCommand('linux', target)).toEqual({
      command: 'xdg-open',
      args: [target],
    });
    // Falls through to the same xdg-open branch for anything that is
    // neither win32 nor darwin — freebsd, sunos, aix, … — rather than
    // silently doing nothing for a platform this file has never enumerated.
    expect(resolveOpenerCommand('freebsd', target).command).toBe('xdg-open');
  });

  it.each([
    ['win32', 'C:\\Users\\dev name\\has & spaces\\a "quote" too.html'],
    ['darwin', '/Users/dev name/has & an ampersand/a "quote" too.html'],
    ['linux', '/home/dev name/has & an ampersand/a "quote" too.html'],
  ])(
    'security property (%s): a target containing shell metacharacters (& " spaces) reaches argv as ONE untouched element, never interpolated into a joined command string',
    (platform, target) => {
      // This is the property the coordinator's review named explicitly:
      // "argv is still an array and shell:false still holds — nothing is
      // interpolated into a command string." It is testable ONLY by giving
      // resolveOpenerCommand a target a shell would otherwise mangle (an
      // unescaped `&` starts a new command; unescaped spaces/quotes split
      // tokens) and confirming it survives byte-for-byte as its own array
      // element — never concatenated with '/c', 'start', or anything else
      // into a single string, which is what `shell: true` (or a hand-rolled
      // string command) would require and what this implementation must not
      // do.
      const { args } = resolveOpenerCommand(platform, target);
      // Exactly one element equals target, verbatim.
      const matches = args.filter((a: string) => a === target);
      expect(matches).toHaveLength(1);
      // No element merges target with anything else (would show up as a
      // longer string that CONTAINS target but isn't equal to it).
      for (const a of args) {
        if (a !== target) expect(a.includes(target)).toBe(false);
      }
    },
  );
});
