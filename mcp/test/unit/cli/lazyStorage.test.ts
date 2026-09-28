/**
 * Unit tests for `isNodeSqliteUnavailable`, exported from
 * `cli/dev-guardian.mjs` — Task 5 of the 2026-09-25 full review, item 2.
 *
 * `storage/db.ts` requires `node:sqlite` at MODULE LOAD TIME via
 * `createRequire(import.meta.url)('node:sqlite')`. On a Node version below
 * this project's floor (>= 22.13, no `--experimental-sqlite` anywhere — see
 * Global Constraint 12), that throws `ERR_UNKNOWN_BUILTIN_MODULE`. This
 * predicate is what `loadDashboardModules()` (see `mcp/test/e2e/
 * cliLazyStorage.test.ts` for the behavioural half of this fix) uses to
 * decide between printing a friendly "requires Node.js >= 22.13" message and
 * re-throwing a genuine, unrelated failure inside `storage`/`dashboard`.
 *
 * See `browserOpener.test.ts` for why a relative specifier (not a hand-built
 * `file://` URL) is required to import a path outside `mcp/` under Vite's
 * resolver, and why the entry-point guard at the bottom of
 * `cli/dev-guardian.mjs` is what makes importing this file at all safe.
 */

import { describe, expect, it } from 'vitest';

// mcp/test/unit/cli -> ../../../.. -> repo root -> cli/dev-guardian.mjs
const { isNodeSqliteUnavailable } = await import('../../../../cli/dev-guardian.mjs');

describe('isNodeSqliteUnavailable', () => {
  it('matches Node\'s ERR_UNKNOWN_BUILTIN_MODULE code', () => {
    const err: NodeJS.ErrnoException = new Error('No such built-in module: node:sqlite');
    err.code = 'ERR_UNKNOWN_BUILTIN_MODULE';
    expect(isNodeSqliteUnavailable(err)).toBe(true);
  });

  it('matches on message alone when the code is absent (Node has reworded this error before)', () => {
    expect(isNodeSqliteUnavailable(new Error('node:sqlite is not supported in this build'))).toBe(true);
  });

  it('is case-insensitive on the message match', () => {
    expect(isNodeSqliteUnavailable(new Error('Node:Sqlite unavailable'))).toBe(true);
  });

  it('does NOT match an unrelated error — a real bug must not be misreported as a Node-version problem', () => {
    expect(isNodeSqliteUnavailable(new Error('ENOENT: no such file or directory'))).toBe(false);
    const codedErr: NodeJS.ErrnoException = new Error('some other builtin missing');
    codedErr.code = 'ERR_UNKNOWN_BUILTIN_MODULE';
    // Even with the matching code, an unrelated message alone (no code) must not match.
    expect(isNodeSqliteUnavailable(new Error('unrelated failure'))).toBe(false);
    // But the code alone IS sufficient regardless of message wording.
    expect(isNodeSqliteUnavailable(codedErr)).toBe(true);
  });

  it('handles a non-Error thrown value', () => {
    expect(isNodeSqliteUnavailable('plain string mentioning node:sqlite')).toBe(true);
    expect(isNodeSqliteUnavailable('unrelated plain string')).toBe(false);
  });
});
