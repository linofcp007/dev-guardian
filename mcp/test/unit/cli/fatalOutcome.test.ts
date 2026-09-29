/**
 * `fatalOutcome`, exported from `cli/dev-guardian.mjs`: what the CLI's
 * last-resort handler (`fatal`, the `.catch` on every async subcommand)
 * prints, and its exit code.
 *
 * A `GuardianDbError` (`mcp/src/storage/dbError.ts`) is not an unexpected
 * error: it is a database dev-guardian cannot use, said in one line that
 * names the file and what to do. The handler used to print every rejection as
 * `dev-guardian: unexpected error: <message>` — which, for this one, reads as
 * a crash in dev-guardian rather than as the condition it names. It is now
 * printed alone, with exit 3: what `status` and `dashboard` already exit with
 * when they refuse an unusable database themselves.
 */

import { describe, expect, it } from 'vitest';

import { GuardianDbError } from '../../../src/storage/dbError.js';

// mcp/test/unit/cli -> ../../../.. -> repo root -> cli/dev-guardian.mjs
const { fatalOutcome } = await import('../../../../cli/dev-guardian.mjs');

describe('fatalOutcome', () => {
  it('prints a GuardianDbError as its own message, never as an unexpected error, and exits 3', () => {
    const message = "the database 'C:\\p\\.guardian\\guardian.db' cannot be read (file is not a database)";
    const out = fatalOutcome(new GuardianDbError('corrupt', 'C:\\p\\.guardian\\guardian.db', message, 'file is not a database'));
    expect(out.text).toBe(`dev-guardian: ${message}\n`);
    expect(out.text).not.toMatch(/unexpected/);
    expect(out.exitCode).toBe(3);
  });

  it('recognises it by name too — the CLI loads the storage layer lazily, from mcp/dist', () => {
    const e = new Error("'/home/u/.local/share/dev-guardian' is not a directory");
    e.name = 'GuardianDbError';
    expect(fatalOutcome(e)).toEqual({ text: `dev-guardian: ${e.message}\n`, exitCode: 3 });
  });

  it('every kind: the message alone', () => {
    for (const kind of ['schema', 'corrupt', 'untrusted', 'data-dir'] as const) {
      const out = fatalOutcome(new GuardianDbError(kind, '/x', `problem of kind ${kind}`));
      expect(out.text, kind).toBe(`dev-guardian: problem of kind ${kind}\n`);
    }
  });

  it('anything else is still an unexpected error, exit 3', () => {
    expect(fatalOutcome(new TypeError('boom'))).toEqual({ text: 'dev-guardian: unexpected error: boom\n', exitCode: 3 });
    expect(fatalOutcome('a thrown string')).toEqual({
      text: 'dev-guardian: unexpected error: a thrown string\n',
      exitCode: 3,
    });
  });
});
