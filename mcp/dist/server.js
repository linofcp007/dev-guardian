#!/usr/bin/env node
// The dev-guardian MCP server: started from the engine bundle (mcp/src/engine.ts), built by `npm run build`.
import { existsSync, lstatSync, mkdirSync } from 'node:fs';
import module from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// compile-cache:begin — the same in hooks/guardian-hook.mjs, cli/dev-guardian.mjs and
// dist/server.js (mcp/scripts/bundleOptions.mjs, SERVER_JS); hooksDispatcher.test.ts holds them equal.
/**
 * Where Node's on-disk compile cache may live: `undefined` for Node's own
 * default, `null` for no cache at all. Never a temp directory that is not
 * there (Node creates the cache's directory with every missing parent, and a
 * TMPDIR that is not there must stay not there). On Windows, Node's default
 * under the account's own `%TEMP%`. Elsewhere, a directory of this account's
 * own in the temp directory, made `0700` and used only when it is a directory
 * this account owns that nobody else can write: in a temp directory every
 * account shares (Linux's `/tmp`), Node's default `node-compile-cache/<version>-<uid>`
 * is used as it is found — another account can create it first, writable,
 * and plant compiled code this process then runs (measured, Node 22.13 and 24).
 *
 * @returns {string | null | undefined}
 */
function compileCacheDir() {
  const tmp = tmpdir();
  if (!existsSync(tmp)) return null;
  if (process.platform === 'win32') return undefined;
  const uid = process.getuid?.() ?? -1;
  const dir = join(tmp, `dev-guardian-node-compile-cache-${uid}`);
  try {
    mkdirSync(dir, { mode: 0o700 });
  } catch (err) {
    if (/** @type {NodeJS.ErrnoException} */ (err).code !== 'EEXIST') return null;
  }
  const st = lstatSync(dir);
  return st.isDirectory() && st.uid === uid && (st.mode & 0o077) === 0 ? dir : null;
}
try {
  const dir = compileCacheDir();
  if (dir !== null) module.enableCompileCache?.(dir);
} catch {
  /* no cache: it only runs slower */
}
// compile-cache:end

const engine = await import('./engine.js');
module.flushCompileCache?.();
await engine.startServer();
