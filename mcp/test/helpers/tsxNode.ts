/**
 * Running TypeScript SOURCE in a child process.
 *
 * Some storage and server behaviour only exists across processes — several
 * connections racing to create one database file, a second process holding a
 * write lock, the server's own stdout being closed under it. Those tests need
 * a real child that runs `src/`, not `dist/`: a test against `dist/` would
 * pass or fail on whatever was last built, not on the change being tested.
 *
 * `--import <tsx loader>` makes plain `node` run `.ts` files with the same
 * `.js`-suffixed relative imports the source uses. The loader is passed as an
 * absolute file URL, so the child's own working directory (usually a temp
 * project with no `node_modules`) does not affect how it resolves.
 */

import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const require = createRequire(import.meta.url);

/** `mcp/` — the package root, whatever the caller's cwd. */
export const MCP_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

/** Arguments to put before a `.ts` entry point in `spawn(process.execPath, …)`. */
export const TSX_NODE_ARGS: readonly string[] = ['--import', pathToFileURL(require.resolve('tsx')).href];
