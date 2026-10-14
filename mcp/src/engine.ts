/**
 * The engine bundle's entry: `scripts/bundle.mjs` builds this module into
 * `dist/engine.js`, the one self-contained file the MCP server and the CLI
 * both run (review 8, finding 2). They shared 98.8% of their code as two
 * separate 3.7 MB bundles; one bundle cannot ship the server and the CLI from
 * different builds, and halves what an install carries.
 *
 * - The CLI (`cli/dev-guardian.mjs`) imports it for everything `cli.ts`
 *   exports — the light helpers directly, the scan pipeline and the storage
 *   layer through its lazy `load*Modules()`.
 * - `dist/server.js` is a short file that turns the compile cache on, imports it and calls
 *   {@link startServer} (`scripts/bundleOptions.mjs#SERVER_JS`), so every path
 *   that names the server — `plugin.json`, the host configurations
 *   `mcp-config` writes — stays what it was.
 *
 * `startServer` reaches `server.ts` through a dynamic `import()`, which the
 * bundle keeps lazy (esbuild wraps a module reached only that way in an
 * initializer that runs on the first call, as for `cli.ts`'s loaders): the
 * CLI never evaluates the server's module graph — the SDK, every tool module — and
 * `server.ts` stays the entry `npm run dev` runs with tsx, starting itself on
 * import.
 */

export * from './cli.js';

/** Starts the MCP server on stdio: evaluates `server.ts`, whose top level runs its `main()`. */
export async function startServer(): Promise<void> {
  await import('./server.js');
}
