/**
 * Whether the plugin's engine bundle, `mcp/dist/engine.js` — what the MCP
 * server and the CLI run — is the one the build wrote, checked without loading
 * it (review of 3.3.0: with it missing or cut short, SessionStart still said
 * "active", and the MCP tools and the CLI could not start). The build defines
 * the engine's size and SHA-256 into the hooks bundle (`scripts/bundleOptions.mjs`,
 * `ENGINE_DIGEST`); outside a bundle (tsx, vitest) there is none, and only a
 * missing file is told.
 *
 * Reads the plugin's own file, never a project's.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

declare const __GUARDIAN_ENGINE_DIGEST__: { bytes: number; sha256: string } | undefined;

/** The digest the build wrote, or none outside a bundle. */
function builtDigest(): { bytes: number; sha256: string } | undefined {
  return typeof __GUARDIAN_ENGINE_DIGEST__ === 'undefined' ? undefined : __GUARDIAN_ENGINE_DIGEST__;
}

/**
 * What is wrong with `<distDir>/engine.js` — `missing`, `unreadable`, or
 * `damaged (…)` — or `null` when it is the build's.
 */
export function engineDamage(distDir: string, expected = builtDigest()): string | null {
  let bytes: Buffer;
  try {
    bytes = readFileSync(join(distDir, 'engine.js'));
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === 'ENOENT' ? 'missing' : 'unreadable';
  }
  if (expected === undefined) return null;
  if (bytes.length !== expected.bytes) return `damaged (${bytes.length} bytes, where the build wrote ${expected.bytes})`;
  if (createHash('sha256').update(bytes).digest('hex') !== expected.sha256) return 'damaged (its content is not what the build wrote)';
  return null;
}
