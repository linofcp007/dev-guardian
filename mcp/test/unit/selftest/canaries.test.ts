/**
 * The secret canary is synthetic and is nowhere whole: neither the sources,
 * nor the shipped canaries, nor the bundles hold the string a scanner would
 * report — it is put together at run time (`src/selftest/canaries.ts`).
 */

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { scanForSecrets } from '../../../src/hooks/secretScan.js';
import { canaryToken, TOKEN_PLACEHOLDER } from '../../../src/selftest/canaries.js';

const REPO_ROOT = fileURLToPath(new URL('../../../..', import.meta.url));

/** Every file below `dir`. */
function filesBelow(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...filesBelow(path));
    else out.push(path);
  }
  return out;
}

describe('the secret canary', () => {
  it('T-17 has the format the rules look for, and the hooks own detector reports it', () => {
    const token = canaryToken();
    // An AWS access key id: the prefix, then 16 characters of base32.
    expect(token).toMatch(/^(AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}$/);
    // Not an example the scanners are told to ignore.
    expect(token).not.toMatch(/EXAMPLE/);
    const hits = scanForSecrets(`aws.accessKeyId=${token}\n`, { minConfidence: 'medium' });
    expect(hits.length).toBeGreaterThan(0);
  });

  it('T-17 the whole string is in no source, no shipped canary and no bundle', () => {
    const token = canaryToken();
    const places = [
      ...filesBelow(join(REPO_ROOT, 'mcp', 'src')),
      ...filesBelow(join(REPO_ROOT, 'configs', 'selftest')),
      ...filesBelow(join(REPO_ROOT, 'mcp', 'dist')).filter((f) => f.endsWith('.js')),
      join(REPO_ROOT, 'cli', 'dev-guardian.mjs'),
    ];
    expect(places.length).toBeGreaterThan(100);
    expect(places.some((f) => f.endsWith(join('dist', 'engine.js')))).toBe(true);
    const holding = places.filter((f) => readFileSync(f, 'utf8').includes(token));
    expect(holding).toEqual([]);
    // The seeded secret file is a template: the placeholder, never the token.
    const templates = filesBelow(join(REPO_ROOT, 'configs', 'selftest')).filter((f) => readFileSync(f, 'utf8').includes(TOKEN_PLACEHOLDER));
    expect(templates).toHaveLength(1);
  });
});
