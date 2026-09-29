/**
 * SECURITY.md's "Supported versions" table names the release line that gets
 * security fixes. After 3.0.0 it still said 2.0.x (review 3.0, round 2):
 * the table was a literal nobody bumped with a release. It is held here to
 * the version `.claude-plugin/plugin.json` reports — the one the MCP server
 * reports at runtime — so the next release that forgets it fails.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { REPO_ROOT } from './pluginDocs.js';

const version = (JSON.parse(readFileSync(resolve(REPO_ROOT, '.claude-plugin', 'plugin.json'), 'utf8')) as { version: string })
  .version;
const line = version.split('.').slice(0, 2).join('.');
const security = readFileSync(resolve(REPO_ROOT, 'SECURITY.md'), 'utf8');
const rows = security
  .slice(security.indexOf('## Supported versions'), security.indexOf('## Reporting a vulnerability'))
  .split('\n')
  .filter((l) => /^\|\s*[^-\s|]/.test(l) && !/^\|\s*Version\b/.test(l))
  .map((l) => l.split('|').map((c) => c.trim()).filter((c) => c !== ''));

describe('SECURITY.md supported versions', () => {
  it(`marks the current release line (${line}.x) supported`, () => {
    expect(rows).toContainEqual([`${line}.x`, '✅']);
  });

  it('marks everything older unsupported, and nothing else supported', () => {
    expect(rows).toContainEqual([`< ${line}`, '❌']);
    expect(rows.filter((r) => r[1] === '✅').map((r) => r[0])).toEqual([`${line}.x`]);
  });
});
