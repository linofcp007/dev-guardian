/**
 * This repo's own `.guardianignore` — Task 13 of the 2026-09-25 full review.
 *
 * A self-scan of dev-guardian reported its deliberately vulnerable fixtures
 * as critical and high findings of the project: every rule pack's `hits/`
 * corpus exists to be flagged, and the scanner fixtures carry fake secrets
 * and known-vulnerable lockfiles. The ignore file names those trees — and
 * nothing that is the project's own code.
 */

import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { loadProjectExclusions } from '../../../src/platform/guardianIgnore.js';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../../..', import.meta.url)));

const loaded = await loadProjectExclusions(REPO_ROOT);

describe("the repo's .guardianignore", () => {
  const ex = loaded;
  if (ex === null || 'error' in ex) throw new Error(`${REPO_ROOT}/.guardianignore missing or unreadable`);

  it('excludes the deliberately vulnerable fixture trees', () => {
    for (const p of [
      'mcp/test/fixtures/bugfix-js/hits/unchecked-find.ts',
      'mcp/test/fixtures/scanners/gitleaks.json',
      'mcp/test/fixtures/dast-app/server.js',
      'mcp/test/e2e/eval-vuln-fixture/app.js',
    ]) {
      expect(ex.ignores(p), p).toBe(true);
    }
    expect(ex.excludedDirs).toEqual(expect.arrayContaining(['mcp/test/e2e/eval-vuln-fixture', 'mcp/test/fixtures']));
    expect(ex.excludedFileCount).toBeGreaterThan(100);
  });

  it("excludes none of the project's own code, tests, rules or configs", () => {
    for (const p of [
      'mcp/src/server.ts',
      'mcp/src/platform/guardianIgnore.ts',
      'mcp/test/unit/platform/guardianIgnore.test.ts',
      'mcp/test/e2e/evalVulnFixture.test.ts',
      'configs/semgrep/bugfix-js.yml',
      'hooks/guardian-hook.mjs',
      'cli/dev-guardian.mjs',
    ]) {
      expect(ex.ignores(p), p).toBe(false);
    }
  });
});
