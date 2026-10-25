/**
 * `writeSarif`, exported from `cli/dev-guardian.mjs`: where `scan --sarif`
 * puts its report.
 *
 * The generated pipelines write `dev-guardian-results.sarif` in the checkout,
 * which is the pull request's. The report was written with `writeFileSync`,
 * which follows a link: a pull request committing that name as a link to a
 * file outside the checkout had the SARIF overwrite it — any file the CI user
 * can write.
 */

import { lstatSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

// mcp/test/unit/cli -> ../../../.. -> repo root -> cli/dev-guardian.mjs
const { writeSarif } = await import('../../../../cli/dev-guardian.mjs');

afterAll(cleanupTempDirs);

/** A file outside every project, and a link to it at `link`; false when this host cannot make links. */
function plantLink(link: string): { victim: string } | null {
  const victim = join(makeTempDir('sarif-victim-'), 'authorized_keys');
  writeFileSync(victim, 'do not touch\n');
  try {
    symlinkSync(victim, link, 'file');
  } catch {
    return null;
  }
  return { victim };
}

describe('scan --sarif never writes through a link', () => {
  it('a link the checkout holds at the report name is refused, and what it points at is untouched', (t) => {
    const project = makeTempDir('sarif-project-');
    const sarif = join(project, 'dev-guardian-results.sarif');
    const planted = plantLink(sarif);
    if (planted === null) return t.skip(); // no symlink privilege on this host
    expect(writeSarif(sarif, '{"version":"2.1.0"}', { projectPath: project, repoPrefix: '' })).toMatch(/is a link/);
    expect(readFileSync(planted.victim, 'utf8')).toBe('do not touch\n');
    expect(lstatSync(sarif).isSymbolicLink()).toBe(true);
  });

  it('a project below the repository root: a link at the root, where the report goes, is refused too', (t) => {
    const repo = makeTempDir('sarif-repo-');
    const project = join(repo, 'packages', 'api');
    mkdirSync(project, { recursive: true });
    const sarif = join(repo, 'dev-guardian-results.sarif');
    const planted = plantLink(sarif);
    if (planted === null) return t.skip();
    expect(writeSarif(sarif, '{}', { projectPath: project, repoPrefix: 'packages/api/' })).toMatch(/is a link/);
    expect(readFileSync(planted.victim, 'utf8')).toBe('do not touch\n');
  });

  it('a directory on the way that links out of the repository is refused', (t) => {
    const project = makeTempDir('sarif-project-');
    const outside = makeTempDir('sarif-outside-');
    try {
      symlinkSync(outside, join(project, 'out'), 'junction');
    } catch {
      return t.skip();
    }
    expect(writeSarif(join(project, 'out', 'results.sarif'), '{}', { projectPath: project, repoPrefix: '' })).toMatch(/a directory on the way/);
  });

  it('outside the repository — the operator\'s own path — a link at the name is still refused', (t) => {
    const project = makeTempDir('sarif-project-');
    const sarif = join(makeTempDir('sarif-elsewhere-'), 'results.sarif');
    const planted = plantLink(sarif);
    if (planted === null) return t.skip();
    expect(writeSarif(sarif, '{}', { projectPath: project, repoPrefix: '' })).toMatch(/is a link/);
    expect(readFileSync(planted.victim, 'utf8')).toBe('do not touch\n');
  });

  it('a plain path is written, its directories made — inside the project and outside it, and over an old report', () => {
    const project = makeTempDir('sarif-project-');
    const inside = join(project, 'reports', 'dev-guardian-results.sarif');
    expect(writeSarif(inside, '{"a":1}', { projectPath: project, repoPrefix: '' })).toBeUndefined();
    expect(readFileSync(inside, 'utf8')).toBe('{"a":1}');
    expect(writeSarif(inside, '{"a":2}', { projectPath: project, repoPrefix: '' })).toBeUndefined();
    expect(readFileSync(inside, 'utf8')).toBe('{"a":2}');
    const outside = join(makeTempDir('sarif-elsewhere-'), 'deep', 'results.sarif');
    expect(writeSarif(outside, '{"b":1}', { projectPath: project, repoPrefix: '' })).toBeUndefined();
    expect(readFileSync(outside, 'utf8')).toBe('{"b":1}');
  });
});
