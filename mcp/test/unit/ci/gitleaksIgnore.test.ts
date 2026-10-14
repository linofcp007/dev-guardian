/**
 * `ci/gitleaksIgnore.ts` against a real git repository (review 12, finding
 * 11): the CI gate's full-content secrets pass reads files, and gitleaks
 * matches a files-pass finding against `.gitleaksignore`'s `<file>:<rule>:<line>`
 * form only — so a key a team had accepted by its history fingerprint
 * (`<commit>:<file>:<rule>:<line>`) came back as new whenever a pull request
 * touched its file. No gitleaks needed: the findings are what its files pass
 * reports.
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { acceptedByHistoryIgnores, parseHistoryIgnores } from '../../../src/ci/gitleaksIgnore.js';
import type { Finding } from '../../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

function repo(): { dir: string; git: (...args: string[]) => string } {
  const dir = makeTempDir('gitleaks-ignore-');
  const git = (...args: string[]): string => {
    const r = spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'core.autocrlf=false', '-c', 'commit.gpgsign=false', ...args], {
      cwd: dir,
      encoding: 'utf8',
    });
    if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
    return r.stdout.trim();
  };
  git('init', '-q');
  return { dir, git };
}

/** A key-shaped block (no credential-shaped literal: the markers are built). */
const block = (seed: string): string[] => [`${'-----'}BEGIN TEST ${'KEY-----'}`, `${seed}a`.repeat(20), `${seed}b`.repeat(20), `${'-----'}END TEST ${'KEY-----'}`];

const finding = (path: string, start: number, end: number): Finding => ({
  fingerprint: `${path}:${start}`,
  tool: 'gitleaks',
  severity: 'high',
  category: 'security',
  title: 'key',
  rule_id: 'private-key',
  file_path: path,
  line_start: start,
  line_end: end,
  snippet: 'rule=private-key',
  fix_available: false,
});

describe('parseHistoryIgnores', () => {
  it('history-form entries only — a comment, a blank line and a file-form entry are left out; a path may hold ":"', () => {
    const sha = 'a'.repeat(40);
    const text = ['# accepted fixtures', '', `${sha}:keys/a.pem:private-key:3`, 'keys/b.pem:private-key:1', `${sha}:odd:name.pem:private-key:12`, '  '].join('\r\n');
    expect(parseHistoryIgnores(text)).toEqual([
      { commit: sha, file: 'keys/a.pem', rule: 'private-key', line: 3 },
      { commit: sha, file: 'odd:name.pem', rule: 'private-key', line: 12 },
    ]);
  });
});

describe('acceptedByHistoryIgnores', () => {
  it('the same lines, wherever they now sit, are accepted; a key replaced in place, another rule or another file is not', async () => {
    const { dir, git } = repo();
    mkdirSync(join(dir, 'app', 'fixtures'), { recursive: true });
    writeFileSync(join(dir, 'app', 'fixtures', 'key.pem'), `${block('p').join('\n')}\n`);
    git('add', '-A');
    git('commit', '-qm', 'fixture');
    const at = git('rev-parse', 'HEAD');
    writeFileSync(join(dir, 'app', '.gitleaksignore'), `${at}:app/fixtures/key.pem:private-key:1\n`);

    // The project is `app/`: findings are relative to it, the entry to the repository.
    const project = join(dir, 'app');
    writeFileSync(join(project, 'fixtures', 'key.pem'), `# moved down, re-indented\n\n${block('p').map((l) => `  ${l}`).join('\n')}\n`);
    const moved = finding('fixtures/key.pem', 3, 6);
    expect([...(await acceptedByHistoryIgnores(project, [moved]))]).toEqual([moved]);

    const otherRule = { ...moved, rule_id: 'generic-api-key' };
    const otherFile = { ...moved, file_path: 'fixtures/copy.pem' };
    writeFileSync(join(project, 'fixtures', 'copy.pem'), `# moved down, re-indented\n\n${block('p').join('\n')}\n`);
    expect((await acceptedByHistoryIgnores(project, [otherRule, otherFile])).size).toBe(0);

    writeFileSync(join(project, 'fixtures', 'key.pem'), `${block('q').join('\n')}\n`);
    expect((await acceptedByHistoryIgnores(project, [finding('fixtures/key.pem', 1, 4)])).size).toBe(0);
  });

  it('no .gitleaksignore, or a commit git does not know: nothing accepted', async () => {
    const { dir, git } = repo();
    writeFileSync(join(dir, 'key.pem'), `${block('p').join('\n')}\n`);
    git('add', '-A');
    git('commit', '-qm', 'fixture');
    expect((await acceptedByHistoryIgnores(dir, [finding('key.pem', 1, 4)])).size).toBe(0);
    writeFileSync(join(dir, '.gitleaksignore'), `${'f'.repeat(40)}:key.pem:private-key:1\n`);
    expect((await acceptedByHistoryIgnores(dir, [finding('key.pem', 1, 4)])).size).toBe(0);
  });
});
