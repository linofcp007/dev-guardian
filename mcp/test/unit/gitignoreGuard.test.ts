import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { ensureGuardianIgnored } from '../../src/gitignoreGuard.js';
import { makeTempDir, cleanupTempDirs } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

function fixture(setup: 'no-git' | 'git-no-gitignore' | 'git-empty' | 'git-already'): string {
  const dir = makeTempDir('guard-');
  if (setup === 'no-git') return dir;
  mkdirSync(join(dir, '.git'));
  if (setup === 'git-no-gitignore') return dir;
  if (setup === 'git-empty') writeFileSync(join(dir, '.gitignore'), '# header\nnode_modules/\n');
  if (setup === 'git-already')
    writeFileSync(join(dir, '.gitignore'), 'node_modules/\n.guardian/\n');
  return dir;
}

describe('ensureGuardianIgnored', () => {
  it('does nothing when the directory is not a git repo', () => {
    const dir = fixture('no-git');
    expect(ensureGuardianIgnored(dir)).toEqual({ updated: false, reason: 'not_a_repo' });
  });

  it('creates .gitignore when missing', () => {
    const dir = fixture('git-no-gitignore');
    const r = ensureGuardianIgnored(dir);
    expect(r).toEqual({ updated: true, reason: 'created' });
    expect(readFileSync(join(dir, '.gitignore'), 'utf8')).toContain('.guardian/');
  });

  it('appends to an existing .gitignore that lacks the entry', () => {
    const dir = fixture('git-empty');
    const r = ensureGuardianIgnored(dir);
    expect(r).toEqual({ updated: true, reason: 'added' });
    const content = readFileSync(join(dir, '.gitignore'), 'utf8');
    expect(content).toContain('node_modules/');
    expect(content).toContain('.guardian/');
  });

  it('leaves a .gitignore that already lists .guardian alone', () => {
    const dir = fixture('git-already');
    const r = ensureGuardianIgnored(dir);
    expect(r).toEqual({ updated: false, reason: 'already_present' });
  });

  it('also recognises /.guardian and bare .guardian without slash', () => {
    const dir = fixture('git-empty');
    writeFileSync(join(dir, '.gitignore'), '.guardian\n');
    expect(ensureGuardianIgnored(dir)).toEqual({ updated: false, reason: 'already_present' });

    writeFileSync(join(dir, '.gitignore'), '/.guardian\n');
    expect(ensureGuardianIgnored(dir)).toEqual({ updated: false, reason: 'already_present' });
  });
});
