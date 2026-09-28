import { spawnSync } from 'node:child_process';
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

  it('creates .gitignore with **/.guardian/* + the baseline negation when missing', () => {
    const dir = fixture('git-no-gitignore');
    const r = ensureGuardianIgnored(dir);
    expect(r).toEqual({ updated: true, reason: 'created' });
    const content = readFileSync(join(dir, '.gitignore'), 'utf8');
    expect(content).toContain('**/.guardian/*');
    expect(content).toContain('!**/.guardian/baseline.json');
  });

  it('appends to an existing .gitignore that lacks the entry', () => {
    const dir = fixture('git-empty');
    const r = ensureGuardianIgnored(dir);
    expect(r).toEqual({ updated: true, reason: 'added' });
    const content = readFileSync(join(dir, '.gitignore'), 'utf8');
    expect(content).toContain('node_modules/');
    expect(content).toContain('**/.guardian/*');
    expect(content).toContain('!**/.guardian/baseline.json');
  });

  it('leaves a .gitignore that already has the current form alone', () => {
    const dir = fixture('git-empty');
    writeFileSync(
      join(dir, '.gitignore'),
      'node_modules/\n# dev-guardian outputs\n**/.guardian/*\n!**/.guardian/baseline.json\n',
    );
    expect(ensureGuardianIgnored(dir)).toEqual({ updated: false, reason: 'already_present' });
  });

  // Regression guard for the defect this file exists to fix: `.guardian/`
  // (a bare directory pattern) is what every earlier release of this tool
  // wrote, and git CANNOT re-include a file under an already-excluded
  // directory — `!.guardian/baseline.json` written anywhere else in the
  // same file is silently powerless while a `.guardian/`-shaped line
  // survives. So a repo carrying the old line must be upgraded, not left
  // "already present": the CI gate's committed `.guardian/baseline.json`
  // would otherwise stay un-addable forever.
  describe('upgrades the exact line earlier releases wrote', () => {
    it.each([
      ['.guardian', '.guardian\n'],
      ['.guardian/', '.guardian/\n'],
      ['/.guardian', '/.guardian\n'],
      ['/.guardian/', '/.guardian/\n'],
    ])('replaces bare "%s" with **/.guardian/* + the baseline negation', (_label, oldLine) => {
      const dir = fixture('git-empty');
      writeFileSync(join(dir, '.gitignore'), `node_modules/\n${oldLine}`);

      const r = ensureGuardianIgnored(dir);
      expect(r).toEqual({ updated: true, reason: 'upgraded' });

      const content = readFileSync(join(dir, '.gitignore'), 'utf8');
      expect(content).toContain('node_modules/');
      expect(content).toContain('**/.guardian/*');
      expect(content).toContain('!**/.guardian/baseline.json');
      // The bare directory-exclude line must be GONE, not merely
      // supplemented — its mere presence defeats the negation regardless
      // of where in the file it sits.
      const lines = content.split(/\r?\n/).map((l) => l.trim());
      expect(lines).not.toContain(oldLine.trim());
    });

    it('is idempotent: upgrading twice settles on already_present', () => {
      const dir = fixture('git-already'); // 'node_modules/\n.guardian/\n' — the old bare line
      const first = ensureGuardianIgnored(dir);
      expect(first).toEqual({ updated: true, reason: 'upgraded' });

      const second = ensureGuardianIgnored(dir);
      expect(second).toEqual({ updated: false, reason: 'already_present' });
    });
  });

  // Coordinator fix round 1: the upgrade path dropped only the bare entry
  // line, never the `# dev-guardian outputs` HEADER the old code always
  // wrote directly above it — so upgrading re-appended a second header
  // below, leaving it duplicated. These reproduce the REAL byte-for-byte
  // shapes the pre-fix code wrote (a header line immediately followed by
  // the bare entry), not just a bare entry on its own.
  describe('upgrades the real legacy header+entry pair the pre-fix code wrote', () => {
    it('replaces the legacy "created" pair (exact bytes of the old writeFileSync call)', () => {
      const dir = fixture('git-no-gitignore');
      // Byte-for-byte what the pre-fix `created` branch wrote:
      // `${HEADER}\n${ENTRY}\n` with the OLD ENTRY value '.guardian/'.
      writeFileSync(join(dir, '.gitignore'), '# dev-guardian outputs\n.guardian/\n');

      const r = ensureGuardianIgnored(dir);
      expect(r).toEqual({ updated: true, reason: 'upgraded' });

      const content = readFileSync(join(dir, '.gitignore'), 'utf8');
      expect(content).toBe('# dev-guardian outputs\n**/.guardian/*\n!**/.guardian/baseline.json\n');
      expect(content.match(/# dev-guardian outputs/g)).toHaveLength(1);
    });

    it('replaces the legacy "added" pair (exact bytes of the old appendFileSync call)', () => {
      const dir = fixture('git-empty'); // '# header\nnode_modules/\n'
      const priorContent = readFileSync(join(dir, '.gitignore'), 'utf8');
      // Byte-for-byte what the pre-fix `added` branch appended: suffix
      // ('' — priorContent already ends in \n) + '\n' + HEADER + '\n' +
      // the OLD ENTRY '.guardian/' + '\n'.
      writeFileSync(join(dir, '.gitignore'), `${priorContent}\n# dev-guardian outputs\n.guardian/\n`);

      const r = ensureGuardianIgnored(dir);
      expect(r).toEqual({ updated: true, reason: 'upgraded' });

      const content = readFileSync(join(dir, '.gitignore'), 'utf8');
      expect(content).toBe(
        '# header\nnode_modules/\n# dev-guardian outputs\n**/.guardian/*\n!**/.guardian/baseline.json\n',
      );
      expect(content.match(/# dev-guardian outputs/g)).toHaveLength(1);
    });
  });

  // Coordinator fix round 2: the rewrite always joined/wrote with a bare
  // `\n`, so a CRLF `.gitignore` (the Windows default; also common wherever
  // `core.autocrlf` is on) came back as LF — every line's ending flips, and
  // git shows the WHOLE file as changed for a two-line functional edit.
  describe("preserves the file's existing line-ending style", () => {
    it('keeps a CRLF .gitignore CRLF when adding the missing entry', () => {
      const dir = fixture('git-empty'); // overwritten below with a CRLF file
      writeFileSync(join(dir, '.gitignore'), '# header\r\nnode_modules/\r\n');

      const r = ensureGuardianIgnored(dir);
      expect(r).toEqual({ updated: true, reason: 'added' });

      const content = readFileSync(join(dir, '.gitignore'), 'utf8');
      expect(content).toBe(
        '# header\r\nnode_modules/\r\n# dev-guardian outputs\r\n**/.guardian/*\r\n!**/.guardian/baseline.json\r\n',
      );
      // No bare LF anywhere — every line ending stayed CRLF.
      expect(content).not.toMatch(/(?<!\r)\n/);
    });

    it('keeps a CRLF .gitignore CRLF when upgrading the legacy header+entry pair', () => {
      const dir = fixture('git-no-gitignore');
      writeFileSync(join(dir, '.gitignore'), '# dev-guardian outputs\r\n.guardian/\r\n');

      const r = ensureGuardianIgnored(dir);
      expect(r).toEqual({ updated: true, reason: 'upgraded' });

      const content = readFileSync(join(dir, '.gitignore'), 'utf8');
      expect(content).toBe('# dev-guardian outputs\r\n**/.guardian/*\r\n!**/.guardian/baseline.json\r\n');
      expect(content).not.toMatch(/(?<!\r)\n/);
    });

    // Follow-up (Task 12 minor): a MIXED-ending file came back with every
    // line in one ending — a diff of lines nobody edited. Each line keeps its
    // own; the lines this adds take the file's dominant ending.
    it('keeps each line of a mixed-ending file in its own ending; added lines take the dominant one (CRLF)', () => {
      const dir = fixture('git-no-gitignore');
      writeFileSync(join(dir, '.gitignore'), 'a/\r\nb/\nc/\r\nd/\r\n');
      expect(ensureGuardianIgnored(dir)).toEqual({ updated: true, reason: 'added' });
      expect(readFileSync(join(dir, '.gitignore'), 'utf8')).toBe(
        'a/\r\nb/\nc/\r\nd/\r\n# dev-guardian outputs\r\n**/.guardian/*\r\n!**/.guardian/baseline.json\r\n',
      );
    });

    it('… and LF when LF dominates, upgrading a legacy pair without touching its neighbours', () => {
      const dir = fixture('git-no-gitignore');
      writeFileSync(join(dir, '.gitignore'), 'a/\nb/\r\n# dev-guardian outputs\r\n.guardian/\nc/\nd/\n');
      expect(ensureGuardianIgnored(dir)).toEqual({ updated: true, reason: 'upgraded' });
      expect(readFileSync(join(dir, '.gitignore'), 'utf8')).toBe(
        'a/\nb/\r\nc/\nd/\n# dev-guardian outputs\n**/.guardian/*\n!**/.guardian/baseline.json\n',
      );
    });

    it('a tie goes to the first ending; a last line without one gets the dominant ending', () => {
      const dir = fixture('git-no-gitignore');
      writeFileSync(join(dir, '.gitignore'), 'a/\r\nb/\nc/');
      expect(ensureGuardianIgnored(dir)).toEqual({ updated: true, reason: 'added' });
      expect(readFileSync(join(dir, '.gitignore'), 'utf8')).toBe(
        'a/\r\nb/\nc/\r\n# dev-guardian outputs\r\n**/.guardian/*\r\n!**/.guardian/baseline.json\r\n',
      );
    });
  });

  it('leaves .guardian/baseline.json re-includable by git (a same-behaviour check-ignore proxy)', () => {
    // A behavioural pin on WHY .guardian/* was chosen over .guardian/: with
    // the bare directory form, `!.guardian/baseline.json` can never apply —
    // the negation line existing at all is not enough, so this asserts the
    // shape that makes it work rather than re-deriving git's own rule.
    const dir = fixture('git-no-gitignore');
    ensureGuardianIgnored(dir);
    const content = readFileSync(join(dir, '.gitignore'), 'utf8');
    const lines = content.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0 && !l.startsWith('#'));
    expect(lines).toContain('**/.guardian/*');
    expect(lines).toContain('!**/.guardian/baseline.json');
    expect(lines).not.toContain('.guardian/');
    expect(lines).not.toContain('.guardian');
  });

  // An unreleased build upgraded `.guardian/` — which matched at every depth —
  // to a root-only `.guardian/*` pair, and a sub-project's `.guardian/` (its
  // database and reports) turned up untracked in `git status`.
  it('replaces the root-only pair an unreleased build wrote, header included', () => {
    const dir = fixture('git-empty'); // '# header\nnode_modules/\n'
    writeFileSync(
      join(dir, '.gitignore'),
      '# header\nnode_modules/\n# dev-guardian outputs\n.guardian/*\n!.guardian/baseline.json\n',
    );
    expect(ensureGuardianIgnored(dir)).toEqual({ updated: true, reason: 'upgraded' });
    expect(readFileSync(join(dir, '.gitignore'), 'utf8')).toBe(
      '# header\nnode_modules/\n# dev-guardian outputs\n**/.guardian/*\n!**/.guardian/baseline.json\n',
    );
    expect(ensureGuardianIgnored(dir)).toEqual({ updated: false, reason: 'already_present' });
  });

  it('as git reads it: every .guardian ignored at any depth, every baseline.json committable', () => {
    const dir = makeTempDir('guard-real-git-');
    const git = (...args: string[]) => spawnSync('git', args, { cwd: dir, encoding: 'utf8' });
    expect(git('init', '-q').status).toBe(0);
    ensureGuardianIgnored(dir);
    // `check-ignore -q`: exit 0 = ignored, 1 = not ignored.
    const ignored = (path: string): boolean => git('check-ignore', '-q', '--no-index', path).status === 0;
    expect(ignored('.guardian/guardian.db')).toBe(true);
    expect(ignored('.guardian/reports/scan.json')).toBe(true);
    expect(ignored('packages/api/.guardian/guardian.db')).toBe(true);
    expect(ignored('packages/api/.guardian/reports/scan.json')).toBe(true);
    expect(ignored('.guardian/baseline.json')).toBe(false);
    expect(ignored('packages/api/.guardian/baseline.json')).toBe(false);
    expect(ignored('src/guardian.ts')).toBe(false);
  });
});
