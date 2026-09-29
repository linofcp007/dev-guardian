/**
 * `platform/gitSafety.ts` — the policy (pure: a `git config` listing in, the
 * overrides out) and the environment it produces. What each override does
 * to a REAL git is `test/integration/gitHardening.test.ts`.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';
import {
  applyGitSafety,
  COMMAND_KEYS_REGEX,
  describeNotApplied,
  dockerGitEnvArgs,
  execGit,
  forgetGitConfigReads,
  gitSafetyFor,
  gitSafetyForSync,
  noHooksPath,
  PROBE_KEY,
  safetyFromListing,
  staticGitSafety,
  withoutHooksPath,
  type GitSafety,
} from '../../../src/platform/gitSafety.js';
import { buildHostileRepo } from '../../helpers/hostileRepo.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

// The real-git block builds a repository (about twenty git processes) per
// test: seconds idle, well past the default under a full-suite load (17 s
// measured) — a hang-breaker, not a budget any test asserts by reaching.
vi.setConfig({ testTimeout: 120_000 });

afterAll(cleanupTempDirs);
afterEach(() => {
  vi.unstubAllEnvs();
});

type Row = readonly [scope: string, key: string, value: string | null];

/** `git config --show-scope -z --get-regexp` output for these rows, the sentinel first. */
function listing(rows: readonly Row[], sentinel = true): Buffer {
  const all: Row[] = sentinel ? [['command', PROBE_KEY, '1'], ...rows] : [...rows];
  return Buffer.concat(
    all.map(([scope, key, value]) => Buffer.from(`${scope}\0${key}${value === null ? '' : `\n${value}`}\0`, 'utf8')),
  );
}

const pairsOf = (s: GitSafety): string[] => s.config.map(([k, v]) => `${k}=${v}`);
const dynamic = (s: GitSafety): string[] => pairsOf(s).slice(staticGitSafety().config.length);

describe('the static layer', () => {
  it('hooks are looked for beneath a regular file: node.exe on Windows, /dev/null elsewhere', () => {
    expect(noHooksPath('win32', 'C:\\Program Files\\nodejs\\node.exe')).toBe('C:/Program Files/nodejs/node.exe/no-git-hooks');
    expect(noHooksPath('linux', '/usr/local/bin/node')).toBe('/dev/null/no-git-hooks');
    expect(noHooksPath('darwin', '/opt/homebrew/bin/node')).toBe('/dev/null/no-git-hooks');
  });

  it('turns off fsmonitor, hooks, ext::, signature checks by log and automatic gc — and pager and editors', () => {
    const s = staticGitSafety('linux');
    expect(pairsOf(s)).toEqual([
      'core.fsmonitor=false',
      'core.hooksPath=/dev/null/no-git-hooks',
      'protocol.ext.allow=never',
      'log.showSignature=false',
      'gc.auto=0',
      'maintenance.auto=false',
    ]);
    expect(s.vars).toEqual({ GIT_PAGER: 'cat', GIT_EDITOR: ':', GIT_SEQUENCE_EDITOR: ':' });
    expect(s.refused).toBeNull();
  });
});

describe('applyGitSafety: the environment', () => {
  const safety = staticGitSafety('linux');

  it('counts from zero when the environment has no entries of its own', () => {
    const env = applyGitSafety(safety, { PATH: '/bin' }, 'linux');
    expect(env['GIT_CONFIG_COUNT']).toBe('6');
    expect(env['GIT_CONFIG_KEY_0']).toBe('core.fsmonitor');
    expect(env['GIT_CONFIG_VALUE_0']).toBe('false');
    expect(env['GIT_CONFIG_KEY_5']).toBe('maintenance.auto');
    expect(env['PATH']).toBe('/bin');
    expect(env['GIT_PAGER']).toBe('cat');
  });

  it("APPENDS after the user's own entries, which it keeps", () => {
    const env = applyGitSafety(
      safety,
      { GIT_CONFIG_COUNT: '2', GIT_CONFIG_KEY_0: 'user.name', GIT_CONFIG_VALUE_0: 'Me', GIT_CONFIG_KEY_1: 'a.b', GIT_CONFIG_VALUE_1: 'c' },
      'linux',
    );
    expect(env['GIT_CONFIG_COUNT']).toBe('8');
    expect(env['GIT_CONFIG_KEY_0']).toBe('user.name');
    expect(env['GIT_CONFIG_VALUE_1']).toBe('c');
    expect(env['GIT_CONFIG_KEY_2']).toBe('core.fsmonitor');
    expect(env['GIT_CONFIG_KEY_7']).toBe('maintenance.auto');
  });

  it('on Windows, one variable per name whatever its case', () => {
    const env = applyGitSafety(safety, { Git_Config_Count: '1', GIT_CONFIG_KEY_0: 'a.b', GIT_CONFIG_VALUE_0: 'c', git_pager: 'less' }, 'win32');
    const names = Object.keys(env);
    expect(names.filter((n) => n.toUpperCase() === 'GIT_CONFIG_COUNT')).toEqual(['Git_Config_Count']);
    expect(env['Git_Config_Count']).toBe('7');
    expect(names.filter((n) => n.toUpperCase() === 'GIT_PAGER')).toEqual(['GIT_PAGER']);
    expect(env['GIT_CONFIG_KEY_1']).toBe('core.fsmonitor');
  });

  it('a count git itself would refuse ("bogus count") is left for git to refuse, never repaired', () => {
    const env = applyGitSafety(safety, { GIT_CONFIG_COUNT: 'x1' }, 'linux');
    expect(env['GIT_CONFIG_COUNT']).toBe('x1');
    expect(env['GIT_CONFIG_KEY_0']).toBeUndefined();
  });

  it('withoutHooksPath keeps every override but the hooks redirect (precommit_install)', () => {
    const s = withoutHooksPath(staticGitSafety('linux'));
    expect(pairsOf(s)).toEqual(['core.fsmonitor=false', 'protocol.ext.allow=never', 'log.showSignature=false', 'gc.auto=0', 'maintenance.auto=false']);
    expect(s.vars).toEqual(staticGitSafety('linux').vars);
  });

  it('dockerGitEnvArgs: the same overrides into a container, counted from zero, with a POSIX hooks path', () => {
    const args = dockerGitEnvArgs(staticGitSafety('win32'));
    expect(args).toContain('GIT_CONFIG_KEY_1=core.hooksPath');
    expect(args).toContain('GIT_CONFIG_VALUE_1=/dev/null/no-git-hooks');
    expect(args).toContain('GIT_CONFIG_COUNT=6');
    expect(args).toContain('GIT_PAGER=cat');
    for (let i = 0; i < args.length; i += 2) expect(args[i]).toBe('-e');
  });
});

describe('safetyFromListing: what the repository asked for, and what it gets instead', () => {
  it('a filter driver: its commands emptied and `required` forced false (required + empty makes git die)', () => {
    const s = safetyFromListing('/r', listing([['local', 'filter.lfs.smudge', 'evil'], ['local', 'filter.lfs.process', 'evil']]), {}, 'linux');
    expect(dynamic(s)).toEqual(['filter.lfs.smudge=', 'filter.lfs.process=', 'filter.lfs.required=false']);
    expect(s.notApplied).toEqual(['filter.lfs.process', 'filter.lfs.smudge']);
  });

  it("the user's own value for the same key wins over the neutral one — and then required is theirs", () => {
    const s = safetyFromListing(
      '/r',
      listing([
        ['global', 'filter.lfs.smudge', 'git-lfs smudge -- %f'],
        ['local', 'filter.lfs.smudge', 'evil'],
      ]),
      {},
      'linux',
    );
    expect(dynamic(s)).toEqual(['filter.lfs.smudge=git-lfs smudge -- %f']);
  });

  it('textconv: identity (`cat`), because an EMPTY textconv makes git die', () => {
    const s = safetyFromListing('/r', listing([['local', 'diff.tv.textconv', 'evil']]), {}, 'linux');
    expect(dynamic(s)).toEqual(['diff.tv.textconv=cat']);
  });

  it('external diff and merge drivers: empty, which git refuses loudly', () => {
    const s = safetyFromListing(
      '/r',
      listing([['local', 'diff.external', 'x'], ['local', 'diff.tv.command', 'x'], ['local', 'merge.m.driver', 'x']]),
      {},
      'linux',
    );
    expect(dynamic(s)).toEqual(['diff.external=', 'diff.tv.command=', 'merge.m.driver=']);
  });

  it("credential helpers: the list reset, then the user's own replayed in order", () => {
    const s = safetyFromListing(
      '/r',
      listing([
        ['system', 'credential.helper', 'manager'],
        ['global', 'credential.https://example.invalid.helper', 'store'],
        ['local', 'credential.helper', '!evil'],
        ['local', 'credential.https://example.invalid.helper', '!evil2'],
      ]),
      {},
      'linux',
    );
    expect(dynamic(s)).toEqual(['credential.helper=', 'credential.helper=manager', 'credential.https://example.invalid.helper=store']);
    expect(s.notApplied).toEqual(['credential.helper', 'credential.https://example.invalid.helper']);
  });

  it('core.sshCommand: `ssh`, or the user\'s GIT_SSH quoted for the shell git runs it through', () => {
    const rows: Row[] = [['local', 'core.sshcommand', 'evil']];
    expect(dynamic(safetyFromListing('/r', listing(rows), {}, 'linux'))).toEqual(['core.sshcommand=ssh']);
    const withGitSsh = safetyFromListing('/r', listing(rows), { GIT_SSH: "C:\\Program Files\\PuTTY\\plink's.exe" }, 'linux');
    expect(dynamic(withGitSsh)).toEqual([`core.sshcommand='C:\\Program Files\\PuTTY\\plink'\\''s.exe'`]);
  });

  it("gpg programs: git's own defaults; askPass, alias, alternateRefsCommand, defaultKeyCommand: empty", () => {
    const s = safetyFromListing(
      '/r',
      listing([
        ['local', 'gpg.program', 'e'],
        ['local', 'gpg.openpgp.program', 'e'],
        ['local', 'gpg.x509.program', 'e'],
        ['local', 'gpg.ssh.program', 'e'],
        ['local', 'gpg.ssh.defaultkeycommand', 'e'],
        ['local', 'core.askpass', 'e'],
        ['local', 'alias.lfs', '!e'],
        ['local', 'core.alternaterefscommand', 'e'],
      ]),
      {},
      'linux',
    );
    expect(dynamic(s)).toEqual([
      'gpg.program=gpg',
      'gpg.openpgp.program=gpg',
      'gpg.x509.program=gpgsm',
      'gpg.ssh.program=ssh-keygen',
      'gpg.ssh.defaultkeycommand=',
      'core.askpass=',
      'alias.lfs=',
      'core.alternaterefscommand=',
    ]);
  });

  it('core.gitProxy (first match wins): GIT_PROXY_COMMAND, unless the user set one', () => {
    const rows: Row[] = [['local', 'core.gitproxy', 'evil for example.invalid']];
    expect(safetyFromListing('/r', listing(rows), {}, 'linux').vars['GIT_PROXY_COMMAND']).toBe('');
    expect(safetyFromListing('/r', listing(rows), { GIT_PROXY_COMMAND: 'mine' }, 'linux').vars['GIT_PROXY_COMMAND']).toBeUndefined();
  });

  it('remote uploadpack/receivepack (FIRST value wins): named; uploadpack also turns lazy fetch off', () => {
    const s = safetyFromListing(
      '/r',
      listing([['local', 'remote.origin.uploadpack', 'evil'], ['local', 'remote.origin.receivepack', 'evil']]),
      {},
      'linux',
    );
    expect(dynamic(s)).toEqual([]);
    expect(s.vars['GIT_NO_LAZY_FETCH']).toBe('1');
    expect(s.notApplied).toEqual(['remote.origin.receivepack', 'remote.origin.uploadpack']);
  });

  it('keys the static layer already overrides are named, not overridden twice', () => {
    const s = safetyFromListing(
      '/r',
      listing([['local', 'core.fsmonitor', 'e'], ['local', 'core.hookspath', '.githooks'], ['worktree', 'pager.log', 'e']]),
      {},
      'linux',
    );
    expect(dynamic(s)).toEqual([]);
    expect(s.notApplied).toEqual(['core.fsmonitor', 'core.hookspath', 'pager.log']);
  });

  it('every scope but system, global and command is the repository\'s: worktree included', () => {
    const s = safetyFromListing('/r', listing([['worktree', 'diff.w.textconv', 'e']]), {}, 'linux');
    expect(dynamic(s)).toEqual(['diff.w.textconv=cat']);
  });

  it('a subsection written in any case is overridden exactly as git spells it', () => {
    const s = safetyFromListing('/r', listing([['local', 'filter.EvIl.clean', 'e']]), {}, 'linux');
    expect(dynamic(s)).toEqual(['filter.EvIl.clean=', 'filter.EvIl.required=false']);
  });

  it('REFUSED when git did not read GIT_CONFIG_COUNT (the sentinel is missing) — older than 2.31', () => {
    const s = safetyFromListing('/r', listing([['local', 'filter.x.clean', 'e']], false), {}, 'linux');
    expect(s.refused).toMatch(/GIT_CONFIG_COUNT needs git 2\.31/);
  });

  it("the repository's own copy of the sentinel is not the sentinel", () => {
    const s = safetyFromListing('/r', listing([['local', PROBE_KEY, '1']], false), {}, 'linux');
    expect(s.refused).not.toBeNull();
  });

  it('REFUSED for a key that is not UTF-8: it cannot be named in an environment variable git would match', () => {
    const bytes = Buffer.concat([listing([]), Buffer.from('local\0filter.', 'utf8'), Buffer.from([0xff, 0xfe]), Buffer.from('.clean\nx\0', 'utf8')]);
    const s = safetyFromListing('/r', bytes, {}, 'linux');
    expect(s.refused).toMatch(/not UTF-8/);
  });

  it('REFUSED past 200 command keys in one repository', () => {
    const rows: Row[] = Array.from({ length: 201 }, (_, i) => ['local', `alias.a${i}`, '!e'] as const);
    expect(safetyFromListing('/r', listing(rows), {}, 'linux').refused).toMatch(/more than 200/);
  });

  it('a key with no value (`[alias] x`) is still overridden', () => {
    const s = safetyFromListing('/r', listing([['local', 'alias.x', null]]), {}, 'linux');
    expect(dynamic(s)).toEqual(['alias.x=']);
  });
});

describe('the regular expression names what the policy handles', () => {
  const re = new RegExp(COMMAND_KEYS_REGEX);
  it.each([
    'filter.a.clean',
    'filter.a.b.smudge',
    'filter.x.process',
    'diff.x.textconv',
    'diff.x.command',
    'diff.external',
    'merge.x.driver',
    'core.sshcommand',
    'core.askpass',
    'core.gitproxy',
    'core.alternaterefscommand',
    'core.fsmonitor',
    'core.hookspath',
    'core.pager',
    'core.editor',
    'sequence.editor',
    'pager.log',
    'credential.helper',
    'credential.https://example.invalid/a.b.helper',
    'gpg.program',
    'gpg.ssh.program',
    'gpg.ssh.defaultkeycommand',
    'alias.st',
    'remote.origin.uploadpack',
    'remote.a.b.receivepack',
    PROBE_KEY,
  ])('matches %s', (key) => {
    expect(re.test(key)).toBe(true);
  });
  it.each(['filter.a.required', 'diff.x.binary', 'core.editorx', 'user.name', 'remote.origin.url', 'credential.helperx'])(
    'does not match %s',
    (key) => {
      expect(re.test(key)).toBe(false);
    },
  );
});

describe('gitSafetyFor against a real git', () => {
  it("reads the repository's configuration — include.path and all — and names what it overrides", async () => {
    const repo = buildHostileRepo();
    for (const [k, v] of Object.entries(repo.env)) vi.stubEnv(k, v);
    const s = await gitSafetyFor([repo.root]);
    expect(s.refused).toBeNull();
    expect(s.notApplied).toEqual([
      'core.fsmonitor',
      'diff.inctv.textconv',
      'diff.tv.textconv',
      'filter.evil.clean',
      'filter.evil.smudge',
      'filter.evil2.clean',
      'filter.evil2.smudge',
      'gpg.program',
    ]);
    expect(gitSafetyForSync([repo.root])).toEqual(s);
    expect(repo.markersWritten()).toEqual([]);
  });

  it('a reading is reused inside its window in the same environment — never past it, never across environments', async () => {
    const repo = buildHostileRepo();
    for (const [k, v] of Object.entries(repo.env)) vi.stubEnv(k, v);
    forgetGitConfigReads();
    // The window fixed per call, so the test does not race the 2 s default.
    const hour = { reuseMs: 3_600_000 };
    const before = await gitSafetyFor([repo.root], hour);
    repo.plainGit(['config', 'diff.later.textconv', 'evil']);
    // Same environment, inside the window: the same reading.
    expect((await gitSafetyFor([repo.root], hour)).notApplied).toEqual(before.notApplied);
    expect(gitSafetyForSync([repo.root], hour).notApplied).toEqual(before.notApplied);
    // Past the window: read again.
    expect((await gitSafetyFor([repo.root], { reuseMs: -1 })).notApplied).toContain('diff.later.textconv');
    forgetGitConfigReads();
    const fresh = await gitSafetyFor([repo.root], hour);
    repo.plainGit(['config', 'diff.later2.textconv', 'evil']);
    // Another environment — here one more directory git will not cross into — is another reading.
    vi.stubEnv('GIT_CEILING_DIRECTORIES', join(repo.base, 'nowhere'));
    expect((await gitSafetyFor([repo.root], hour)).notApplied).toContain('diff.later2.textconv');
    expect(fresh.notApplied).not.toContain('diff.later2.textconv');
  });

  it('GIT_CONFIG — which redirects `git config` alone — does not hide the repository from the read', async () => {
    const repo = buildHostileRepo();
    for (const [k, v] of Object.entries(repo.env)) vi.stubEnv(k, v);
    const empty = join(repo.base, 'empty.gitconfig');
    writeFileSync(empty, '');
    vi.stubEnv('GIT_CONFIG', empty);
    const s = await gitSafetyFor([repo.root]);
    expect(s.notApplied).toContain('filter.evil.smudge');
  });

  it('a directory in no repository, or none at all, adds nothing and refuses nothing', async () => {
    const plain = makeTempDir('guardian-plain-');
    mkdirSync(join(plain, 'sub'));
    expect((await gitSafetyFor([join(plain, 'sub')])).refused).toBeNull();
    const missing = await gitSafetyFor([join(plain, 'does-not-exist')]);
    expect(missing.refused).toBeNull();
    expect(missing.notApplied).toEqual([]);
  });

  it("a configuration git itself cannot read (a bad line, in the file or an include; an include cycle) is nothing to neutralise — and git refuses the repository too", async () => {
    const repo = buildHostileRepo();
    for (const [k, v] of Object.entries(repo.env)) vi.stubEnv(k, v);
    const broken = join(repo.base, 'broken.inc');
    writeFileSync(broken, 'garbage line without a section\n');
    repo.plainGit(['config', '--add', 'include.path', broken.replace(/\\/g, '/')]);
    forgetGitConfigReads();
    const s = await gitSafetyFor([repo.root]);
    expect(s.refused).toBeNull();
    expect(s.notApplied).toEqual([]);
    const r = await execGit(repo.root, ['status', '--porcelain']);
    expect(r.status).toBe(128);
    expect(r.stderr).toMatch(/bad config line 1/);
    expect(repo.markersWritten()).toEqual([]);
  });

  it('no git installed: nothing can run it — the static layer, not a refusal', async () => {
    const s = await gitSafetyFor([makeTempDir('guardian-nogit-')], { git: 'no-such-git-executable-xyz' });
    expect(s.refused).toBeNull();
    expect(s.config).toEqual(staticGitSafety().config);
  });

  it('a GIT_CONFIG_COUNT git refuses is refused here too, and execGit does not run git', async () => {
    vi.stubEnv('GIT_CONFIG_COUNT', 'nonsense');
    const s = await gitSafetyFor([makeTempDir('guardian-bogus-')]);
    expect(s.refused).toMatch(/GIT_CONFIG_COUNT in the environment is "nonsense"/);
    const r = await execGit(makeTempDir('guardian-bogus2-'), ['--version']);
    expect(r.failure?.code).toBe('refused');
    expect(r.status).toBeNull();
    expect(r.stderr).toMatch(/^dev-guardian did not run git: /);
  });

  it("the user's own GIT_CONFIG_COUNT entries still reach git, before ours", async () => {
    vi.stubEnv('GIT_CONFIG_COUNT', '1');
    vi.stubEnv('GIT_CONFIG_KEY_0', 'devguardian.userentry');
    vi.stubEnv('GIT_CONFIG_VALUE_0', 'kept');
    const r = await execGit(makeTempDir('guardian-userenv-'), ['config', '--show-scope', '--get-regexp', '^(devguardian\\.userentry|core\\.fsmonitor)$']);
    expect(r.stdout.split(/\r?\n/).filter(Boolean)).toEqual(['command\tdevguardian.userentry kept', 'command\tcore.fsmonitor false']);
  });
});

describe('describeNotApplied', () => {
  it('names the first six, then how many more', () => {
    expect(describeNotApplied([])).toBeNull();
    const text = describeNotApplied(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h']);
    expect(text).toMatch(/for a, b, c, d, e, f and 2 more — dev-guardian never runs a command a scanned repository configures/);
  });
});
