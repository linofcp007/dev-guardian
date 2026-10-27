/**
 * `../../../src/deps/nugetCredentials.ts` — whether a restore would send a
 * NuGet credential of the user's to a feed the repository named. The
 * measurements behind each rule are in that module's header (SDK 10.0.403,
 * Windows and Linux); these pin the comparison without an SDK, with the
 * user's configuration in a temporary directory — never the real one.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { nugetRestoreRefusal, parseNugetConfig, type NugetEnvironment } from '../../../src/deps/nugetCredentials.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';
import { expectLinear } from '../../helpers/timing.js';

afterAll(cleanupTempDirs);

function write(root: string, rel: string, content: string): string {
  const abs = join(root, rel);
  mkdirSync(join(abs, '..'), { recursive: true });
  writeFileSync(abs, content, 'utf8');
  return abs;
}

const config = (body: string): string => `<?xml version="1.0" encoding="utf-8"?>\n<configuration>${body}</configuration>`;
const sources = (...adds: Array<[string, string]>): string =>
  `<packageSources>${adds.map(([k, v]) => `<add key="${k}" value="${v}" />`).join('')}</packageSources>`;
const creds = (name: string): string =>
  `<packageSourceCredentials><${name}><add key="Username" value="me" /><add key="ClearTextPassword" value="s3cret" /></${name}></packageSourceCredentials>`;

const OWN = 'https://corp.example/v3/index.json';
const ATTACKER = 'https://attacker.example/v3/index.json';

/** A repository, the user's APPDATA (or HOME), and the environment pointing at it. */
function setup(user: string | null, opts: { platform?: NodeJS.Platform; env?: NodeJS.ProcessEnv } = {}): {
  repo: string;
  userDir: string;
  nuget: NugetEnvironment;
} {
  const repo = makeTempDir('nuget-repo-');
  const home = makeTempDir('nuget-user-');
  const platform = opts.platform ?? 'win32';
  const userDir = platform === 'win32' ? join(home, 'NuGet') : join(home, '.nuget', 'NuGet');
  if (user !== null) write(userDir, 'NuGet.Config', config(user));
  const env = platform === 'win32' ? { APPDATA: home, ...opts.env } : { HOME: home, ...opts.env };
  return { repo, userDir, nuget: { env, platform, machineConfigDir: null } };
}

describe('parseNugetConfig', () => {
  it('reads the feeds in order, a <clear/>, the credential names decoded — and nothing inside a comment', () => {
    const parsed = parseNugetConfig(
      config(
        '<!-- <packageSources><add key="old" value="https://old.example/" /></packageSources> -->' +
          '<PackageSources><clear /><add key="a&amp;b" value=\'https://x.example/?a=1&amp;b=2\' /><add key=" spaced " value="./local" /></PackageSources>' +
          '<packageSourceCredentials><My_x0020_Feed><add key="Username" value="u" /></My_x0020_Feed><clear /></packageSourceCredentials>',
      ),
    );
    expect(parsed.adds).toEqual([
      { key: 'a&b', value: 'https://x.example/?a=1&b=2' },
      { key: 'spaced', value: './local' },
    ]);
    expect(parsed.clears).toBe(true);
    expect(parsed.credentialNames).toEqual(['My Feed']);
    expect(parsed.values).toContain('u');
    expect(parsed.values).not.toContain('https://old.example/');
  });

  it('an unterminated comment hides the rest; a self-closing section declares nothing', () => {
    expect(parseNugetConfig(config(`<packageSources /><!-- ${sources(['x', OWN])}`)).adds).toEqual([]);
  });

  it('a section after a self-closing one, a closing tag in any case and spacing, and none for a section left open', () => {
    expect(parseNugetConfig(config(`<packageSources/>${sources(['a', OWN])}`)).adds).toEqual([{ key: 'a', value: OWN }]);
    expect(parseNugetConfig(config(`<packageSources><add key="a" value="${OWN}"/></PACKAGESOURCES >`)).adds).toEqual([
      { key: 'a', value: OWN },
    ]);
    expect(parseNugetConfig(config(`<packageSources><add key="a" value="${OWN}"/>`)).adds).toEqual([]);
  });

  it("an attribute's name is its whole run of name characters, past leading digits — never a tail of a longer name", () => {
    const parsed = parseNugetConfig(config(`<packageSources><add xkey="no" 1key="a" value="${OWN}" /></packageSources>`));
    expect(parsed.adds).toEqual([{ key: 'a', value: OWN }]);
  });
});

// A NuGet.config is the scanned repository's, up to 1 MB: each shape hands a
// search that restarts at every tag (or every character of a word) as many
// starting points as it can.
describe('parseNugetConfig stays linear on a hostile configuration', () => {
  const fill = (chunk: string, size: number): string => chunk.repeat(Math.ceil(size / chunk.length)).slice(0, size);
  it.each([
    ['opening tags alone', (n: number): string => fill('<packageSources>', n)],
    ['opening tags with no >', (n: number): string => fill('<packageSources ', n)],
    ['opening tags, then one self-closing end', (n: number): string => `${fill('<packageSources ', n)}/>`],
    ['<add with no >', (n: number): string => `<packageSources>${fill('<add ', n)}</packageSources>`],
    ['credential elements with no >', (n: number): string => `<packageSourceCredentials>${fill('<a', n)}</packageSourceCredentials>`],
    ['an attribute of one long word', (n: number): string => `<packageSources><add ${fill('a', n)}/></packageSources>`],
    ['an attribute of digits and letters', (n: number): string => `<packageSources><add ${fill('1a', n)}/></packageSources>`],
  ])('%s: eight times the configuration costs well under 22.6 times as much', (label, make) => {
    expectLinear(label, (n) => parseNugetConfig(make(n)), 8_000);
  }, 120_000);
});

describe('nugetRestoreRefusal', () => {
  it('refuses a repository feed of a name the user holds a credential for, on another server — naming the file, the feed and the host only', () => {
    const { repo, nuget } = setup(sources(['corp', OWN]) + creds('corp'));
    write(repo, 'NuGet.config', config(sources(['corp', `${ATTACKER}?token=x`])));
    const refusal = nugetRestoreRefusal(repo, [repo], nuget);
    expect(refusal?.code).toBe('nuget_credential_rebound');
    expect(refusal?.reason).toMatch(/^not restored: NuGet\.config points the NuGet feed "corp" at https:\/\/attacker\.example, and you hold a credential/);
    expect(refusal?.reason).toContain('on another server');
    expect(refusal?.reason).not.toMatch(/s3cret|token=x|v3\/index/);
  });

  it('lets the same feed through: the same URL, or the same scheme, host and port', () => {
    const { repo, nuget } = setup(sources(['corp', OWN]) + creds('corp'));
    write(repo, 'NuGet.config', config(sources(['corp', OWN])));
    expect(nugetRestoreRefusal(repo, [repo], nuget)).toBeNull();
    write(repo, 'NuGet.config', config(sources(['CORP', 'https://CORP.example:443/other/index.json'])));
    expect(nugetRestoreRefusal(repo, [repo], nuget)).toBeNull();
  });

  it('a scheme or port of its own is another server', () => {
    const { repo, nuget } = setup(sources(['corp', OWN]) + creds('corp'));
    write(repo, 'NuGet.config', config(sources(['corp', 'http://corp.example/v3/index.json'])));
    expect(nugetRestoreRefusal(repo, [repo], nuget)?.code).toBe('nuget_credential_rebound');
    write(repo, 'NuGet.config', config(sources(['corp', 'https://corp.example:8443/v3/index.json'])));
    expect(nugetRestoreRefusal(repo, [repo], nuget)?.code).toBe('nuget_credential_rebound');
  });

  it('matches the name without case, through a <clear/>, and below a solution (a project directory starts its own chain)', () => {
    const { repo, nuget } = setup(sources(['corp', OWN]) + creds('corp'));
    write(repo, 'NuGet.config', config(`<packageSources><clear /><add key="CORP" value="${ATTACKER}" /></packageSources>`));
    expect(nugetRestoreRefusal(repo, [repo], nuget)?.code).toBe('nuget_credential_rebound');

    const nested = setup(sources(['corp', OWN]) + creds('corp'));
    write(nested.repo, 'src/App/NuGet.Config', config(sources(['corp', ATTACKER])));
    expect(nugetRestoreRefusal(nested.repo, [nested.repo], nested.nuget)).toBeNull();
    const refusal = nugetRestoreRefusal(nested.repo, [nested.repo, join(nested.repo, 'src', 'App')], nested.nuget);
    expect(refusal?.reason).toContain('src/App/NuGet.Config points the NuGet feed "corp"');
  });

  it('a credential in the environment, a drop-in or an encoded name counts — with no feed of that name of the user\'s', () => {
    const env = setup('', { env: { NuGetPackageSourceCredentials_corp: 'Username=u;Password=p' } });
    write(env.repo, 'nuget.config', config(sources(['corp', ATTACKER])));
    const refusal = nugetRestoreRefusal(env.repo, [env.repo], env.nuget);
    expect(refusal?.reason).toContain('(the variable NuGetPackageSourceCredentials_corp) — NuGet binds');
    expect(refusal?.reason).not.toContain('Password=p');

    const dropIn = setup(sources(['corp', OWN]));
    write(dropIn.userDir, 'config/creds.config', config(creds('corp')));
    write(dropIn.repo, 'nuget.config', config(sources(['corp', ATTACKER])));
    expect(nugetRestoreRefusal(dropIn.repo, [dropIn.repo], dropIn.nuget)?.code).toBe('nuget_credential_rebound');

    const encoded = setup(sources(['My Feed', OWN]) + creds('My_x0020_Feed'));
    write(encoded.repo, 'nuget.config', config(sources(['my feed', ATTACKER])));
    expect(nugetRestoreRefusal(encoded.repo, [encoded.repo], encoded.nuget)?.code).toBe('nuget_credential_rebound');
  });

  it('on Linux the user configuration is under DOTNET_CLI_HOME, else HOME', () => {
    const { repo, nuget } = setup(sources(['corp', OWN]) + creds('corp'), { platform: 'linux' });
    write(repo, 'nuget.config', config(sources(['corp', ATTACKER])));
    expect(nugetRestoreRefusal(repo, [repo], nuget)?.code).toBe('nuget_credential_rebound');
    const cliHome = makeTempDir('nuget-cli-home-');
    expect(nugetRestoreRefusal(repo, [repo], { ...nuget, env: { ...nuget.env, DOTNET_CLI_HOME: cliHome } })).toBeNull();
  });

  it('nothing to refuse: no credential held, a feed the user has no credential for, a local folder, a commented-out feed', () => {
    const none = setup(sources(['corp', OWN]));
    write(none.repo, 'nuget.config', config(sources(['corp', ATTACKER])));
    expect(nugetRestoreRefusal(none.repo, [none.repo], none.nuget)).toBeNull();

    const { repo, nuget } = setup(sources(['corp', OWN]) + creds('corp'));
    write(repo, 'nuget.config', config(sources(['other', ATTACKER], ['corp', './packages'])));
    expect(nugetRestoreRefusal(repo, [repo], nuget)).toBeNull();
    write(repo, 'nuget.config', config(`<!-- ${sources(['corp', ATTACKER])} -->`));
    expect(nugetRestoreRefusal(repo, [repo], nuget)).toBeNull();
  });

  it('a %VAR% in the repository URL is any URL', () => {
    const { repo, nuget } = setup(sources(['corp', OWN]) + creds('corp'));
    write(repo, 'nuget.config', config(sources(['corp', '%FEED_URL%'])));
    expect(nugetRestoreRefusal(repo, [repo], nuget)?.code).toBe('nuget_credential_rebound');
  });

  it("a config above the repository root is the user's: its feed is the one the name means", () => {
    const parent = makeTempDir('nuget-parent-');
    const repo = join(parent, 'repo');
    mkdirSync(join(repo, '.git'), { recursive: true });
    write(parent, 'NuGet.Config', config(sources(['corp', OWN])));
    const home = makeTempDir('nuget-user-');
    write(home, 'NuGet/NuGet.Config', config(creds('corp')));
    const nuget: NugetEnvironment = { env: { APPDATA: home }, platform: 'win32', machineConfigDir: null };
    write(repo, 'NuGet.config', config(sources(['corp', OWN])));
    expect(nugetRestoreRefusal(repo, [repo], nuget)).toBeNull();
    write(repo, 'NuGet.config', config(sources(['corp', ATTACKER])));
    expect(nugetRestoreRefusal(repo, [repo], nuget)?.code).toBe('nuget_credential_rebound');
  });

  it('a start directory outside the repository is not judged', () => {
    const { repo, nuget } = setup(sources(['corp', OWN]) + creds('corp'));
    const elsewhere = makeTempDir('nuget-elsewhere-');
    write(elsewhere, 'nuget.config', config(sources(['corp', ATTACKER])));
    expect(nugetRestoreRefusal(repo, [repo, elsewhere], nuget)).toBeNull();
  });

  it('a network path anywhere in a repository config is refused, credential or not', () => {
    const { repo, nuget } = setup(null);
    write(repo, 'nuget.config', config('<config><add key="globalPackagesFolder" value="\\\\files.example\\share\\pkgs" /></config>'));
    const refusal = nugetRestoreRefusal(repo, [repo], nuget);
    expect(refusal).toEqual({
      code: 'nuget_network_path',
      reason: 'not restored: nuget.config names a network path (\\\\files.example), which NuGet would open — and Windows authenticate to its host',
    });
    write(repo, 'nuget.config', config(sources(['x', 'file://files.example/share/'])));
    expect(nugetRestoreRefusal(repo, [repo], nuget)?.code).toBe('nuget_network_path');
    write(repo, 'nuget.config', config(sources(['x', 'file:///C:/feeds/'])));
    expect(nugetRestoreRefusal(repo, [repo], nuget)).toBeNull();
  });

  it('a configuration that is there and could not be read is a refusal, never "nothing declared"', () => {
    const { repo, nuget } = setup(sources(['corp', OWN]) + creds('corp'));
    mkdirSync(join(repo, 'NuGet.config'));
    expect(nugetRestoreRefusal(repo, [repo], nuget)).toMatchObject({
      code: 'nuget_config_unread',
      reason: expect.stringMatching(/^not restored: the repository's NuGet configuration NuGet\.config it is not a regular file/),
    });
    const big = setup(null);
    write(big.repo, 'NuGet.config', `<configuration>${' '.repeat(1024 * 1024 + 1)}</configuration>`);
    expect(nugetRestoreRefusal(big.repo, [big.repo], big.nuget)?.code).toBe('nuget_config_unread');

    const user = setup(null);
    mkdirSync(join(user.userDir, 'NuGet.Config'), { recursive: true });
    expect(nugetRestoreRefusal(user.repo, [user.repo], user.nuget)?.reason).toMatch(/^not restored: your NuGet configuration .*NuGet\.Config: it is not a regular file/);
  });
});
