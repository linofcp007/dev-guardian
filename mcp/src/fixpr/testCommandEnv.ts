/**
 * The environment `create_fix_pr` runs the project's test command in.
 *
 * The test command is the PROJECT's code: `npm test` runs `scripts.test`,
 * pytest imports every `conftest.py`, `cargo test` builds and runs `build.rs`,
 * `go test` runs whatever the package's tests do — on a dry run too. It ran
 * with this server's full environment, so a repository's test could read and
 * send whatever the server was started with: a `GITHUB_TOKEN`, an
 * `NPM_TOKEN`, cloud credentials, `GUARDIAN_*` settings.
 *
 * So it runs with `extendEnv: false` and only what a test runner needs to
 * find its toolchain and a place to write:
 *
 *   - `PATH`, the home directory (`HOME`, `USERPROFILE`, `HOMEDRIVE`,
 *     `HOMEPATH`), the temp directory (`TEMP`, `TMP`, `TMPDIR`), `LANG`,
 *     `LANGUAGE`, `LC_*`, `TZ`, `TERM` and `CI`;
 *   - on Windows, what every process there expects: `SystemRoot`, `SystemDrive`,
 *     `windir`, `ComSpec`, `PATHEXT`, `APPDATA`, `LOCALAPPDATA`, `ProgramData`,
 *     `ProgramFiles`, `ProgramFiles(x86)`, `CommonProgramFiles`,
 *     `NUMBER_OF_PROCESSORS`, `PROCESSOR_ARCHITECTURE`, `OS`;
 *   - the toolchains' own locations and switches: `NODE_*`, `PYTHON*`,
 *     `VIRTUAL_ENV`, `CONDA_PREFIX`, `CARGO_HOME`, `RUSTUP_HOME`,
 *     `RUSTUP_TOOLCHAIN`, `GOPATH`, `GOROOT`, `GOCACHE`, `GOMODCACHE`,
 *     `JAVA_HOME`, `DOTNET_ROOT`.
 *
 * A name matching a credential — `TOKEN`, `SECRET`, `PASSWORD`, `PASSWD`,
 * `CREDENTIAL`, `AUTH`, `API_KEY`, `PRIVATE_KEY`, `SESSION`, `COOKIE` — is
 * dropped even from those families (`NODE_AUTH_TOKEN` is `NODE_*`), and so is
 * every `GUARDIAN_*` and `npm_config_*` variable. A test that needs anything
 * else fails in the worktree and in the base-commit tree alike, and the
 * differential then reads it as already failing, never as the fix's fault.
 */

import { homedir } from 'node:os';
import { join } from 'node:path';
import { readSmallTextFile } from '../hooks/configFile.js';

const EXACT = new Set(
  [
    'PATH',
    'HOME',
    'USERPROFILE',
    'HOMEDRIVE',
    'HOMEPATH',
    'TEMP',
    'TMP',
    'TMPDIR',
    'LANG',
    'LANGUAGE',
    'TZ',
    'TERM',
    'CI',
    'SYSTEMROOT',
    'SYSTEMDRIVE',
    'WINDIR',
    'COMSPEC',
    'PATHEXT',
    'APPDATA',
    'LOCALAPPDATA',
    'PROGRAMDATA',
    'PROGRAMFILES',
    'PROGRAMFILES(X86)',
    'COMMONPROGRAMFILES',
    'NUMBER_OF_PROCESSORS',
    'PROCESSOR_ARCHITECTURE',
    'OS',
    'VIRTUAL_ENV',
    'CONDA_PREFIX',
    'CARGO_HOME',
    'RUSTUP_HOME',
    'RUSTUP_TOOLCHAIN',
    'GOPATH',
    'GOROOT',
    'GOCACHE',
    'GOMODCACHE',
    'JAVA_HOME',
    'DOTNET_ROOT',
  ].map((n) => n.toUpperCase()),
);

/** Families kept by prefix (upper-cased names). */
const PREFIXES = ['LC_', 'NODE_', 'PYTHON'];

/** Never passed, whatever family the name is in. */
const CREDENTIAL = /TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH|API_?KEY|PRIVATE_?KEY|SESSION|COOKIE/i;

/** Whether `name` reaches the project's test command. */
export function testEnvAllows(name: string): boolean {
  const upper = name.toUpperCase();
  if (upper.startsWith('GUARDIAN_') || upper.startsWith('NPM_CONFIG_')) return false;
  if (CREDENTIAL.test(upper)) return false;
  return EXACT.has(upper) || PREFIXES.some((p) => upper.startsWith(p));
}

/**
 * The environment for the project's test command, from `source` (this
 * process's by default) — to be passed with `extendEnv: false`. Names keep
 * their own spelling (`Path` on Windows).
 */
export function testCommandEnv(source: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const [name, value] of Object.entries(source)) {
    if (value !== undefined && testEnvAllows(name)) out[name] = value;
  }
  return out;
}

// ------------------------------------------------------ package managers

/**
 * The package manager's own configuration, held in the environment: the
 * registry, index, mirror and proxy a user set for npm, Yarn, pip, Composer,
 * Cargo, Bundler, Go and NuGet — and the credentials that go with them.
 * Passed to a package manager whole: it is the user's configuration, and
 * with the repository's own configuration set aside
 * (`fixpr/repoPackageConfig.ts`) it can only send a request, or a token,
 * where the user pointed it. Dropping it would be worse than leaking nothing:
 * an internal package name the user resolves from a private index would be
 * looked up on the public one instead.
 */
const PM_CONFIG_PREFIXES = [
  'NPM_CONFIG_',
  'YARN_',
  'PIP_',
  'COMPOSER_',
  'CARGO_REGISTRIES_',
  'CARGO_REGISTRY_',
  'CARGO_NET_',
  'CARGO_HTTP_',
  'BUNDLE_',
  'NUGET_',
  'NUGETPACKAGESOURCECREDENTIALS_',
];
const PM_CONFIG_EXACT = new Set([
  'GOPROXY',
  'GOPRIVATE',
  'GONOPROXY',
  'GONOSUMDB',
  'GONOSUMCHECK',
  'GOSUMDB',
  'GOINSECURE',
  'GOFLAGS',
  'GOTOOLCHAIN',
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'NO_PROXY',
  'ALL_PROXY',
]);

/** Whether `name` is a package manager's own configuration variable. */
export function isPackageManagerConfigVar(name: string): boolean {
  const upper = name.toUpperCase();
  return PM_CONFIG_EXACT.has(upper) || PM_CONFIG_PREFIXES.some((p) => upper.startsWith(p));
}

/** The largest user configuration file read for `${VAR}` references. */
const MAX_USER_CONFIG_BYTES = 1024 * 1024;

/** `${VAR}` and `${VAR:-default}` / `${VAR-default}` (npm, Yarn Berry). */
const VAR_REFERENCE = /\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-[^}]*)?\}/g;

function lookup(source: NodeJS.ProcessEnv, name: string): [string, string] | undefined {
  const exact = source[name];
  if (exact !== undefined) return [name, exact];
  if (process.platform !== 'win32') return undefined;
  const upper = name.toUpperCase();
  for (const [k, v] of Object.entries(source)) if (k.toUpperCase() === upper && v !== undefined) return [k, v];
  return undefined;
}

/**
 * The user's own package-manager configuration files: `~/.npmrc` (or the
 * file `NPM_CONFIG_USERCONFIG` names — npm reads that one instead), and
 * Yarn's `~/.yarnrc` and `~/.yarnrc.yml`. Never a file of the repository's.
 */
export function userPackageManagerConfigFiles(
  source: NodeJS.ProcessEnv = process.env,
  home: string = homedir(),
): string[] {
  const userconfig = lookup(source, 'NPM_CONFIG_USERCONFIG')?.[1] ?? lookup(source, 'npm_config_userconfig')?.[1];
  const npmrc = userconfig !== undefined && userconfig !== '' ? userconfig : join(home, '.npmrc');
  return [npmrc, join(home, '.yarnrc'), join(home, '.yarnrc.yml')];
}

/**
 * The names the user's own configuration files reference as `${VAR}` —
 * `//registry.example.com/:_authToken=${NPM_TOKEN}` — so the token the user
 * configured for their own registry still reaches it. Read bounded and
 * regular-files-only (`hooks/configFile.ts`).
 */
export function userConfigReferences(files: readonly string[]): string[] {
  const names = new Set<string>();
  for (const file of files) {
    const text = readSmallTextFile(file, MAX_USER_CONFIG_BYTES);
    if (text === undefined) continue;
    for (const m of text.matchAll(VAR_REFERENCE)) if (m[1] !== undefined) names.add(m[1]);
  }
  return [...names].sort();
}

/**
 * The environment for a package-manager process `create_fix_pr` runs — an
 * install, `npm ci`, `npm outdated`, `npm audit`, `pip-audit`, `composer`,
 * `bundle`, `cargo`, `go`, `dotnet restore`: {@link testCommandEnv}'s
 * allowlist, plus the package managers' own configuration variables
 * ({@link isPackageManagerConfigVar}), plus exactly the variables the user's
 * own configuration files reference ({@link userConfigReferences}). No other
 * token, cloud credential or `GUARDIAN_*` variable. To be passed with
 * `extendEnv: false`.
 */
export function packageManagerEnv(
  source: NodeJS.ProcessEnv = process.env,
  home: string = homedir(),
): NodeJS.ProcessEnv {
  const out = testCommandEnv(source);
  for (const [name, value] of Object.entries(source)) {
    if (value !== undefined && isPackageManagerConfigVar(name)) out[name] = value;
  }
  for (const ref of userConfigReferences(userPackageManagerConfigFiles(source, home))) {
    const hit = lookup(source, ref);
    if (hit !== undefined && !hit[0].toUpperCase().startsWith('GUARDIAN_')) out[hit[0]] = hit[1];
  }
  return out;
}
