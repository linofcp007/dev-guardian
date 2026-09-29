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
