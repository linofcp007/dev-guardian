/**
 * Which packages is this shell command about to install?
 *
 * Used by the PreToolUse hook on every Bash/PowerShell command, so the first
 * job is to say "none" fast and correctly for the 99% of commands that
 * install nothing, and the second is never to invent a package name. A word
 * this file mistakes for a package gets looked up; if the registry has never
 * heard of it, the hook DENIES the command as a hallucinated dependency. So
 * every rule below errs toward skipping:
 *
 *   - Segmentation, quoting and heredocs come from `splitShell` (the same
 *     scanner the catastrophic-command guard uses), so `git commit -m "npm
 *     install x"` and `echo npm install x` install nothing.
 *   - Flags are skipped, and so are the VALUES of flags that take one. A
 *     long flag this file does not know is assumed to take a value — missing
 *     one package is fail-open; vetting a flag's value as a package name is
 *     a false DENY.
 *   - Paths, tarballs, URLs, git/GitHub specs, `file:`/`link:`/`workspace:`
 *     protocols, requirement/constraint/editable files and words carrying
 *     shell expansion (`$PKG`) are skipped and listed with a reason — never
 *     looked up.
 *   - Whatever remains must be a syntactically valid name for its registry.
 *
 * Pure functions. No I/O. Imports only `hooks/bashGuard.js`, which is itself
 * dependency-free — the hook loads this file from `mcp/dist`.
 */

import { splitShell, type ShellWord } from '../hooks/bashGuard.js';
import { powershellAsPosix } from '../hooks/powershellText.js';

export { powershellAsPosix };
import type { PackageSpec, PkgEcosystem, SkippedSpec } from './types.js';

export interface InstallCommand {
  ecosystem: PkgEcosystem;
  /** The tool that runs the install: npm, pnpm, yarn, bun, pip, uv, poetry, composer, dotnet. */
  manager: string;
  packages: PackageSpec[];
  skipped: SkippedSpec[];
  /**
   * A registry / index / source named on the command line itself
   * (`--registry`, `-i`, `--index-url`, `--extra-index-url`, `--no-index`,
   * `--source`). A name missing from the PUBLIC registry is then not
   * evidence of anything.
   */
  customRegistry?: string;
  /** EVERY registry / index / source named on the command line, in order. */
  registries: string[];
  /**
   * Why this command may not DENY a name the public registry does not
   * have. Empty exactly when the whole command has the confident shape
   * (controller ruling, round 2: ONE plain install statement, bare tool
   * name, allowlisted flags only — see `confidentShape`); otherwise the
   * first reason is the shape's, followed by any specific signals found
   * (an unknown flag, an inline environment assignment, a directory
   * change, a workspace context) for the warning text. Registry
   * configuration, auth tokens and workspace package names are checked
   * later, against the files.
   */
  uncertain: string[];
}

// ───────────────────────────────────────────────────────────── names

const NAME_RE: Record<PkgEcosystem, RegExp> = {
  npm: /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-zA-Z0-9][a-zA-Z0-9._~-]*$/,
  pypi: /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/,
  packagist: /^[a-z0-9](?:[_.-]?[a-z0-9]+)*\/[a-z0-9](?:(?:[_.]|-{1,2})?[a-z0-9]+)*$/i,
  nuget: /^[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9_])?$/,
};

const SHELL_EXPANSION = /[$`*?{}[\]<>|&;]/;
const URL_OR_VCS = /^(?:[a-z][a-z0-9+.-]*:\/\/|git\+|git:|hg\+|svn\+|bzr\+|github:|gitlab:|bitbucket:|gist:|file:|link:|workspace:|portal:|patch:|exec:)/i;
const ARCHIVE = /\.(?:tgz|tar|tar\.gz|tar\.bz2|tar\.xz|zip|whl|egg|nupkg)$/i;

function isPathLike(word: string): boolean {
  return (
    word === '.' ||
    word === '..' ||
    word.startsWith('./') ||
    word.startsWith('../') ||
    word.startsWith('.\\') ||
    word.startsWith('..\\') ||
    word.startsWith('/') ||
    word.startsWith('~') ||
    word.startsWith('\\') ||
    /^[A-Za-z]:[\\/]/.test(word)
  );
}

/** `git@github.com:user/repo.git` — scp-style SSH git; the host has a dot, which `name@npm:x` never does. */
const SCP_GIT = /^[A-Za-z0-9._-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+:/;

/** A reason this word is not a package name, or `null` when it may be one. */
function notAPackage(word: string): string | null {
  if (word.length === 0) return 'empty';
  if (SCP_GIT.test(word)) return 'SSH git spec (user@host:path) — not looked up';
  if (isPathLike(word)) return 'local path — not looked up';
  if (URL_OR_VCS.test(word)) return 'URL / VCS / protocol spec — not looked up';
  if (ARCHIVE.test(word)) return 'archive file — not looked up';
  return null;
}

function skip(raw: string, reason: string): SkippedSpec {
  return { raw, reason };
}

function checkName(ecosystem: PkgEcosystem, name: string, raw: string): PackageSpec | SkippedSpec {
  if (SHELL_EXPANSION.test(name)) return skip(raw, 'not a literal package name (shell expansion or glob)');
  if (!NAME_RE[ecosystem].test(name)) return skip(raw, `not a valid ${ecosystem} package name`);
  return { ecosystem, name, raw };
}

function withRange(spec: PackageSpec | SkippedSpec, range: string | undefined): PackageSpec | SkippedSpec {
  if (!('name' in spec)) return spec;
  const r = range?.trim();
  return r !== undefined && r !== '' ? { ...spec, range: r } : spec;
}

function parseNpm(raw: string): PackageSpec | SkippedSpec {
  if (/[$`]/.test(raw)) return skip(raw, 'not a literal package name (shell expansion)');
  const bad = notAPackage(raw);
  if (bad !== null) return skip(raw, bad);
  const scoped = raw.startsWith('@');
  const at = raw.indexOf('@', scoped ? 1 : 0);
  const name = at > 0 ? raw.slice(0, at) : raw;
  let range = at > 0 ? raw.slice(at + 1) : undefined;
  if (!scoped && name.includes('/')) return skip(raw, 'GitHub shorthand (user/repo) — not looked up');
  if (range !== undefined) {
    if (range.startsWith('npm:')) {
      // `alias@npm:real@range` installs `real` under the name `alias`.
      const real = parseNpm(range.slice(4));
      return 'name' in real ? { ...real, raw } : skip(raw, real.reason);
    }
    const rangeBad = notAPackage(range);
    if (rangeBad !== null || URL_OR_VCS.test(range)) return skip(raw, rangeBad ?? 'URL / VCS / protocol spec — not looked up');
    if (range === 'latest') range = undefined;
  }
  return withRange(checkName('npm', name, raw), range);
}

const PEP440_OP = /(===|==|~=|!=|<=|>=|<|>)/;

function parsePython(raw: string, poetryAt: boolean): PackageSpec | SkippedSpec {
  let text = raw.trim();
  const semi = text.indexOf(';');
  if (semi >= 0) text = text.slice(0, semi).trim(); // environment marker
  if (/[$`]/.test(text)) return skip(raw, 'not a literal package name (shell expansion)');
  if (/\s@\s|@\s*(?:[a-z][a-z0-9+.-]*:\/\/|git\+|file:)/i.test(text)) return skip(raw, 'direct URL reference — not looked up');
  const bad = notAPackage(text);
  if (bad !== null) return skip(raw, bad);
  if (/[\\/]/.test(text)) return skip(raw, 'local path — not looked up');
  let name = text;
  let range: string | undefined;
  const at = text.indexOf('@');
  if (at > 0 && (poetryAt || !PEP440_OP.test(text))) {
    name = text.slice(0, at);
    range = text.slice(at + 1).trim();
    if (range === 'latest') range = undefined;
  } else {
    const m = PEP440_OP.exec(text);
    if (m !== null) {
      name = text.slice(0, m.index);
      range = text.slice(m.index).replace(/\s+/g, '');
    }
  }
  name = name.replace(/\[[^\]]*\]/, '').replace(/\s*\(.*$/, '').trim();
  return withRange(checkName('pypi', name, raw), range);
}

function parseComposer(raw: string): PackageSpec | SkippedSpec {
  if (/[$`]/.test(raw)) return skip(raw, 'not a literal package name (shell expansion)');
  const bad = notAPackage(raw);
  if (bad !== null) return skip(raw, bad);
  const sep = raw.search(/[:=\s]/);
  let name = sep > 0 ? raw.slice(0, sep) : raw;
  let range = sep > 0 ? raw.slice(sep + 1) : undefined;
  if (sep < 0 && raw.includes('@') && !raw.startsWith('@')) {
    const at = raw.indexOf('@');
    name = raw.slice(0, at);
    range = raw.slice(at + 1);
  }
  if (!name.includes('/')) return skip(raw, 'platform package or not a vendor/name — not looked up');
  return withRange(checkName('packagist', name, raw), range);
}

function parseNuget(raw: string): PackageSpec | SkippedSpec {
  if (/[$`]/.test(raw)) return skip(raw, 'not a literal package name (shell expansion)');
  const bad = notAPackage(raw);
  if (bad !== null) return skip(raw, bad);
  const at = raw.indexOf('@');
  const name = at > 0 ? raw.slice(0, at) : raw;
  const range = at > 0 ? raw.slice(at + 1) : undefined;
  return withRange(checkName('nuget', name, raw), range);
}

/**
 * One package spec as a user or tool call writes it: `name`, `name@version`,
 * plus each ecosystem's own spelling (`name==1.2`, `vendor/pkg:^2`).
 */
export function parsePackageSpec(ecosystem: PkgEcosystem, raw: string): PackageSpec | SkippedSpec {
  switch (ecosystem) {
    case 'npm':
      return parseNpm(raw.trim());
    case 'pypi':
      return parsePython(raw, false);
    case 'packagist':
      return parseComposer(raw.trim());
    case 'nuget':
      return parseNuget(raw.trim());
    default:
      return skip(raw, 'unsupported ecosystem');
  }
}

// ───────────────────────────────────────────────────────────── flags

interface FlagTable {
  /** Flags whose next word is their value. */
  value: ReadonlySet<string>;
  /** Flags known to take no value. */
  bool: ReadonlySet<string>;
  /** Value flags that name a registry / index / source. */
  registry: ReadonlySet<string>;
  /** Flags that by themselves mean "not the public registry". */
  registryBool?: ReadonlySet<string>;
  /** Value flags whose value is reported as skipped (a file of requirements, an editable path). */
  reported?: ReadonlyMap<string, string>;
  /**
   * Flags that run the install in ANOTHER directory, whose registry
   * configuration this parse has not read (`--prefix`, `-C`, `--cwd`,
   * `--working-dir`, `--directory`, …).
   */
  dir?: ReadonlySet<string>;
  /** Flags that put the install in a workspace context, where a name may be a local package. */
  workspace?: ReadonlySet<string>;
}

const set = (...xs: string[]): ReadonlySet<string> => new Set(xs);

const NPM_COMMON_BOOL = [
  '--save', '-S', '--save-dev', '-D', '--save-optional', '-O', '--save-peer', '--save-exact', '-E',
  '--save-bundle', '-B', '--no-save', '--save-prod', '-P', '--global', '-g', '--legacy-peer-deps',
  '--strict-peer-deps', '--force', '-f', '--ignore-scripts', '--no-audit', '--audit', '--no-fund', '--fund',
  '--dry-run', '--prefer-offline', '--prefer-online', '--offline', '--no-package-lock', '--package-lock-only',
  '--foreground-scripts', '--install-links', '--no-optional', '--production', '--dev', '--no-bin-links',
  '--bin-links', '--global-style', '--legacy-bundling', '--no-shrinkwrap', '--silent', '--quiet', '-q',
  '--verbose', '-d', '--json', '--progress', '--no-progress', '--color', '--no-color', '--workspaces',
  '--include-workspace-root', '--if-present', '--yes', '-y', '--no-workspaces', '--no-update-notifier',
  '--exact', '--peer', '--optional', '--tilde', '-T', '--frozen-lockfile', '--no-frozen-lockfile',
];

const FLAGS: Record<string, FlagTable> = {
  npm: {
    // `-C` is npm's short form of `--prefix`.
    value: set('--registry', '--prefix', '-C', '--tag', '--workspace', '-w', '--omit', '--include',
      '--install-strategy', '--cache', '--userconfig', '--globalconfig', '--before', '--loglevel', '--save-prefix',
      '--otp', '--scope', '--cpu', '--os', '--libc', '--location'),
    bool: set(...NPM_COMMON_BOOL),
    registry: set('--registry'),
    dir: set('--prefix', '-C'),
    workspace: set('--workspace', '-w', '--workspaces'),
  },
  pnpm: {
    value: set('--registry', '--filter', '-F', '--dir', '-C', '--reporter', '--store-dir', '--global-dir',
      '--modules-dir', '--virtual-store-dir', '--lockfile-dir', '--network-concurrency', '--config', '--loglevel',
      '--allow-build'),
    bool: set(...NPM_COMMON_BOOL, '--workspace', '-w', '--workspace-root', '--recursive', '-r'),
    registry: set('--registry'),
    dir: set('--dir', '-C'),
    workspace: set('--workspace', '--filter', '-F'),
  },
  yarn: {
    value: set('--registry', '--cwd', '--network-timeout', '--modules-folder', '--cache-folder', '--mutex', '--scope',
      '--mode'),
    bool: set(...NPM_COMMON_BOOL, '--ignore-workspace-root-check', '-W', '--cached', '--interactive', '-i',
      '--prefer-dev'),
    registry: set('--registry'),
    dir: set('--cwd'),
  },
  bun: {
    value: set('--registry', '--cwd', '--backend', '--cache-dir', '--config', '-c', '--concurrent-scripts',
      '--network-concurrency', '--omit', '--linker', '--ca', '--cafile', '--filter'),
    bool: set(...NPM_COMMON_BOOL, '--trust', '--analyze', '-a', '--only-missing', '--save-text-lockfile',
      '--no-cache', '-p'),
    registry: set('--registry'),
    dir: set('--cwd'),
    workspace: set('--filter'),
  },
  pip: {
    value: set('-r', '--requirement', '-c', '--constraint', '-e', '--editable', '-t', '--target', '--prefix',
      '--root', '-i', '--index-url', '--extra-index-url', '-f', '--find-links', '--trusted-host', '--platform',
      '--python-version', '--implementation', '--abi', '--src', '--upgrade-strategy', '--progress-bar', '--log',
      '--proxy', '--retries', '--timeout', '--exists-action', '--cert', '--client-cert', '--cache-dir',
      '--no-binary', '--only-binary', '--config-settings', '-C', '--global-option', '--report', '--python',
      '--root-user-action', '--keyring-provider', '--group', '--index-strategy', '--extra', '--override',
      '-p', '--prerelease', '--resolution'),
    bool: set('-U', '--upgrade', '--user', '--no-deps', '--pre', '--force-reinstall', '-I', '--ignore-installed',
      '--no-cache-dir', '--no-cache', '-q', '-v', '--quiet', '--verbose', '--break-system-packages', '--dry-run',
      '--no-build-isolation', '--require-hashes', '--isolated', '--disable-pip-version-check', '--no-input',
      '--compile', '--no-compile', '--prefer-binary', '--no-warn-script-location', '--use-pep517', '--no-clean',
      '--check-build-dependencies', '--ignore-requires-python', '--system', '--all-extras', '--no-index',
      '--compile-bytecode'),
    registry: set('-i', '--index-url', '--extra-index-url', '-f', '--find-links', '--index', '--default-index'),
    registryBool: set('--no-index'),
    reported: new Map([
      ['-r', 'requirements file (-r) — its contents are not vetted'],
      ['--requirement', 'requirements file (-r) — its contents are not vetted'],
      ['-c', 'constraints file (-c) — not vetted'],
      ['--constraint', 'constraints file (-c) — not vetted'],
      ['-e', 'editable install (-e) — local or VCS source, not looked up'],
      ['--editable', 'editable install (-e) — local or VCS source, not looked up'],
    ]),
  },
  uv: {
    value: set('--group', '--optional', '--index', '--index-url', '--default-index', '--extra-index-url', '--extra',
      '--package', '--script', '-r', '--requirements', '--constraints', '-c', '--rev', '--tag', '--branch',
      '--python', '-p', '--bounds', '--directory', '--project', '--config-file', '--cache-dir', '--marker', '-m',
      '--find-links', '-f', '--index-strategy', '--keyring-provider', '--resolution', '--prerelease',
      '--exclude-newer', '--link-mode', '--no-binary-package', '--no-build-package',
      '--upgrade-package', '-P', '--reinstall-package', '--refresh-package', '--config-setting', '-C'),
    bool: set('--dev', '--editable', '--no-editable', '--raw', '--raw-sources', '--frozen', '--locked', '--no-sync',
      '--workspace', '--no-workspace', '--active', '-U', '--upgrade', '--offline', '--no-cache', '-n', '-q', '-v',
      '--quiet', '--verbose', '--native-tls', '--no-index', '--no-build-isolation', '--refresh', '--reinstall',
      '--no-build', '--no-binary', '--no-config', '--no-progress', '--compile-bytecode'),
    registry: set('--index', '--index-url', '--default-index', '--extra-index-url', '--find-links', '-f'),
    registryBool: set('--no-index'),
    reported: new Map([
      ['-r', 'requirements file (-r) — its contents are not vetted'],
      ['--requirements', 'requirements file (-r) — its contents are not vetted'],
    ]),
    dir: set('--directory', '--project'),
    workspace: set('--package'),
  },
  poetry: {
    value: set('--group', '-G', '--extras', '-E', '--python', '--platform', '--source', '--markers', '--directory',
      '-C', '--project', '-P', '--optional'),
    bool: set('--dev', '-D', '--editable', '-e', '--allow-prereleases', '--dry-run', '--lock',
      '--no-interaction', '-n', '-q', '-v', '-vv', '-vvv', '--quiet', '--verbose', '--no-ansi', '--ansi'),
    registry: set('--source'),
    dir: set('--directory', '-C', '--project', '-P'),
  },
  composer: {
    dir: set('--working-dir', '-d'),
    value: set('--working-dir', '-d'),
    bool: set('--dev', '--no-dev', '--no-update', '--no-install', '--no-audit', '--no-security-blocking',
      '--update-with-dependencies', '-w', '--update-with-all-dependencies', '-W', '--with-dependencies',
      '--with-all-dependencies', '--prefer-dist', '--prefer-source', '--prefer-install', '--dry-run',
      '--no-progress', '--no-scripts', '--no-plugins', '--update-no-dev', '--ignore-platform-reqs',
      '--prefer-stable', '--prefer-lowest', '--sort-packages', '--optimize-autoloader', '-o', '--classmap-authoritative',
      '-a', '--apcu-autoloader', '--fixed', '-n', '--no-interaction', '-q', '--quiet', '-v', '-vv', '-vvv',
      '--ansi', '--no-ansi', '--no-cache', '--minimal-changes', '-m'),
    registry: set(),
  },
  dotnet: {
    value: set('-v', '--version', '-f', '--framework', '-s', '--source', '--package-directory'),
    bool: set('-n', '--no-restore', '--interactive', '--prerelease'),
    registry: set('-s', '--source'),
  },
};

interface Positional {
  value: string;
}

interface WalkResult {
  positionals: Positional[];
  skipped: SkippedSpec[];
  customRegistry?: string;
  registries: string[];
  /** Reasons a missing name in this command must not be denied (ruling (a), (c), (f)). */
  uncertain: string[];
}

const SHORT_CLUSTER = /^-[A-Za-z]{2,}/;

/**
 * Separates flags (and their values) from positional words.
 *
 * Short-flag clusters are expanded letter by letter (`-qr req.txt` is `-q`
 * then `-r req.txt`; `-rreq.txt` is `-r req.txt`): the first letter that
 * takes a value takes the rest of the cluster, or the next word. A flag
 * this table does not know makes the parse uncertain; an unknown LONG flag
 * still swallows the next word (missing a package fails open, vetting a
 * flag's value as a name does not).
 */
function walk(words: readonly ShellWord[], table: FlagTable): WalkResult {
  const positionals: Positional[] = [];
  const skipped: SkippedSpec[] = [];
  const uncertain: string[] = [];
  let customRegistry: string | undefined;
  const registries: string[] = [];
  const note = (flag: string, value: string | undefined): void => {
    if (table.registry.has(flag) && value !== undefined) {
      registries.push(value);
      customRegistry = customRegistry ?? value;
    }
    if (table.registryBool?.has(flag)) {
      registries.push(flag);
      customRegistry = customRegistry ?? flag;
    }
    const why = table.reported?.get(flag);
    if (why !== undefined && value !== undefined) skipped.push(skip(value, why));
    if (table.dir?.has(flag)) uncertain.push(`directory changed by ${flag}`);
    if (table.workspace?.has(flag)) uncertain.push(`workspace context (${flag})`);
  };
  const known = (flag: string): boolean => table.value.has(flag) || table.bool.has(flag);
  for (let i = 0; i < words.length; i += 1) {
    const w = words[i];
    if (w === undefined) break;
    const v = w.value;
    if (v === '--') continue;
    if (!v.startsWith('-') || v.length === 1) {
      positionals.push({ value: v });
      continue;
    }
    const eqAt = v.indexOf('=');
    if (eqAt > 0) {
      const flag = v.slice(0, eqAt);
      if (!known(flag)) uncertain.push(`unknown flag ${flag}`);
      note(flag, v.slice(eqAt + 1));
      continue;
    }
    if (table.value.has(v)) {
      note(v, words[i + 1]?.value);
      i += 1;
      continue;
    }
    if (table.bool.has(v)) {
      note(v, undefined);
      continue;
    }
    if (!v.startsWith('--') && SHORT_CLUSTER.test(v)) {
      for (let k = 1; k < v.length; k += 1) {
        const flag = `-${v.charAt(k)}`;
        if (table.value.has(flag)) {
          const rest = v.slice(k + 1);
          if (rest !== '') note(flag, rest);
          else {
            note(flag, words[i + 1]?.value);
            i += 1;
          }
          break;
        }
        if (!table.bool.has(flag)) uncertain.push(`unknown flag ${flag}`);
        note(flag, undefined);
      }
      continue;
    }
    uncertain.push(`unknown flag ${v}`);
    if (v.startsWith('--') && !v.startsWith('--no-')) i += 1;
  }
  const out: WalkResult = { positionals, skipped, uncertain, registries };
  if (customRegistry !== undefined) out.customRegistry = customRegistry;
  return out;
}

// ─────────────────────────────────────────────────────────── commands

const RUNNERS = new Set(['sudo', 'doas', 'env', 'command', 'exec', 'builtin', 'nohup', 'nice', 'time', 'timeout', 'setsid', 'stdbuf']);
const RUNNER_VALUE_FLAGS = new Set(['-u', '-g', '-n', '-C', '-k', '-s', '--user', '--group']);
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

function base(word: string): string {
  const last = word.split(/[\\/]/).pop() ?? word;
  return last.toLowerCase().replace(/\.(?:exe|cmd|bat|ps1)$/, '');
}

/** Index of the word that names the command, past `VAR=x`, `sudo -E`, `env`, `timeout 30`… */
function commandStart(words: readonly ShellWord[]): number {
  let i = 0;
  for (let guard = 0; guard < 32 && i < words.length; guard += 1) {
    const w = words[i];
    if (w === undefined) break;
    if (ASSIGNMENT.test(w.value)) {
      i += 1;
      continue;
    }
    const name = base(w.value);
    if (!RUNNERS.has(name)) break;
    i += 1;
    while (i < words.length) {
      const a = words[i];
      if (a === undefined) break;
      if (ASSIGNMENT.test(a.value)) i += 1;
      else if (a.value.startsWith('-') && a.value.length > 1) i += RUNNER_VALUE_FLAGS.has(a.value) ? 2 : 1;
      else if ((name === 'timeout' || name === 'nice') && /^[+-]?\d+(?:\.\d+)?[smhd]?$/.test(a.value)) i += 1;
      else break;
    }
  }
  return i;
}

const NPM_INSTALL = new Set(['install', 'i', 'add', 'in', 'ins', 'inst', 'insta', 'instal', 'isnt', 'isnta', 'isntal', 'isntall']);
const COMPOSER_REQUIRE = new Set(['require', 'r', 'req', 'requ', 'requi', 'requir']);
const BUN_ADD = new Set(['add', 'a', 'install', 'i']);

interface Detected {
  manager: string;
  ecosystem: PkgEcosystem;
  /** Words after the install subcommand (flags included). */
  args: ShellWord[];
  /** Flags before the subcommand, which may name a registry too. */
  pre: ShellWord[];
  /** Reasons found while locating the subcommand (a workspace, a project argument). */
  uncertain: string[];
}

/** First positional (non-flag) index at or after `from`, honouring the table's value flags. */
function nextPositional(words: readonly ShellWord[], from: number, table: FlagTable): number {
  for (let i = from; i < words.length; i += 1) {
    const v = words[i]?.value ?? '';
    if (v.startsWith('-') && v.length > 1) {
      if (!v.includes('=') && table.value.has(v)) i += 1;
      continue;
    }
    return i;
  }
  return -1;
}

function detect(words: readonly ShellWord[]): Detected | null {
  const start = commandStart(words);
  const headWord = words[start];
  if (headWord === undefined) return null;
  let head = base(headWord.value);
  let i = start + 1;

  // python -m pip …, py -3 -m pip …, php composer.phar …
  if (/^(?:python[0-9.]*|py)$/.test(head)) {
    const m = words.findIndex((w, idx) => idx > start && w.value === '-m');
    const mod = m >= 0 ? words[m + 1]?.value : undefined;
    if (mod === undefined || !/^(?:pip[0-9.]*|uv)$/.test(mod)) return null;
    head = mod.startsWith('pip') ? 'pip' : 'uv';
    i = m + 2;
  } else if (head === 'php') {
    const script = words[start + 1]?.value ?? '';
    if (!/composer(?:\.phar)?$/i.test(script)) return null;
    head = 'composer';
    i = start + 2;
  }
  if (/^pip[0-9.]*$/.test(head)) head = 'pip';
  if (head === 'composer.phar') head = 'composer';

  const table = FLAGS[head];
  if (table === undefined) return null;
  const sub = nextPositional(words, i, table);
  if (sub < 0) return null;
  const subWord = words[sub]?.value ?? '';
  const pre = words.slice(i, sub);

  switch (head) {
    case 'npm':
      return NPM_INSTALL.has(subWord) ? { manager: head, ecosystem: 'npm', args: words.slice(sub + 1), pre, uncertain: [] } : null;
    case 'pnpm':
      return subWord === 'add' ? { manager: head, ecosystem: 'npm', args: words.slice(sub + 1), pre, uncertain: [] } : null;
    case 'bun':
      // `bun a`, and `bun i <pkg>` / `bun install <pkg>` add too; a bare `bun install` names nothing.
      return BUN_ADD.has(subWord) ? { manager: head, ecosystem: 'npm', args: words.slice(sub + 1), pre, uncertain: [] } : null;
    case 'yarn': {
      let at = sub;
      const uncertain: string[] = [];
      if (subWord === 'global') at = nextPositional(words, sub + 1, table);
      else if (subWord === 'workspace') {
        const ws = nextPositional(words, sub + 1, table);
        at = ws < 0 ? -1 : nextPositional(words, ws + 1, table);
        uncertain.push('workspace context (yarn workspace)');
      }
      if (at < 0 || words[at]?.value !== 'add') return null;
      return { manager: head, ecosystem: 'npm', args: words.slice(at + 1), pre, uncertain };
    }
    case 'pip':
      return subWord === 'install' ? { manager: head, ecosystem: 'pypi', args: words.slice(sub + 1), pre, uncertain: [] } : null;
    case 'uv': {
      if (subWord === 'add') return { manager: 'uv', ecosystem: 'pypi', args: words.slice(sub + 1), pre, uncertain: [] };
      if (subWord === 'pip') {
        const inst = nextPositional(words, sub + 1, table);
        if (inst >= 0 && words[inst]?.value === 'install') {
          return { manager: 'uv-pip', ecosystem: 'pypi', args: words.slice(inst + 1), pre, uncertain: [] };
        }
      }
      return null;
    }
    case 'poetry':
      return subWord === 'add' ? { manager: head, ecosystem: 'pypi', args: words.slice(sub + 1), pre, uncertain: [] } : null;
    case 'composer':
      return COMPOSER_REQUIRE.has(subWord)
        ? { manager: head, ecosystem: 'packagist', args: words.slice(sub + 1), pre, uncertain: [] }
        : null;
    case 'dotnet': {
      if (subWord !== 'add') return null;
      // dotnet add [<PROJECT>] package <NAME>
      let at = nextPositional(words, sub + 1, table);
      const uncertain: string[] = [];
      if (at >= 0 && words[at]?.value !== 'package') {
        uncertain.push('dotnet project argument (the NuGet configuration next to that project was not read)');
        at = nextPositional(words, at + 1, table);
      }
      if (at < 0 || words[at]?.value !== 'package') return null;
      return { manager: head, ecosystem: 'nuget', args: words.slice(at + 1), pre, uncertain };
    }
    default:
      return null;
  }
}

/** Composer lets a constraint follow its package as a separate word: `vendor/pkg "^2.0"`. */
const COMPOSER_CONSTRAINT = /^(?:[\^~<>=!*]|v?\d|dev-|@)/;

function collect(d: Detected, context: readonly string[]): InstallCommand {
  const table = FLAGS[d.manager === 'uv-pip' ? 'pip' : d.manager] ?? FLAGS['npm'];
  const flagTable = table ?? { value: set(), bool: set(), registry: set() };
  const preWalk = walk(d.pre, flagTable);
  const { positionals, skipped, customRegistry, uncertain, registries } = walk(d.args, flagTable);
  const packages: PackageSpec[] = [];
  const out: InstallCommand = {
    ecosystem: d.ecosystem,
    manager: d.manager,
    packages,
    skipped,
    uncertain: [...new Set([...context, ...d.uncertain, ...preWalk.uncertain, ...uncertain])],
    registries: [...preWalk.registries, ...registries],
  };
  const registry = preWalk.customRegistry ?? customRegistry;
  if (registry !== undefined) out.customRegistry = registry;

  let lastComposer: PackageSpec | undefined;
  for (const p of positionals) {
    let spec: PackageSpec | SkippedSpec;
    switch (d.ecosystem) {
      case 'npm':
        spec = parseNpm(p.value);
        break;
      case 'pypi':
        spec = parsePython(p.value, d.manager === 'poetry');
        break;
      case 'packagist':
        if (lastComposer !== undefined && lastComposer.range === undefined && !p.value.includes('/') && COMPOSER_CONSTRAINT.test(p.value)) {
          lastComposer.range = p.value;
          continue;
        }
        spec = parseComposer(p.value);
        break;
      case 'nuget':
        spec = parseNuget(p.value);
        break;
      default:
        spec = skip(p.value, 'unsupported ecosystem');
    }
    if ('name' in spec) {
      packages.push(spec);
      lastComposer = d.ecosystem === 'packagist' ? spec : undefined;
    } else {
      skipped.push(spec);
      lastComposer = undefined;
    }
  }

  if (d.ecosystem === 'nuget') {
    // One package per `dotnet add package`; its version is a flag.
    const extra = packages.splice(1);
    for (const e of extra) skipped.push(skip(e.raw, 'unexpected extra argument to dotnet add package'));
    const first = packages[0];
    const version = flagValue(d.args, ['-v', '--version']);
    if (first !== undefined && version !== undefined) first.range = version;
  }
  return out;
}

function flagValue(words: readonly ShellWord[], names: readonly string[]): string | undefined {
  for (let i = 0; i < words.length; i += 1) {
    const v = words[i]?.value ?? '';
    for (const n of names) {
      if (v === n) return words[i + 1]?.value;
      if (v.startsWith(`${n}=`)) return v.slice(n.length + 1);
    }
  }
  return undefined;
}

/** Which shell will run the command: the Bash tool (POSIX, or Git Bash on Windows) or the PowerShell tool. */
export type CommandShell = 'bash' | 'powershell';

/** Why a package found only by reading the command as PowerShell does is never denied as missing. */
const POWERSHELL_READING =
  'found by reading the command as PowerShell does (a comma list, a backtick escape or continuation, a doubled quote, a Unicode space) — vetted for malicious versions only';

function packageKey(p: PackageSpec): string {
  return `${p.ecosystem}\0${p.name.toLowerCase()}\0${p.range ?? ''}`;
}

/**
 * Every install command in `command`, with the packages each would fetch
 * from a registry. `[]` for a command that installs nothing by name —
 * including a bare `npm install` or `pip install -r requirements.txt`.
 *
 * The command is read the POSIX way `splitShell` reads every command. For the
 * PowerShell tool (`shell: 'powershell'`) it is ALSO read the way PowerShell
 * reads it ({@link powershellAsPosix}): `npm i a,b` hands npm two packages,
 * a backtick-newline continues the line, `''` inside `'…'` is one quote, and a
 * no-break space separates words. A package only that second reading finds is
 * added — and marked uncertain, so it can only ever be denied as MALICIOUS,
 * never as missing (follow-up Part Y, item 5).
 */
export function parseInstallCommands(command: string, opts: { shell?: CommandShell } = {}): InstallCommand[] {
  const text = stripComments(command);
  const out = parseReading(text, null);
  if (opts.shell !== 'powershell') return out;
  const asPowerShell = powershellAsPosix(text);
  if (asPowerShell === text) return out;
  const seen = new Set(out.flatMap((c) => c.packages.map(packageKey)));
  for (const c of parseReading(asPowerShell, POWERSHELL_READING)) {
    const packages = c.packages.filter((p) => !seen.has(packageKey(p)));
    if (packages.length === 0) continue;
    for (const p of packages) seen.add(packageKey(p));
    out.push({ ...c, packages, skipped: [] });
  }
  return out;
}

/**
 * The install commands of one reading of the command. `forced`, when given,
 * is the reason no package of this reading may be denied as missing;
 * otherwise the controller ruling's confident-shape test decides.
 */
function parseReading(text: string, forced: string | null): InstallCommand[] {
  const out: InstallCommand[] = [];
  let split;
  try {
    split = splitShell(text);
  } catch {
    return out;
  }
  // Controller ruling, round 2: an ALLOWLIST of confident shapes, not a
  // denylist of uncertainty signals. `null` = deny-eligible.
  const notConfident = forced ?? confidentShape(text);
  const envChange = changesEnvironment(text, split.statements);
  let dirChanged = false;
  for (const statement of split.statements) {
    for (const words of statement.commands) {
      const d = detect(words);
      if (d !== null) {
        const context: string[] = [];
        if (envChange) context.push('inline environment assignment in the command (it can redirect the registry)');
        if (dirChanged) context.push('directory change earlier in the command (that directory’s registry configuration was not read)');
        const c = collect(d, context);
        c.uncertain = notConfident === null ? [] : [...new Set([notConfident, ...c.uncertain])];
        out.push(c);
      }
      if (changesDirectory(words)) dirChanged = true;
    }
  }
  return out;
}

/**
 * The command without its unquoted comments: `# …` to end of line (a `#`
 * that STARTS a word — `user/repo#main` is not a comment) and PowerShell
 * `<# … #>` blocks. Quotes are respected (`'…'`, `"…"` with `\` or `` ` ``
 * escapes). Without this, `pip install requests  # for http calls` vetted —
 * and denied — `for`, `http` and `calls`.
 */
export function stripComments(command: string): string {
  let out = '';
  let quote: '"' | "'" | null = null;
  let i = 0;
  while (i < command.length) {
    const ch = command.charAt(i);
    if (quote === "'") {
      out += ch;
      if (ch === "'") quote = null;
      i += 1;
      continue;
    }
    if (quote === '"') {
      out += ch;
      if ((ch === '\\' || ch === '`') && i + 1 < command.length) {
        out += command.charAt(i + 1);
        i += 2;
        continue;
      }
      if (ch === '"') quote = null;
      i += 1;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      out += ch;
      i += 1;
      continue;
    }
    if (ch === '\\' && i + 1 < command.length) {
      out += ch + command.charAt(i + 1);
      i += 2;
      continue;
    }
    if (ch === '<' && command.charAt(i + 1) === '#') {
      const end = command.indexOf('#>', i + 2);
      i = end < 0 ? command.length : end + 2;
      out += ' ';
      continue;
    }
    if (ch === '#' && (out === '' || /[\s;&|(]$/.test(out))) {
      const nl = command.indexOf('\n', i);
      i = nl < 0 ? command.length : nl;
      continue;
    }
    out += ch;
    i += 1;
  }
  return out;
}

// ─────────────────────────────────────────── the confident-shape allowlist

interface Allow {
  bool: ReadonlySet<string>;
  value: ReadonlySet<string>;
}

const NPM_ALLOW_BOOL = ['-D', '--save-dev', '-E', '--save-exact', '-O', '--save-optional', '-P', '--save-prod', '-S', '--save'];

/**
 * Flags that do not change WHERE or HOW a package is looked up: dependency
 * kind, exactness, global install, verbosity, `--user`, … Anything else —
 * registry, config file, directory, workspace, tag, requirements file,
 * any flag not listed — takes the command out of the confident shape.
 */
const ALLOW: Record<string, Allow> = {
  npm: {
    bool: set(...NPM_ALLOW_BOOL, '-B', '--save-bundle', '-g', '--global', '--save-peer', '--no-save', '--ignore-scripts',
      '--no-audit', '--no-fund', '--silent', '--verbose', '--legacy-peer-deps'),
    value: set(),
  },
  pnpm: {
    bool: set(...NPM_ALLOW_BOOL.filter((f) => f !== '-S' && f !== '--save'), '--save-peer', '-g', '--global',
      '--ignore-scripts', '--silent'),
    value: set(),
  },
  yarn: {
    bool: set('-D', '--dev', '-P', '--peer', '-O', '--optional', '-E', '--exact', '-T', '--tilde', '--silent',
      '--ignore-scripts'),
    value: set(),
  },
  bun: {
    bool: set('-d', '-D', '--dev', '--optional', '--peer', '-E', '--exact', '-g', '--global', '--no-save', '--silent',
      '--verbose'),
    value: set(),
  },
  pip: {
    bool: set('-U', '--upgrade', '--user', '--no-deps', '-q', '--quiet', '-v', '--verbose', '--pre', '--force-reinstall',
      '--no-cache-dir', '--break-system-packages', '--disable-pip-version-check'),
    value: set(),
  },
  uv: { bool: set('--dev', '-q', '--quiet', '-v', '--verbose', '--no-sync'), value: set('--group', '--optional') },
  'uv-pip': { bool: set('-U', '--upgrade', '-q', '--quiet', '-v', '--verbose', '--no-deps', '--system'), value: set() },
  poetry: {
    bool: set('--dev', '-D', '--allow-prereleases', '--dry-run', '--lock', '-q', '--quiet', '-v', '--verbose', '-n',
      '--no-interaction'),
    value: set('--group', '-G', '--optional'),
  },
  // Not `--no-update` / `--no-install` (composer) or `--no-restore` / `-n`
  // (dotnet): each defers the lookup the command would make, so a name the
  // public registry lacks is not yet a failed install (follow-up Part Y).
  composer: {
    bool: set('--dev', '-W', '--with-all-dependencies', '-w', '--with-dependencies', '--update-with-dependencies',
      '--update-with-all-dependencies', '--no-scripts', '--no-progress', '-n', '--no-interaction', '-q', '--quiet',
      '--sort-packages'),
    value: set(),
  },
  dotnet: { bool: set('--prerelease'), value: set('-v', '--version', '-f', '--framework') },
};

/**
 * Characters that, outside quotes, make a command something other than ONE
 * plain simple statement. `,` too: PowerShell hands a native command each
 * element of `a,b` as its own argument.
 */
const NOT_SIMPLE = /[;&|()<>`$\\\n\r{}*?[\],]/;

function notSingle(why: string): string {
  return `not a single plain install statement (${why})`;
}

function notPlain(why: string): string {
  return `not a plain install command (${why})`;
}

/**
 * Controller ruling (round 2): a name missing from the public registry may
 * be DENIED only when the whole command — comments stripped — is exactly
 * ONE simple install statement: no `&&`/`||`/`;`/`|`/`&`, no second line,
 * no subshell, `$(…)`, backticks, variables, globs, redirections or
 * heredocs; the executable a bare package-manager name (never a path like
 * `.venv/bin/pip`, never behind `sudo`/`env`/`VAR=x`); and every flag on
 * the tool's {@link ALLOW} list. Returns why the shape is NOT confident, or
 * `null` when it is. Everything that is not confident only warns.
 */
export function confidentShape(text: string): string | null {
  const t = text.trim();
  const words: string[] = [];
  let cur = '';
  let has = false;
  let quote: '"' | "'" | null = null;
  for (let i = 0; i < t.length; i += 1) {
    const ch = t.charAt(i);
    if (quote === "'") {
      if (ch !== "'") cur += ch;
      // `'a''b'`: two spans to a POSIX shell, ONE with a literal quote to PowerShell.
      else if (t.charAt(i + 1) === "'") return notSingle("adjacent '…' spans (PowerShell reads '' as a quote)");
      else quote = null;
      continue;
    }
    if (quote === '"') {
      if (ch === '"') quote = null;
      else if (ch === '$' || ch === '`' || ch === '\\') return notSingle(`'${ch}' inside double quotes`);
      else cur += ch;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      has = true;
      continue;
    }
    if (ch === ' ' || ch === '\t') {
      if (has) words.push(cur);
      cur = '';
      has = false;
      continue;
    }
    if (NOT_SIMPLE.test(ch)) return notSingle(`'${ch === '\n' || ch === '\r' ? 'newline' : ch}' outside quotes`);
    cur += ch;
    has = true;
  }
  if (quote !== null) return notSingle('unterminated quote');
  if (has) words.push(cur);

  const [tool, ...rest] = words;
  if (tool === undefined) return notSingle('empty');
  const at = (k: number): string => rest[k] ?? '';
  let key: string;
  let args: string[];
  switch (tool) {
    case 'npm':
      if (!NPM_INSTALL.has(at(0))) return notPlain(`'npm ${at(0)}'`);
      [key, args] = ['npm', rest.slice(1)];
      break;
    case 'pnpm':
    case 'yarn':
      if (at(0) !== 'add') return notPlain(`'${tool} ${at(0)}'`);
      [key, args] = [tool, rest.slice(1)];
      break;
    case 'bun':
      if (!BUN_ADD.has(at(0))) return notPlain(`'bun ${at(0)}'`);
      [key, args] = ['bun', rest.slice(1)];
      break;
    case 'pip':
    case 'pip3':
      if (at(0) !== 'install') return notPlain(`'${tool} ${at(0)}'`);
      [key, args] = ['pip', rest.slice(1)];
      break;
    case 'python':
    case 'python3':
    case 'py':
      if (at(0) !== '-m' || (at(1) !== 'pip' && at(1) !== 'pip3') || at(2) !== 'install') return notPlain(`'${tool} ${rest.join(' ')}'`);
      [key, args] = ['pip', rest.slice(3)];
      break;
    case 'uv':
      if (at(0) === 'add') [key, args] = ['uv', rest.slice(1)];
      else if (at(0) === 'pip' && at(1) === 'install') [key, args] = ['uv-pip', rest.slice(2)];
      else return notPlain(`'uv ${at(0)}'`);
      break;
    case 'poetry':
      if (at(0) !== 'add') return notPlain(`'poetry ${at(0)}'`);
      [key, args] = ['poetry', rest.slice(1)];
      break;
    case 'composer':
      if (at(0) !== 'require') return notPlain(`'composer ${at(0)}'`);
      [key, args] = ['composer', rest.slice(1)];
      break;
    case 'dotnet':
      if (at(0) !== 'add' || at(1) !== 'package') return notPlain(`'dotnet ${at(0)} ${at(1)}' (dotnet add <project> package …)`);
      [key, args] = ['dotnet', rest.slice(2)];
      break;
    default:
      return notPlain(`'${tool}' is not a bare package-manager name`);
  }
  const allow = ALLOW[key];
  if (allow === undefined) return notPlain(`no allowlist for ${key}`);
  let positionals = 0;
  for (let k = 0; k < args.length; k += 1) {
    const w = args[k] ?? '';
    if (!w.startsWith('-') || w === '-') {
      positionals += 1;
      continue;
    }
    const eqAt = w.indexOf('=');
    if (eqAt > 0) {
      const flag = w.slice(0, eqAt);
      if (!allow.value.has(flag)) return `flag ${flag} is not on the confident-shape allowlist`;
      continue;
    }
    if (allow.bool.has(w)) continue;
    if (allow.value.has(w)) {
      if (k + 1 >= args.length) return `flag ${w} has no value`;
      k += 1;
      continue;
    }
    if (!w.startsWith('--') && SHORT_CLUSTER.test(w)) {
      const bad = [...w.slice(1)].map((c) => `-${c}`).find((f) => !allow.bool.has(f));
      if (bad === undefined) continue;
      return `flag ${bad} is not on the confident-shape allowlist`;
    }
    return `flag ${w} is not on the confident-shape allowlist`;
  }
  return positionals > 0 ? null : notPlain('no package named');
}

const DIR_COMMANDS = new Set(['cd', 'chdir', 'pushd', 'popd', 'set-location', 'push-location', 'pop-location', 'sl', 'cd..']);

function changesDirectory(words: readonly ShellWord[]): boolean {
  const head = words[commandStart(words)];
  return head !== undefined && DIR_COMMANDS.has(base(head.value));
}

const ENV_COMMANDS = new Set(['export', 'declare', 'typeset', 'local', 'readonly', 'set', 'setx']);
/**
 * PowerShell setting an environment variable: `$env:X =`,
 * `SetEnvironmentVariable`, or `Set-Item` / `New-Item` followed by `env:` in
 * the same `;`/newline segment. The last one was one regex whose `[^;\n]*`
 * restarted at every `Set-Item` — 250 KB of them took 14 s, on every command
 * the hook sees (fix round 3). Per segment, one search after the first
 * cmdlet decides it the same way.
 */
function powershellSetsEnv(command: string): boolean {
  if (/\$env:[A-Za-z_][A-Za-z0-9_]*\s*=|SetEnvironmentVariable/i.test(command)) return true;
  for (const segment of command.split(/[;\n]/)) {
    const m = /\b(?:Set-Item|New-Item)\b/i.exec(segment);
    if (m !== null && /\benv:/i.test(segment.slice(m.index + m[0].length))) return true;
  }
  return false;
}

/**
 * Ruling (b): does ANY part of the command set an environment variable —
 * `VAR=x cmd`, `env VAR=x cmd`, `export VAR=x`, `set VAR=x`, `setx`,
 * PowerShell `$env:X=` / `Set-Item Env:`? Any of them can point the package
 * manager at another registry (`NPM_CONFIG_REGISTRY`, `PIP_INDEX_URL`, …),
 * so a name missing from the PUBLIC registry proves nothing afterwards.
 */
function changesEnvironment(command: string, statements: ReadonlyArray<{ commands: ShellWord[][] }>): boolean {
  if (powershellSetsEnv(command)) return true;
  for (const statement of statements) {
    for (const words of statement.commands) {
      const start = commandStart(words);
      for (let i = 0; i < start; i += 1) {
        const w = words[i];
        if (w !== undefined && (ASSIGNMENT.test(w.value) || base(w.value) === 'env')) return true;
      }
      const head = words[start];
      if (head === undefined) continue;
      const name = base(head.value);
      if (name === 'env') return true;
      if (ENV_COMMANDS.has(name)) {
        const args = words.slice(start + 1);
        if (name === 'export' || name === 'setx' || args.some((a) => a.value.includes('='))) return true;
      }
    }
  }
  return false;
}
