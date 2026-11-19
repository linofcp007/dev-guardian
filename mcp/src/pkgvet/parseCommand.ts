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
 * Pure functions. No I/O. Imports only the shell guard's tokenizer
 * (`hooks/shell/`), which is dependency-free — the hook loads this file from `mcp/dist`.
 */

import { commandWordIndex, resolveCommand } from '../hooks/shell/command.js';
import { withoutRedirectWords } from '../hooks/shell/effects.js';
import { splitShell, type ShellWord } from '../hooks/shell/split.js';
import { workdirs } from '../hooks/shell/workdir.js';
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
  /**
   * A launcher that runs an installed bin when the project has one — `npx`,
   * `npm exec`, `bunx`, `bun x` — and fetches the package only when it has
   * not (review of 3.0.0, P1): the hook drops a package it finds installed.
   */
  localFirst?: boolean;
  /**
   * The packages were named by the launcher's package flag (`npx -p pkg cmd`),
   * not as the program it runs: a `node_modules/.bin/<pkg>` says nothing about
   * whether `pkg` is installed (review of 3.3.0).
   */
  byPackageFlag?: boolean;
  /**
   * Where the command runs when a directory change earlier in the line moved
   * it: the targets of those `cd` / `pushd` / `Set-Location` words in order,
   * each relative to the one before (the hook resolves them against its own
   * working directory, and checks that each is a directory: a `cd` to one that
   * is not there moved nothing) — `cd mcp && npx vitest run` runs `mcp`'s
   * vitest. Only a move that surely ran counts (`shell/workdir.ts`'s `sure`,
   * the shell guard's tracker): `null` when one may not have (`false && cd
   * web`, `if …; then cd web; fi`, a function body, `{ cd web; } &`, under
   * `CDPATH`), or went somewhere this parse cannot tell (`cd "$X"`, `popd`
   * past the stack), or when the launcher itself runs elsewhere (`env -C`,
   * `sudo -D`); absent when nothing moved it.
   */
  workdir?: readonly string[] | null;
  /**
   * The launcher was given npm's `--prefix` (`-C`): it looks for the project
   * there, not where the command runs — so nothing is taken as installed
   * (review of 3.4.0, finding 5). Set for an install command too, by any of
   * its manager's directory flags (`--prefix`, `-C`, `--dir`, `--cwd`): the
   * manifest it installs is then not the one where the command runs.
   */
  prefixed?: boolean;
  /**
   * A global install, read only when it is certain ({@link saysGlobal}; Yarn only by `yarn global add`): the manager
   * puts the package in its global directory and does not obey the project's own configuration file for the registry
   * (measured 2026-11-19 with npm 11, pnpm 10, Yarn 1.22 and 4, bun 1.4). In doubt it is absent: a line too many, never
   * one too few.
   */
  global?: boolean;
  /**
   * The command installs what a manifest says: the `package.json` of the
   * directory it runs in (`npm install` with no package, `npm ci`, `pnpm
   * install`, `yarn`, `bun install`), or the requirement files given to `pip
   * install -r`, as written and in order. Present also when `packages` is
   * empty; absent for an install that names everything it fetches. Reading
   * the file is the hook's (`pkgvet/manifest.ts`): this module does no I/O.
   */
  manifest?: { kind: 'package-json' } | { kind: 'requirements'; files: readonly string[] };
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
/**
 * What a word that ends like an archive may be. One list for every manager was the bug: a package called
 * `lodash.zip` was skipped unvetted, though the manager fetches it from the registry. Each manager reads only its
 * own endings as a FILE (measured 2026-11-18); every other word is a name.
 */
const NPM_FILE = /\.(?:tgz|tar\.gz|tar)$/i;
const PIP_FILE = /\.(?:zip|whl|tar|tar\.gz|tgz|tar\.bz2|tbz|tar\.xz|txz|tlz|tar\.lz|tar\.lzma)$/i;
const UV_FILE = /\.(?:zip|whl|tgz|tar\.gz|tar)$/i;
const POETRY_FILE = /\.(?:zip|tar|tar\.gz|tgz|tar\.bz2|tbz|tar\.xz|txz|tlz|tar\.lz|tar\.lzma)$/i;
/** The endings of the old single list: what a version or range of a Python, Composer or NuGet word is still skipped for. */
const ARCHIVE = /\.(?:tgz|tar|tar\.gz|tar\.bz2|tar\.xz|zip|whl|egg|nupkg)$/i;
/** What an unmeasured manager may read as a file: every ending a measured manager reads as one, plus `.egg` and `.nupkg`. */
const UNMEASURED_FILE = /\.(?:zip|whl|tar|tar\.gz|tgz|tar\.bz2|tbz|tar\.xz|txz|tlz|tar\.lz|tar\.lzma|egg|nupkg)$/i;
/** The managers nobody measured: a word that ends like an archive is vetted as a name, and the command is uncertain. */
const UNMEASURED = new Set(['pipx', 'composer', 'dotnet']);
const UNMEASURED_ARCHIVE =
  'a name that ends like an archive file — this package manager was not measured, so whether it reads the word as a file or as a registry name is not known';

/**
 * Whether `manager` reads a version part or a manifest value that ends like `.tgz`, `.tar.gz` or `.tar` as a file to
 * install, not a tag: npm and bun do, pnpm and Yarn are taken not to; with no manager named nothing is a file (a spec
 * handed to `vet_packages` is a name). The one rule of the command line's `name@<part>` and of a `package.json`
 * value (`manifest.ts` names its default manager itself).
 */
export function readsFileValue(manager: string | undefined, value: string): boolean {
  return (manager === 'npm' || manager === 'npx' || manager === 'bun') && NPM_FILE.test(value);
}

/** The endings `manager` reads as a file in a bare word; `null` when it reads none (or the caller names no manager). */
function fileEndings(manager: string | undefined, scoped: boolean): RegExp | null {
  switch (manager) {
    case 'npm':
    case 'npx':
      return scoped ? null : NPM_FILE;
    case 'bun':
      return NPM_FILE;
    case 'pip':
      return PIP_FILE;
    case 'uv':
    case 'uv-pip':
      return UV_FILE;
    case 'poetry':
      return POETRY_FILE;
    default:
      return null;
  }
}

/** Why a bare name of an unmeasured manager is uncertain, or `undefined`. */
function unmeasuredReason(manager: string, spec: PackageSpec): string | undefined {
  return UNMEASURED.has(manager) && spec.name === spec.raw && UNMEASURED_FILE.test(spec.raw) ? UNMEASURED_ARCHIVE : undefined;
}

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
function notAPackage(word: string, archive: RegExp | null): string | null {
  if (word.length === 0) return 'empty';
  if (SCP_GIT.test(word)) return 'SSH git spec (user@host:path) — not looked up';
  if (isPathLike(word)) return 'local path — not looked up';
  if (URL_OR_VCS.test(word)) return 'URL / VCS / protocol spec — not looked up';
  if (archive !== null && archive.test(word)) return 'archive file — not looked up';
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

/** `alias`: the word is the real name after `npm:` (read in any letter case, as npm does) — a name for every manager, whatever it ends in. */
function parseNpm(raw: string, manager?: string, alias = false): PackageSpec | SkippedSpec {
  if (/[$`]/.test(raw)) return skip(raw, 'not a literal package name (shell expansion)');
  const scoped = raw.startsWith('@');
  const at = raw.indexOf('@', scoped ? 1 : 0);
  // A bare word is a file only for a manager that reads its ending as one; with a version the part after `@` decides below.
  const bad = notAPackage(raw, at > 0 || alias ? null : fileEndings(manager, scoped));
  if (bad !== null) return skip(raw, bad);
  const name = at > 0 ? raw.slice(0, at) : raw;
  let range = at > 0 ? raw.slice(at + 1) : undefined;
  if (!scoped && name.includes('/')) return skip(raw, 'GitHub shorthand (user/repo) — not looked up');
  if (range !== undefined) {
    if (/^npm:/i.test(range)) {
      // `alias@npm:real@range` installs `real` under the name `alias`.
      const real = parseNpm(range.slice(4), manager, true);
      return 'name' in real ? { ...real, raw } : skip(raw, real.reason);
    }
    const rangeBad = notAPackage(range, null);
    if (rangeBad !== null || URL_OR_VCS.test(range)) return skip(raw, rangeBad ?? 'URL / VCS / protocol spec — not looked up');
    if (readsFileValue(manager, range)) return skip(raw, 'archive file — not looked up');
    if (range === 'latest') range = undefined;
  }
  return withRange(checkName('npm', name, raw), range);
}

const PEP440_OP = /(===|==|~=|!=|<=|>=|<|>)/;

function parsePython(raw: string, poetryAt: boolean, manager?: string): PackageSpec | SkippedSpec {
  let text = raw.trim();
  const semi = text.indexOf(';');
  if (semi >= 0) text = text.slice(0, semi).trim(); // environment marker
  if (/[$`]/.test(text)) return skip(raw, 'not a literal package name (shell expansion)');
  if (/\s@\s|@\s*(?:[a-z][a-z0-9+.-]*:\/\/|git\+|file:)/i.test(text)) return skip(raw, 'direct URL reference — not looked up');
  const versioned = PEP440_OP.test(text) || text.indexOf('@') > 0;
  const bad = notAPackage(text, versioned ? ARCHIVE : fileEndings(manager, false));
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
  const versioned = raw.search(/[:=\s]/) > 0 || (raw.includes('@') && !raw.startsWith('@'));
  const bad = notAPackage(raw, versioned ? ARCHIVE : null);
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
  const bad = notAPackage(raw, raw.indexOf('@') > 0 ? ARCHIVE : null);
  if (bad !== null) return skip(raw, bad);
  const at = raw.indexOf('@');
  const name = at > 0 ? raw.slice(0, at) : raw;
  const range = at > 0 ? raw.slice(at + 1) : undefined;
  return withRange(checkName('nuget', name, raw), range);
}

/**
 * One package spec as a user or tool call writes it: `name`, `name@version`,
 * plus each ecosystem's own spelling (`name==1.2`, `vendor/pkg:^2`). With no
 * `manager` a bare word is a name whatever it ends in; with one, the endings that
 * manager reads as a file are skipped as an archive.
 */
export function parsePackageSpec(ecosystem: PkgEcosystem, raw: string, manager?: string): PackageSpec | SkippedSpec {
  switch (ecosystem) {
    case 'npm':
      return parseNpm(raw.trim(), manager);
    case 'pypi':
      return parsePython(raw, false, manager);
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
  /**
   * A literal `true` or `false` right after a boolean flag is that flag's value, not a package: `npm install -D false`
   * installs the manifest ({@link takesBoolWord}). Measured 2026-11-19 (npm 11.19.0 / 11.20.0, pnpm 10.33.2), the same
   * for both: after an exact boolean flag, and after a short cluster of boolean letters when the cluster's LAST letter
   * takes it (`-qD false` yes; `-Dq false` no — the word is then a package). `except` are the boolean flags that take
   * NO word, whose word stays a package: the loglevel shorthands `--silent`, `--quiet`, `-q`, `--verbose`, `-d`. A flag
   * written with `=` takes nothing after it. Absent for the other managers and the launchers, which were not measured
   * (or fetch the word as a package: `npx --yes false pkg`).
   */
  boolWord?: { except: ReadonlySet<string> };
  /** Flags that put the install in a workspace context, where a name may be a local package. */
  workspace?: ReadonlySet<string>;
  /**
   * A launcher's flags whose value is the package to fetch, instead of its
   * first positional word — which is then the command to run (`npx -p pkg
   * cmd`, `uvx --from pkg cmd`, `pipx run --spec pkg cmd`).
   */
  packageFlags?: ReadonlySet<string>;
  /** Flags whose value is a package fetched as well (`uvx --with x`, `pipx install --preinstall x`); commas separate several. */
  extraPackageFlags?: ReadonlySet<string>;
  /** Flags after which the positional word is shell text, not a package (`npx -c '…'`). */
  shellFlags?: ReadonlySet<string>;
  /** Flags that forbid fetching anything (`npx --no-install`). */
  noFetchFlags?: ReadonlySet<string>;
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

/** The loglevel shorthands of npm and pnpm: boolean flags that take no `true` / `false` word (measured 2026-11-19). */
const LOGLEVEL_FLAGS: ReadonlySet<string> = new Set(['--silent', '--quiet', '-q', '--verbose', '-d']);

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
    boolWord: { except: LOGLEVEL_FLAGS },
  },
  pnpm: {
    value: set('--registry', '--filter', '-F', '--dir', '-C', '--reporter', '--store-dir', '--global-dir',
      '--modules-dir', '--virtual-store-dir', '--lockfile-dir', '--network-concurrency', '--config', '--loglevel',
      '--allow-build'),
    bool: set(...NPM_COMMON_BOOL, '--workspace', '-w', '--workspace-root', '--recursive', '-r'),
    registry: set('--registry'),
    dir: set('--dir', '-C'),
    workspace: set('--workspace', '--filter', '-F'),
    boolWord: { except: LOGLEVEL_FLAGS },
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
      '-p', '--prerelease', '--resolution', '--requirements'),
    bool: set('-U', '--upgrade', '--user', '--no-deps', '--pre', '--force-reinstall', '-I', '--ignore-installed',
      '--no-cache-dir', '--no-cache', '-q', '-v', '--quiet', '--verbose', '--break-system-packages', '--dry-run',
      '--no-build-isolation', '--require-hashes', '--isolated', '--disable-pip-version-check', '--no-input',
      '--compile', '--no-compile', '--prefer-binary', '--no-warn-script-location', '--use-pep517', '--no-clean',
      '--check-build-dependencies', '--ignore-requires-python', '--system', '--all-extras', '--no-index',
      '--compile-bytecode'),
    registry: set('-i', '--index-url', '--extra-index-url', '-f', '--find-links', '--index', '--default-index'),
    registryBool: set('--no-index'),
    reported: new Map([
      ['-r', 'requirements file (-r) — read as a manifest, not as a package name'],
      ['--requirement', 'requirements file (-r) — read as a manifest, not as a package name'],
      // `uv pip install` spells it in the plural.
      ['--requirements', 'requirements file (-r) — read as a manifest, not as a package name'],
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

const UV_VALUED = [
  '--python', '-p', '--index', '--index-url', '--default-index', '--extra-index-url', '--find-links', '-f',
  '--index-strategy', '--keyring-provider', '--resolution', '--prerelease', '--exclude-newer', '--link-mode',
  '--directory', '--project', '--config-file', '--cache-dir', '--constraints', '--overrides', '--env-file',
  '--with-requirements', '--with-editable', '--python-preference', '--color',
];
const UV_BOOL = [
  '--isolated', '--offline', '-q', '--quiet', '-v', '--verbose', '--no-cache', '-n', '--refresh', '--reinstall',
  '--upgrade', '-U', '--native-tls', '--no-config', '--no-progress', '--no-python-downloads', '--force',
  '--no-index', '--compile-bytecode',
];
const UV_REGISTRY = ['--index', '--index-url', '--default-index', '--extra-index-url', '--find-links', '-f'];

/**
 * The launchers that download a package and run it (review of 3.0.0, P1):
 * `npx`, `npm exec`, `pnpm dlx` / `pnpx`, `yarn dlx`, `bunx` / `bun x`,
 * `uvx` / `uv tool run`, `uv tool install`, `pipx run` and `pipx install`.
 * Keyed by the `Detected.flags` name.
 */
const LAUNCH_FLAGS: Record<string, FlagTable> = {
  npx: {
    value: set('--package', '-p', '--call', '-c', '--registry', '--cache', '--userconfig', '--prefix', '-C', '--workspace', '-w',
      '--loglevel', '--node-options'),
    bool: set('--yes', '-y', '--no', '--no-install', '--ignore-existing', '--quiet', '-q', '--silent', '--prefer-offline',
      '--prefer-online', '--offline', '--workspaces', '--include-workspace-root', '--verbose'),
    registry: set('--registry'),
    workspace: set('--workspace', '-w', '--workspaces'),
    packageFlags: set('--package', '-p'),
    shellFlags: set('--call', '-c'),
    noFetchFlags: set('--no', '--no-install', '--offline'),
  },
  'pnpm-dlx': {
    value: set('--package', '--allow-build', '--registry', '--dir', '-C', '--reporter'),
    bool: set('--silent', '-s', '--shell-mode', '-c'),
    registry: set('--registry'),
    dir: set('--dir', '-C'),
    packageFlags: set('--package'),
    shellFlags: set('--shell-mode', '-c'),
  },
  'yarn-dlx': {
    value: set('--package', '-p'),
    bool: set('--quiet', '-q'),
    registry: set(),
    packageFlags: set('--package', '-p'),
  },
  bunx: {
    value: set('--package', '-p'),
    bool: set('--bun', '--silent', '--verbose'),
    registry: set(),
    packageFlags: set('--package', '-p'),
  },
  uvx: {
    value: set(...UV_VALUED, '--from', '--with', '-w'),
    bool: set(...UV_BOOL),
    registry: set(...UV_REGISTRY),
    registryBool: set('--no-index'),
    dir: set('--directory', '--project'),
    packageFlags: set('--from'),
    extraPackageFlags: set('--with', '-w'),
  },
  'uv-tool-install': {
    value: set(...UV_VALUED, '--with', '-w', '--editable', '-e'),
    bool: set(...UV_BOOL),
    registry: set(...UV_REGISTRY),
    registryBool: set('--no-index'),
    dir: set('--directory', '--project'),
    extraPackageFlags: set('--with', '-w'),
    reported: new Map([
      ['--editable', 'editable install (-e) — local or VCS source, not looked up'],
      ['-e', 'editable install (-e) — local or VCS source, not looked up'],
    ]),
  },
  'pipx-install': {
    value: set('--index-url', '-i', '--suffix', '--python', '--preinstall', '--spec'),
    bool: set('--force', '-f', '--include-deps', '--editable', '-e', '--system-site-packages', '--global', '--quiet', '-q',
      '--verbose', '-v', '--fetch-missing-python'),
    registry: set('--index-url', '-i'),
    extraPackageFlags: set('--preinstall', '--spec'),
  },
  'pipx-run': {
    value: set('--spec', '--index-url', '-i', '--python', '--path'),
    bool: set('--no-cache', '--quiet', '-q', '--verbose', '-v', '--system-site-packages', '--fetch-missing-python'),
    registry: set('--index-url', '-i'),
    packageFlags: set('--spec'),
  },
};

interface Positional {
  value: string;
  /** The word after a long flag the table does not know: a possible package, or that flag's value ({@link afterUnknownFlag}). */
  candidate?: true;
}

interface WalkResult {
  positionals: Positional[];
  skipped: SkippedSpec[];
  customRegistry?: string;
  registries: string[];
  /** Reasons a missing name in this command must not be denied (ruling (a), (c), (f)). */
  uncertain: string[];
  /** Every flag seen, with its value when it took one — what a launcher's packages are read from. */
  flags: Array<{ flag: string; value?: string }>;
  /** How many flags the table of the manager does not know: npm reads abbreviations (`--loc=project`) that it does not hold. */
  unknownFlags: number;
}

const SHORT_CLUSTER = /^-[A-Za-z]{2,}/;

const isBoolWord = (word: string | undefined): boolean => word === 'true' || word === 'false';

/**
 * The one rule for the word after a flag the table does not know: `walk` and `nextPositional` both ask it, so the
 * flag is read the same way in a package position and in the subcommand position. The tables are hand-written lists
 * and the managers have more boolean flags than they hold: a long flag (no `=`, not `--no-...`) is followed by a word
 * that may be its value or a package, and the hook cannot tell. `candidate`: the word stays a possible value AND is
 * vetted as a possible package; `value`: npm and pnpm read a `true` / `false` as the value (measured 2026-11-19);
 * `none`: the flag takes no word (a short flag, one written with `=`, `--no-...`, one the table knows, or one followed
 * by a flag).
 */
function afterUnknownFlag(v: string, next: string | undefined, table: FlagTable): 'none' | 'value' | 'candidate' {
  if (table.value.has(v) || table.bool.has(v)) return 'none';
  if (!v.startsWith('--') || v === '--' || v.startsWith('--no-') || v.includes('=')) return 'none';
  if (next === undefined || (next.startsWith('-') && next.length > 1)) return 'none';
  return table.boolWord !== undefined && isBoolWord(next) ? 'value' : 'candidate';
}

/**
 * Whether the flag word `v` (no `=`) is one that takes a following `true` / `false` as its value, in a table with
 * {@link FlagTable.boolWord}: an exact boolean flag that is not a loglevel shorthand, or a short cluster of boolean
 * letters whose LAST letter is such a flag (measured 2026-11-19: npm 11.20.0, pnpm 10.33.2).
 */
function takesBoolWord(v: string, table: FlagTable): boolean {
  const rule = table.boolWord;
  if (rule === undefined) return false;
  if (table.bool.has(v)) return !rule.except.has(v);
  if (v.startsWith('--') || !SHORT_CLUSTER.test(v)) return false;
  const letters = [...v.slice(1)].map((c) => `-${c}`);
  const last = letters[letters.length - 1];
  return letters.every((flag) => table.bool.has(flag)) && last !== undefined && !rule.except.has(last);
}

/**
 * Separates flags (and their values) from positional words.
 *
 * Short-flag clusters are expanded letter by letter (`-qr req.txt` is `-q`
 * then `-r req.txt`; `-rreq.txt` is `-r req.txt`): the first letter that
 * takes a value takes the rest of the cluster, or the next word. A flag
 * this table does not know makes the parse uncertain; the word after an
 * unknown LONG flag is both a possible value and a candidate package
 * ({@link afterUnknownFlag}): vetting a flag's value as a name only warns, and
 * missing a package fails open.
 */
function walk(words: readonly ShellWord[], table: FlagTable): WalkResult {
  const positionals: Positional[] = [];
  const skipped: SkippedSpec[] = [];
  const uncertain: string[] = [];
  let unknownFlags = 0;
  let customRegistry: string | undefined;
  const registries: string[] = [];
  const flags: Array<{ flag: string; value?: string }> = [];
  const note = (flag: string, value: string | undefined): void => {
    flags.push(value === undefined ? { flag } : { flag, value });
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
  let candidateAt = -1;
  for (let i = 0; i < words.length; i += 1) {
    const w = words[i];
    if (w === undefined) break;
    const v = w.value;
    if (v === '--') continue;
    if (!v.startsWith('-') || v.length === 1) {
      positionals.push(i === candidateAt ? { value: v, candidate: true } : { value: v });
      continue;
    }
    const eqAt = v.indexOf('=');
    if (eqAt > 0) {
      const flag = v.slice(0, eqAt);
      if (!known(flag)) {
        uncertain.push(`unknown flag ${flag}`);
        unknownFlags += 1;
      }
      note(flag, v.slice(eqAt + 1));
      continue;
    }
    if (table.value.has(v)) {
      note(v, words[i + 1]?.value);
      i += 1;
      continue;
    }
    if (table.bool.has(v)) {
      const word = words[i + 1]?.value;
      if (takesBoolWord(v, table) && isBoolWord(word)) {
        note(v, word);
        i += 1;
      } else note(v, undefined);
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
        if (!table.bool.has(flag)) {
          uncertain.push(`unknown flag ${flag}`);
          unknownFlags += 1;
        }
        note(flag, undefined);
      }
      if (takesBoolWord(v, table) && isBoolWord(words[i + 1]?.value)) i += 1;
      continue;
    }
    uncertain.push(`unknown flag ${v}`);
    unknownFlags += 1;
    const after = afterUnknownFlag(v, words[i + 1]?.value, table);
    if (after === 'value') i += 1;
    else if (after === 'candidate') candidateAt = i + 1;
  }
  const out: WalkResult = { positionals, skipped, uncertain, registries, flags, unknownFlags };
  if (customRegistry !== undefined) out.customRegistry = customRegistry;
  return out;
}

// ─────────────────────────────────────────────────────────── commands

const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

function base(word: string): string {
  const last = word.split(/[\\/]/).pop() ?? word;
  return last.toLowerCase().replace(/\.(?:exe|cmd|bat|ps1)$/, '');
}

/**
 * Index of the word that names the command, past `VAR=x`, `sudo -E`, `env`,
 * `timeout 30`… — the shell guard's own resolver, each runner read with its
 * own options: a table shared by every runner made `sudo -n npm i x` read
 * `npm` as the value of `-n`, and vet nothing (review of 3.0.0).
 */
function commandStart(words: readonly ShellWord[]): number {
  return commandWordIndex(words);
}

const NPM_INSTALL = new Set(['install', 'i', 'add', 'in', 'ins', 'inst', 'insta', 'instal', 'isnt', 'isnta', 'isntal', 'isntall']);
/** npm's subcommands that install the manifest and take no package: `ci`, `install-test`, `install-ci-test` and their aliases. */
const NPM_MANIFEST_INSTALL = new Set([
  'ci', 'clean-install', 'ic', 'install-clean', 'isntall-clean', 'install-test', 'it', 'install-ci-test', 'cit', 'clean-install-test', 'sit',
]);
const COMPOSER_REQUIRE = new Set(['require', 'r', 'req', 'requ', 'requi', 'requir']);
const BUN_ADD = new Set(['add', 'a', 'install', 'i']);
/** pnpm's install subcommand: with a package it adds it, with none it installs the manifest. */
const PNPM_INSTALL = new Set(['install', 'i']);
/** Flags after which a bare `yarn` installs nothing: it prints and leaves. */
const YARN_PRINTS = new Set(['--version', '-v', '-V', '--help', '-h']);
/** The flags of pip and `uv pip` that name a requirements file. */
const REQUIREMENT_FLAGS = new Set(['-r', '--requirement', '--requirements']);
/** The flags that make an npm-family install a global one: no project manifest is installed. */
const isGlobalFlag = (f: { flag: string; value?: string }): boolean =>
  ((f.flag === '-g' || f.flag === '--global') && f.value !== 'false') || (f.flag === '--location' && f.value === 'global');

/** The words a flag can come from: what follows a `--` word is no flag. */
const beforeDoubleDash = (words: readonly ShellWord[]): ShellWord[] => {
  const at = words.findIndex((w) => w.value === '--');
  return at < 0 ? [...words] : words.slice(0, at);
};

/**
 * Whether an npm, pnpm or bun command says it is a GLOBAL install, and no word can take that back — measured
 * 2026-11-19 (npm 11, pnpm 10, Yarn 1.22 and 4, bun 1.4): the project's registry file is not obeyed by a global install,
 * but is by `--global=false`, `-g false`, `-g --no-global`, `-g --location=project`. The words before the subcommand
 * and the words after it are two lists, each read up to a `--` word. In doubt the answer is no:
 *   - a word with a shell expansion (`$` or a backtick) may be `false` or `--no-global`: not global;
 *   - says global: the exact words `-g` and `--global` (not when the next word of the list is `false`), `--global=true`,
 *     and for npm `--location=global` and `--location global`;
 *   - takes it back: any other word that starts with `-` and has `global` or `location` in it, or starts `-g=`;
 *   - a short cluster that holds a `g` (`-gD`, `-Dg false`) takes it back: the word after it may be the value of its `g`
 *     (measured 2026-11-19, npm 11.20.0: `-g -Dg false` installs the manifest); a package name with "global" in it takes
 *     nothing back.
 * It is only part of the answer: a global word that stands where another flag's value goes (`--otp --global`) is that
 * flag's value, not a flag — the caller also asks the walker's flags ({@link isGlobalFlag}), which know the flags that
 * take a value, and a flag the manager's table does not know (npm's abbreviations: `--loc=project`) leaves it not global.
 * Yarn is global only by its subcommand (`yarn global add`, {@link Detected.global}): a flag never makes it so (Yarn 1's
 * `-g` takes a value, Yarn 4 refuses it).
 */
function saysGlobal(manager: string, pre: readonly ShellWord[], args: readonly ShellWord[]): boolean {
  if (manager !== 'npm' && manager !== 'pnpm' && manager !== 'bun') return false;
  if ([...pre, ...args].some((w) => /[$`]/.test(w.value))) return false;
  let says = false;
  for (const list of [beforeDoubleDash(pre), beforeDoubleDash(args)]) {
    for (const [at, w] of list.entries()) {
      const v = w.value;
      const next = list[at + 1]?.value;
      if (!v.startsWith('-')) continue;
      if (v === '-g' || v === '--global') {
        if (next === 'false') return false;
        says = true;
      } else if (v === '--global=true') says = true;
      else if (manager === 'npm' && (v === '--location=global' || (v === '--location' && next === 'global'))) says = true;
      else if (v.startsWith('-g=') || /global|location/.test(v.toLowerCase())) return false;
      else if (/^-[A-Za-z]{2,}$/.test(v) && v.includes('g')) return false; // a cluster with a `g`: its word may be the value of that `g`
    }
  }
  return says;
}

interface Detected {
  manager: string;
  ecosystem: PkgEcosystem;
  /** Words after the install subcommand (flags included). */
  args: ShellWord[];
  /** Flags before the subcommand, which may name a registry too. */
  pre: ShellWord[];
  /** Reasons found while locating the subcommand (a workspace, a project argument). */
  uncertain: string[];
  /** `yarn global add`: the install is a global one. */
  global?: boolean;
  /**
   * A launcher (review P1), and its {@link LAUNCH_FLAGS} table: `run` fetches
   * the package its first positional word names (or its package flags do)
   * and hands every later word to the program; `install` installs every
   * positional word, as an install command does.
   */
  launch?: { style: 'run' | 'install'; flags: string; localFirst?: boolean };
  /**
   * An install of the project's `package.json`: `always` for a subcommand
   * that takes no package (`npm ci`, `pnpm install`, `yarn install`, a bare
   * `yarn`), whose positional words are then no packages; `bare` for one that
   * installs the manifest only when it names nothing (`npm install`, `bun
   * install`).
   */
  manifest?: 'always' | 'bare';
}

/** A launcher as `detect` returns it. */
function launcher(
  manager: string,
  ecosystem: PkgEcosystem,
  args: ShellWord[],
  pre: ShellWord[],
  launch: NonNullable<Detected['launch']>,
): Detected {
  return { manager, ecosystem, args, pre, uncertain: [], launch };
}

/**
 * First positional (non-flag) index at or after `from`, honouring the table's value flags, with whether that word
 * follows a flag the table does not know ({@link afterUnknownFlag}: it may be that flag's value). With
 * `candidateAsValue` such a word is read as the value and skipped.
 */
function scanPositional(words: readonly ShellWord[], from: number, table: FlagTable, candidateAsValue: boolean): { at: number; candidate: boolean } {
  let candidateAt = -1;
  for (let i = from; i < words.length; i += 1) {
    const v = words[i]?.value ?? '';
    if (v.startsWith('-') && v.length > 1) {
      if (v.includes('=')) continue;
      if (table.value.has(v)) i += 1;
      // `npm -D false install`: the word after a boolean flag is its value, not the subcommand.
      else if (takesBoolWord(v, table) && isBoolWord(words[i + 1]?.value)) i += 1;
      else {
        const after = afterUnknownFlag(v, words[i + 1]?.value, table);
        if (after === 'value' || (after === 'candidate' && candidateAsValue)) i += 1;
        else if (after === 'candidate') candidateAt = i + 1;
      }
      continue;
    }
    return { at: i, candidate: i === candidateAt };
  }
  return { at: -1, candidate: false };
}

/**
 * The command at `words`, read twice when it needs it: a word after a flag the table does not know may be that flag's
 * value (`npm --fetch-retries 0 install p`, `yarn --network-concurrency 1`), so when the first reading (the word as
 * the subcommand) finds nothing to read, the second reads it as the flag's value.
 */
function detect(words: readonly ShellWord[]): Detected | null {
  return detectReading(words, false) ?? detectReading(words, true);
}

function detectReading(words: readonly ShellWord[], flagWordIsValue: boolean): Detected | null {
  const nextPositional = (ws: readonly ShellWord[], from: number, table: FlagTable): number =>
    scanPositional(ws, from, table, flagWordIsValue).at;
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

  // The launchers named by themselves (review P1).
  const rest = words.slice(i);
  if (head === 'npx') return launcher('npx', 'npm', rest, [], { style: 'run', flags: 'npx', localFirst: true });
  if (head === 'pnpx') return launcher('pnpm', 'npm', rest, [], { style: 'run', flags: 'pnpm-dlx' });
  if (head === 'bunx') return launcher('bun', 'npm', rest, [], { style: 'run', flags: 'bunx', localFirst: true });
  if (head === 'uvx') return launcher('uv', 'pypi', rest, [], { style: 'run', flags: 'uvx' });
  if (head === 'pipx') {
    const sub = nextPositional(words, i, LAUNCH_FLAGS['pipx-run'] ?? FLAGS['pip'] ?? { value: set(), bool: set(), registry: set() });
    const subWord = sub < 0 ? '' : (words[sub]?.value ?? '');
    if (subWord === 'install') return launcher('pipx', 'pypi', words.slice(sub + 1), words.slice(i, sub), { style: 'install', flags: 'pipx-install' });
    if (subWord === 'run') return launcher('pipx', 'pypi', words.slice(sub + 1), words.slice(i, sub), { style: 'run', flags: 'pipx-run' });
    return null;
  }

  const table = FLAGS[head];
  if (table === undefined) return null;
  const sub = nextPositional(words, i, table);
  if (sub < 0) {
    // A bare `yarn` — flags only — installs the project's manifest, unless a flag only prints.
    if (head === 'yarn' && !rest.some((w) => YARN_PRINTS.has(w.value))) {
      return { manager: head, ecosystem: 'npm', args: rest, pre: [], uncertain: [], manifest: 'always' };
    }
    return null;
  }
  // The launchers that are a package manager's subcommand (review P1).
  const subName = words[sub]?.value ?? '';
  const after = words.slice(sub + 1);
  const before = words.slice(i, sub);
  if (head === 'npm' && (subName === 'exec' || subName === 'x')) {
    return launcher('npm', 'npm', after, before, { style: 'run', flags: 'npx', localFirst: true });
  }
  if (head === 'pnpm' && subName === 'dlx') return launcher('pnpm', 'npm', after, before, { style: 'run', flags: 'pnpm-dlx' });
  if (head === 'yarn' && subName === 'dlx') return launcher('yarn', 'npm', after, before, { style: 'run', flags: 'yarn-dlx' });
  if (head === 'bun' && subName === 'x') return launcher('bun', 'npm', after, before, { style: 'run', flags: 'bunx', localFirst: true });
  if (head === 'uv' && subName === 'tool') {
    const toolTable = LAUNCH_FLAGS['uvx'] ?? table;
    const verb = nextPositional(words, sub + 1, toolTable);
    const verbName = verb < 0 ? '' : (words[verb]?.value ?? '');
    const tail = words.slice(verb + 1);
    if (verbName === 'run') return launcher('uv', 'pypi', tail, before, { style: 'run', flags: 'uvx' });
    if (verbName === 'install') return launcher('uv', 'pypi', tail, before, { style: 'install', flags: 'uv-tool-install' });
    return null;
  }
  const subWord = words[sub]?.value ?? '';
  const pre = words.slice(i, sub);

  switch (head) {
    case 'npm':
      // A bare `npm install` installs the manifest; `npm ci` and its kin always do.
      if (NPM_INSTALL.has(subWord)) return { manager: head, ecosystem: 'npm', args: words.slice(sub + 1), pre, uncertain: [], manifest: 'bare' };
      if (NPM_MANIFEST_INSTALL.has(subWord)) return { manager: head, ecosystem: 'npm', args: words.slice(sub + 1), pre, uncertain: [], manifest: 'always' };
      return null;
    case 'pnpm':
      if (subWord === 'add') return { manager: head, ecosystem: 'npm', args: words.slice(sub + 1), pre, uncertain: [] };
      // `pnpm install <pkg>` / `pnpm i <pkg>` is pnpm's `add` (measured, pnpm 10.33: it resolves the name as a direct
      // dependency); with no package it installs the manifest. Up to and including 3.10.0 the form with a package was not read at all.
      if (PNPM_INSTALL.has(subWord)) return { manager: head, ecosystem: 'npm', args: words.slice(sub + 1), pre, uncertain: [], manifest: 'bare' };
      return null;
    case 'bun': {
      // `bun a`, and `bun i <pkg>` / `bun install <pkg>` add too; a bare `bun install` installs the manifest.
      if (!BUN_ADD.has(subWord)) return null;
      const d: Detected = { manager: head, ecosystem: 'npm', args: words.slice(sub + 1), pre, uncertain: [] };
      return subWord === 'install' || subWord === 'i' ? { ...d, manifest: 'bare' } : d;
    }
    case 'yarn': {
      if (subWord === 'install') return { manager: head, ecosystem: 'npm', args: words.slice(sub + 1), pre, uncertain: [], manifest: 'always' };
      let at = sub;
      const uncertain: string[] = [];
      if (subWord === 'global') at = nextPositional(words, sub + 1, table);
      else if (subWord === 'workspace') {
        const ws = nextPositional(words, sub + 1, table);
        at = ws < 0 ? -1 : nextPositional(words, ws + 1, table);
        uncertain.push('workspace context (yarn workspace)');
      }
      if (at < 0 || words[at]?.value !== 'add') return null;
      return { manager: head, ecosystem: 'npm', args: words.slice(at + 1), pre, uncertain, ...(subWord === 'global' ? { global: true } : {}) };
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

/**
 * A launcher's packages (review P1): the values of its package flags, else —
 * unless it runs shell text (`npx -c`) or may fetch nothing (`npx
 * --no-install`) — its positional words: for `run`, only the first, the rest
 * being the program's own arguments; for `install`, all. Plus the packages a
 * flag adds (`uvx --with x`).
 */
function collectLaunch(d: Detected, launch: NonNullable<Detected['launch']>, context: readonly string[]): InstallCommand {
  const table = LAUNCH_FLAGS[launch.flags] ?? { value: set(), bool: set(), registry: set() };
  const pre = walk(d.pre, table);
  let body = d.args;
  if (launch.style === 'run') {
    // The word after a flag the table does not know may be that flag's value: then the next positional is a package too.
    let scan = scanPositional(d.args, 0, table, false);
    let end = scan.at;
    while (scan.at >= 0 && scan.candidate) {
      scan = scanPositional(d.args, scan.at + 1, table, false);
      if (scan.at >= 0) end = scan.at;
    }
    if (end >= 0) body = d.args.slice(0, end + 1);
  }
  const w = walk(body, table);
  const flags = [...pre.flags, ...w.flags];
  const has = (names: ReadonlySet<string> | undefined): boolean => names !== undefined && flags.some((f) => names.has(f.flag));
  const values = (names: ReadonlySet<string> | undefined): string[] =>
    names === undefined
      ? []
      : flags
          .filter((f) => names.has(f.flag))
          .flatMap((f) => (f.value ?? '').split(','))
          .map((v) => v.trim())
          .filter((v) => v !== '');
  const raws: string[] = [];
  let byPackageFlag = false;
  if (!has(table.noFetchFlags)) {
    const named = values(table.packageFlags);
    if (named.length > 0) {
      raws.push(...named);
      byPackageFlag = true;
    } else if (!has(table.shellFlags)) raws.push(...w.positionals.map((p) => p.value));
    raws.push(...values(table.extraPackageFlags));
  }
  const packages: PackageSpec[] = [];
  const skipped: SkippedSpec[] = [...pre.skipped, ...w.skipped];
  const unsure: string[] = [];
  for (const raw of raws) {
    const spec = d.ecosystem === 'npm' ? parseNpm(raw, d.manager) : parsePython(raw, false, d.manager);
    if ('name' in spec) {
      packages.push(spec);
      const why = unmeasuredReason(d.manager, spec);
      if (why !== undefined) unsure.push(why);
    } else skipped.push(spec);
  }
  const out: InstallCommand = {
    ecosystem: d.ecosystem,
    manager: d.manager,
    packages,
    skipped,
    uncertain: [...new Set([...context, ...pre.uncertain, ...w.uncertain, ...unsure])],
    registries: [...pre.registries, ...w.registries],
  };
  const registry = pre.customRegistry ?? w.customRegistry;
  if (registry !== undefined) out.customRegistry = registry;
  if (launch.localFirst === true) out.localFirst = true;
  if (byPackageFlag) out.byPackageFlag = true;
  if (flags.some((f) => f.flag === '--prefix' || f.flag === '-C')) out.prefixed = true;
  return out;
}

function collect(d: Detected, context: readonly string[]): InstallCommand {
  if (d.launch !== undefined) return collectLaunch(d, d.launch, context);
  const table = FLAGS[d.manager === 'uv-pip' ? 'pip' : d.manager] ?? FLAGS['npm'];
  const flagTable = table ?? { value: set(), bool: set(), registry: set() };
  const preWalk = walk(d.pre, flagTable);
  const walked = walk(d.args, flagTable);
  const { skipped, customRegistry, uncertain, registries } = walked;
  // A subcommand that takes no package names none: its positional words are not looked up.
  const positionals = d.manifest === 'always' ? [] : walked.positionals;
  const allFlags = [...preWalk.flags, ...walked.flags];
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

  // A candidate (the word after a flag the table does not know) may be that flag's value: it is vetted, but it is not a
  // thing the command surely names, so it does not stop the manifest from being read.
  let candidateSkipped = 0;
  let namedPackages = 0;
  let lastComposer: PackageSpec | undefined;
  for (const p of positionals) {
    let spec: PackageSpec | SkippedSpec;
    switch (d.ecosystem) {
      case 'npm':
        spec = parseNpm(p.value, d.manager);
        break;
      case 'pypi':
        spec = parsePython(p.value, d.manager === 'poetry', d.manager);
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
      if (p.candidate !== true) namedPackages += 1;
      const why = unmeasuredReason(d.manager, spec);
      if (why !== undefined && !out.uncertain.includes(why)) out.uncertain.push(why);
      lastComposer = d.ecosystem === 'packagist' ? spec : undefined;
    } else {
      skipped.push(spec);
      if (p.candidate === true) candidateSkipped += 1;
      lastComposer = undefined;
    }
  }

  if (d.ecosystem === 'nuget') {
    // One package per `dotnet add package`; its version is a flag. With a candidate on the line (the word after a flag
    // the table does not know) the real name may be any of the words: none is dropped.
    const extra = positionals.some((p) => p.candidate === true) ? [] : packages.splice(1);
    for (const e of extra) skipped.push(skip(e.raw, 'unexpected extra argument to dotnet add package'));
    const first = packages[0];
    const version = flagValue(d.args, ['-v', '--version']);
    if (first !== undefined && version !== undefined) first.range = version;
  }

  // What the command installs from a manifest, beside what it names.
  if (allFlags.some((f) => flagTable.dir?.has(f.flag) === true)) out.prefixed = true;
  // Three readings must agree (npm 11.20.0, measured 2026-11-19). The walker knows which flags take a value (`--otp
  // --global` hands `--global` to `--otp`, and npm then obeys the project's file); the raw words know what takes a
  // global flag back; and every flag must be one the manager's table knows, because npm reads abbreviations and
  // shorthands the table does not hold (`-g --loc=project` and `-g --g=false` obey the project's file). In doubt: no.
  const knownFlagsOnly = preWalk.unknownFlags + walked.unknownFlags === 0;
  if (d.global === true || (knownFlagsOnly && allFlags.some(isGlobalFlag) && saysGlobal(d.manager, d.pre, d.args))) out.global = true;
  if (d.manager === 'pip' || d.manager === 'uv-pip') {
    const files = walked.flags.flatMap((f) => (REQUIREMENT_FLAGS.has(f.flag) && f.value !== undefined && f.value !== '' ? [f.value] : []));
    if (files.length > 0) out.manifest = { kind: 'requirements', files };
  } else if (d.manifest !== undefined && out.global !== true) {
    // The manifest is left unread only for an install that is global FOR CERTAIN (`out.global`); in doubt — `-g $X`,
    // `-g --location=project`, `npm ci --global=false` — it is read: vetting more, never less (measured 2026-11-19).
    // `npm i ./pkg.tgz` installs that, not the manifest: a word that was skipped counts as a thing named.
    // A word with a shell expansion beside a global-looking flag may be the flag's value or `--no-global` itself: no thing
    // is surely named, so the manifest is read.
    const maybeFlags = allFlags.some(isGlobalFlag) && skipped.length > 0 && skipped.every((s) => /[$`]/.test(s.raw));
    if (d.manifest === 'always' || (namedPackages === 0 && (skipped.length === candidateSkipped || maybeFlags))) out.manifest = { kind: 'package-json' };
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
 *
 * `nested`: the scripts the command hands a shell, as the shell guard reads
 * them (`BashAssessment.scripts` — `bash -c '…'`, a `cmd /c` line,
 * `pwsh -c '…'`, `echo '…' | sh`). Their installs are added the same way, each
 * script read as its own shell reads it, and marked uncertain: a nested install
 * is never one plain install statement (review of 3.3.0: `bash -c 'npm i x'`
 * was not vetted at all, while `npm i x` was). Where the outer command changes
 * directory, a launcher in a nested script is not taken as running an
 * installed copy: where it runs is not known here.
 */
export function parseInstallCommands(
  command: string,
  opts: { shell?: CommandShell; nested?: ReadonlyArray<{ text: string; shell: CommandShell }>; cdpath?: boolean } = {},
): InstallCommand[] {
  const cdpath = opts.cdpath === true;
  const out = readingsOf(command, opts.shell ?? 'bash', null, cdpath);
  if (opts.nested === undefined || opts.nested.length === 0) return out;
  const seen = new Set(out.flatMap((c) => c.packages.map(packageKey)));
  const moved = movesDirectory(stripComments(command));
  for (const script of opts.nested) {
    for (const c of readingsOf(script.text, script.shell, NESTED_SCRIPT, cdpath)) {
      const packages = c.packages.filter((p) => !seen.has(packageKey(p)));
      if (packages.length === 0 && c.manifest === undefined) continue;
      for (const p of packages) seen.add(packageKey(p));
      // Where a nested command runs is not known once the outer one moved: no installed copy is assumed, no manifest read.
      const unknownDir = moved && (c.localFirst === true || c.manifest !== undefined);
      out.push({ ...c, packages, ...(unknownDir ? { workdir: null } : {}) });
    }
  }
  return out;
}

/** What tells two manifest installs of one line apart: the kind, the files, and where each runs. */
function manifestKey(c: InstallCommand): string {
  const m = c.manifest;
  if (m === undefined) return '';
  return JSON.stringify([m.kind, m.kind === 'requirements' ? m.files : [], c.workdir ?? null, c.prefixed === true]);
}

/** Why a package found in a script the command hands a shell is never denied as missing. */
const NESTED_SCRIPT = 'found in a script the command hands a shell (bash -c, cmd /c, pwsh -c, a script piped to a shell) — vetted, never denied as missing';

/** The install commands of `command` read the POSIX way and — for PowerShell — the way PowerShell reads it. */
function readingsOf(command: string, shell: CommandShell, forced: string | null, cdpath: boolean): InstallCommand[] {
  const text = stripComments(command);
  const out = parseReading(text, forced, cdpath);
  if (shell !== 'powershell') return out;
  const asPowerShell = powershellAsPosix(text);
  if (asPowerShell === text) return out;
  const seen = new Set(out.flatMap((c) => c.packages.map(packageKey)));
  const seenManifests = new Set(out.map(manifestKey));
  for (const c of parseReading(asPowerShell, POWERSHELL_READING, cdpath)) {
    const packages = c.packages.filter((p) => !seen.has(packageKey(p)));
    // A manifest install only this reading finds is kept; one both readings find is the same install.
    const newManifest = c.manifest !== undefined && !seenManifests.has(manifestKey(c));
    if (packages.length === 0 && !newManifest) continue;
    for (const p of packages) seen.add(packageKey(p));
    seenManifests.add(manifestKey(c));
    const { manifest: _same, ...withoutManifest } = c;
    out.push({ ...(newManifest ? c : withoutManifest), packages, skipped: [] });
  }
  return out;
}

/** Whether any statement of `text` changes directory ({@link changesDirectory}); an unreadable text may. */
function movesDirectory(text: string): boolean {
  try {
    return splitShell(text).statements.some((s) => s.commands.some((words) => changesDirectory(words)));
  } catch {
    return true;
  }
}

/**
 * The install commands of one reading of the command. `forced`, when given,
 * is the reason no package of this reading may be denied as missing;
 * otherwise the controller ruling's confident-shape test decides.
 */
function parseReading(text: string, forced: string | null, cdpath: boolean): InstallCommand[] {
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
  // Where each command runs, as the shell guard's tracker reads the `cd`s
  // (review of 3.4.0, finding 5): only a move that surely ran counts.
  const dirs = workdirs(split.statements, { cdpath });
  let dirChanged = false;
  split.statements.forEach((statement, s) => {
    statement.commands.forEach((words, w) => {
      // A redirection is no package: `pip install x 2>&1` named a package `2`
      // (PEP 508 reads `2>&1` as `2` at a version `>&1`), `2> err.log` two.
      const d = detect(withoutRedirectWords(words));
      if (d !== null) {
        const context: string[] = [];
        if (envChange) context.push('inline environment assignment in the command (it can redirect the registry)');
        if (dirChanged) context.push('directory change earlier in the command (that directory’s registry configuration was not read)');
        const c = collect(d, context);
        // A confident shape has no reason of its own, but a name of a manager nobody measured that ends like an archive does.
        const unmeasured = c.uncertain.filter((r) => r === UNMEASURED_ARCHIVE);
        c.uncertain = notConfident === null ? unmeasured : [...new Set([notConfident, ...c.uncertain])];
        const sure = dirs[s]?.[w]?.sure ?? null;
        if (runsElsewhere(words)) c.workdir = null;
        else if (sure === null || sure.length > 0) c.workdir = sure;
        out.push(c);
      }
      if (changesDirectory(words)) dirChanged = true;
    });
  });
  return out;
}

/** A runner in front of the command that moves it elsewhere first: `env -C dir`, `env --chdir=dir`, `sudo -D dir`, `sudo --chdir dir`. */
function runsElsewhere(words: readonly ShellWord[]): boolean {
  const at = resolveCommand(words).index;
  let runner = '';
  for (const w of words.slice(0, at)) {
    const name = base(w.value);
    if (name === 'env' || name === 'sudo' || name === 'doas') runner = name;
    else if (runner === 'env' && /^(?:-[A-Za-z]*C|--chdir(?:=|$))/.test(w.value)) return true;
    else if (runner === 'sudo' && /^(?:-[A-Za-z]*D|--chdir(?:=|$))/.test(w.value)) return true;
  }
  return false;
}

/**
 * The command without its unquoted comments: `# …` to end of line (a `#`
 * that STARTS a word — `user/repo#main` is not a comment) and PowerShell
 * `<# … #>` blocks. Quotes are respected (`'…'`, `"…"` with `\` or `` ` ``
 * escapes). Without this, `pip install requests  # for http calls` vetted —
 * and denied — `for`, `http` and `calls`.
 */
function stripComments(command: string): string {
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
  // The launchers (review P1): consent and verbosity only. A package flag
  // (`-p`, `--from`, `--spec`), a registry or `--pip-args` takes the command
  // out of the confident shape.
  npx: { bool: set('-y', '--yes', '-q', '--quiet', '--silent'), value: set() },
  'pnpm-dlx': { bool: set('--silent', '-s'), value: set() },
  'yarn-dlx': { bool: set('-q', '--quiet'), value: set() },
  bunx: { bool: set('--bun', '--silent', '--verbose'), value: set() },
  uvx: { bool: set('-q', '--quiet', '-v', '--verbose', '--isolated'), value: set() },
  'uv-tool-install': { bool: set('-q', '--quiet', '-v', '--verbose', '--force', '--upgrade', '-U'), value: set() },
  'pipx-install': { bool: set('--force', '-f', '-q', '--quiet', '-v', '--verbose', '--include-deps'), value: set() },
  'pipx-run': { bool: set('-q', '--quiet', '-v', '--verbose', '--no-cache'), value: set() },
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
function confidentShape(text: string): string | null {
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
  // A launcher (review P1): its first positional word is the package, and
  // every word after it the program's own — never judged here.
  let launch = false;
  switch (tool) {
    case 'npx':
    case 'bunx':
    case 'uvx':
      [key, args, launch] = [tool, rest, true];
      break;
    case 'pnpx':
      [key, args, launch] = ['pnpm-dlx', rest, true];
      break;
    case 'pipx':
      if (at(0) === 'install') [key, args] = ['pipx-install', rest.slice(1)];
      else if (at(0) === 'run') [key, args, launch] = ['pipx-run', rest.slice(1), true];
      else return notPlain(`'pipx ${at(0)}'`);
      break;
    case 'npm':
      if (at(0) === 'exec' || at(0) === 'x') {
        [key, args, launch] = ['npx', rest.slice(1), true];
        break;
      }
      if (!NPM_INSTALL.has(at(0))) return notPlain(`'npm ${at(0)}'`);
      [key, args] = ['npm', rest.slice(1)];
      break;
    case 'pnpm':
    case 'yarn':
      if (at(0) === 'dlx') {
        [key, args, launch] = [`${tool}-dlx`, rest.slice(1), true];
        break;
      }
      // `pnpm install <pkg>` is as plain an install statement as `pnpm add <pkg>`; yarn's `install` takes no package.
      if (at(0) !== 'add' && !(tool === 'pnpm' && PNPM_INSTALL.has(at(0)))) return notPlain(`'${tool} ${at(0)}'`);
      [key, args] = [tool, rest.slice(1)];
      break;
    case 'bun':
      if (at(0) === 'x') {
        [key, args, launch] = ['bunx', rest.slice(1), true];
        break;
      }
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
      else if (at(0) === 'tool' && at(1) === 'run') [key, args, launch] = ['uvx', rest.slice(2), true];
      else if (at(0) === 'tool' && at(1) === 'install') [key, args] = ['uv-tool-install', rest.slice(2)];
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
    // `npm exec -- pkg`: the end of the launcher's own options.
    if (launch && w === '--') continue;
    if (!w.startsWith('-') || w === '-') {
      if (launch) return null;
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
