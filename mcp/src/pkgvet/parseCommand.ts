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

/** A reason this word is not a package name, or `null` when it may be one. */
function notAPackage(word: string): string | null {
  if (word.length === 0) return 'empty';
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
    value: set('--registry', '--prefix', '--tag', '--workspace', '-w', '--omit', '--include', '--install-strategy',
      '--cache', '--userconfig', '--globalconfig', '--before', '--loglevel', '--save-prefix', '--otp', '--scope',
      '--cpu', '--os', '--libc', '--location'),
    bool: set(...NPM_COMMON_BOOL),
    registry: set('--registry'),
  },
  pnpm: {
    value: set('--registry', '--filter', '-F', '--dir', '-C', '--reporter', '--store-dir', '--global-dir',
      '--modules-dir', '--virtual-store-dir', '--lockfile-dir', '--network-concurrency', '--config', '--loglevel'),
    bool: set(...NPM_COMMON_BOOL, '--workspace', '-w', '--workspace-root', '--recursive', '-r', '--allow-build'),
    registry: set('--registry'),
  },
  yarn: {
    value: set('--registry', '--cwd', '--network-timeout', '--modules-folder', '--cache-folder', '--mutex', '--scope'),
    bool: set(...NPM_COMMON_BOOL, '--ignore-workspace-root-check', '-W', '--cached', '--interactive', '-i',
      '--prefer-dev', '--mode'),
    registry: set('--registry'),
  },
  bun: {
    value: set('--registry', '--cwd', '--backend', '--cache-dir', '--config', '-c', '--concurrent-scripts',
      '--network-concurrency', '--omit', '--linker', '--ca', '--cafile'),
    bool: set(...NPM_COMMON_BOOL, '--trust', '--analyze', '-a', '--only-missing', '--save-text-lockfile',
      '--no-cache', '-p'),
    registry: set('--registry'),
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
      '--check-build-dependencies', '--ignore-requires-python', '--system', '--all-extras', '--no-index'),
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
      '--exclude-newer', '--link-mode', '--compile-bytecode', '--no-binary-package', '--no-build-package',
      '--upgrade-package', '-P', '--reinstall-package', '--refresh-package', '--config-setting', '-C'),
    bool: set('--dev', '--editable', '--no-editable', '--raw', '--raw-sources', '--frozen', '--locked', '--no-sync',
      '--workspace', '--no-workspace', '--active', '-U', '--upgrade', '--offline', '--no-cache', '-n', '-q', '-v',
      '--quiet', '--verbose', '--native-tls', '--no-index', '--no-build-isolation', '--refresh', '--reinstall',
      '--no-build', '--no-binary', '--no-config', '--no-progress'),
    registry: set('--index', '--index-url', '--default-index', '--extra-index-url', '--find-links', '-f'),
    registryBool: set('--no-index'),
    reported: new Map([
      ['-r', 'requirements file (-r) — its contents are not vetted'],
      ['--requirements', 'requirements file (-r) — its contents are not vetted'],
    ]),
  },
  poetry: {
    value: set('--group', '-G', '--extras', '-E', '--python', '--platform', '--source', '--markers', '--directory',
      '-C', '--project', '-P'),
    bool: set('--dev', '-D', '--editable', '-e', '--optional', '--allow-prereleases', '--dry-run', '--lock',
      '--no-interaction', '-n', '-q', '-v', '-vv', '-vvv', '--quiet', '--verbose', '--no-ansi', '--ansi'),
    registry: set('--source'),
  },
  composer: {
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
}

/** Separates flags (and their values) from positional words. */
function walk(words: readonly ShellWord[], table: FlagTable): WalkResult {
  const positionals: Positional[] = [];
  const skipped: SkippedSpec[] = [];
  let customRegistry: string | undefined;
  for (let i = 0; i < words.length; i += 1) {
    const w = words[i];
    if (w === undefined) break;
    const v = w.value;
    if (v === '--') continue;
    if (v.startsWith('-') && v.length > 1) {
      const eqAt = v.indexOf('=');
      const flag = eqAt > 0 ? v.slice(0, eqAt) : v;
      let value: string | undefined;
      if (eqAt > 0) value = v.slice(eqAt + 1);
      else if (table.value.has(flag) || (!table.bool.has(flag) && flag.startsWith('--') && !flag.startsWith('--no-'))) {
        value = words[i + 1]?.value;
        i += 1;
      }
      if (table.registry.has(flag) && value !== undefined) customRegistry = value;
      if (table.registryBool?.has(flag)) customRegistry = customRegistry ?? flag;
      const why = table.reported?.get(flag);
      if (why !== undefined && value !== undefined) skipped.push(skip(value, why));
      continue;
    }
    positionals.push({ value: v });
  }
  return customRegistry === undefined ? { positionals, skipped } : { positionals, skipped, customRegistry };
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

interface Detected {
  manager: string;
  ecosystem: PkgEcosystem;
  /** Words after the install subcommand (flags included). */
  args: ShellWord[];
  /** Flags before the subcommand, which may name a registry too. */
  pre: ShellWord[];
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
      return NPM_INSTALL.has(subWord) ? { manager: head, ecosystem: 'npm', args: words.slice(sub + 1), pre } : null;
    case 'pnpm':
    case 'bun':
      return subWord === 'add' || (head === 'bun' && subWord === 'a')
        ? { manager: head, ecosystem: 'npm', args: words.slice(sub + 1), pre }
        : null;
    case 'yarn': {
      let at = sub;
      if (subWord === 'global') at = nextPositional(words, sub + 1, table);
      else if (subWord === 'workspace') {
        const ws = nextPositional(words, sub + 1, table);
        at = ws < 0 ? -1 : nextPositional(words, ws + 1, table);
      }
      if (at < 0 || words[at]?.value !== 'add') return null;
      return { manager: head, ecosystem: 'npm', args: words.slice(at + 1), pre };
    }
    case 'pip':
      return subWord === 'install' ? { manager: head, ecosystem: 'pypi', args: words.slice(sub + 1), pre } : null;
    case 'uv': {
      if (subWord === 'add') return { manager: 'uv', ecosystem: 'pypi', args: words.slice(sub + 1), pre };
      if (subWord === 'pip') {
        const inst = nextPositional(words, sub + 1, table);
        if (inst >= 0 && words[inst]?.value === 'install') {
          return { manager: 'uv-pip', ecosystem: 'pypi', args: words.slice(inst + 1), pre };
        }
      }
      return null;
    }
    case 'poetry':
      return subWord === 'add' ? { manager: head, ecosystem: 'pypi', args: words.slice(sub + 1), pre } : null;
    case 'composer':
      return COMPOSER_REQUIRE.has(subWord)
        ? { manager: head, ecosystem: 'packagist', args: words.slice(sub + 1), pre }
        : null;
    case 'dotnet': {
      if (subWord !== 'add') return null;
      // dotnet add [<PROJECT>] package <NAME>
      let at = nextPositional(words, sub + 1, table);
      if (at >= 0 && words[at]?.value !== 'package') at = nextPositional(words, at + 1, table);
      if (at < 0 || words[at]?.value !== 'package') return null;
      return { manager: head, ecosystem: 'nuget', args: words.slice(at + 1), pre };
    }
    default:
      return null;
  }
}

/** Composer lets a constraint follow its package as a separate word: `vendor/pkg "^2.0"`. */
const COMPOSER_CONSTRAINT = /^(?:[\^~<>=!*]|v?\d|dev-|@)/;

function collect(d: Detected): InstallCommand {
  const table = FLAGS[d.manager === 'uv-pip' ? 'pip' : d.manager] ?? FLAGS['npm'];
  const flagTable = table ?? { value: set(), bool: set(), registry: set() };
  const preWalk = walk(d.pre, flagTable);
  const { positionals, skipped, customRegistry } = walk(d.args, flagTable);
  const packages: PackageSpec[] = [];
  const out: InstallCommand = { ecosystem: d.ecosystem, manager: d.manager, packages, skipped };
  const registry = customRegistry ?? preWalk.customRegistry;
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

/**
 * Every install command in `command`, with the packages each would fetch
 * from a registry. `[]` for a command that installs nothing by name —
 * including a bare `npm install` or `pip install -r requirements.txt`.
 */
export function parseInstallCommands(command: string): InstallCommand[] {
  const out: InstallCommand[] = [];
  let split;
  try {
    split = splitShell(command);
  } catch {
    return out;
  }
  for (const statement of split.statements) {
    for (const words of statement.commands) {
      const d = detect(words);
      if (d !== null) out.push(collect(d));
    }
  }
  return out;
}
