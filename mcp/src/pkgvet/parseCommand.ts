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
import { wordsWithoutRedirections } from '../hooks/shell/effects.js';
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
   * How many distinct candidates (words after a flag the table does not know) were left out past
   * {@link MAX_CANDIDATES_PER_COMMAND}: the decision says they were not vetted.
   */
  candidatesDropped?: number;
  /**
   * The packages (of {@link packages}) that are only candidates: the word after a flag the table does not know, which
   * may be that flag's value. Under a ceiling the packages the command surely names are vetted before them.
   */
  candidates?: PackageSpec[];
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
   * directory it runs in (`npm install`, `npm ci`, `pnpm install`, `yarn`,
   * `bun install`, and `npm install <pkg>`, `pnpm add`, `yarn add`, `bun add`,
   * which install it beside the names), or the requirement files given to
   * `pip install -r`, as written and in order. Present also when `packages` is
   * empty; absent for a global install for certain and for a launcher. Reading
   * the file is the hook's (`pkgvet/manifest.ts`): this module does no I/O.
   */
  manifest?: { kind: 'package-json' } | { kind: 'requirements'; files: readonly string[] };
  /**
   * The manifest install is an UPDATE (`npm update`, `pnpm up`, `yarn upgrade`, `yarn up <pattern>`, `bun update`): the
   * manager moves the direct dependencies past what the lockfile pins (measured 2026-11-19), so the pins are not what
   * will be installed. The words after the verb select dependencies of the manifest: `packages` stays empty. Only
   * together with `manifest`.
   */
  update?: true;
  /**
   * The names given to an update verb, read apart from `packages` (which stays empty for one): what the manager fetches
   * when they are installed already (measured 2026-11-20: npm 11.19, pnpm 11.24, bun 1.4, Yarn 1.22 / 3.8 / 4.18). Present
   * only for an npm, pnpm or bun update with a global flag word on the line ({@link hasGlobalFlagWord}), for `yarn global
   * upgrade` and for Yarn's `up` forms; `[]` when the verb has no positional word. A glob pattern, a path and a URL are no name.
   */
  updateNames?: PackageSpec[];
  /**
   * The command updates EVERY tool the manager installed — `pipx upgrade-all`, `uv tool upgrade --all` — and names no package for
   * it: the tools are the machine's, not the command line's, so none of them is vetted (measured 2026-11-20 and 2026-11-21 in a
   * Linux container: each installed tool is asked of the index). `updateNames` is then `[]`, or the names given beside `--all`.
   */
  updatesEveryTool?: true;
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
/** Why `npx name@` and the other launchers may not deny a missing name: what a launcher does with a word that ends in `@` was not measured. */
const LAUNCHER_NAME_AT = 'a name ending in @ under a launcher was not measured';
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
export function notAPackage(word: string, archive: RegExp | null): string | null {
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

/** One word of a semver range: `||`, a hyphen, a wildcard, or a version with its comparator. */
const SEMVER_WORD = /^(?:\|\||-|\*|[xX]|[<>=~^]{0,2}v?\d[A-Za-z0-9.+-]*|[<>=~^]{1,2}\*)$/;

/** Whether the text is a version or a range (`1.0.0`, `1.x`, `^1.2.3 <2`), not a dist-tag or a name: the one test of a manifest value and of a command's `key@npm:rest`. */
export function isSemverRange(text: string): boolean {
  return text.split(/\s+/).every((word) => SEMVER_WORD.test(word));
}

/**
 * How `key@npm:rest` is read (measured, table B of pkgvet-yarn-berry-npm-protocol). npm and pnpm read an alias: `rest` is
 * the package. Yarn 4 and bun (measured; Yarn 2 and 3 were not, the reading follows Yarn 4) read the registry protocol: the
 * package is `key` and `rest` a version, a range or a tag — or an alias when `rest` has a `@range` of its own. Yarn 1 reads an
 * alias, and bun either by the shape of `rest`; the hook does not know which runs, so a `rest` that is a valid name without a
 * range is read both ways. `rest` that is a path, a URL or a shell
 * expansion is `alias`: it is skipped, as for every manager. The rule of the command line; a `package.json` value starts from
 * it and reads pnpm 11 and a `~` word as the managers do there (`manifest.ts`, `npmValueReading`).
 *
 * - `alias`: only `rest` is the package (or the word is skipped);
 * - `key`: only `key` is the package, `rest` is its range;
 * - `both`: `key` and `rest` are each a package, and the command is uncertain; `key` is asked at `rest` when that is a version or a range.
 */
export function npmProtocolReading(manager: string | undefined, rest: string): 'alias' | 'key' | 'both' {
  if (manager !== 'yarn' && manager !== 'bun') return 'alias';
  if (/[$`]/.test(rest)) return 'alias';
  if (rest.indexOf('@', rest.startsWith('@') ? 1 : 0) > 0) return 'alias';
  // A version or a range is a range before it is a path: `~1.2.3` starts like the home directory `~`.
  if (rest !== '' && !isSemverRange(rest) && notAPackage(rest, null) !== null) return 'alias';
  return NAME_RE.npm.test(rest) ? 'both' : 'key';
}

/** The longest range a command or a manifest value may give a package: a longer one is not taken for a range. */
export const MAX_RANGE_LENGTH = 100;

/**
 * The range `key` keeps in a `key@npm:rest` read as the registry protocol (`key` and `both`): `rest` when it is a version or a
 * range the manager takes there — not an archive bun reads as a file — and nothing when it is a word (a tag, a name, a path). The one
 * rule of the command line and of a `package.json` value.
 */
export function npmKeyRange(manager: string | undefined, rest: string): string | undefined {
  return rest.length <= MAX_RANGE_LENGTH && isSemverRange(rest) && !readsFileValue(manager, rest) ? rest : undefined;
}

/**
 * The second package of a `key@npm:rest` that {@link npmProtocolReading} reads both ways: `rest`, which {@link parseNpm} did
 * not return (it returned `key`). `undefined` for every other word.
 */
function npmProtocolRest(raw: string, manager: string | undefined): PackageSpec | undefined {
  const at = raw.indexOf('@', raw.startsWith('@') ? 1 : 0);
  const range = at > 0 ? raw.slice(at + 1) : '';
  if (!/^npm:/i.test(range) || npmProtocolReading(manager, range.slice(4)) !== 'both') return undefined;
  const real = parseNpm(range.slice(4), manager, true);
  return 'name' in real ? { ...real, raw } : undefined;
}

/** What the reason of a `key@npm:rest` read both ways says of the word: a confident command keeps this reason, it is no doubt about the shape. */
const TWO_READINGS = ' is read two ways';

/** Why a command that names `key@npm:rest` read both ways is uncertain: said once, for the first word and how many more are like it. */
function bothReadings(pairs: ReadonlyArray<readonly [PackageSpec, PackageSpec]>): string | undefined {
  const [first, second] = pairs[0] ?? [];
  if (first === undefined || second === undefined) return undefined;
  const more = pairs.length - 1;
  const others = more === 0 ? '' : ` (and ${more} more ${more === 1 ? 'word' : 'words'} like it)`;
  return `\`${first.raw}\`${others}${TWO_READINGS} — Yarn 4 asks the registry for \`${first.name}\`, Yarn 1 for \`${second.name}\`, and bun for one or the other — both are looked up`;
}

/** What a word of an npm install names: its package, and the second one of a `key@npm:rest` read both ways (the pair is kept to say why the command is uncertain). */
function npmReadings(spec: PackageSpec, manager: string | undefined): { packages: PackageSpec[]; pair?: readonly [PackageSpec, PackageSpec] } {
  const second = npmProtocolRest(spec.raw, manager);
  return second === undefined ? { packages: [spec] } : { packages: [spec, second], pair: [spec, second] };
}

/** A `~` word with no slash or backslash after it: a spec of the registry, never a path (`~x`, `~abc`, a lone `~`); `~/x` and `~user/x` are paths. */
export function isTildeWord(word: string): boolean {
  return word.startsWith('~') && !/[\\/]/.test(word);
}

/**
 * Why the text after the `@` of `name@<text>`, or the value of a `package.json` dependency, is no spec of the registry — a path,
 * a URL or VCS spec, an SSH git spec — or `null` when it is one. A version or a range is a range before it is a path, and a `~`
 * opens a path only with a slash after it. The one rule of the command line and of the manifest.
 */
export function notARegistryRange(text: string): string | null {
  if (isSemverRange(text) || isTildeWord(text)) return null;
  return notAPackage(text, null) ?? (URL_OR_VCS.test(text) ? 'URL / VCS / protocol spec — not looked up' : null);
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
  // `name@` with nothing after the @ is the package with no range: npm, pnpm, bun and Yarn 1 install the latest (measured 2026-11-20).
  if (range === '') range = undefined;
  if (range !== undefined) {
    if (/^npm:/i.test(range)) {
      const rest = range.slice(4);
      const reading = alias ? 'alias' : npmProtocolReading(manager, rest);
      // Yarn and bun: `key@npm:rest` asks for `key`; the `rest` that is a range stays its range (`both` adds `rest` as a name).
      if (reading !== 'alias') return withRange(checkName('npm', name, raw), npmKeyRange(manager, rest));
      // `alias@npm:real@range` installs `real` under the name `alias`.
      const real = parseNpm(range.slice(4), manager, true);
      return 'name' in real ? { ...real, raw } : skip(raw, real.reason);
    }
    // A `~` opens a path only with a slash after it (`~/x`, `~user/x`): the managers ask the registry for `~1.0.0`, `~x`, `~abc` and a lone `~`
    // (measured). A version or a range is a range before it is a path; a `~` word with no slash is a registry spec the hook does not read
    // as a range, so the package is vetted with none.
    const rangeBad = notARegistryRange(range);
    if (rangeBad !== null) return skip(raw, rangeBad);
    if (readsFileValue(manager, range)) return skip(raw, 'archive file — not looked up');
    if (isTildeWord(range) && !isSemverRange(range)) range = undefined;
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
  /**
   * For a launcher that does not follow npm's {@link boolWord} rule: the boolean flags that nevertheless take a `true` /
   * `false` word as their value (`npx --no false pkg` asks for `pkg`, measured 2026-11-19). A flag of `noFetchFlags` or
   * `shellFlags` that has such a value is off, not on.
   */
  optionalWord?: ReadonlySet<string>;
  /**
   * What a launcher that does not follow {@link boolWord} does with a `true` / `false` after a flag whose reading the hook
   * cannot tell: `clusters` after a group of letters (`npx -qy false pkg` asks for `pkg`), `flags` after an exact flag of
   * the table too (`bunx --quiet false pkg` asks for `false`). The word is vetted as a package AND the next positional is
   * too ({@link Positional.candidate}), and the command is uncertain.
   */
  bothWays?: 'clusters' | 'flags';
  /** After a shell-mode flag a positional of ONE word is the package (`pnpm dlx -c pkg`, measured 2026-11-19); several words are shell text. */
  shellWord?: true;
  /** Short flags noted under the long flag they are, for the rules that read the long name (npm's `-L` is `--location`). */
  long?: ReadonlyMap<string, string>;
  /**
   * Value flags of type String: they do not take a next word that looks like a flag ({@link NOPT_FLAG_LIKE}), which is then
   * read as one — npm's option parser (`npm i -m -g P` is global; the owner's answer A to question 5, 2026-11-21).
   */
  stringValue?: ReadonlySet<string>;
  /**
   * Value flags known only as a word of their own: in a group of letters each stays a letter the table does not know, as
   * before it was added. The launchers' `-L` and `-m` (2026-11-21): a group inside a launcher keeps the reading of before
   * (`npx -yL global P` looks up `global`), which was not measured.
   */
  notInGroups?: ReadonlySet<string>;
  /**
   * `npm`: a group of letters is opened as npm 11.19.0 opens it ({@link openNpmGroup}). Absent: the first letter that takes a
   * value takes the rest of the group, or the next word (pip's `-rreq.txt`), as for every other manager and the launchers.
   */
  groups?: 'npm';
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
const LOGLEVEL_FLAGS: ReadonlySet<string> = new Set(['--silent', '--quiet', '-q', '--verbose', '-d', '-s']);

/**
 * npm's value flags as they were before its groups of letters were read as npm reads them (install-vet-global-in-short-cluster,
 * 2026-11-21): the launchers `npm exec` and `npm init` are built from these, and keep the rule of a group they had.
 */
const NPM_VALUE_FLAGS = [
  // `-C` is npm's short form of `--prefix`.
  '--registry', '--prefix', '-C', '--tag', '--workspace', '-w', '--omit', '--include',
  '--install-strategy', '--cache', '--userconfig', '--globalconfig', '--before', '--loglevel', '--save-prefix',
  '--otp', '--scope', '--cpu', '--os', '--libc', '--location',
  // npm 11.20.0 `config` (docs/content/using-npm/config.md, measurements/flags/npm-11.20.0-config.txt): each takes a value.
  '--fetch-retries', '--fetch-retry-factor', '--fetch-retry-mintimeout', '--fetch-retry-maxtimeout',
  '--fetch-timeout', '--cache-min', '--cache-max', '--maxsockets', '--depth', '--node-options', '--script-shell',
  '--auth-type', '--cafile', '--https-proxy', '--proxy', '--noproxy', '--local-address', '--user-agent',
  '--min-release-age',
];
/**
 * npm's boolean flags as they were before its groups were read as npm reads them, the set the launchers are built from.
 * npm 11.20.0 `config`: Boolean. (`--prefer-dedupe` and `--engine-strict` are Boolean too and left unknown: the regression
 * tests of install-vet-unknown-flag-hides-package use them as the examples of a flag the table lacks.) `-s` is npm's loglevel
 * shorthand for `--silent` (measured 2026-11-20, npm 11.20.0: `-sy true P` asks for P, `-ys true P` for `true`).
 */
const NPM_BOOL_FLAGS = [...NPM_COMMON_BOOL, '--allow-same-version', '--strict-ssl', '-s'];
/** npm's flags of a workspace context as they were before its groups were read as npm reads them (`-ws` is NPM_TABLE's own). */
const NPM_WORKSPACE_FLAGS = ['--workspace', '-w', '--workspaces'];

/** npm's `-L` is `--location`: noted under that name, so that the global rules read it (`-L global` is `--location global`). */
const NPM_LONG: ReadonlyMap<string, string> = new Map([['-L', '--location']]);

/**
 * npm's single letters and the words npm expands each to — measured 2026-11-20 with npm 11.19.0 (the config definitions and
 * shorthands, `.specs/_findings-2026-11-20/measurements/cmd-forms/explore-linux-container-2026-11-20.txt:305-366`), confirmed
 * 2026-11-21 (`.specs/install-vet-global-in-short-cluster/measurements/single-dash-words-linux-container-2026-11-21.txt:11-15`).
 * A constant of its own: `NPM_TABLE` holds Yarn's `-T` as well, which npm does not have. `?` is left out: a group is made of
 * letters only ({@link SHORT_CLUSTER}).
 */
const NPM_LETTERS: ReadonlyMap<string, string> = new Map([
  // No value. `d`, `q` and `s` are two words each.
  ['a', '--all'], ['f', '--force'], ['g', '--global'], ['l', '--long'], ['p', '--parseable'], ['S', '--save'],
  ['B', '--save-bundle'], ['D', '--save-dev'], ['E', '--save-exact'], ['O', '--save-optional'], ['P', '--save-prod'],
  ['y', '--yes'], ['h', '--usage'], ['H', '--usage'], ['v', '--version'], ['n', '--no-yes'],
  ['d', '--loglevel info'], ['q', '--loglevel warn'], ['s', '--loglevel silent'],
  // A value: `c` and `m` are of type String; `L`, `C` and `w` take any word.
  ['c', '--call'], ['m', '--message'], ['L', '--location'], ['C', '--prefix'], ['w', '--workspace'],
]);
/**
 * The letters of {@link NPM_LETTERS} that take a value and, standing before another letter of the group, take that letter's
 * first word as it (`-Cg` is `--prefix --global`, `-Lq` is `--location --loglevel` and leaves `warn` a positional: measured,
 * `single-dash-words…:24-25, 27`).
 */
const NPM_TAKE_NEXT_LETTER: ReadonlySet<string> = new Set(['L', 'C', 'w']);
/**
 * The letters of {@link NPM_LETTERS} of type String: they take no letter of the group after them, and no word that looks like
 * a flag ({@link NOPT_FLAG_LIKE}): `-mg` is `--message --global`, global (measured, M-1 474 and 476; `single-dash-words…:31-32`).
 */
const NPM_STRING_LETTERS: ReadonlySet<string> = new Set(['c', 'm']);
/** What npm's option parser (`nopt`) takes for a flag, not for the value of a String flag: `-` or `--` and another character. */
const NOPT_FLAG_LIKE = /^-{1,2}[^-]/;

const NPM_TABLE: FlagTable = {
  // The value letters of npm 11.19.0 (`-L` is noted as `--location`, NPM_LONG), and `-ca` and `-call`, two of the six words
  // npm reads whole instead of opening them (`--ca` and `--call`; measured, `single-dash-words…:13-14`).
  value: set(...NPM_VALUE_FLAGS, '-L', '-m', '-c', '-ca', '-call'),
  // The letters npm has and the table had not (`-a` … `-H`), and the four other whole words: `-all` (`--all`), `-ws`
  // (`--workspaces`), `-dd` and `-ddd` (`--loglevel verbose|silly`).
  bool: set(...NPM_BOOL_FLAGS, '-a', '-l', '-p', '-n', '-h', '-v', '-H', '-all', '-ws', '-dd', '-ddd'),
  registry: set('--registry'),
  dir: set('--prefix', '-C'),
  workspace: set(...NPM_WORKSPACE_FLAGS, '-ws'),
  // The letters added, `-all` and the two loglevel words take no `true` / `false` either: the word after them is a package.
  boolWord: { except: new Set([...LOGLEVEL_FLAGS, '-a', '-l', '-p', '-n', '-h', '-v', '-H', '-all', '-dd', '-ddd']) },
  long: NPM_LONG,
  stringValue: set('-m', '-c', '-call'),
  groups: 'npm',
};

const PIP_REQUIREMENTS_REASON = 'requirements file (-r) — read as a manifest, not as a package name';
const PIP_CONSTRAINTS_REASON = 'constraints file (-c) — not vetted';
const PIP_EDITABLE_REASON = 'editable install (-e) — local or VCS source, not looked up';

// `pip download` and `pip wheel` (pip 23.0.1, the parser of each verb dumped flag by flag, measured 2026-11-21: 68 and 67 spellings).
// The flags the two share; each verb adds its own below. A flag of `pip install` that the verb does not have (`-U`, `--user`, `-t`,
// `--dry-run`, …) is not here: pip refuses it, and a line that has one is uncertain and only warns.
const PIP_FETCH_VALUE = [
  '-c', '--constraint', '-r', '--requirement', '--global-option', '--no-binary', '--only-binary', '--src', '--source',
  '--source-dir', '--source-directory', '--progress-bar', '-i', '--index-url', '--pypi-url', '--extra-index-url', '-f',
  '--find-links', '--python', '--log', '--log-file', '--local-log', '--proxy', '--retries', '--timeout', '--default-timeout',
  '--exists-action', '--trusted-host', '--cert', '--client-cert', '--cache-dir', '--use-feature', '--use-deprecated',
];
const PIP_FETCH_BOOL = [
  '--no-deps', '--no-dependencies', '--prefer-binary', '--pre', '--require-hashes', '--no-build-isolation', '--use-pep517',
  '--no-use-pep517', '--check-build-dependencies', '--ignore-requires-python', '--no-clean', '--no-index', '--debug',
  '--isolated', '--require-virtualenv', '--require-venv', '-v', '--verbose', '-V', '--version', '-q', '--quiet', '--no-input',
  '--no-cache-dir', '--disable-pip-version-check', '--no-color', '--no-python-version-warning',
];
const PIP_FETCH_REGISTRY = ['-i', '--index-url', '--pypi-url', '--extra-index-url', '-f', '--find-links'];
const PIP_FETCH_REPORTED: Array<[string, string]> = [
  ['-r', PIP_REQUIREMENTS_REASON],
  ['--requirement', PIP_REQUIREMENTS_REASON],
  ['-c', PIP_CONSTRAINTS_REASON],
  ['--constraint', PIP_CONSTRAINTS_REASON],
];
const PIP_DOWNLOAD_TABLE: FlagTable = {
  value: set(...PIP_FETCH_VALUE, '-d', '--dest', '--destination-dir', '--destination-directory', '--platform',
    '--python-version', '--implementation', '--abi'),
  bool: set(...PIP_FETCH_BOOL),
  registry: set(...PIP_FETCH_REGISTRY),
  registryBool: set('--no-index'),
  reported: new Map(PIP_FETCH_REPORTED),
};
const PIP_WHEEL_TABLE: FlagTable = {
  value: set(...PIP_FETCH_VALUE, '-w', '--wheel-dir', '-e', '--editable', '--config-settings', '--build-option'),
  bool: set(...PIP_FETCH_BOOL, '--no-verify'),
  registry: set(...PIP_FETCH_REGISTRY),
  registryBool: set('--no-index'),
  reported: new Map([...PIP_FETCH_REPORTED, ['-e', PIP_EDITABLE_REASON], ['--editable', PIP_EDITABLE_REASON]]),
};

// `pipx upgrade` (pipx, the parser dumped 2026-11-21): the one object of the reading of the verb and of `--install`, which reads it
// as an install.
const PIPX_UPGRADE_TABLE: FlagTable = {
  value: set('--python', '--index-url', '-i', '--pip-args', '--cooldown', '--backend', '--fetch-python', '--output'),
  bool: set('--install', '--include-injected', '--force', '-f', '--system-site-packages', '--editable', '-e', '--quiet', '-q',
    '--verbose', '-v', '--skip-maintenance', '--global', '--fetch-missing-python'),
  registry: set('--index-url', '-i'),
};

// `uv tool upgrade` (uv, the 64 flags its parser knows, the hidden ones among them, probed 2026-11-21): not `UV_VALUED` / `UV_BOOL`,
// which hold seven flags the verb refuses.
const UV_TOOL_UPGRADE_TABLE: FlagTable = {
  value: set('--python', '-p', '--index', '--index-url', '-i', '--default-index', '--extra-index-url', '--find-links', '-f',
    '--index-strategy', '--keyring-provider', '--resolution', '--prerelease', '--prerelease-package', '--fork-strategy',
    '--exclude-newer', '--exclude-newer-package', '--link-mode', '--directory', '--project', '--config-file', '--cache-dir',
    '--color', '--python-platform', '--no-sources-package', '--reinstall-package', '-C', '--config-setting',
    '--config-settings', '--config-setting-package', '--no-build-isolation-package', '--no-build-package',
    '--no-binary-package', '--allow-insecure-host', '--python-preference'),
  bool: set('--all', '--offline', '-q', '--quiet', '-v', '--verbose', '--no-cache', '-n', '--reinstall', '--no-config',
    '--no-progress', '--no-python-downloads', '--no-index', '--compile-bytecode', '--managed-python', '--no-managed-python',
    '--no-sources', '--no-build-isolation', '--no-build', '--no-binary', '--require-build-hashes', '--no-require-build-hashes',
    '--system-certs', '--isolated', '--upgrade', '-U', '--native-tls', '--no-offline', '--force-reinstall'),
  registry: set('--index', '--index-url', '-i', '--default-index', '--extra-index-url', '--find-links', '-f'),
  registryBool: set('--no-index'),
  dir: set('--directory', '--project'),
};

const FLAGS: Record<string, FlagTable> = {
  npm: NPM_TABLE,
  pnpm: {
    value: set('--registry', '--filter', '-F', '--dir', '-C', '--reporter', '--store-dir', '--global-dir',
      '--modules-dir', '--virtual-store-dir', '--lockfile-dir', '--network-concurrency', '--config', '--loglevel',
      '--allow-build',
      // pnpm 10.33.2 `add --help` / `install --help` (measurements/flags/pnpm-*-help.txt): shown with an argument.
      '--child-concurrency', '--hoist-pattern', '--public-hoist-pattern', '--filter-prod', '--test-pattern',
      '--changed-files-ignore-pattern', '--trust-policy-exclude', '--trust-policy-ignore-after'),
    // pnpm 10.33.2 `add --help` / `install --help`: shown without one. (`--shamefully-hoist` is one too and left
    // unknown, like npm's `--prefer-dedupe`: the regression tests use it as the example of a flag the table lacks.)
    bool: set(...NPM_COMMON_BOOL, '--workspace', '-w', '--workspace-root', '--recursive', '-r', '--ignore-pnpmfile',
      '--prefer-frozen-lockfile', '--fix-lockfile', '--ignore-workspace', '--lockfile-only', '--merge-git-branch-lockfiles',
      '--optimistic-repeat-install', '--resolution-only', '--side-effects-cache', '--side-effects-cache-readonly',
      '--strict-peer-dependencies', '--use-running-store-server', '--use-store-server', '--use-stderr', '--stream',
      '--aggregate-output', '--fail-if-no-match', '--save-catalog', '--prod'),
    registry: set('--registry'),
    dir: set('--dir', '-C'),
    workspace: set('--workspace', '--filter', '-F'),
    boolWord: { except: LOGLEVEL_FLAGS },
  },
  yarn: {
    value: set('--registry', '--cwd', '--network-timeout', '--modules-folder', '--cache-folder', '--mutex', '--scope',
      '--mode',
      // Yarn 1.22.22 `yarn --help` (measurements/flags/yarn-1.22.22-help.txt): shown with an argument.
      '--network-concurrency', '--link-folder', '--global-folder', '--preferred-cache-folder', '--use-yarnrc',
      '--https-proxy', '--proxy', '--otp'),
    // Yarn 1.22.22 `yarn --help`: shown without one. Left out: `--emoji`, `--scripts-prepend-node-path` and `--prod` /
    // `--production`, whose argument is optional (`[bool]`, `[prod]`), and `--ignore-engines`, the example of a flag the
    // table lacks in the regression tests of this fix.
    bool: set(...NPM_COMMON_BOOL, '--ignore-workspace-root-check', '-W', '--cached', '--interactive', '-i',
      '--prefer-dev', '--check-files', '--disable-pnp', '--enable-pnp', '--pnp', '--flat', '--focus', '--har',
      '--ignore-optional', '--ignore-platform', '--link-duplicates', '--no-default-rc', '--non-interactive',
      '--no-node-version-check', '--pure-lockfile', '--skip-integrity-check', '--strict-semver', '--update-checksums',
      '-A'),
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
      '-p', '--prerelease', '--resolution', '--requirements',
      // pip 26.2.1 `install --help` (measurements/flags/pip-install-help.txt): shown with an argument.
      '--use-feature', '--use-deprecated', '--all-releases', '--build-constraint', '--only-final', '--resume-retries',
      '--refresh-package', '--requirements-from-script', '--uploaded-prior-to'),
    bool: set('-U', '--upgrade', '--user', '--no-deps', '--pre', '--force-reinstall', '-I', '--ignore-installed',
      '--no-cache-dir', '--no-cache', '-q', '-v', '--quiet', '--verbose', '--break-system-packages', '--dry-run',
      '--no-build-isolation', '--require-hashes', '--isolated', '--disable-pip-version-check', '--no-input',
      '--compile', '--no-compile', '--prefer-binary', '--no-warn-script-location', '--use-pep517', '--no-clean',
      '--check-build-dependencies', '--ignore-requires-python', '--system', '--all-extras', '--no-index',
      '--compile-bytecode',
      // pip 26.2.1 `install --help`: shown without one.
      '--debug', '--only-deps'),
    registry: set('-i', '--index-url', '--extra-index-url', '-f', '--find-links', '--index', '--default-index'),
    registryBool: set('--no-index'),
    reported: new Map([
      ['-r', PIP_REQUIREMENTS_REASON],
      ['--requirement', PIP_REQUIREMENTS_REASON],
      // `uv pip install` spells it in the plural.
      ['--requirements', PIP_REQUIREMENTS_REASON],
      ['-c', PIP_CONSTRAINTS_REASON],
      ['--constraint', PIP_CONSTRAINTS_REASON],
      ['-e', PIP_EDITABLE_REASON],
      ['--editable', PIP_EDITABLE_REASON],
    ]),
  },
  'pip-download': PIP_DOWNLOAD_TABLE,
  'pip-wheel': PIP_WHEEL_TABLE,
  'pipx-upgrade': PIPX_UPGRADE_TABLE,
  'pipx-reinstall': {
    value: set('--python', '--fetch-python', '--backend', '--output'),
    bool: set('--quiet', '-q', '--verbose', '-v', '--skip-maintenance', '--global', '--fetch-missing-python'),
    registry: set(),
  },
  'pipx-upgrade-all': {
    value: set('--skip', '--pip-args', '--backend', '--index-url', '-i', '--cooldown', '--output'),
    bool: set('--include-injected', '--force', '-f', '--quiet', '-q', '--verbose', '-v', '--skip-maintenance', '--global',
      '--system-site-packages', '--editable', '-e'),
    registry: set('--index-url', '-i'),
  },
  'uv-tool-upgrade': UV_TOOL_UPGRADE_TABLE,
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
    // composer 2.10.3 `require --help` (measurements/flags/composer-require-help.txt): these options take a value
    // (`--prefer-install` was listed below as a boolean: it is `--prefer-install=PREFER-INSTALL`).
    value: set('--working-dir', '-d', '--prefer-install', '--ignore-platform-req', '--audit-format', '--apcu-autoloader-prefix'),
    bool: set('--dev', '--no-dev', '--no-update', '--no-install', '--no-audit', '--no-security-blocking',
      '--update-with-dependencies', '-w', '--update-with-all-dependencies', '-W', '--with-dependencies',
      '--with-all-dependencies', '--prefer-dist', '--prefer-source', '--dry-run',
      '--no-progress', '--no-scripts', '--no-plugins', '--update-no-dev', '--ignore-platform-reqs',
      '--prefer-stable', '--prefer-lowest', '--sort-packages', '--optimize-autoloader', '-o', '--classmap-authoritative',
      '-a', '--apcu-autoloader', '--fixed', '-n', '--no-interaction', '-q', '--quiet', '-v', '-vv', '-vvv',
      '--ansi', '--no-ansi', '--no-cache', '--minimal-changes', '-m', '--profile', '--no-blocking', '--no-suggest'),
    registry: set(),
  },
  dotnet: {
    // dotnet 10.0.404 `add package --help` (measurements/flags/dotnet-add-package-help.txt): `--project` and `--file` take one.
    value: set('-v', '--version', '-f', '--framework', '-s', '--source', '--package-directory', '--project', '--file'),
    bool: set('-n', '--no-restore', '--interactive', '--prerelease'),
    registry: set('-s', '--source'),
  },
  // dotnet 10.0.404 `tool install --help` (.specs/install-vet-dotnet-forms/measurements/help/dotnet-tool-install-help.txt):
  // `-v` is the MSBuild verbosity here (a version in `add package`), and the sources are `--add-source` and `--source`;
  // `--configfile` names a NuGet configuration, which may hold a private source: it is read as one.
  'dotnet-tool': {
    value: set('--tool-path', '--version', '--configfile', '--tool-manifest', '--add-source', '--source', '--framework', '-v',
      '--verbosity', '-a', '--arch'),
    bool: set('-g', '--global', '--local', '--prerelease', '--disable-parallel', '--ignore-failed-sources', '--no-http-cache',
      '--interactive', '--allow-downgrade', '--create-manifest-if-needed', '--allow-roll-forward'),
    registry: set('--add-source', '--source', '--configfile'),
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
    // `-L` (`--location`) and `-m` (`--message`, of type String): measured 2026-11-21 (npm 11.19.0), `npx -L global P` asks the
    // registry for P, never for `global` (M-4; the owner's answer B to question 4). A group of letters keeps the rule of today.
    value: set('--package', '-p', '--call', '-c', '--registry', '--cache', '--userconfig', '--prefix', '-C', '--workspace', '-w',
      '--loglevel', '--node-options', '-L', '-m'),
    bool: set('--yes', '-y', '--no', '--no-install', '--ignore-existing', '--quiet', '-q', '--silent', '--prefer-offline',
      '--prefer-online', '--offline', '--workspaces', '--include-workspace-root', '--verbose', '--no-yes'),
    registry: set('--registry'),
    workspace: set(...NPM_WORKSPACE_FLAGS),
    packageFlags: set('--package', '-p'),
    shellFlags: set('--call', '-c'),
    noFetchFlags: set('--no', '--no-install', '--offline'),
    // Measured 2026-11-19 (npx, npm 11.20.0): `--no false P` and `--no-yes false P` ask for P; the word is their value.
    // `--no-install false P` and `--offline false P` fetch nothing (measured); they are read like `--no` (the word is their
    // value, the next one is looked up, the command is uncertain): looking up more, never less (US-1.AC-4).
    optionalWord: set('--no', '--no-yes', '--no-install', '--offline'),
    bothWays: 'clusters',
    long: NPM_LONG,
    stringValue: set('-m'),
    notInGroups: set('-L', '-m'),
  },
  // `npm exec` / `npm x` are npm's own command: npm's flags and its `true` / `false` rule, not npx's (measured 2026-11-19:
  // `-p` is a boolean flag here, `--no-install` does not stop the download, `--no` / `--no-yes` / `--ignore-existing` are booleans).
  // Built from npm's flags as they were before its groups were read as npm reads them, plus `-L` and `-m` (M-4; the owner's
  // answer B to question 4): `npm exec -L global P` and `npm exec -m <v> P` ask for P. A group of letters keeps the rule of today.
  'npm-exec': {
    value: set(...NPM_VALUE_FLAGS, '--package', '--call', '-c', '-L', '-m'),
    bool: set(...NPM_BOOL_FLAGS, '-p', '--no', '--no-install', '--no-yes', '--ignore-existing'),
    registry: NPM_TABLE.registry,
    workspace: set(...NPM_WORKSPACE_FLAGS),
    packageFlags: set('--package'),
    shellFlags: set('--call', '-c'),
    noFetchFlags: set('--no', '--offline'),
    boolWord: { except: LOGLEVEL_FLAGS },
    long: NPM_LONG,
    stringValue: set('-m'),
    notInGroups: set('-L', '-m'),
  },
  // `npm init` / `create` / `innit` (one npm command): npm's flags and its `true` / `false` rule, plus the flags of `npm init --help`
  // (the stored help of npm 11.20.0). Measured 2026-11-20 (npm 11.20.0): `init -y X`, `init --yes X`, `init -q X`, `init --quiet X`,
  // `init --silent X` and `init -w <dir> X` ask the registry for `create-X`.
  // Built, as `npm exec`, from npm's flags of before plus `-L` and `-m`: `npm init -L global x` asks for `create-x` (M-4).
  'npm-init': {
    value: set(...NPM_VALUE_FLAGS, '--init-author-name', '--init-author-url', '--init-license', '--init-module', '--init-type', '--init-version',
      '-L', '-m'),
    bool: set(...NPM_BOOL_FLAGS, '--init-private', '--no-workspaces-update'),
    registry: NPM_TABLE.registry,
    dir: NPM_TABLE.dir,
    workspace: set(...NPM_WORKSPACE_FLAGS),
    boolWord: { except: LOGLEVEL_FLAGS },
    long: NPM_LONG,
    stringValue: set('-m'),
    notInGroups: set('-L', '-m'),
  },
  // `yarn create`: `-p` / `--package` (the help of Yarn 3 and 4; Yarn 1 has none, not measured) and `-q` / `--quiet` (measured, Yarn 1, 3 and 4).
  'yarn-create': {
    value: set('--package', '-p'),
    bool: set('--quiet', '-q'),
    registry: set(),
    packageFlags: set('--package', '-p'),
  },
  // `pnpm create` (pnpm 11.24.0): the flags of `pnpm dlx` that are no package flags; no flag was measured with it.
  'pnpm-create': {
    value: set('--allow-build', '--registry', '--dir', '-C', '--reporter'),
    bool: set('--silent', '-s', '--quiet', '--verbose'),
    registry: set('--registry'),
    dir: set('--dir', '-C'),
  },
  // `bun create` / `bun c`: no flag was measured.
  'bun-create': { value: set(), bool: set(), registry: set() },
  'pnpm-dlx': {
    value: set('--package', '--allow-build', '--registry', '--dir', '-C', '--reporter'),
    // `--quiet` and `--verbose` (measured 2026-11-19, pnpm 10.33.2: `--quiet false P` asks for `false`).
    bool: set('--silent', '-s', '--shell-mode', '-c', '--quiet', '--verbose', '-p'),
    registry: set('--registry'),
    dir: set('--dir', '-C'),
    packageFlags: set('--package'),
    shellFlags: set('--shell-mode', '-c'),
    // Measured 2026-11-19 (pnpm 10.33.2): `-c P`, `--shell-mode P`, `-c false P` and `-p false P` ask for P.
    optionalWord: set('--shell-mode', '-c', '-p'),
    shellWord: true,
    bothWays: 'flags',
  },
  'yarn-dlx': {
    value: set('--package', '-p'),
    bool: set('--quiet', '-q'),
    registry: set(),
    packageFlags: set('--package', '-p'),
    bothWays: 'flags',
  },
  bunx: {
    value: set('--package', '-p'),
    // `--quiet` (bun 1.4.4, measured 2026-11-19: `bunx --quiet false P` asks for `false`).
    bool: set('--bun', '--silent', '--verbose', '--quiet'),
    registry: set(),
    packageFlags: set('--package', '-p'),
    bothWays: 'flags',
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
    value: set('--spec', '--index-url', '-i', '--python', '--path', '--with'),
    bool: set('--no-cache', '--quiet', '-q', '--verbose', '-v', '--system-site-packages', '--fetch-missing-python'),
    registry: set('--index-url', '-i'),
    packageFlags: set('--spec'),
    extraPackageFlags: set('--with'),
  },
  // `pipx inject <environment> <package>…` (pipx, the parser dumped 2026-11-21, 23 spellings): `--include-resources-from` names a
  // package pipx fetches as well, and `-r` a requirements file pip reads (its manifest is read, `collectLaunch`).
  'pipx-inject': {
    value: set('-r', '--requirement', '--include-resources-from', '--index-url', '-i', '--pip-args', '--cooldown', '--backend', '--output'),
    bool: set('--quiet', '-q', '--verbose', '-v', '--skip-maintenance', '--global', '--include-apps', '--include-deps',
      '--system-site-packages', '--editable', '-e', '--force', '-f', '--with-suffix'),
    registry: set('--index-url', '-i'),
    reported: new Map([['-r', PIP_REQUIREMENTS_REASON], ['--requirement', PIP_REQUIREMENTS_REASON]]),
    extraPackageFlags: set('--include-resources-from'),
  },
  // `pipx runpip <environment> <pip arguments>`: only pipx's own flags, the rest is a pip command ({@link runpipDetected}).
  'pipx-runpip': {
    value: set(),
    bool: set('--quiet', '-q', '--verbose', '-v', '--global', '--skip-maintenance'),
    registry: set(),
  },
  'pipx-upgrade': PIPX_UPGRADE_TABLE,
};

/**
 * The most distinct candidate words one command contributes (the words after flags the table does not know). The same
 * number as the decision's limit of packages named on a command line (`MAX_VETTED_PACKAGES`): past it a word would not
 * be looked up anyway, and each one costs the hook a lookup in the project's files before that limit applies.
 */
export const MAX_CANDIDATES_PER_COMMAND = 50;

interface Positional {
  value: string;
  /** The index of the word among the words that were walked. */
  at: number;
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
  flags: Array<{ flag: string; value?: string; eq?: true }>;
  /** How many flags the table of the manager does not know: npm reads abbreviations (`--loc=project`) that it does not hold. */
  unknownFlags: number;
}

/** The positionals with each candidate once and at most {@link MAX_CANDIDATES_PER_COMMAND} of them; `dropped` counts the rest. */
function limitCandidates(positionals: readonly Positional[]): { kept: Positional[]; dropped: number } {
  const seen = new Set<string>();
  const kept: Positional[] = [];
  let dropped = 0;
  for (const p of positionals) {
    if (p.candidate !== true) {
      kept.push(p);
      continue;
    }
    if (seen.has(p.value)) continue;
    if (seen.size >= MAX_CANDIDATES_PER_COMMAND) {
      dropped += 1;
      continue;
    }
    seen.add(p.value);
    kept.push(p);
  }
  return { kept, dropped };
}

const SHORT_CLUSTER = /^-[A-Za-z]{2,}/;

const isBoolWord = (word: string | undefined): boolean => word === 'true' || word === 'false';

/** An npm group of letters as npm 11.19.0 opens it ({@link openNpmGroup}). */
interface NpmGroup {
  /** The flags, in order, as the table names them; a value letter that is not the last carries the first word of the letter after it. */
  flags: Array<{ flag: string; value?: string }>;
  /** The second word of a `d`, `q` or `s` whose first word a value letter took: npm asks the registry for it (`-Cd` leaves `info`). */
  positionals: string[];
  /** What the word after the group is to its last flag: the value (`value`), the value unless it looks like a flag (`string`), nothing (`none`). */
  next: 'value' | 'string' | 'none';
}

/** Whether `v` is a word of letters that `table` opens as npm does: npm's table, and not one of its exact flags (the six words npm reads whole are). */
const isNpmGroupWord = (v: string, table: FlagTable): boolean =>
  table.groups === 'npm' && !v.startsWith('--') && SHORT_CLUSTER.test(v) && !table.value.has(v) && !table.bool.has(v);

/**
 * Opens an npm word of letters as npm 11.19.0 does (measured 2026-11-20 and 2026-11-21, {@link NPM_LETTERS}): each letter is the
 * flag written alone, in order. A letter of {@link NPM_TAKE_NEXT_LETTER} that is not the last takes the first word of the letter
 * after it as its value, and that letter no longer counts — when it is `d`, `q` or `s` its second word (`info`, `warn`, `silent`)
 * is a positional, which npm installs (the owner's answer A to question 6). `c` and `m` take nothing inside the group.
 * `undefined` when a letter is not one of npm's: npm reads the whole word as a flag it does not know (`-gx` is `--gx`, `-gT`
 * too — `T` is Yarn's). The callers ask {@link isNpmGroupWord} first. One pass over the letters.
 */
function openNpmGroup(word: string): NpmGroup | undefined {
  const letters = [...word.slice(1)];
  if (!letters.every((c) => NPM_LETTERS.has(c))) return undefined;
  const group: NpmGroup = { flags: [], positionals: [], next: 'none' };
  for (let k = 0; k < letters.length; k += 1) {
    const letter = letters[k] ?? '';
    const after = letters[k + 1];
    if (after === undefined) {
      group.flags.push({ flag: `-${letter}` });
      group.next = NPM_TAKE_NEXT_LETTER.has(letter) ? 'value' : NPM_STRING_LETTERS.has(letter) ? 'string' : 'none';
    } else if (NPM_TAKE_NEXT_LETTER.has(letter)) {
      const [first = '', second] = (NPM_LETTERS.get(after) ?? '').split(' ');
      group.flags.push({ flag: `-${letter}`, value: first });
      if (second !== undefined) group.positionals.push(second);
      k += 1;
    } else group.flags.push({ flag: `-${letter}` });
  }
  return group;
}

/** Whether a flag that reads the next word as `next` (a value flag: `value`; one of type String: `string`) takes `word`. */
const takesNextWord = (next: NpmGroup['next'], word: string | undefined): boolean =>
  word !== undefined && (next === 'value' || (next === 'string' && !NOPT_FLAG_LIKE.test(word)));

/** How the exact value flag `v` of `table` reads the next word: of type String ({@link FlagTable.stringValue}) or any word. */
const valueKind = (v: string, table: FlagTable): NpmGroup['next'] => (table.stringValue?.has(v) === true ? 'string' : 'value');

/**
 * The one rule for the word after a flag the table does not know: `walk` and `nextPositional` both ask it, so the
 * flag is read the same way in a package position and in the subcommand position. The tables are hand-written lists
 * and the managers have more boolean flags than they hold: a long flag (no `=`, not `--no-...`) is followed by a word
 * that may be its value or a package, and the hook cannot tell. `candidate`: the word stays a possible value AND is
 * vetted as a possible package; `value`: a `true` / `false` is the value;
 * `none`: the flag takes no word (a short flag, one written with `=`, `--no-...`, one the table knows, or one followed
 * by a flag).
 */
function afterUnknownFlag(v: string, next: string | undefined, table: FlagTable): 'none' | 'value' | 'candidate' {
  if (table.value.has(v) || table.bool.has(v)) return 'none';
  if (!v.startsWith('--') || v === '--' || v.startsWith('--no-') || v.includes('=')) return 'none';
  if (next === undefined || (next.startsWith('-') && next.length > 1)) return 'none';
  // After a flag the table does not know, `true` / `false` is its value for every manager: the only packages with those
  // names are npm's security placeholder and a harmless one nobody else can publish (review round 1: `yarn add --emoji true x`).
  return isBoolWord(next) ? 'value' : 'candidate';
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

/** Whether a `true` / `false` after the flag `v` is that flag's value: npm's rule ({@link takesBoolWord}) or the launcher's own list. */
function takesWord(v: string, table: FlagTable): boolean {
  return takesBoolWord(v, table) || table.optionalWord?.has(v) === true;
}

/** Whether a `true` / `false` after the flag `v` is read both ways, by the table's {@link FlagTable.bothWays}. */
function readsBothWays(v: string, next: string | undefined, table: FlagTable): boolean {
  if (table.bothWays === undefined || !isBoolWord(next)) return false;
  if (!v.startsWith('--') && SHORT_CLUSTER.test(v)) return true;
  return table.bothWays === 'flags' && table.bool.has(v);
}

/** Why a command whose `true` / `false` after a flag is read both ways is uncertain (it keeps this reason in a confident shape). */
const bothWaysReason = (word: string, flag: string): string =>
  `\`${word}\` after \`${flag}\`${TWO_READINGS} — the value of the flag, or the package — both are looked up`;

/** Why a Yarn line with a `true` / `false` between `--production` and the subcommand is uncertain: no manager installs the word as a package. */
const productionWordReason = (word: string): string =>
  `\`${word}\` after \`--production\`${TWO_READINGS} — Yarn 1 takes it as the value of the flag and Yarn 4 as the subcommand; no manager installs it as a package, so it is not looked up and the manifest is read`;

/**
 * Separates flags (and their values) from positional words.
 *
 * Short-flag clusters are expanded letter by letter (`-qr req.txt` is `-q`
 * then `-r req.txt`; `-rreq.txt` is `-r req.txt`): the first letter that
 * takes a value takes the rest of the cluster, or the next word — except in
 * npm's table, whose groups are opened as npm opens them ({@link openNpmGroup}:
 * `-gD` is `-g -D`, `-gL project` is `-g --location project`). A flag
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
  const flags: Array<{ flag: string; value?: string; eq?: true }> = [];
  const note = (written: string, value: string | undefined, eq?: true): void => {
    const flag = table.long?.get(written) ?? written;
    flags.push(value === undefined ? { flag } : eq === true ? { flag, value, eq } : { flag, value });
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
      positionals.push(i === candidateAt ? { value: v, at: i, candidate: true } : { value: v, at: i });
      continue;
    }
    const eqAt = v.indexOf('=');
    if (eqAt > 0) {
      const flag = v.slice(0, eqAt);
      if (!known(flag)) {
        uncertain.push(`unknown flag ${flag}`);
        unknownFlags += 1;
      }
      note(flag, v.slice(eqAt + 1), true);
      continue;
    }
    if (table.value.has(v)) {
      const word = words[i + 1]?.value;
      if (takesNextWord(valueKind(v, table), word)) {
        note(v, word);
        i += 1;
      } else note(v, undefined);
      continue;
    }
    if (table.bool.has(v)) {
      const word = words[i + 1]?.value;
      if (takesWord(v, table) && isBoolWord(word)) {
        note(v, word);
        i += 1;
      } else {
        note(v, undefined);
        if (readsBothWays(v, word, table)) {
          candidateAt = i + 1;
          uncertain.push(bothWaysReason(word ?? '', v));
        }
      }
      continue;
    }
    if (isNpmGroupWord(v, table)) {
      const group = openNpmGroup(v);
      if (group === undefined) {
        // A letter npm does not have: the whole word is one flag npm does not know (`-gx`), and a short flag takes no word.
        uncertain.push(`unknown flag ${v}`);
        unknownFlags += 1;
        continue;
      }
      const word = words[i + 1]?.value;
      const last = group.flags.length - 1;
      for (const [k, f] of group.flags.entries()) {
        if (k < last || f.value !== undefined) note(f.flag, f.value);
        // The word after the group is the last letter's: its value, or the `true` / `false` of the rule of today (`-Dg false` is `-g false`).
        else if (takesNextWord(group.next, word) || (takesWord(v, table) && isBoolWord(word))) {
          note(f.flag, word);
          i += 1;
        } else note(f.flag, undefined);
      }
      for (const value of group.positionals) positionals.push({ value, at: i });
      continue;
    }
    if (!v.startsWith('--') && SHORT_CLUSTER.test(v)) {
      for (let k = 1; k < v.length; k += 1) {
        const flag = `-${v.charAt(k)}`;
        if (table.value.has(flag) && table.notInGroups?.has(flag) !== true) {
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
      const word = words[i + 1]?.value;
      if (takesWord(v, table) && isBoolWord(word)) i += 1;
      else if (readsBothWays(v, word, table)) {
        candidateAt = i + 1;
        uncertain.push(bothWaysReason(word ?? '', v));
      }
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

/**
 * The six names corepack 0.36.0 takes as the first word after `corepack` (measured, and read in its code: the word is
 * split at its first `@`, lower case only, and no flag of corepack may stand before it), with the name each is read as:
 * `yarnpkg` is Yarn's second name.
 */
const COREPACK_MANAGERS: ReadonlyMap<string, string> = new Map([
  ['yarn', 'yarn'], ['yarnpkg', 'yarn'], ['pnpm', 'pnpm'], ['pnpx', 'pnpx'], ['npm', 'npm'], ['npx', 'npx'],
]);

/** The manager `corepack <word>` runs — `yarn@4.18.1`, `npm@^11`, `pnpm@latest` — or `undefined` when the word is none of the six. */
function corepackManager(word: string | undefined): string | undefined {
  if (word === undefined) return undefined;
  const at = word.indexOf('@');
  return COREPACK_MANAGERS.get(at < 0 ? word : word.slice(0, at));
}

const NPM_INSTALL = new Set(['install', 'i', 'add', 'in', 'ins', 'inst', 'insta', 'instal', 'isnt', 'isnta', 'isntal', 'isntall', 'install-test', 'it']);
/** npm's subcommands that install the manifest and take no package: `ci`, `install-ci-test` and their aliases (`install-test` and `it` take a package, as `install` does: they are in {@link NPM_INSTALL}). */
const NPM_MANIFEST_INSTALL = new Set([
  'ci', 'clean-install', 'ic', 'install-clean', 'isntall-clean', 'install-ci-test', 'cit', 'clean-install-test', 'sit',
]);
/** npm's `update` and its aliases (`npm help update`: u, up, upgrade, udpate): the direct dependencies move past the lockfile's pins. */
const NPM_UPDATE = new Set(['update', 'u', 'up', 'upgrade', 'udpate']);
/** npm's other subcommands that install the manifest as `install` does (the lockfile is obeyed): `dedupe` and its alias, `prune`. */
const NPM_MAINTENANCE = new Set(['dedupe', 'ddp', 'prune']);
const PNPM_UPDATE = new Set(['update', 'up', 'upgrade']);
/** Yarn 1's `upgrade` (and its interactive form): the manifest moves past the lockfile's pins. */
const YARN_UPDATE = new Set(['upgrade', 'upgrade-interactive']);
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

/**
 * Whether the line has a word that may say GLOBAL, before a `--` word: `-g`, `--global`, `--global=<value>`, `--location`,
 * `--location=<value>`, or a short cluster that holds a `g`. It only decides whether an update verb keeps the names it is
 * given ({@link InstallCommand.updateNames}); whether the command IS global stays {@link saysGlobal}'s answer.
 */
const GLOBAL_FLAG_WORD = /^(?:--global(?:=.*)?|--location(?:=.*)?|-[A-Za-z]*g[A-Za-z]*)$/;
const hasGlobalFlagWord = (pre: readonly ShellWord[], args: readonly ShellWord[]): boolean =>
  [...beforeDoubleDash(pre), ...beforeDoubleDash(args)].some((w) => GLOBAL_FLAG_WORD.test(w.value));

/** The words a flag can come from: what follows a `--` word is no flag. */
const beforeDoubleDash = (words: readonly ShellWord[]): ShellWord[] => {
  const at = words.findIndex((w) => w.value === '--');
  return at < 0 ? [...words] : words.slice(0, at);
};

/**
 * Whether an npm, pnpm or bun command says it is a GLOBAL install, and no word can take that back — measured
 * 2026-11-19 (npm 11, pnpm 10, Yarn 1.22 and 4, bun 1.4): the project's registry file is not obeyed by a global install,
 * but is by `--global=false`, `-g false` and `-g --no-global`. `-g --location=project` is global and does not obey it either
 * (`.specs/install-vet-project-registry-said/measurements/global-spellings-windows-2026-11-19.txt:15`; so `-gL project` and
 * `-L project -g`, measured 2026-11-21), and is read as a doubt on purpose: a line too many, never one too few. The words
 * before the subcommand and the words after it are two lists, each read up to a `--` word. For npm each list is read as npm
 * reads it ({@link npmFlagWords}): a group of letters is its flags written apart (`-gD` is `-g -D`, `-Dg false` is
 * `-D -g false`, measured 2026-11-21 with npm 11.19.0) and `-L` is `--location`. In doubt the answer is no:
 *   - a word with a shell expansion (`$` or a backtick) may be `false` or `--no-global`: not global;
 *   - says global: the exact words `-g` and `--global` (not when the next word of the list is `false`), `--global=true`,
 *     and for npm `--location=global` and `--location global`;
 *   - takes it back: any other word that starts with `-` and has `global` or `location` in it, or starts `-g=`;
 *   - for pnpm and bun, a short cluster that holds a `g` (`-gD`, `-Dg false`) takes it back: the word after it may be the
 *     value of its `g` (measured 2026-11-19 with npm 11.20.0: `-g -Dg false` installs the manifest; pnpm's and bun's groups
 *     were not measured); a package name with "global" in it takes nothing back.
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
    const read = manager === 'npm' ? npmFlagWords(list) : rawFlagWords(list);
    for (const { flag: v, next } of read) {
      if (v === '-g' || v === '--global') {
        if (next === 'false') return false;
        says = true;
      } else if (v === '--global=true') says = true;
      else if (manager === 'npm' && (v === '--location=global' || (v === '--location' && next === 'global'))) says = true;
      else if (v.startsWith('-g=') || /global|location/.test(v.toLowerCase())) return false;
      // pnpm and bun: a cluster with a `g` takes it back, its word may be the value of that `g`. npm's groups are opened above.
      else if (manager !== 'npm' && /^-[A-Za-z]{2,}$/.test(v) && v.includes('g')) return false;
    }
  }
  return says;
}

/** The flag words of `list` as written, each with the word after it. */
const rawFlagWords = (list: readonly ShellWord[]): Array<{ flag: string; next: string | undefined }> =>
  list.flatMap((w, at) => (w.value.startsWith('-') ? [{ flag: w.value, next: list[at + 1]?.value }] : []));

/**
 * The flag words of `list` as npm reads them, each with the word after it: a group of letters is opened ({@link openNpmGroup},
 * the one function `walk` and `scanPositional` use too) — its flags in order, a value letter's word being the letter it took
 * (`-Lg` is `--location` with `--global`) and the last flag's the word after the group — and `-L` is `--location`. A word
 * npm does not open (one with a letter npm does not have) stays as written.
 */
function npmFlagWords(list: readonly ShellWord[]): Array<{ flag: string; next: string | undefined }> {
  const out: Array<{ flag: string; next: string | undefined }> = [];
  for (const { flag: v, next } of rawFlagWords(list)) {
    const group = isNpmGroupWord(v, NPM_TABLE) ? openNpmGroup(v) : undefined;
    if (group === undefined) {
      out.push({ flag: NPM_LONG.get(v) ?? v, next });
      continue;
    }
    for (const [k, f] of group.flags.entries()) {
      const following = group.flags[k + 1];
      out.push({ flag: NPM_LONG.get(f.flag) ?? f.flag, next: f.value ?? (following === undefined ? next : following.flag) });
    }
  }
  return out;
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
  /** The {@link FLAGS} key of the command's own flags, when they are not its manager's (`dotnet tool install`). */
  flagTable?: string;
  /** `yarn global add`: the install is a global one. */
  global?: boolean;
  /**
   * A launcher (review P1), and its {@link LAUNCH_FLAGS} table: `run` fetches
   * the package its first positional word names (or its package flags do)
   * and hands every later word to the program; `install` installs every
   * positional word, as an install command does.
   */
  launch?: {
    style: 'run' | 'install';
    flags: string;
    localFirst?: boolean;
    initializer?: true;
    /** How the launcher is written (`npx`, `npm exec`, `npm x`, `pnpm dlx`, `pnpx`, `yarn dlx`, `bunx`, `bun x`): `flags` joins spellings. */
    spelling?: string;
    /** The line began `corepack <manager>[@version]` before the launcher. */
    viaCorepack?: true;
  };
  /**
   * An install of the project's `package.json`: `always` for a subcommand
   * that takes no package (`npm ci`, `pnpm install`, `yarn install`, a bare
   * `yarn`), whose positional words are then no packages; `bare` for one that
   * takes packages too (`npm install`, `pnpm add`, `yarn add`, `bun add`):
   * the manager installs the manifest beside what the command names.
   */
  manifest?: 'always' | 'bare';
  /** An update verb: a manifest install that moves the direct dependencies past the lockfile's pins ({@link InstallCommand.update}). */
  update?: true;
  /** An update verb that keeps the names it is given ({@link InstallCommand.updateNames}): always, or only with a global flag word on the line. */
  names?: 'always' | 'global-word';
  /**
   * An update verb that updates every installed tool ({@link InstallCommand.updatesEveryTool}): `always` (`pipx upgrade-all`, which
   * takes no name: its words are read as none), or `all-flag` when the line has `--all` (`uv tool upgrade --all`).
   */
  everyTool?: 'always' | 'all-flag';
  /**
   * The first word of `args` is only a candidate: it follows a flag the table does not know, so the word before it (the
   * environment of `pipx inject`, which `pre` holds) may have been that flag's value ({@link afterUnknownFlag}).
   */
  firstIsCandidate?: true;
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
 * follows a flag the table does not know ({@link afterUnknownFlag}: it may be that flag's value). With `subcommands`
 * (the position of a subcommand) such a word is the subcommand only when it is one the hook reads; any other is that
 * flag's value, and the scan goes on: one pass, however many unknown flags come first.
 */
function scanPositional(
  words: readonly ShellWord[],
  from: number,
  table: FlagTable,
  subcommands?: ReadonlySet<string>,
): { at: number; candidate: boolean } {
  let candidateAt = -1;
  for (let i = from; i < words.length; i += 1) {
    const v = words[i]?.value ?? '';
    if (v.startsWith('-') && v.length > 1) {
      if (v.includes('=')) continue;
      const next = words[i + 1]?.value;
      // An npm group, opened as `walk` opens it: `npm -gL project install P` — the last letter takes the word.
      const group = isNpmGroupWord(v, table) ? openNpmGroup(v) : undefined;
      // `npm -L global install P`, `npm -m <v> install P` (the String rule: not `npm -m -g install P`).
      if (table.value.has(v)) {
        if (takesNextWord(valueKind(v, table), next)) i += 1;
      }
      // `npm -D false install`: the word after a boolean flag is its value, not the subcommand.
      else if (takesWord(v, table) && isBoolWord(next)) i += 1;
      else if (readsBothWays(v, next, table)) candidateAt = i + 1;
      else if (group !== undefined) {
        if (takesNextWord(group.next, next)) i += 1;
      } else {
        const after = afterUnknownFlag(v, next, table);
        if (after === 'value' || (after === 'candidate' && subcommands !== undefined && !subcommands.has(next ?? ''))) i += 1;
        else if (after === 'candidate') candidateAt = i + 1;
      }
      continue;
    }
    return { at: i, candidate: i === candidateAt };
  }
  return { at: -1, candidate: false };
}

const NPM_INITIALIZER: ReadonlySet<string> = new Set(['create', 'init', 'innit']);
const CREATE_ONLY: ReadonlySet<string> = new Set(['create']);
const BUN_INITIALIZER: ReadonlySet<string> = new Set(['create', 'c']);

/**
 * The verbs that run an initializer — they download `create-<x>` and run it (measured 2026-11-20: npm 11.20.0, Yarn 1.22.22 / 3.8.7 /
 * 4.18.1, pnpm 11.24.0, bun 1.4.4) — and the {@link LAUNCH_FLAGS} table of each manager's.
 */
const INITIALIZER_VERBS: Record<string, ReadonlySet<string>> = { npm: NPM_INITIALIZER, pnpm: CREATE_ONLY, yarn: CREATE_ONLY, bun: BUN_INITIALIZER };
const INITIALIZER_FLAGS: Record<string, string> = { npm: 'npm-init', pnpm: 'pnpm-create', yarn: 'yarn-create', bun: 'bun-create' };

/** The subcommands `detect` reads for each manager: a word after an unknown flag that is none of them is that flag's value. */
const SUBCOMMANDS: Record<string, ReadonlySet<string>> = {
  npm: new Set([...NPM_INSTALL, ...NPM_MANIFEST_INSTALL, ...NPM_UPDATE, ...NPM_MAINTENANCE, 'audit', 'exec', 'x', ...NPM_INITIALIZER]),
  pnpm: new Set(['add', 'dlx', 'dedupe', ...PNPM_INSTALL, ...PNPM_UPDATE, ...CREATE_ONLY]),
  bun: new Set([...BUN_ADD, 'update', 'x', ...BUN_INITIALIZER]),
  yarn: new Set(['install', 'add', 'global', 'workspace', 'workspaces', 'dlx', 'dedupe', 'up', ...YARN_UPDATE, ...CREATE_ONLY]),
  pip: new Set(['install', 'download', 'wheel']),
  uv: new Set(['add', 'pip', 'tool']),
  poetry: new Set(['add']),
  composer: COMPOSER_REQUIRE,
  dotnet: new Set(['add', 'package', 'tool']),
};
/** The verbs of pipx the hook reads: the ones that fetch a package, or an update of one that is installed. */
const PIPX_SUBCOMMANDS: ReadonlySet<string> = new Set(['install', 'run', 'inject', 'upgrade', 'reinstall', 'runpip', 'upgrade-all']);
/** The verbs of `uv tool` the hook reads. */
const UV_TOOL_SUBCOMMANDS: ReadonlySet<string> = new Set(['run', 'install', 'upgrade']);
/** The verbs of pip that fetch a package, and the {@link FLAGS} table of the flags of each (`install`: pip's own). */
const PIP_FETCH_TABLES: ReadonlyMap<string, string | undefined> = new Map([['install', undefined], ['download', 'pip-download'], ['wheel', 'pip-wheel']]);
const ADD_ONLY: ReadonlySet<string> = new Set(['add']);
const ADD_OR_UP: ReadonlySet<string> = new Set(['add', 'up']);
const ADD_OR_UPGRADE: ReadonlySet<string> = new Set(['add', 'upgrade']);
const FOREACH_ONLY: ReadonlySet<string> = new Set(['foreach']);
const FOREACH_UNKNOWN_FLAG = 'a flag of yarn workspaces foreach the hook does not know';
/**
 * The flags of `yarn workspaces foreach` (the help of Yarn 4.18.1, `.specs/_findings-2026-11-20/measurements/cmd-forms/explore-linux-container-2026-11-20.txt`):
 * its own table, not Yarn's own. `--since` takes an optional value, so it is not here.
 */
const FOREACH_VALUE: ReadonlySet<string> = new Set(['--from', '--include', '--exclude', '-j', '--jobs']);
const FOREACH_BOOL: ReadonlySet<string> = new Set(['-A', '--all', '-R', '--recursive', '-W', '--worktree', '-v', '--verbose', '-p', '--parallel', '-i', '--interlaced', '-t', '--topological', '--topological-dev', '--no-private', '-n', '--dry-run']);

/** The verb (`up` or `add`) after the flags of `yarn workspaces foreach`, from `from`; `unknown` when a flag is not in the table. */
function foreachVerb(words: readonly ShellWord[], from: number): { at: number; unknown: boolean } {
  let unknown = false;
  for (let i = from; i < words.length; i += 1) {
    const v = words[i]?.value ?? '';
    if (!v.startsWith('-') || v.length === 1) return ADD_OR_UP.has(v) ? { at: i, unknown } : { at: -1, unknown };
    const flag = v.includes('=') ? v.slice(0, v.indexOf('=')) : v;
    if (FOREACH_VALUE.has(flag)) {
      if (!v.includes('=')) i += 1;
    } else if (!FOREACH_BOOL.has(flag)) unknown = true;
  }
  return { at: -1, unknown };
}

/** What `yarn workspace <w>` and `yarn workspaces foreach` give after their words: `up` is read as `yarn up`, `add` as `yarn add`; any other verb is not read. */
function yarnWorkspaceVerb(
  words: readonly ShellWord[],
  at: number,
  table: FlagTable,
  head: string,
  pre: ShellWord[],
  uncertain: string[],
  tag: (d: Detected) => Detected,
): Detected | null {
  const verb = words[at]?.value;
  if (verb === 'up') {
    const update = scanPositional(words, at + 1, table).at >= 0;
    return tag({ manager: head, ecosystem: 'npm', args: words.slice(at + 1), pre, uncertain, manifest: 'always', names: 'always', ...(update ? { update: true as const } : {}) });
  }
  if (verb !== 'add') return null;
  return tag({ manager: head, ecosystem: 'npm', args: words.slice(at + 1), pre, uncertain, manifest: 'bare' });
}
/**
 * `pipx inject <environment> <package>…`: an install into an environment that exists. The environment is the first positional word
 * `walk` gives with the flags of the verb — a group of letters is opened (`-fr reqs.txt T P`, `-qi URL T P`), which `scanPositional`
 * does not do — and it is never looked up: the words before it (flags and their values) are `pre`, the ones after it the packages.
 * When that first word follows a flag the table does not know it may be that flag's value, and the next word the environment: the
 * first package is then only a candidate ({@link Detected.firstIsCandidate}).
 */
function injectDetected(after: ShellWord[], before: ShellWord[]): Detected | null {
  const table = LAUNCH_FLAGS['pipx-inject'];
  const environment = table === undefined ? undefined : walk(after, table).positionals[0];
  if (environment === undefined) return null;
  const d = launcher('pipx', 'pypi', after.slice(environment.at + 1), [...before, ...after.slice(0, environment.at + 1)], {
    style: 'install',
    flags: 'pipx-inject',
  });
  return environment.candidate === true ? { ...d, firstIsCandidate: true } : d;
}

/**
 * `pipx runpip <environment> <pip arguments>`: the arguments after the environment are a pip command, read as one (`null` when its
 * verb is not one pip fetches a package with). The environment is the first positional word, never looked up. After a flag of pipx
 * the table does not know the first word may be that flag's value: the pip command then starts at the first of its verbs that is
 * the second or the third positional word, and the environment is the word before it.
 */
function runpipDetected(after: ShellWord[], before: ShellWord[]): Detected | null {
  const table = LAUNCH_FLAGS['pipx-runpip'];
  const [first, second, third] = table === undefined ? [] : walk(after, table).positionals;
  if (table === undefined || first === undefined) return null;
  let environment = first;
  if (first.candidate === true && !(second !== undefined && PIP_FETCH_TABLES.has(second.value))) {
    if (second === undefined || third === undefined || !PIP_FETCH_TABLES.has(third.value)) return null;
    environment = second;
  }
  const word = after[environment.at];
  if (word === undefined) return null;
  const inner = detect([{ ...word, value: 'pip' }, ...after.slice(environment.at + 1)]);
  if (inner === null) return null;
  const own = walk([...before, ...after.slice(0, environment.at + 1)], table).uncertain;
  return { ...inner, uncertain: [...own, ...inner.uncertain] };
}

/** `pipx upgrade`: with `--install` it installs what is not installed, so it is read as an install; without, the words are names given to an update. */
function upgradeDetected(after: ShellWord[], before: ShellWord[]): Detected {
  if (walk(after, PIPX_UPGRADE_TABLE).flags.some((f) => f.flag === '--install')) {
    return launcher('pipx', 'pypi', after, before, { style: 'install', flags: 'pipx-upgrade' });
  }
  return { manager: 'pipx', ecosystem: 'pypi', args: after, pre: before, uncertain: [], flagTable: 'pipx-upgrade', names: 'always' };
}
const INSTALL_ONLY: ReadonlySet<string> = new Set(['install']);
const PACKAGE_ONLY: ReadonlySet<string> = new Set(['package']);

/**
 * The command at `words`. A word after a flag the table does not know may be that flag's value (`npm --fetch-retries 0
 * install p`, `yarn --network-concurrency 1`): the scan for the subcommand takes it as one unless it is a subcommand
 * the hook reads, word by word and in one pass.
 */
function detect(input: readonly ShellWord[]): Detected | null {
  let words = input;
  const nextPositional = (ws: readonly ShellWord[], from: number, table: FlagTable, subcommands?: ReadonlySet<string>): number =>
    scanPositional(ws, from, table, subcommands).at;
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
  if (head === 'yarnpkg') head = 'yarn';
  let viaCorepack = false;
  if (head === 'corepack') {
    // `corepack <manager>[@version] <rest>` runs the manager on <rest>; `use <manager>` and `up` install the project's manifest.
    const first = words[start + 1]?.value;
    const via = corepackManager(first);
    if (via !== undefined) {
      head = via;
      viaCorepack = true;
      i = start + 2;
    } else if (first === 'up' || (first === 'use' && corepackManager(words[start + 2]?.value) !== undefined)) {
      return { manager: 'npm', ecosystem: 'npm', args: [], pre: [], uncertain: [], manifest: 'always' };
    } else return null;
  }

  // The launchers named by themselves (review P1).
  const rest = words.slice(i);
  const corepackMark = viaCorepack ? ({ viaCorepack: true } as const) : {};
  if (head === 'npx') return launcher('npx', 'npm', rest, [], { style: 'run', flags: 'npx', localFirst: true, spelling: 'npx', ...corepackMark });
  if (head === 'pnpx') return launcher('pnpm', 'npm', rest, [], { style: 'run', flags: 'pnpm-dlx', spelling: 'pnpx', ...corepackMark });
  if (head === 'bunx') return launcher('bun', 'npm', rest, [], { style: 'run', flags: 'bunx', localFirst: true, spelling: 'bunx', ...corepackMark });
  if (head === 'uvx') return launcher('uv', 'pypi', rest, [], { style: 'run', flags: 'uvx' });
  if (head === 'pipx') {
    const sub = nextPositional(words, i, LAUNCH_FLAGS['pipx-run'] ?? FLAGS['pip'] ?? { value: set(), bool: set(), registry: set() }, PIPX_SUBCOMMANDS);
    const subWord = sub < 0 ? '' : (words[sub]?.value ?? '');
    const after = words.slice(sub + 1);
    const before = words.slice(i, sub);
    switch (subWord) {
      case 'install':
        return launcher('pipx', 'pypi', after, before, { style: 'install', flags: 'pipx-install' });
      case 'run':
        return launcher('pipx', 'pypi', after, before, { style: 'run', flags: 'pipx-run' });
      case 'inject':
        return injectDetected(after, before);
      case 'runpip':
        return runpipDetected(after, before);
      case 'upgrade':
        return upgradeDetected(after, before);
      // The names of an update (`names`), read with the flags of the verb ({@link FLAGS}).
      case 'reinstall':
        return { manager: 'pipx', ecosystem: 'pypi', args: after, pre: before, uncertain: [], flagTable: 'pipx-reinstall', names: 'always' };
      // `pipx upgrade-all` takes no name: its words are none (a word after `--skip a` is another value of `--skip`).
      case 'upgrade-all':
        return { manager: 'pipx', ecosystem: 'pypi', args: after, pre: before, uncertain: [], flagTable: 'pipx-upgrade-all', everyTool: 'always' };
      default:
        return null;
    }
  }

  const table = FLAGS[head];
  if (table === undefined) return null;
  // An initializer verb after a flag the table does not know may be that flag's value (`npm --dgunknown create install p`,
  // `yarn --dgunknown create`): it is the verb unless the positional after it is a subcommand of the manager that is no
  // initializer, or none follows; then the line is read as before these verbs were read, from the word after it.
  const initVerbs = INITIALIZER_VERBS[head];
  const subcommands = SUBCOMMANDS[head];
  let first = scanPositional(words, i, table, subcommands);
  while (initVerbs !== undefined && first.at >= 0 && first.candidate && initVerbs.has(words[first.at]?.value ?? '')) {
    const following = scanPositional(words, first.at + 1, table, subcommands).at;
    const followingWord = following < 0 ? undefined : (words[following]?.value ?? '');
    if (followingWord !== undefined && !(subcommands?.has(followingWord) === true && !initVerbs.has(followingWord))) break;
    first = scanPositional(words, first.at + 1, table, subcommands);
  }
  let sub = first.at;
  // Yarn 1 reads a `true` / `false` after `--production` as that flag's value (measured 2026-11-19), Yarn 4 and the scan above
  // as the subcommand, and no measured manager installs it as a package (EC-5): the word is taken out of the line, the rest is
  // read as the subcommand says, and the command says it has two readings.
  let productionWord: string | undefined;
  const wordAt = words[sub];
  if (head === 'yarn' && wordAt !== undefined && isBoolWord(wordAt.value) && words[sub - 1]?.value === '--production') {
    productionWord = wordAt.value;
    words = [...words.slice(0, sub), ...words.slice(sub + 1)];
    sub = nextPositional(words, sub, table, SUBCOMMANDS[head]);
  }
  const tag = (d: Detected): Detected =>
    productionWord === undefined
      ? d
      : { ...d, uncertain: [...d.uncertain, productionWordReason(productionWord)] };
  if (sub < 0) {
    // A bare `yarn` — flags only — installs the project's manifest, unless a flag only prints.
    if (head === 'yarn' && !rest.some((w) => YARN_PRINTS.has(w.value))) {
      return tag({ manager: head, ecosystem: 'npm', args: rest, pre: [], uncertain: [], manifest: 'always' });
    }
    return null;
  }
  // The launchers that are a package manager's subcommand (review P1).
  const subName = words[sub]?.value ?? '';
  const after = words.slice(sub + 1);
  const before = words.slice(i, sub);
  if (head === 'npm' && (subName === 'exec' || subName === 'x')) {
    return launcher('npm', 'npm', after, before, { style: 'run', flags: 'npm-exec', localFirst: true, spelling: `npm ${subName}`, ...corepackMark });
  }
  if (head === 'pnpm' && subName === 'dlx') return launcher('pnpm', 'npm', after, before, { style: 'run', flags: 'pnpm-dlx', spelling: 'pnpm dlx', ...corepackMark });
  if (head === 'yarn' && subName === 'dlx') return launcher('yarn', 'npm', after, before, { style: 'run', flags: 'yarn-dlx', spelling: 'yarn dlx', ...corepackMark });
  if (head === 'bun' && subName === 'x') return launcher('bun', 'npm', after, before, { style: 'run', flags: 'bunx', localFirst: true, spelling: 'bun x', ...corepackMark });
  if (initVerbs?.has(subName) === true) return initializerLaunch(head, after, before);
  if (head === 'uv' && subName === 'tool') {
    const toolTable = LAUNCH_FLAGS['uvx'] ?? table;
    const verb = nextPositional(words, sub + 1, toolTable, UV_TOOL_SUBCOMMANDS);
    const verbName = verb < 0 ? '' : (words[verb]?.value ?? '');
    const tail = words.slice(verb + 1);
    if (verbName === 'run') return launcher('uv', 'pypi', tail, before, { style: 'run', flags: 'uvx' });
    if (verbName === 'install') return launcher('uv', 'pypi', tail, before, { style: 'install', flags: 'uv-tool-install' });
    if (verbName === 'upgrade') {
      return { manager: 'uv', ecosystem: 'pypi', args: tail, pre: before, uncertain: [], flagTable: 'uv-tool-upgrade', names: 'always', everyTool: 'all-flag' };
    }
    return null;
  }
  const subWord = words[sub]?.value ?? '';
  const pre = words.slice(i, sub);

  switch (head) {
    case 'npm':
      // `npm install` installs the manifest, with or without a package; `npm ci` and its kin always do.
      if (NPM_INSTALL.has(subWord)) return { manager: head, ecosystem: 'npm', args: words.slice(sub + 1), pre, uncertain: [], manifest: 'bare' };
      if (NPM_MANIFEST_INSTALL.has(subWord) || NPM_MAINTENANCE.has(subWord)) {
        return { manager: head, ecosystem: 'npm', args: words.slice(sub + 1), pre, uncertain: [], manifest: 'always' };
      }
      // The names after an update verb select dependencies of the manifest: none is a package (`manifest: 'always'`).
      if (NPM_UPDATE.has(subWord)) return { manager: head, ecosystem: 'npm', args: words.slice(sub + 1), pre, uncertain: [], manifest: 'always', update: true, names: 'global-word' };
      // `npm audit fix` installs the lockfile's packages; `npm audit` and `npm audit signatures` install nothing.
      if (subWord === 'audit' && words[nextPositional(words, sub + 1, table)]?.value === 'fix') {
        return { manager: head, ecosystem: 'npm', args: words.slice(sub + 1), pre, uncertain: [], manifest: 'always' };
      }
      return null;
    case 'pnpm':
      if (subWord === 'add') return { manager: head, ecosystem: 'npm', args: words.slice(sub + 1), pre, uncertain: [], manifest: 'bare' };
      // `pnpm install <pkg>` / `pnpm i <pkg>` is pnpm's `add` (measured, pnpm 10.33: it resolves the name as a direct
      // dependency), and installs the manifest too. Up to and including 3.10.0 the form with a package was not read at all.
      if (PNPM_INSTALL.has(subWord)) return { manager: head, ecosystem: 'npm', args: words.slice(sub + 1), pre, uncertain: [], manifest: 'bare' };
      if (subWord === 'dedupe') return { manager: head, ecosystem: 'npm', args: words.slice(sub + 1), pre, uncertain: [], manifest: 'always' };
      if (PNPM_UPDATE.has(subWord)) return { manager: head, ecosystem: 'npm', args: words.slice(sub + 1), pre, uncertain: [], manifest: 'always', update: true, names: 'global-word' };
      return null;
    case 'bun': {
      // `bun a`, and `bun i <pkg>` / `bun install <pkg>` add too, and install the manifest.
      if (subWord === 'update') return { manager: head, ecosystem: 'npm', args: words.slice(sub + 1), pre, uncertain: [], manifest: 'always', update: true, names: 'global-word' };
      if (!BUN_ADD.has(subWord)) return null;
      return { manager: head, ecosystem: 'npm', args: words.slice(sub + 1), pre, uncertain: [], manifest: 'bare' };
    }
    case 'yarn': {
      if (subWord === 'install' || subWord === 'dedupe') return tag({ manager: head, ecosystem: 'npm', args: words.slice(sub + 1), pre, uncertain: [], manifest: 'always' });
      if (YARN_UPDATE.has(subWord)) return tag({ manager: head, ecosystem: 'npm', args: words.slice(sub + 1), pre, uncertain: [], manifest: 'always', update: true });
      if (subWord === 'up') {
        // Yarn 4: `yarn up <pattern>` moves that dependency to its latest; without a pattern it installs the manifest as `install` does.
        const update = nextPositional(words, sub + 1, table) >= 0;
        return tag({ manager: head, ecosystem: 'npm', args: words.slice(sub + 1), pre, uncertain: [], manifest: 'always', names: 'always', ...(update ? { update: true as const } : {}) });
      }
      let at = sub;
      const uncertain: string[] = [];
      if (subWord === 'workspaces') {
        // `yarn workspaces foreach <flags> up|add …` (Yarn 4.18; Yarn 3.8 has no such command): read as `yarn up` and `yarn workspace <w> add`.
        const foreach = nextPositional(words, sub + 1, table, FOREACH_ONLY);
        if (foreach < 0 || words[foreach]?.value !== 'foreach') return null;
        const verb = foreachVerb(words, foreach + 1);
        if (verb.at < 0) return null;
        uncertain.push('workspace context (yarn workspaces)');
        if (verb.unknown) uncertain.push(FOREACH_UNKNOWN_FLAG);
        return yarnWorkspaceVerb(words, verb.at, table, head, pre, uncertain, tag);
      }
      if (subWord === 'global') at = nextPositional(words, sub + 1, table, ADD_OR_UPGRADE);
      else if (subWord === 'workspace') {
        const ws = nextPositional(words, sub + 1, table);
        at = ws < 0 ? -1 : nextPositional(words, ws + 1, table, ADD_OR_UP);
        uncertain.push('workspace context (yarn workspace)');
      }
      if (at < 0) return null;
      if (subWord === 'global' && words[at]?.value === 'upgrade') {
        // Measured 2026-11-20 (Yarn 1.22): `yarn global upgrade <P>` fetches P when it is installed globally; the project is not read.
        return tag({ manager: head, ecosystem: 'npm', args: words.slice(at + 1), pre, uncertain, global: true, names: 'always' });
      }
      if (subWord === 'global') {
        if (words[at]?.value !== 'add') return null;
        return tag({ manager: head, ecosystem: 'npm', args: words.slice(at + 1), pre, uncertain, manifest: 'bare', global: true });
      }
      return yarnWorkspaceVerb(words, at, table, head, pre, uncertain, tag);
    }
    case 'pip': {
      // `pip download` and `pip wheel` fetch the package (and build its sdist) as `install` does, with the flags of their own verb.
      if (!PIP_FETCH_TABLES.has(subWord)) return null;
      const flagTable = PIP_FETCH_TABLES.get(subWord);
      const d: Detected = { manager: head, ecosystem: 'pypi', args: words.slice(sub + 1), pre, uncertain: [] };
      return flagTable === undefined ? d : { ...d, flagTable };
    }
    case 'uv': {
      if (subWord === 'add') return { manager: 'uv', ecosystem: 'pypi', args: words.slice(sub + 1), pre, uncertain: [] };
      if (subWord === 'pip') {
        const inst = nextPositional(words, sub + 1, table, INSTALL_ONLY);
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
      // dotnet package add <NAME> (.NET 10: the same command as `add package`, the project a flag)
      if (subWord === 'package') {
        const verb = nextPositional(words, sub + 1, table, ADD_ONLY);
        if (verb < 0 || words[verb]?.value !== 'add') return null;
        const args = words.slice(verb + 1);
        const uncertain = args.some((w) => /^--(?:project|file)(?:=|$)/.test(w.value))
          ? ['dotnet project argument (the NuGet configuration next to that project was not read)']
          : [];
        return { manager: head, ecosystem: 'nuget', args, pre, uncertain };
      }
      // dotnet tool install <NAME>: the tool is a NuGet package, asked of the sources as `add package` asks.
      if (subWord === 'tool') {
        const toolTable = FLAGS['dotnet-tool'] ?? table;
        const verb = nextPositional(words, sub + 1, toolTable, INSTALL_ONLY);
        if (verb < 0 || words[verb]?.value !== 'install') return null;
        return { manager: head, ecosystem: 'nuget', args: words.slice(verb + 1), pre, uncertain: [], flagTable: 'dotnet-tool' };
      }
      if (subWord !== 'add') return null;
      // dotnet add [<PROJECT>] package <NAME>
      let at = nextPositional(words, sub + 1, table);
      const uncertain: string[] = [];
      if (at >= 0 && words[at]?.value !== 'package') {
        uncertain.push('dotnet project argument (the NuGet configuration next to that project was not read)');
        at = nextPositional(words, at + 1, table, PACKAGE_ONLY);
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
 * The index of the last word of a launcher's arguments its package may be: the first positional, and past it while that word
 * follows a flag the table does not know (it may be that flag's value, so the next positional is a candidate too). `-1` when
 * there is no positional.
 */
function launchEnd(args: readonly ShellWord[], table: FlagTable): number {
  let scan = scanPositional(args, 0, table);
  let end = scan.at;
  while (scan.at >= 0 && scan.candidate) {
    scan = scanPositional(args, scan.at + 1, table);
    if (scan.at >= 0) end = scan.at;
  }
  return end;
}

/** Whether a word given to an initializer is a registry name: not a path, a URL, an archive, `user/repo` or a bad range. */
function isInitializerName(word: string, manager: string): boolean {
  // The word as written decides first: a path, a URL, an SSH spec or an archive is no registry name, whatever a `create-` in
  // front would make of it (`npm init .` is not the package `create-.`, nor `npm init ~` the package `create-~`).
  const scoped = word.startsWith('@');
  const versioned = word.indexOf('@', scoped ? 1 : 0) > 0;
  if (notAPackage(word, versioned ? null : fileEndings(manager, scoped)) !== null) return false;
  // Then it is judged by the package it is made into: a lone scope (`@s`) is no name by itself, but `@s/create` is one.
  return 'name' in parseNpm(initializerNames(word, manager).names[0] ?? word, manager);
}

/**
 * `<verb> <x>` of an initializer verb: the launcher that fetches what the manager asks the registry for (`create-<x>`). `null`
 * (nothing is read, as before these verbs were) when no word it would read is a registry name: no word at all (`npm init`,
 * `yarn create`), a path, a URL, `user/repo`. A candidate after a flag the table does not know that is no name stays that flag's value.
 */
function initializerLaunch(head: string, after: ShellWord[], before: ShellWord[]): Detected | null {
  const flags = INITIALIZER_FLAGS[head];
  const table = flags === undefined ? undefined : LAUNCH_FLAGS[flags];
  if (flags === undefined || table === undefined) return null;
  const end = launchEnd(after, table);
  if (end < 0) return null;
  if (!walk(after.slice(0, end + 1), table).positionals.some((p) => isInitializerName(p.value, head))) return null;
  return launcher(head, 'npm', after, before, { style: 'run', flags, initializer: true });
}

/**
 * What the registry is asked for when `word` follows an initializer verb (measured 2026-11-20): `<x>[@v]` is `create-<x>[@v]`,
 * `@s[@v]` is `@s/create[@v]`, `@s/<x>[@v]` is `@s/create-<x>[@v]`. A word that already starts with `create-` is `create-create-<x>`
 * for npm and bun, `create-<x>` for pnpm, and either for Yarn (1 and 3 the first, 4 the second: both are looked up). Not measured, so
 * both are looked up: the word `create` alone and a scope whose name starts with `create-`; and `yarn create @s@<v>`, which Yarn 1
 * does not send to the registry. `why` is the reason the command is then uncertain ({@link TWO_READINGS}, which a confident command keeps).
 */
function initializerNames(word: string, manager: string): { names: string[]; why?: string } {
  const scoped = word.startsWith('@');
  const at = word.indexOf('@', scoped ? 1 : 0);
  const bare = at > 0 ? word.slice(0, at) : word;
  const version = at > 0 ? word.slice(at) : '';
  const unmeasured = (names: string[]): { names: string[]; why: string } => ({
    names,
    why: `\`${word}\`${TWO_READINGS} — with the \`create-\` prefix added again, or as written (not measured) — both are looked up`,
  });
  if (scoped) {
    const slash = bare.indexOf('/');
    if (slash < 0) {
      const names = [`${bare}/create${version}`];
      if (manager !== 'yarn' || version === '') return { names };
      return {
        names,
        why: `\`${word}\`${TWO_READINGS} — Yarn 3 and 4 ask the registry for \`${bare}/create\`, Yarn 1 does not ask it — \`${bare}/create\` is looked up`,
      };
    }
    const scope = bare.slice(0, slash);
    const rest = bare.slice(slash + 1);
    if (rest === 'create' || rest.startsWith('create-')) return unmeasured([`${scope}/create-${rest}${version}`, `${bare}${version}`]);
    return { names: [`${scope}/create-${rest}${version}`] };
  }
  if (bare === 'create') return unmeasured([`create-create${version}`, `create${version}`]);
  if (bare.startsWith('create-')) {
    if (manager === 'pnpm') return { names: [`${bare}${version}`] };
    if (manager === 'yarn') {
      return {
        names: [`create-${bare}${version}`, `${bare}${version}`],
        why: `\`${word}\`${TWO_READINGS} — Yarn 1 and 3 ask the registry for \`create-${bare}\`, Yarn 4 for \`${bare}\` — both are looked up`,
      };
    }
  }
  return { names: [`create-${bare}${version}`] };
}

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
    const end = launchEnd(d.args, table);
    if (end >= 0) body = d.args.slice(0, end + 1);
  }
  const w = walk(body, table);
  // The environment `pipx inject` skipped may have been a flag's value: the first word after it is then no more than a candidate.
  const firstWord = w.positionals[0];
  if (d.firstIsCandidate === true && firstWord !== undefined) w.positionals[0] = { ...firstWord, candidate: true };
  const flags = [...pre.flags, ...w.flags];
  // A flag of `names` is ON unless it carries a `true` / `false` word (`--no false`, `-c false`): then it is off, and the
  // positional after it is looked up, the command being uncertain (the word may be read the other way).
  const has = (names: ReadonlySet<string> | undefined): boolean =>
    names !== undefined && flags.some((f) => names.has(f.flag) && !isBoolWord(f.value));
  // A flag written with `=` takes no word after it: there are not two readings.
  const wordFlags = (names: ReadonlySet<string> | undefined): Array<{ flag: string; value?: string }> =>
    names === undefined ? [] : flags.filter((f) => names.has(f.flag) && isBoolWord(f.value) && f.eq !== true);
  const values = (names: ReadonlySet<string> | undefined): string[] =>
    names === undefined
      ? []
      : flags
          .filter((f) => names.has(f.flag))
          .flatMap((f) => (d.ecosystem === 'pypi' ? splitOutsideBrackets(f.value ?? '') : (f.value ?? '').split(',')))
          .map((v) => v.trim())
          .filter((v) => v !== '');
  const raws: string[] = [];
  // An initializer's words are rewritten to the package the manager asks for; a candidate that is no registry name is a flag's value.
  const initializer = launch.initializer === true;
  const limited = limitCandidates(initializer ? w.positionals.filter((p) => isInitializerName(p.value, d.manager)) : w.positionals);
  const written = new Map<string, string>();
  const initWhy: string[] = [];
  let byPackageFlag = false;
  if (initializer) {
    // The value of a package flag (`yarn create -p pkg`) is looked up as written; the command word too, with its prefix.
    raws.push(...values(table.packageFlags));
    for (const p of limited.kept) {
      const read = initializerNames(p.value, d.manager);
      for (const name of read.names) {
        raws.push(name);
        written.set(name, p.value);
      }
      if (read.why !== undefined) initWhy.push(read.why);
    }
  } else if (!has(table.noFetchFlags)) {
    const named = values(table.packageFlags);
    if (named.length > 0) {
      raws.push(...named);
      byPackageFlag = true;
    } else if (!has(table.shellFlags)) raws.push(...limited.kept.map((p) => p.value));
    // In shell mode the positional is shell text — but a line of ONE word is a package for pnpm (`pnpm dlx -c pkg`, measured
    // 2026-11-19); with more words after it (`-c a b`) or spaces inside it (`-c 'a --version'`) it is a command, not looked up.
    else if (table.shellWord === true && d.args.length === body.length) raws.push(...limited.kept.map((p) => p.value).filter((v) => !/\s/.test(v)));
    raws.push(...values(table.extraPackageFlags));
  }
  const packages: PackageSpec[] = [];
  const candidates: PackageSpec[] = [];
  const certainRaws = new Set(limited.kept.filter((p) => p.candidate !== true).map((p) => p.value));
  const candidateRaws = new Set(limited.kept.filter((p) => p.candidate === true).map((p) => p.value));
  const skipped: SkippedSpec[] = [...pre.skipped, ...w.skipped];
  const unsure: string[] = [...wordFlags(table.noFetchFlags), ...wordFlags(table.shellFlags)].map((f) => bothWaysReason(f.value ?? '', f.flag));
  const bothPairs: Array<readonly [PackageSpec, PackageSpec]> = [];
  for (const raw of raws) {
    const parsed = d.ecosystem === 'npm' ? parseNpm(raw, d.manager) : parsePython(raw, false, d.manager);
    // The `raw` of an initializer's package is the word as written, not the name made of it.
    const asWritten = written.get(raw) ?? raw;
    const spec = asWritten === raw ? parsed : { ...parsed, raw: asWritten };
    if ('name' in spec) {
      const read = d.ecosystem === 'npm' ? npmReadings(spec, d.manager) : { packages: [spec] };
      for (const each of read.packages) {
        packages.push(each);
        if (!byPackageFlag && candidateRaws.has(asWritten) && !certainRaws.has(asWritten)) candidates.push(each);
      }
      if ('pair' in read && read.pair !== undefined) bothPairs.push(read.pair);
      const why = unmeasuredReason(d.manager, spec);
      if (why !== undefined) unsure.push(why);
      if (d.ecosystem === 'npm' && asWritten.endsWith('@')) unsure.push(LAUNCHER_NAME_AT);
    } else skipped.push(spec);
  }
  const bothWhy = bothReadings(bothPairs);
  if (bothWhy !== undefined) unsure.push(bothWhy);
  unsure.push(...initWhy);
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
  if (limited.dropped > 0) out.candidatesDropped = limited.dropped;
  if (candidates.length > 0) out.candidates = candidates;
  if (flags.some((f) => f.flag === '--prefix' || f.flag === '-C')) out.prefixed = true;
  // The requirements files `pipx inject -r` hands to pip, as `pip install -r` hands them, in the order written.
  if (launch.flags === 'pipx-inject') {
    const files = requirementFiles(flags, PIPX_REQUIREMENT_FLAGS);
    if (files.length > 0) out.manifest = { kind: 'requirements', files };
  }
  return out;
}

/** The flags of `pipx inject` that name a requirements file. */
const PIPX_REQUIREMENT_FLAGS: ReadonlySet<string> = new Set(['-r', '--requirement']);

/** The values of the flags `names` among `flags`, in order, none empty. */
function requirementFiles(flags: ReadonlyArray<{ flag: string; value?: string }>, names: ReadonlySet<string>): string[] {
  return flags.flatMap((f) => (names.has(f.flag) && f.value !== undefined && f.value !== '' ? [f.value] : []));
}

/**
 * The value of a package flag of a launcher of the PyPI split at its commas outside `[...]` (`uvx --with "P[x,y],D"` is `P[x,y]` and
 * `D`; measured 2026-11-21, M-02 F16: uv reads the extras of one package as one). A counter that a `[` raises and a `]` lowers, never
 * below 0: a comma at depth 0 separates. A range with a comma (`P>=1,<2`) stays split.
 */
function splitOutsideBrackets(value: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (let k = 0; k < value.length; k += 1) {
    const ch = value.charAt(k);
    if (ch === '[') depth += 1;
    else if (ch === ']') depth = Math.max(0, depth - 1);
    else if (ch === ',' && depth === 0) {
      parts.push(value.slice(start, k));
      start = k + 1;
    }
  }
  parts.push(value.slice(start));
  return parts;
}

function collect(d: Detected, context: readonly string[]): InstallCommand {
  if (d.launch !== undefined) return collectLaunch(d, d.launch, context);
  const table = FLAGS[d.flagTable ?? (d.manager === 'uv-pip' ? 'pip' : d.manager)] ?? FLAGS['npm'];
  const flagTable = table ?? { value: set(), bool: set(), registry: set() };
  const preWalk = walk(d.pre, flagTable);
  const walked = walk(d.args, flagTable);
  const { skipped, customRegistry, uncertain, registries } = walked;
  // A subcommand that takes no package names none: its positional words are not looked up.
  const limited = limitCandidates(walked.positionals);
  // The words after an update verb are its names ({@link InstallCommand.updateNames}), never packages.
  const readsNoPackage = d.manifest === 'always' || d.names !== undefined || d.everyTool === 'always';
  const positionals = readsNoPackage ? [] : limited.kept;
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
  if (limited.dropped > 0 && !readsNoPackage) out.candidatesDropped = limited.dropped;

  // A candidate (the word after a flag the table does not know) may be that flag's value: it is vetted, but it is not a
  // thing the command surely names, so it does not stop the manifest from being read.
  const candidatePackages: PackageSpec[] = [];
  const bothPairs: Array<readonly [PackageSpec, PackageSpec]> = [];
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
      const read = d.ecosystem === 'npm' ? npmReadings(spec, d.manager) : { packages: [spec] };
      for (const each of read.packages) {
        packages.push(each);
        if (p.candidate === true) candidatePackages.push(each);
      }
      if ('pair' in read && read.pair !== undefined) bothPairs.push(read.pair);
      const why = unmeasuredReason(d.manager, spec);
      if (why !== undefined && !out.uncertain.includes(why)) out.uncertain.push(why);
      lastComposer = d.ecosystem === 'packagist' ? spec : undefined;
    } else {
      skipped.push(spec);
      lastComposer = undefined;
    }
  }

  const bothWhy = bothReadings(bothPairs);
  if (bothWhy !== undefined) out.uncertain.push(bothWhy);
  if (candidatePackages.length > 0) out.candidates = candidatePackages;

  if (d.ecosystem === 'nuget') {
    // One package per `dotnet add package`; its version is a flag. With a candidate on the line (the word after a flag
    // the table does not know) the real name may be any of the words: none is dropped.
    const extra = positionals.some((p) => p.candidate === true) ? [] : packages.splice(1);
    for (const e of extra) skipped.push(skip(e.raw, 'unexpected extra argument to dotnet add package'));
    const first = packages[0];
    const version = flagValue(d.args, d.flagTable === 'dotnet-tool' ? ['--version'] : ['-v', '--version']);
    if (first !== undefined && version !== undefined) first.range = version;
  }

  // What the command installs from a manifest, beside what it names.
  if (allFlags.some((f) => flagTable.dir?.has(f.flag) === true)) out.prefixed = true;
  // Three readings must agree (npm 11.20.0, measured 2026-11-19). The walker knows which flags take a value (`--otp
  // --global` hands `--global` to `--otp`, and npm then obeys the project's file); the raw words know what takes a
  // global flag back; and every flag must be one the manager's table knows, because npm reads abbreviations and
  // shorthands the table does not hold (`-g --loc=project` and `-g --g=false` obey the project's file). In doubt: no.
  const knownFlagsOnly = preWalk.unknownFlags + walked.unknownFlags === 0;
  // The names of an update verb (not a package: `packages` stays empty for one): a pattern, a path and a URL are none.
  if (d.names === 'always' || (d.names === 'global-word' && hasGlobalFlagWord(d.pre, d.args))) {
    out.updateNames = [];
    for (const p of limited.kept) {
      const spec = d.ecosystem === 'pypi' ? parsePython(p.value, false, d.manager) : parseNpm(p.value, d.manager);
      // A pattern, a path or a URL is no name; it is kept as a skipped word, so that "no word at all" can be told from it.
      if ('name' in spec) out.updateNames.push(spec);
      else skipped.push(spec);
    }
    // The candidate words left out past the ceiling of one command are counted, as they are for an install.
    if (limited.dropped > 0) out.candidatesDropped = limited.dropped;
  } else if (d.everyTool === 'always') out.updateNames = [];
  if (d.everyTool === 'always' || (d.everyTool === 'all-flag' && allFlags.some((f) => f.flag === '--all'))) out.updatesEveryTool = true;
  if (d.global === true || (knownFlagsOnly && allFlags.some(isGlobalFlag) && saysGlobal(d.manager, d.pre, d.args))) out.global = true;
  if (d.manager === 'pip' || d.manager === 'uv-pip') {
    const files = requirementFiles(walked.flags, REQUIREMENT_FLAGS);
    if (files.length > 0) out.manifest = { kind: 'requirements', files };
  } else if (d.manifest !== undefined && out.global !== true) {
    // The manifest is left unread only for an install that is global FOR CERTAIN (`out.global`); in doubt — `-g $X`,
    // `-g --location=project`, `npm ci --global=false` — it is read: vetting more, never less (measured 2026-11-19).
    // An install that names packages installs the project's manifest too (measured 2026-11-19, npm 11, pnpm 10, Yarn,
    // bun), so a package, a skipped word (`npm i ./pkg.tgz`) or a candidate word does not stop it from being read.
    out.manifest = { kind: 'package-json' };
    if (d.update === true) out.update = true;
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
  'found by reading the command as PowerShell does (a comma list, a backtick escape or continuation, a doubled quote, a Unicode space, a `>` or `<` glued to a word) — vetted for malicious versions only';

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
      if (packages.length === 0 && c.manifest === undefined && c.updateNames === undefined) continue;
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
  return JSON.stringify([m.kind, m.kind === 'requirements' ? m.files : [], c.workdir ?? null, c.prefixed === true, c.update === true]);
}

/** Why a package found in a script the command hands a shell is never denied as missing. */
const NESTED_SCRIPT = 'found in a script the command hands a shell (bash -c, cmd /c, pwsh -c, a script piped to a shell) — vetted, never denied as missing';

/** The install commands of `command` read the POSIX way and — for PowerShell — the way PowerShell reads it. */
function readingsOf(command: string, shell: CommandShell, forced: string | null, cdpath: boolean): InstallCommand[] {
  const text = stripComments(command);
  const out = parseReading(text, forced, cdpath);
  if (shell !== 'powershell') return out;
  // `>` and `<` after text are part of the word for PowerShell (measured, 7.6 and 5.1): the word reaches the program whole.
  const asPowerShell = powershellAsPosix(text, { literalGluedRedirects: true });
  if (asPowerShell === text) return withoutRanges(out);
  const seen = new Set(out.flatMap((c) => c.packages.map(packageKey)));
  const seenManifests = new Set(out.map(manifestKey));
  for (const c of parseReading(asPowerShell, POWERSHELL_READING, cdpath)) {
    const packages = c.packages.filter((p) => !seen.has(packageKey(p)));
    // A manifest install only this reading finds is kept; one both readings find is the same install.
    const newManifest = c.manifest !== undefined && !seenManifests.has(manifestKey(c));
    if (packages.length === 0 && !newManifest && c.updateNames === undefined) continue;
    for (const p of packages) seen.add(packageKey(p));
    seenManifests.add(manifestKey(c));
    const { manifest: _same, ...withoutManifest } = c;
    out.push({ ...(newManifest ? c : withoutManifest), packages, skipped: [] });
  }
  return withoutRanges(out);
}

/** The managers of the npm family: a range with `<` or `>` written for them reaches a `.cmd` shim, which hands the cmd.exe-read word on (measured: `P@>=1.0.0` becomes `P@`). */
const NPM_FAMILY = new Set(['npm', 'pnpm', 'yarn', 'bun']);

/**
 * For the PowerShell tool: each package of the npm family read with a range that has `<` or `>` is looked up a second time with none,
 * because behind a `.cmd` the cmd.exe reads the line again and hands the manager `name@`, which installs the latest. The second ones come
 * after every package of the line, as commands of their own that keep the certainty of the command they came from.
 */
function withoutRanges(commands: InstallCommand[]): InstallCommand[] {
  const seen = new Set(commands.flatMap((c) => c.packages.map(packageKey)));
  const extra: InstallCommand[] = [];
  for (const c of commands) {
    if (c.ecosystem !== 'npm' || !NPM_FAMILY.has(c.manager)) continue;
    const packages: PackageSpec[] = [];
    for (const p of c.packages) {
      if (p.range === undefined || !/[<>]/.test(p.range)) continue;
      const bare: PackageSpec = { ecosystem: p.ecosystem, name: p.name, raw: p.name };
      if (seen.has(packageKey(bare))) continue;
      seen.add(packageKey(bare));
      packages.push(bare);
    }
    if (packages.length === 0) continue;
    const { manifest: _manifest, updateNames: _names, ...rest } = c;
    extra.push({ ...rest, packages, skipped: [] });
  }
  return [...commands, ...extra];
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
 * The launcher lines whose inner command may DENY a name the registry does not have. Measured 2026-11-20 in a Linux container
 * (Node 24.21.0, npm 11.19.0, pnpm 11.24.0, Yarn 1.22.22 and 4.18.1, bun 1.4.4, corepack 0.36.0) against a substitute registry
 * that logged every request: each pair below, run with `add <P>` and no flag of its own, asked the registry for `P` and for the
 * manifest's dependency and installed both. `npx` also with `-y`; `npm exec` only with a `--` before the launched word, or after
 * `corepack`; behind `corepack` the manager that ran was Yarn 1.22.22. `pnpm dlx` and `yarn dlx` were started as `corepack pnpm@11.24.0
 * dlx …` and `corepack yarn@4.18.1 dlx …`: a `corepack <manager>[@version]` before them is read as the same line. Nothing else was
 * measured: another pair, spelling, launcher flag, `--` or inner verb leaves the inner command uncertain (it only warns).
 */
interface MeasuredLaunch {
  spelling: string;
  /** The launched word, without its version. */
  launched: string;
  /** The launcher's own flags that were part of the measurement. */
  flags: readonly string[];
  /** Where the `--` stood: before the launched word, after it, or nowhere. */
  dash: 'before' | 'after' | 'none';
  /** The manager `corepack` ran (written without a version) when the launched word is `corepack`. */
  behindCorepack?: string;
  /** Whether `corepack <manager>[@version]` may stand before the launcher. */
  prefix?: true;
}
const MEASURED_LAUNCHES: readonly MeasuredLaunch[] = [
  { spelling: 'npx', launched: 'pnpm', flags: ['-y'], dash: 'none' },
  { spelling: 'npx', launched: 'yarn', flags: ['-y'], dash: 'none' },
  { spelling: 'npx', launched: 'corepack', flags: ['-y'], dash: 'none', behindCorepack: 'yarn' },
  { spelling: 'npm exec', launched: 'pnpm', flags: [], dash: 'before' },
  { spelling: 'npm exec', launched: 'corepack', flags: [], dash: 'after', behindCorepack: 'yarn' },
  { spelling: 'pnpm dlx', launched: 'yarn', flags: [], dash: 'none', prefix: true },
  { spelling: 'yarn dlx', launched: 'pnpm', flags: [], dash: 'none', prefix: true },
  { spelling: 'bunx', launched: 'pnpm', flags: [], dash: 'none' },
];
/** The verb of the measured lines. */
const MEASURED_VERB = 'add';
/** The launchers of the npm family ({@link LAUNCH_FLAGS} names): the only ones whose launched package may be a package manager. */
const NPM_LAUNCH_TABLES: ReadonlySet<string> = new Set(['npx', 'npm-exec', 'pnpm-dlx', 'yarn-dlx', 'bunx']);
/** The package managers (and corepack) the hook reads behind a launcher, by the name of the launched word without its version. */
const LAUNCHED_MANAGERS: ReadonlySet<string> = new Set(['npm', 'pnpm', 'yarn', 'yarnpkg', 'bun', 'corepack']);
/** The flags that move a launcher, or its manager, away from where the command runs, or into a workspace (the `dir` and `workspace` sets). */
const MOVING_FLAGS = ['--prefix', '-C', '--dir', '--cwd', '-w', '--workspace', '--workspaces', '--filter', '-F'];

function unmeasuredLaunch(why: string): string {
  return `a package manager run by a launcher — this form was not measured (${why})`;
}

/** What the measurement does not cover about this launcher line, or `undefined` when it is one of the measured forms. */
function unmeasuredForm(
  launch: NonNullable<Detected['launch']>,
  launched: string,
  ownFlags: readonly string[],
  dash: { before: boolean; after: boolean },
  inner: readonly string[],
): string | undefined {
  const spelling = launch.spelling ?? '';
  const ofSpelling = MEASURED_LAUNCHES.filter((m) => m.spelling === spelling);
  if (ofSpelling.length === 0) return unmeasuredLaunch(`the launcher's spelling: ${spelling}`);
  const m = ofSpelling.find((each) => each.launched === launched);
  if (m === undefined || (launch.viaCorepack === true && m.prefix !== true)) return unmeasuredLaunch(`the pair: ${spelling} ${launched}`);
  const stray = ownFlags.find((f) => !m.flags.includes(f));
  if (stray !== undefined) return unmeasuredLaunch(`a flag of the launcher: ${stray}`);
  const placed = dash.before ? (dash.after ? 'both' : 'before') : dash.after ? 'after' : 'none';
  if (placed !== m.dash) return unmeasuredLaunch(`a flag of the launcher: the \`--\` is ${placed === 'none' ? 'missing' : 'not where it was measured'}`);
  if (m.behindCorepack !== undefined && inner[0] !== m.behindCorepack) return unmeasuredLaunch(`the pair: ${spelling} ${launched} ${inner[0] ?? ''}`);
  const verb = inner[m.behindCorepack === undefined ? 0 : 1];
  if (verb !== MEASURED_VERB) return unmeasuredLaunch(`the inner verb: ${verb ?? 'none'}`);
  return undefined;
}

/**
 * The command a launcher of the npm family runs, when what it launches is a package manager the hook reads: the words after the
 * launched word, read as that manager reads them — `npx pnpm add p` is also `pnpm add p`, and `npx corepack yarn add p` is also
 * `corepack yarn add p` (measured 2026-11-20: the manager fetches `p` and installs the project's manifest). One level: this reads
 * the inner command once and never looks inside it for another launcher. `undefined` when the launcher launches anything else, runs
 * shell text (`npx -c`), or the words after the manager are no command the hook reads (`npx pnpm --version`).
 *
 * It is a command of its own: its manager, flags, manifest and registry are the manager's, it has no `localFirst`, and it takes the
 * directory flags of the launcher (`--prefix`, `--dir`, `-w`, …) as its own `prefixed`. It may deny a missing name only when the
 * whole line is plain (`notConfident`, the outer judgement) and is one of the forms measured ({@link MEASURED_LAUNCHES}) with a plain
 * inner command ({@link confidentWords}); otherwise it carries the reason.
 */
function readLaunchedManager(d: Detected, context: readonly string[], notConfident: string | null): InstallCommand | undefined {
  const launch = d.launch;
  if (launch === undefined || launch.style !== 'run' || launch.initializer === true || d.ecosystem !== 'npm' || !NPM_LAUNCH_TABLES.has(launch.flags)) {
    return undefined;
  }
  const table = LAUNCH_FLAGS[launch.flags];
  if (table === undefined) return undefined;
  const found = scanPositional(d.args, 0, table);
  // The word after a flag the table does not know may be that flag's value: it is only a candidate, nothing is read behind it.
  if (found.at < 0 || found.candidate) return undefined;
  const launchedWord = d.args[found.at];
  if (launchedWord === undefined) return undefined;
  const before = [...d.pre, ...d.args.slice(0, found.at)];
  // A shell-text flag (`-c`, `--call`, `--shell-mode`): the word is a command line, not a package.
  if (before.some((w) => table.shellFlags?.has(w.value) === true)) return undefined;
  const spec = parseNpm(launchedWord.value, d.manager);
  if (!('name' in spec) || !LAUNCHED_MANAGERS.has(spec.name)) return undefined;
  const dash = { before: before.some((w) => w.value === '--'), after: d.args[found.at + 1]?.value === '--' };
  const words = d.args.slice(found.at + (dash.after ? 2 : 1));
  const head: ShellWord = { ...launchedWord, value: spec.name };
  const innerDetected = detect([head, ...words]);
  if (innerDetected === null) return undefined;

  const c = collect(innerDetected, context);
  // The directory flags of the launcher make the manifest it installs not the one where the command runs.
  const moving = new Set([...MOVING_FLAGS, ...(table.dir ?? []), ...(table.workspace ?? []), ...(FLAGS[d.manager]?.dir ?? []), ...(FLAGS[d.manager]?.workspace ?? [])]);
  const named = (w: ShellWord): boolean => {
    const eq = w.value.indexOf('=');
    return moving.has(eq > 0 ? w.value.slice(0, eq) : w.value);
  };
  if (before.some(named)) c.prefixed = true;
  // `npm exec` reads the flags after the manager itself unless a `--` stands before them (npm's documentation; not run): `-g` there
  // may be npm's, so the inner command is never global for certain and its manifest is read.
  if (launch.flags === 'npm-exec' && !dash.before && !dash.after && c.global === true) {
    delete c.global;
    if (innerDetected.manifest !== undefined) {
      c.manifest = { kind: 'package-json' };
      if (innerDetected.update === true) c.update = true;
    }
  }
  const ownFlags = before.filter((w) => w.value !== '--').map((w) => w.value);
  const innerWords = words.map((w) => w.value);
  const unmeasured = unmeasuredForm(launch, spec.name, ownFlags, dash, innerWords);
  const shape = notConfident ?? unmeasured ?? confidentWords(spec.name === 'corepack' ? ['corepack', ...innerWords] : [spec.name, ...innerWords]);
  const keep = c.uncertain.filter((r) => r === UNMEASURED_ARCHIVE || r === LAUNCHER_NAME_AT || r.includes(TWO_READINGS));
  c.uncertain = shape === null ? keep : [...new Set([shape, ...c.uncertain])];
  return c;
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
      const d = detect(wordsWithoutRedirections(words));
      if (d !== null) {
        const context: string[] = [];
        if (envChange) context.push('inline environment assignment in the command (it can redirect the registry)');
        if (dirChanged) context.push('directory change earlier in the command (that directory’s registry configuration was not read)');
        const c = collect(d, context);
        // A confident shape has no reason of its own, but a name of a manager nobody measured that ends like an archive does,
        // and so does a `key@npm:rest` that Yarn and bun read as either of two packages.
        const unmeasured = c.uncertain.filter((r) => r === UNMEASURED_ARCHIVE || r === LAUNCHER_NAME_AT || r.includes(TWO_READINGS));
        c.uncertain = notConfident === null ? unmeasured : [...new Set([notConfident, ...c.uncertain])];
        const sure = dirs[s]?.[w]?.sure ?? null;
        const elsewhere = runsElsewhere(words);
        const place = (command: InstallCommand): void => {
          if (elsewhere) command.workdir = null;
          else if (sure === null || sure.length > 0) command.workdir = sure;
        };
        place(c);
        out.push(c);
        // A launcher that runs a package manager: the words after it are a command of that manager, read once and joined to the line.
        const inner = readLaunchedManager(d, context, notConfident);
        if (inner !== undefined) {
          place(inner);
          out.push(inner);
        }
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
  // `dotnet tool install`: no source, configuration file or verbosity flag; a tool is global, local or in a folder.
  'dotnet-tool': {
    bool: set('--prerelease', '-g', '--global', '--local', '--allow-downgrade', '--create-manifest-if-needed', '--allow-roll-forward'),
    value: set('--version', '--framework', '--tool-path'),
  },
  // The launchers (review P1): consent and verbosity only. A package flag
  // (`-p`, `--from`, `--spec`), a registry or `--pip-args` takes the command
  // out of the confident shape.
  npx: { bool: set('-y', '--yes', '-q', '--quiet', '--silent'), value: set() },
  // `npm exec` is npm's own command: `--ignore-scripts` is a boolean flag of npm that changes nothing about the lookup.
  'npm-exec': { bool: set('-y', '--yes', '-q', '--quiet', '--silent', '--ignore-scripts'), value: set() },
  'pnpm-dlx': { bool: set('--silent', '-s'), value: set() },
  // The initializers (measured 2026-11-20): consent and verbosity only; pnpm none, bun has no entry (it never denies).
  'npm-init': { bool: set('-y', '--yes', '-q', '--quiet', '--silent'), value: set() },
  'yarn-create': { bool: set('-q', '--quiet'), value: set() },
  'pnpm-create': { bool: set(), value: set() },
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

const BUN_TEMPLATE_REASON = '`bun create` uses a template of that name from a `.bun-create` folder when there is one, which was not looked for';

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
  return confidentWords(words);
}

/**
 * The word half of {@link confidentShape}: whether the words — the command's own, already split and unquoted — are one plain
 * install statement of a tool with only allowlisted flags. The command inside a launcher (`npx pnpm add p`) is judged by the
 * words after the launcher ({@link readLaunchedManager}).
 */
function confidentWords(words: readonly string[]): string | null {
  // `corepack yarn@4 add p` is as plain as `yarn add p`; `yarnpkg` is `yarn`.
  const viaCorepack = words[0] === 'corepack' ? corepackManager(words[1]) : undefined;
  const [named, ...rest] = viaCorepack === undefined ? words : [viaCorepack, ...words.slice(2)];
  const tool = named === 'yarnpkg' ? 'yarn' : named;
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
        [key, args, launch] = ['npm-exec', rest.slice(1), true];
        break;
      }
      // An initializer (`npm create|init|innit <x>`) is a launcher of `create-<x>`: the first positional closes the judgement.
      if (NPM_INITIALIZER.has(at(0))) {
        [key, args, launch] = ['npm-init', rest.slice(1), true];
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
      if (at(0) === 'create') {
        [key, args, launch] = [`${tool}-create`, rest.slice(1), true];
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
      // `bun create <x>` uses a template of that name from a `.bun-create` folder when there is one and then asks the registry
      // for nothing (measured 2026-11-20, bun 1.4.4): the hook does not read that folder, so a missing name never denies.
      if (BUN_INITIALIZER.has(at(0))) return BUN_TEMPLATE_REASON;
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
      if ((at(0) === 'add' && at(1) === 'package') || (at(0) === 'package' && at(1) === 'add')) [key, args] = ['dotnet', rest.slice(2)];
      else if (at(0) === 'tool' && at(1) === 'install') [key, args] = ['dotnet-tool', rest.slice(2)];
      else return notPlain(`'dotnet ${at(0)} ${at(1)}' (dotnet add <project> package …)`);
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
