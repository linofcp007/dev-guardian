/**
 * What a manifest install fetches from a registry: the dependencies a
 * `package.json` declares, and the packages a requirements file names.
 *
 * `npm install` (with or without a package), `npm ci`, `pnpm install`, `yarn`,
 * `bun install`, `pnpm add`, `yarn add`, `bun add` and `pip install -r` install
 * a manifest (for npm the nearest `package.json` from where the command runs
 * up to the project or repository root), and the install hook used to say
 * nothing about it: `npm
 * install crossenv` was denied while the same package in `package.json`
 * installed in silence. This module turns the manifest into the
 * {@link PackageSpec}s the vetting already knows.
 *
 * Three rules, each with a failure behind it:
 *
 *   - **The file is the repository's, and it is not trusted.** It is read
 *     through the hooks' own reader only (`hooks/configFile.ts`: the
 *     descriptor is `fstat`ed, at most 1 MiB, never a path on the network),
 *     so a FIFO, a device or an unreachable share in its place cannot hold
 *     the hook past the 15 s Claude Code gives it.
 *   - **Only a valid name and a valid range become a package.** A name is
 *     held to its registry's own rule ({@link parsePackageSpec}), and a range
 *     to a stricter one than a command line gets — there the shell has
 *     already split the words, here a value is free text: a semver range or
 *     ONE dist-tag word for npm, a list of PEP 440 specifiers for PyPI. What
 *     fails is not looked up and never reaches a message the model reads.
 *   - **What was not read is said.** A manifest that is there and could not
 *     be read is `unreadable`, with a reason of a fixed list; a requirements
 *     file whose includes were not all read is `incomplete`. Only a manifest
 *     that is not there is silence: the install has nothing to read either.
 *
 * It reads no lockfile and no workspace member, and looks nothing up: the
 * version vetted is the one the manifest's range resolves to. Node built-ins
 * and modules the hook bundle already holds only — it is loaded behind the
 * install gate (`mayInstall.ts`), with the rest of the vetting.
 */

import { dirname, resolve } from 'node:path';

import { isNetworkPath, readSmallText, type TextRead } from '../hooks/configFile.js';
import {
  isSemverRange,
  isTildeWord,
  MAX_RANGE_LENGTH,
  notAPackage,
  notARegistryRange,
  npmKeyRange,
  npmProtocolReading,
  parsePackageSpec,
  readsFileValue,
} from './parseCommand.js';
import type { PackageSpec, PkgEcosystem } from './types.js';

type ManifestStatus = 'ok' | 'absent' | 'unreadable';

export interface ManifestRead {
  /** The file as the command names it — `package.json`, `reqs/dev.txt` — for the message. */
  file: string;
  status: ManifestStatus;
  /** The packages a registry would serve, each once, in the order of the file. */
  packages: PackageSpec[];
  /**
   * Every name the file declares as a dependency, the ones that are no registry spec too (a `workspace:`, `file:` or git value, which
   * are not in `packages`): what a name given to an update is compared with. A requirements file has its packages' names.
   */
  names: string[];
  /** With a list of folders: the folder this file was read in (the one the read of {@link readRequirements} was made from). */
  dir?: string;
  /** The registries / indexes the file itself names (a requirements file's `--index-url` and the like). */
  registries: string[];
  /** With `unreadable`: why, one of {@link MANIFEST_UNREADABLE_REASONS}. */
  reason?: string;
  /** With `ok`: a file this one includes was not read, and why — its packages are not in `packages`. */
  incomplete?: string;
  /** An inline script block names its own index or sources (`[tool.uv]`, or a `[tool]` header): what they serve is not vetted. */
  toolUv?: true;
  /** An inline script block names a package from a URL, a path or a VCS: it is not vetted. */
  otherSource?: true;
}

/** The most of a manifest that is read: the hooks' cap for a `package.json`. */
export const MAX_MANIFEST_BYTES = 1024 * 1024;
/** The most requirement files one command's manifests are read from, includes counted. */
export const MAX_REQUIREMENT_FILES = 8;
/** How deep a requirements file's `-r` includes are followed. */
const MAX_REQUIREMENT_DEPTH = 3;

const REASON = {
  notRegular: 'not a regular file',
  tooLarge: 'over 1 MiB',
  notJson: 'not valid JSON',
  notManifest: 'not a package.json object',
  network: 'on a network path',
  unreadable: 'could not be read',
  tooMany: 'past the limit of 8 requirement files',
  tooDeep: 'included more than 3 levels deep',
  unknownDir: 'where the command runs could not be determined',
  notInForm: 'its `# /// script` block is not in the form the hook reads',
  deadline: 'vetting time budget exhausted',
  notLiteral: 'not a literal file name',
} as const;

/** Why a manifest was not read: the only texts about one that reach a message. */
export const MANIFEST_UNREADABLE_REASONS: readonly string[] = Object.values(REASON);
/** The reason of a manifest whose directory the command line does not tell. */
export const UNKNOWN_DIRECTORY = REASON.unknownDir;

/** npm's own limit on a package name; a longer one is no package. */
const MAX_NAME_LENGTH = 214;
/** The most of a file name that is repeated in a message. */
const MAX_LABEL_LENGTH = 120;

/** A file name as a message may repeat it: no control character, no line break, bounded. */
export function label(file: string): string {
  const clean = file.replace(/[\u0000-\u001f\u007f]+/g, ' ').trim();
  return clean.length > MAX_LABEL_LENGTH ? `${clean.slice(0, MAX_LABEL_LENGTH)}…` : clean;
}

function refusal(read: Exclude<TextRead, { status: 'ok' } | { status: 'absent' }>): string {
  switch (read.reason) {
    case 'not-a-regular-file':
      return REASON.notRegular;
    case 'too-large':
      return REASON.tooLarge;
    case 'remote-link':
      return REASON.network;
    default:
      return REASON.unreadable;
  }
}

/** The text of a file of the project — or that it is not there, or why it was not read. Never throws. */
function readManifestText(path: string, under: string): { status: 'ok'; text: string } | { status: 'absent' } | { status: 'unreadable'; reason: string } {
  if (isNetworkPath(path) || isNetworkPath(under)) return { status: 'unreadable', reason: REASON.network };
  let read: TextRead;
  try {
    read = readSmallText(path, MAX_MANIFEST_BYTES, under);
  } catch {
    return { status: 'unreadable', reason: REASON.unreadable };
  }
  if (read.status === 'ok') return read;
  if (read.status === 'absent') return read;
  return { status: 'unreadable', reason: refusal(read) };
}

/** A registry name of `ecosystem`, and nothing else: the word a command line would name it by, with no range. */
function validName(ecosystem: PkgEcosystem, name: string): boolean {
  if (name.length === 0 || name.length > MAX_NAME_LENGTH) return false;
  const spec = parsePackageSpec(ecosystem, name);
  return 'name' in spec && spec.name === name && spec.range === undefined;
}

function spec(ecosystem: PkgEcosystem, name: string, range: string | undefined): PackageSpec {
  return range === undefined ? { ecosystem, name, raw: name } : { ecosystem, name, range, raw: ecosystem === 'npm' ? `${name}@${range}` : `${name}${range}` };
}

function pushOnce(into: PackageSpec[], seen: Set<string>, pkg: PackageSpec): void {
  const key = `${pkg.name.toLowerCase()}\0${pkg.range ?? ''}`;
  if (seen.has(key)) return;
  seen.add(key);
  into.push(pkg);
}

// ─────────────────────────────────────────────────────────────── package.json

/** The sections of a `package.json` an install fetches (npm 7 and later install peers too). */
const NPM_SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'] as const;

/** A dist-tag: one word that no version can be taken for. */
const DIST_TAG = /^[A-Za-z][A-Za-z0-9._-]{0,63}$/;

/**
 * The protocols the hook knows, a value that names no registry package, and where each comes from: `file:` and `link:` (npm, pnpm,
 * Yarn, bun), `workspace:` (pnpm, Yarn, bun), `portal:`, `patch:` and `exec:` (Yarn 2 and later) and `jsr:` (pnpm, Yarn 4). Most
 * are also in the command line's list of URL and VCS specs ({@link notARegistryRange}); here they are all in one place. Measured on
 * 2026-11-20 (npm 11.20, pnpm 10.33): none of them is asked of the registry; Yarn 1.22 asks for all but `file:` and `link:` (a known
 * limit: the word `yarn` does not say which Yarn runs). A dependency's own value `patch:…` is read before this list
 * ({@link patchDependency}): the list keeps it for the range of an alias and the rest of a patch's source. `catalog:` is not in it:
 * pnpm 11.24, Yarn 4.18 and bun 1.4 fetch the key from the registry, at the version the catalog gives (measured 2026-11-20), so it
 * is the key with no range, like any OTHER `word:rest` (`foo:^1`), a spec of the registry vetted by its name. A drive letter (`C:x`)
 * is a path. `user/repo` with an optional `#branch` is the GitHub shorthand.
 */
const NOT_OF_THE_REGISTRY = /^(?:(?:file|link|workspace|portal|patch|exec|jsr):|[A-Za-z]:|[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:#.*)?$)/i;

/**
 * What a dependency's value asks the registry for: `undefined` for "the default" (an empty value, `latest`) and for a value the
 * hook does not read as a range (it is still a spec of the registry: the package is vetted, with no range); the range or tag; or
 * `null` when the value is positively something else — a path, a protocol (`file:`, `link:`, `workspace:`, `patch:` …), a URL, a
 * git repository, `user/repo`, or an archive the manager reads as a file. The reading fails closed: only those are dropped.
 */
function npmRange(value: string, manager: string): string | undefined | null {
  const v = value.trim();
  if (v === '' || v === 'latest') return undefined;
  if (notARegistryRange(v) !== null || NOT_OF_THE_REGISTRY.test(v) || readsFileValue(manager, v)) return null;
  if (v.length > MAX_RANGE_LENGTH) return undefined;
  if (DIST_TAG.test(v)) return v;
  return isSemverRange(v) ? v : undefined;
}

/** The alias prefix of a value, read in any letter case, as npm reads it. */
const NPM_PROTOCOL = /^npm:/i;
/** A patch of Yarn 2 and later, `patch:<source>#<path and parameters>`, in any letter case. */
const PATCH_PROTOCOL = /^patch:/i;
const PATCH_WORD = 'patch:';

/**
 * The shape of a range in the `<rest>` of `npm:<rest>` when `<rest>` is a valid package name (the grammar G of
 * install-vet-manifest-protocol-values, bug.md → Correção): `v` any number of times, a part, at most two more `.` and a part, and
 * after the third part an optional prerelease (an optional `-`, then identifiers separated by `.`); a part is digits, `x` or `X`.
 * It is node-semver 7.8.5's `validRange` cut down to what a valid name can hold, and widened to its `loose` forms and to a semver
 * older than `invalidXRangeOrder`, so that no pnpm installs the key of such a rest unseen: like pnpm 11.24 it reads `1.0.0`, `1.x`,
 * `1.2`, `v1.2.3`, `vx`, `x.x.x-beta` and `1.0.0-beta` as a range, and `x-foo`, `x.js`, `v`, `1.2.3.4` and `latest` as none; it
 * also reads `x.1`, `1.x.1`, `1.0.0beta`, `01.0.0` and `vv1.2.3`, which pnpm 11.24 reads as an alias (a lookup of the key too many).
 * Tested only on a valid name — at most 214 characters, no space —, which bounds its backtracking.
 */
const NPM_REST_RANGE = /^v*(?:[0-9]+|[xX])(?:\.(?:[0-9]+|[xX])(?:\.(?:[0-9]+|[xX])(?:-?[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*)?)?)?$/;

/**
 * How a `package.json` value `npm:<rest>` is read: {@link npmProtocolReading}, the command line's rule, with what the managers do
 * with a VALUE (install-vet-manifest-protocol-values, measured 2026-11-20 and 21 with npm 11.19, pnpm 11.24, Yarn 4.18, bun 1.4):
 *
 *   - for pnpm, Yarn and bun a `~` word with no slash or backslash after it (`~x`, `~abc`, a lone `~`) is the key, never a path:
 *     the three install the key for `npm:~x`;
 *   - pnpm 11 reads the key when `<rest>` is a range for node-semver and an alias otherwise, and pnpm 10.33 an alias always; the
 *     hook does not know which pnpm runs, so a `<rest>` that is no valid name is the key — with no range expression run on it, as
 *     it may be as long as the file — and a valid name is the alias, and the key too when it has the shape of a range
 *     ({@link NPM_REST_RANGE});
 *   - npm reads an alias always; so does every manager for a `<rest>` with a `@range` of its own or a shell expansion, and a
 *     path or a URL is no package.
 */
function npmValueReading(manager: string, rest: string): 'alias' | 'key' | 'both' {
  const tildeIsKey = manager === 'pnpm' || manager === 'yarn' || manager === 'bun';
  if (!tildeIsKey || /[$`]/.test(rest) || rest.indexOf('@', rest.startsWith('@') ? 1 : 0) > 0) return npmProtocolReading(manager, rest);
  if (isTildeWord(rest)) return 'key';
  if (manager !== 'pnpm') return npmProtocolReading(manager, rest);
  if (validName('npm', rest)) return NPM_REST_RANGE.test(rest) ? 'both' : 'alias';
  return rest !== '' && notAPackage(rest, null) !== null ? 'alias' : 'key';
}

/**
 * `"key": "npm:<rest>"` as the packages a registry would serve ({@link npmValueReading}): an alias is the package after `npm:`
 * (`"x": "npm:real@^1"` is `real`); read as the key, it is `key`, at `<rest>` without the spaces at its ends when that is a
 * version or a range ({@link npmKeyRange}: a word, or an archive bun reads as a file, leaves it with none), and read both ways
 * `<rest>` is a name too. A key that is no valid name leaves the other package alone.
 */
function npmProtocolDependency(key: string, rest: string, manager: string): PackageSpec[] {
  const reading = npmValueReading(manager, rest);
  if (reading === 'alias') {
    const at = rest.indexOf('@', rest.startsWith('@') ? 1 : 0);
    const name = at > 0 ? rest.slice(0, at) : rest;
    const range = npmRange(at > 0 ? rest.slice(at + 1) : '', manager);
    return range !== null && validName('npm', name) ? [spec('npm', name, range)] : [];
  }
  const own = validName('npm', key) ? [spec('npm', key, npmKeyRange(manager, rest.trim()))] : [];
  return reading === 'both' && validName('npm', rest) ? [...own, spec('npm', rest, undefined)] : own;
}

const HEX_DIGITS = '0123456789abcdefABCDEF';
/** The first digit of the `%XX` of an ASCII character, `00` to `7F`. */
const ASCII_HIGH_DIGITS = '01234567';

/**
 * `text` with every `%XX` of an ASCII character (`00` to `7F`, the hex digits in either case) decoded until none is left: the
 * fixed point, the same in any order, as two such sequences never overlap. Any other `%` (`%zz`, `%C3`, one at the end) stays,
 * and a name or a range with it is not valid. One pass, left to right, into a buffer: each character goes to its end, and while
 * the buffer ends in such a `%XX` the three give way to the character they stand for. Each swap shortens the buffer by two, so
 * the work is linear — `decodeURIComponent` again and again is not (`%2525…2531` would take one pass per `25`).
 */
function decodeAsciiEscapes(text: string): string {
  const out: string[] = [];
  for (const c of text) {
    out.push(c);
    for (let n = out.length; n >= 3; n -= 2) {
      const high = out[n - 2];
      const low = out[n - 1];
      if (out[n - 3] !== '%' || high === undefined || low === undefined || !ASCII_HIGH_DIGITS.includes(high) || !HEX_DIGITS.includes(low)) break;
      out.length = n - 3;
      out.push(String.fromCharCode(Number.parseInt(`${high}${low}`, 16)));
    }
  }
  return out.join('');
}

/** How far from its start a name's `@` is looked for: one past the longest valid name, as a longer name names nothing. */
const NAME_SPAN = MAX_NAME_LENGTH + 1;

/** The first `@` of `text` after `from` and before `end`, looked for in the first {@link NAME_SPAN} characters from `from` only; -1 when there is none there. */
function nameEnd(text: string, from: number, end: number): number {
  const stop = Math.min(end, from + NAME_SPAN);
  for (let i = from + 1; i < stop; i += 1) if (text.charCodeAt(i) === 0x40) return i;
  return -1;
}

/** Whether `text` holds `prefix` (lower case) at `at`, in any letter case, before `end`. */
function prefixAt(text: string, at: number, end: number, prefix: string): boolean {
  return at + prefix.length <= end && text.slice(at, at + prefix.length).toLowerCase() === prefix;
}

/**
 * The package the source of a `patch:` value names — what Yarn 3 and 4 install, with the patch (measured 2026-11-20) — or
 * `undefined` when it names none the hook looks up. The grammar of install-vet-manifest-protocol-values (bug.md → Correção):
 *
 *   1. The source runs from after `patch:` to the first `#` as written; what follows (the patch's path) is not read.
 *   2. It is decoded once, to the fixed point ({@link decodeAsciiEscapes}): no level decodes again.
 *   3. A level is an interval of that text, the top one the whole of it. Its name runs to the first `@` after its first
 *      character, or to its end, and its rest follows that `@`.
 *   4. A name that is no valid name names nothing.
 *   5. A rest that starts with `patch:` opens a new level, from after it to the first `#` of the text (looked for once: none is
 *      left inside that cut for the levels below it), and the name is not read.
 *   6. On the last level ({@link sourcePackage}), a rest `npm:<P>@<Q>` is an alias: `P`, at `Q` when that is a version or a
 *      range — nothing when `P` is no valid name or `Q` no registry spec.
 *   7. Any other rest, its `npm:` taken off, that is no registry spec (a path, git, a URL, `file:`, `workspace:` …) names
 *      nothing: what Yarn installs then does not come from the registry.
 *   8. Otherwise the name, at the rest when that is a version or a range of at most 100 characters: the rest is never a second
 *      name.
 *
 * Linear in the value: an `@` is looked for in a name's first 215 characters only, a level is a pair of indexes, the `#` that
 * ends the levels is found once, and steps 6 to 8 run once.
 */
function patchSource(value: string, manager: string): PackageSpec | undefined {
  const hash = value.indexOf('#');
  const text = decodeAsciiEscapes(value.slice(PATCH_WORD.length, hash < 0 ? value.length : hash));
  let start = 0;
  let end = text.length;
  let cut = -1;
  for (;;) {
    const at = nameEnd(text, start, end);
    if (at < 0 && end - start > MAX_NAME_LENGTH) return undefined;
    const name = text.slice(start, at < 0 ? end : at);
    if (!validName('npm', name)) return undefined;
    const rest = at < 0 ? end : at + 1;
    if (!prefixAt(text, rest, end, PATCH_WORD)) return sourcePackage(name, text.slice(rest, end), manager);
    start = rest + PATCH_WORD.length;
    if (cut < 0) {
      const next = text.indexOf('#', start);
      cut = next < 0 ? text.length : next;
    }
    end = cut;
  }
}

/**
 * Steps 6 to 8 of {@link patchSource}, on the last level of the source: its name `name` and its rest `rest`. An alias whose `@`
 * lies past the window {@link nameEnd} looks in has a `P` too long to be a name, so it names nothing (step 6) — the one search
 * for that `@` runs once, as steps 6 to 8 do.
 */
function sourcePackage(name: string, rest: string, manager: string): PackageSpec | undefined {
  const isAlias = NPM_PROTOCOL.test(rest);
  const wanted = isAlias ? rest.slice(4) : rest;
  const at = isAlias ? nameEnd(wanted, 0, wanted.length) : -1;
  if (at > 0) {
    const real = wanted.slice(0, at);
    const range = wanted.slice(at + 1);
    return validName('npm', real) && npmRange(range, manager) !== null ? spec('npm', real, npmKeyRange(manager, range)) : undefined;
  }
  if (isAlias && wanted.indexOf('@', 1) > 0) return undefined;
  return npmRange(wanted, manager) === null ? undefined : spec('npm', name, npmKeyRange(manager, wanted));
}

/**
 * `"key": "patch:<source>#…"` as the packages a registry would serve: the key, once and with no range (bun 1.4 installs the key
 * and reads nothing after `patch:`), and the package of the source ({@link patchSource}), which Yarn 3 and 4 install. When the
 * source names the key itself the two are one entry: at the source's range for Yarn, the version it installs, and with none for
 * the others. A key that is no valid name leaves the source's package alone.
 */
function patchDependency(key: string, value: string, manager: string): PackageSpec[] {
  const source = patchSource(value, manager);
  if (!validName('npm', key)) return source === undefined ? [] : [source];
  const own = spec('npm', key, undefined);
  if (source === undefined) return [own];
  if (source.name === key) return [manager === 'yarn' ? source : own];
  return [own, source];
}

/**
 * A dependency entry as the packages a registry would serve: the key at the range of its value ({@link npmRange}); for
 * `npm:<rest>` the alias or the key the manager reads ({@link npmProtocolDependency}), and for `patch:` the key and the package of
 * its source ({@link patchDependency}). Empty when the value is no registry spec, or when the key is no valid name and the value
 * names no other package.
 */
function npmDependency(key: string, value: string, manager: string): PackageSpec[] {
  const wanted = value.trim();
  if (PATCH_PROTOCOL.test(wanted)) return patchDependency(key, wanted, manager);
  if (NPM_PROTOCOL.test(wanted)) return npmProtocolDependency(key, wanted.slice(4), manager);
  const range = npmRange(wanted, manager);
  return range !== null && validName('npm', key) ? [spec('npm', key, range)] : [];
}

/**
 * The dependencies the `package.json` of `dir` declares — `dependencies`,
 * `devDependencies`, `optionalDependencies` and `peerDependencies` — as the
 * packages a registry would serve. No other field of the file is used. A key is
 * always a name; a value is a registry spec unless `manager` (the command's; npm
 * when none) reads it as a file.
 */
export function readNpmManifest(dir: string, manager = 'npm'): ManifestRead {
  const file = 'package.json';
  const read = readManifestText(resolve(dir, file), dir);
  if (read.status === 'absent') return { file, status: 'absent', packages: [], names: [], registries: [] };
  if (read.status === 'unreadable') return { file, status: 'unreadable', packages: [], names: [], registries: [], reason: read.reason };
  let manifest: unknown;
  try {
    manifest = JSON.parse(read.text);
  } catch {
    return { file, status: 'unreadable', packages: [], names: [], registries: [], reason: REASON.notJson };
  }
  if (manifest === null || typeof manifest !== 'object' || Array.isArray(manifest)) {
    return { file, status: 'unreadable', packages: [], names: [], registries: [], reason: REASON.notManifest };
  }
  const packages: PackageSpec[] = [];
  const names = new Set<string>();
  const seen = new Set<string>();
  for (const section of NPM_SECTIONS) {
    const entries = (manifest as Record<string, unknown>)[section];
    if (entries === null || typeof entries !== 'object' || Array.isArray(entries)) continue;
    for (const [key, value] of Object.entries(entries as Record<string, unknown>)) {
      names.add(key);
      if (typeof value !== 'string') continue;
      for (const pkg of npmDependency(key, value, manager)) pushOnce(packages, seen, pkg);
    }
  }
  return { file, status: 'ok', packages, names: [...names], registries: [] };
}

// ───────────────────────────────────────────────────────────── requirements

/** One PEP 440 version specifier, comparator and all. Tested on at most 100 characters. */
const PEP440_SPECIFIER =
  /^(?:===|==|~=|!=|<=|>=|<|>)v?(?:\d+!)?\d+(?:\.\d+)*(?:[._-]?(?:a|b|c|rc|alpha|beta|pre|preview)[._-]?\d*)?(?:[._-]?(?:post|rev|r)[._-]?\d*)?(?:[._-]?dev[._-]?\d*)?(?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?(?:\.\*)?$/i;

function pypiRange(range: string): boolean {
  return range.length <= MAX_RANGE_LENGTH && range.split(',').every((one) => PEP440_SPECIFIER.test(one));
}

/** An option line's value: what follows the option, by a space or `=`, its quotes taken off. */
function optionValue(line: string, names: readonly string[]): string | undefined {
  for (const name of names) {
    if (!line.startsWith(name)) continue;
    const rest = line.slice(name.length);
    // `-rother.txt` and `-r other.txt`; a long option needs its separator (`--requirement-x` is another option).
    const attached = !name.startsWith('--') && rest !== '' && !/^[\s=]/.test(rest);
    const m = attached ? [rest, rest] : /^(?:\s+|=)(.+)$/.exec(rest);
    if (m === null) continue;
    const value = (m[1] ?? '').trim().replace(/^(['"])(.*)\1$/, '$2');
    if (value !== '') return value;
  }
  return undefined;
}

/** The reasons `parsePackageSpec` gives for a requirement the registry does not serve: a URL, a path, a VCS or an archive. */
const OTHER_SOURCE_REASONS = ['direct URL reference', 'local path', 'URL / VCS / protocol spec', 'SSH git spec', 'archive file'] as const;

/** What a requirement says (a line of a requirements file, or a string of an inline script block): the one reading of it. */
type RequirementReading =
  | { kind: 'package'; name: string; range: string | undefined; rangeUnread: boolean }
  | { kind: 'other-source' }
  | { kind: 'none' };

/**
 * A requirement as the registry would read it: its name, and its range when the hook reads that (`rangeUnread` otherwise, with no
 * `range`: the PEP 508 form in parentheses, a list over 100 characters, a `1.0-1`). A URL, a path or a VCS is another source; any
 * other string that gives no name (or one over 214 characters) is nothing. Each reader decides what to do with the three.
 */
function readRequirement(requirement: string, manager: string): RequirementReading {
  const parsed = parsePackageSpec('pypi', requirement, manager);
  if (!('name' in parsed)) return OTHER_SOURCE_REASONS.some((r) => parsed.reason.startsWith(r)) ? { kind: 'other-source' } : { kind: 'none' };
  if (parsed.name.length > MAX_NAME_LENGTH) return { kind: 'none' };
  const rangeUnread = parsed.range !== undefined && !pypiRange(parsed.range);
  return { kind: 'package', name: parsed.name, range: rangeUnread ? undefined : parsed.range, rangeUnread };
}

/** The lines of a requirements file as pip reads them: a `\` at the end of a line continues it, a `#` starts a comment. */
function requirementLines(text: string): string[] {
  const out: string[] = [];
  let pending = '';
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/(?:^|\s)#.*$/, '');
    if (line.endsWith('\\')) {
      pending += `${line.slice(0, -1)} `;
      continue;
    }
    const whole = (pending + line).trim();
    pending = '';
    if (whole !== '') out.push(whole);
  }
  const last = pending.trim();
  if (last !== '') out.push(last);
  return out;
}

interface RequirementsWalk {
  /** Files read or attempted so far, includes counted, over every `-r` of the command. */
  files: number;
  visited: Set<string>;
  /** The manager of the command: its list of archive endings reads a line as a file or as a name. */
  manager: string;
}

interface RequirementsFound {
  packages: PackageSpec[];
  registries: string[];
  seen: Set<string>;
  incomplete?: string;
}

/** Reads one requirements file into `found`, following its includes. Returns how the file itself read. */
function readRequirementFile(
  path: string,
  under: string,
  depth: number,
  walk: RequirementsWalk,
  found: RequirementsFound,
): { status: 'ok' } | { status: 'absent' } | { status: 'unreadable'; reason: string } {
  if (walk.files >= MAX_REQUIREMENT_FILES) return { status: 'unreadable', reason: REASON.tooMany };
  walk.files += 1;
  walk.visited.add(path);
  const read = readManifestText(path, under);
  if (read.status !== 'ok') return read;
  for (const line of requirementLines(read.text)) {
    if (line.startsWith('-')) {
      const include = optionValue(line, ['--requirement', '-r']);
      if (include !== undefined) {
        const next = resolve(dirname(path), include);
        if (walk.visited.has(next)) continue; // a cycle, or a file read already
        if (depth >= MAX_REQUIREMENT_DEPTH) {
          found.incomplete = found.incomplete ?? REASON.tooDeep;
          continue;
        }
        const included = isNetworkPath(include)
          ? ({ status: 'unreadable', reason: REASON.network } as const)
          : readRequirementFile(next, under, depth + 1, walk, found);
        // An include that is not there fails pip's own install: nothing to say. One that is there and was not read is said.
        if (included.status === 'unreadable') found.incomplete = found.incomplete ?? included.reason;
        continue;
      }
      const index = optionValue(line, ['--index-url', '--extra-index-url', '--find-links', '-i', '-f']);
      if (index !== undefined) found.registries.push(index);
      else if (/^--no-index(?:\s|$)/.test(line)) found.registries.push('--no-index');
      // Every other option line (`-c`, `-e`, `--trusted-host`, `--pre`, …) names no package a registry serves.
      continue;
    }
    // Per-requirement options (`--hash=…`, `--config-settings …`) follow the requirement.
    const requirement = line.replace(/\s+--[A-Za-z].*$/, '').trim();
    const reading = readRequirement(requirement, walk.manager);
    // What is no package, or has a range the hook does not read, is skipped: a file's line is vetted whole or not at all.
    if (reading.kind !== 'package' || reading.rangeUnread) continue;
    pushOnce(found.packages, found.seen, spec('pypi', reading.name, reading.range));
  }
  return { status: 'ok' };
}

/**
 * The packages each requirements file of `files` — the values of a command's
 * `-r`, relative to `dir` — names, with those of the files it includes (three
 * levels, eight files in all for the command). One answer per file given, in
 * order: an include's packages are its includer's.
 *
 * With a list of folders (the places a `..` after a link may mean) every file is read in
 * each folder, in the order of the list, one walk for the whole command (the eight files and
 * the three levels are the command's, not the folder's), and each answer says its folder.
 * `pastDeadline` is asked before each folder after the first: once it says yes, the files
 * of that folder are not opened and read `unreadable`, for the time budget.
 */
export function readRequirements(
  dir: string | readonly string[],
  files: readonly string[],
  manager = 'pip',
  pastDeadline: () => boolean = () => false,
): ManifestRead[] {
  const walk: RequirementsWalk = { files: 0, visited: new Set<string>(), manager };
  const folders = typeof dir === 'string' ? [dir] : dir;
  return folders.flatMap((folder, index) => {
    const late = index > 0 && pastDeadline();
    return files.map((given): ManifestRead => {
      const file = label(given);
      const where = typeof dir === 'string' ? {} : { dir: folder };
      const none = { file, packages: [], names: [], registries: [], ...where };
      if (late) return { ...none, status: 'unreadable', reason: REASON.deadline };
      if (isNetworkPath(given)) return { ...none, status: 'unreadable', reason: REASON.network };
      const found: RequirementsFound = { packages: [], registries: [], seen: new Set<string>() };
      const read = readRequirementFile(resolve(folder, given), folder, 0, walk, found);
      if (read.status === 'absent') return { ...none, status: 'absent' };
      if (read.status === 'unreadable') return { ...none, status: 'unreadable', reason: read.reason };
      const out: ManifestRead = { ...none, status: 'ok', packages: found.packages, names: found.packages.map((p) => p.name), registries: found.registries };
      if (found.incomplete !== undefined) out.incomplete = found.incomplete;
      return out;
    });
  });
}

// ───────────────────────────────────────────────────── inline script metadata (PEP 723)

/** The answer of {@link inlineScriptBlock}: the packages the `script` blocks of a text name, or why a block was not read. */
type InlineBlockRead =
  | { status: 'ok'; packages: PackageSpec[]; toolUv?: true; otherSource?: true; incomplete?: string }
  | { status: 'unreadable'; reason: string };

/** A cursor over the text of a block: one character at a time, never backwards past a decision. */
interface Lex {
  s: string;
  p: number;
}

const isBlank = (c: string | undefined): boolean => c === ' ' || c === '\t';
const isBareKeyChar = (c: string): boolean => {
  const n = c.charCodeAt(0);
  return (n >= 48 && n <= 57) || (n >= 65 && n <= 90) || (n >= 97 && n <= 122) || c === '_' || c === '-';
};
/** The characters of a bare scalar (a number, `true`, a date) of a key the reader ignores. */
const isBareValueChar = (c: string): boolean => isBareKeyChar(c) || c === '.' || c === ':' || c === '+';
const HEX = '0123456789abcdefABCDEF';
const SIMPLE_ESCAPES: Readonly<Record<string, string>> = { b: '\b', t: '\t', n: '\n', f: '\f', r: '\r', '"': '"', '\\': '\\' };

function skipToLineEnd(x: Lex): void {
  while (x.p < x.s.length && x.s[x.p] !== '\n') x.p += 1;
}

function skipBlanks(x: Lex): void {
  while (isBlank(x.s[x.p])) x.p += 1;
}

/** Whitespace, comments and line breaks: what may stand between the elements of an array. */
function skipBlankLines(x: Lex): void {
  for (;;) {
    const c = x.s[x.p];
    if (isBlank(c) || c === '\n') x.p += 1;
    else if (c === '#') skipToLineEnd(x);
    else return;
  }
}

/** Whether the rest of the line is empty or a comment (and moves to its end). */
function endsLine(x: Lex): boolean {
  skipBlanks(x);
  const c = x.s[x.p];
  if (c === undefined || c === '\n') return true;
  if (c !== '#') return false;
  skipToLineEnd(x);
  return true;
}

/** `digits` hexadecimal characters at the cursor, as the character they encode; `undefined` when they are not that or not a scalar value. */
function readCodePoint(x: Lex, digits: number): string | undefined {
  let code = 0;
  for (let i = 0; i < digits; i += 1) {
    const c = x.s[x.p];
    if (c === undefined || !HEX.includes(c)) return undefined;
    code = code * 16 + Number.parseInt(c, 16);
    x.p += 1;
  }
  return code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff) ? undefined : String.fromCodePoint(code);
}

/**
 * A one-line TOML string at the cursor, decoded: basic (`"…"`, with the escapes TOML has) or literal (`'…'`). A string of several
 * lines (`"""`), another escape, a control character other than a tab, or an end of line before the closing quote is `undefined`.
 * One pass, one step per character: a string that never closes costs what it is long, and nothing backtracks.
 */
function readString(x: Lex): string | undefined {
  const quote = x.s[x.p];
  if (x.s[x.p + 1] === quote && x.s[x.p + 2] === quote) return undefined;
  x.p += 1;
  let out = '';
  for (;;) {
    const c = x.s[x.p];
    if (c === undefined || c === '\n') return undefined;
    x.p += 1;
    if (c === quote) return out;
    const code = c.charCodeAt(0);
    if ((code < 0x20 && c !== '\t') || code === 0x7f) return undefined;
    if (quote === "'" || c !== '\\') {
      out += c;
      continue;
    }
    const e = x.s[x.p];
    if (e === undefined) return undefined;
    x.p += 1;
    const decoded = e === 'u' ? readCodePoint(x, 4) : e === 'U' ? readCodePoint(x, 8) : SIMPLE_ESCAPES[e];
    if (decoded === undefined) return undefined;
    out += decoded;
  }
}

/** A key — bare, quoted or dotted, with blanks around the dots — as its decoded parts; `undefined` when it is none. */
function readKey(x: Lex): string[] | undefined {
  const parts: string[] = [];
  for (;;) {
    skipBlanks(x);
    const c = x.s[x.p];
    if (c === undefined) return undefined;
    let part: string | undefined;
    if (c === '"' || c === "'") part = readString(x);
    else {
      const start = x.p;
      while (x.p < x.s.length && isBareKeyChar(x.s[x.p] ?? ' ')) x.p += 1;
      part = x.p > start ? x.s.slice(start, x.p) : undefined;
    }
    if (part === undefined) return undefined;
    parts.push(part);
    skipBlanks(x);
    if (x.s[x.p] !== '.') return parts;
    x.p += 1;
  }
}

/** The one-line scalar value of a key the reader ignores: a string, or a bare word. */
function skipScalar(x: Lex): boolean {
  const c = x.s[x.p];
  if (c === '"' || c === "'") return readString(x) !== undefined;
  const start = x.p;
  while (x.p < x.s.length && isBareValueChar(x.s[x.p] ?? ' ')) x.p += 1;
  return x.p > start;
}

/** `[ "a", 'b', ]` over one line or several, comments and blank lines between: the strings; `undefined` for anything else in it. */
function readStringList(x: Lex): string[] | undefined {
  if (x.s[x.p] !== '[') return undefined;
  x.p += 1;
  const out: string[] = [];
  for (;;) {
    skipBlankLines(x);
    const c = x.s[x.p];
    if (c === ']') {
      x.p += 1;
      return out;
    }
    if (c !== '"' && c !== "'") return undefined;
    const item = readString(x);
    if (item === undefined) return undefined;
    out.push(item);
    skipBlankLines(x);
    const next = x.s[x.p];
    if (next === ',') x.p += 1;
    else if (next !== ']') return undefined;
  }
}

/** A `[header]` or `[[header]]` at the cursor: its decoded key; `undefined` when it is not well formed. */
function readHeader(x: Lex): string[] | undefined {
  x.p += 1;
  const double = x.s[x.p] === '[';
  if (double) x.p += 1;
  const key = readKey(x);
  if (key === undefined) return undefined;
  skipBlanks(x);
  if (x.s[x.p] !== ']') return undefined;
  x.p += 1;
  if (double) {
    if (x.s[x.p] !== ']') return undefined;
    x.p += 1;
  }
  return endsLine(x) ? key : undefined;
}

interface TomlBlock {
  dependencies: string[];
  toolUv: boolean;
}

/**
 * The TOML of a block, as far as the reader goes (bug.md → "O leitor do bloco"): above the first header one statement a line —
 * `dependencies = [ … ]` once, `requires-python = <string>`, any other key with a one-line scalar — and from the first header on
 * only the headers. `undefined` is "not in the form the hook reads".
 */
function readToml(content: string): TomlBlock | undefined {
  const x: Lex = { s: content, p: 0 };
  let dependencies: string[] | undefined;
  let toolUv = false;
  let inTables = false;
  while (x.p < x.s.length) {
    skipBlanks(x);
    const c = x.s[x.p];
    if (c === undefined) break;
    if (c === '\n') {
      x.p += 1;
      continue;
    }
    if (c === '#') {
      skipToLineEnd(x);
      continue;
    }
    if (c === '[') {
      const header = readHeader(x);
      if (header === undefined || header[0] === 'dependencies' || header[0] === 'requires-python') return undefined;
      if (header[0] === 'tool' && (header.length === 1 || header[1] === 'uv')) toolUv = true;
      inTables = true;
      continue;
    }
    if (inTables) {
      skipToLineEnd(x);
      continue;
    }
    const key = readKey(x);
    if (key === undefined) return undefined;
    skipBlanks(x);
    if (x.s[x.p] !== '=') return undefined;
    x.p += 1;
    skipBlanks(x);
    if (key.length === 1 && key[0] === 'dependencies') {
      if (dependencies !== undefined) return undefined;
      dependencies = readStringList(x);
      if (dependencies === undefined || !endsLine(x)) return undefined;
      continue;
    }
    if (key[0] === 'tool' && key[1] === 'uv') toolUv = true;
    if (!skipScalar(x) || !endsLine(x)) return undefined;
  }
  return { dependencies: dependencies ?? [], toolUv };
}

const isOpening = (line: string): boolean => line.startsWith('# /// script') && line.slice('# /// script'.length).trim() === '' && !line.slice('# /// script'.length).includes('\r');
const isContent = (line: string): boolean => line === '#' || line.startsWith('# ');
/** The closing line: `# ///`, blanks and tabs at the end allowed. */
const isClosing = (line: string): boolean => line.startsWith('# ///') && line.slice('# ///'.length).trim() === '' && !line.slice('# ///'.length).includes('\r');

/** The lines of a text split at `\n` alone, a `\r` before it taken off (CRLF): how the uv reads a file. */
function linesAtLineFeed(text: string): string[] {
  return text.split('\n').map((line) => (line.endsWith('\r') ? line.slice(0, -1) : line));
}

/** The lines of a text split at `\r\n`, `\r` and `\n`: how the pipx with the `pip` engine reads a file. */
function linesAtAnyBreak(text: string): string[] {
  const out: string[] = [];
  let start = 0;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (c !== '\r' && c !== '\n') continue;
    out.push(text.slice(start, i));
    if (c === '\r' && text[i + 1] === '\n') i += 1;
    start = i + 1;
  }
  out.push(text.slice(start));
  return out;
}

/** Whether a `\r` stands in the text that no `\n` follows: the two ways of splitting lines then differ. */
function hasLoneCarriageReturn(text: string): boolean {
  for (let i = text.indexOf('\r'); i >= 0; i = text.indexOf('\r', i + 1)) if (text[i + 1] !== '\n') return true;
  return false;
}

/** The `script` blocks of one split of the lines, read; each line is visited a bounded number of times. */
function readBlocksOf(lines: readonly string[], manager: string): InlineBlockRead {
  const packages: PackageSpec[] = [];
  const seen = new Set<string>();
  let toolUv = false;
  let otherSource = false;
  let i = 0;
  while (i < lines.length) {
    if (!isOpening(lines[i] ?? '')) {
      i += 1;
      continue;
    }
    // The content is the run of `#` lines after the opening; the block closes at the LAST `# ///` of that run (PEP 723).
    let end = i + 1;
    let closing = -1;
    while (end < lines.length && isContent(lines[end] ?? '')) {
      if (isClosing(lines[end] ?? '')) closing = end;
      end += 1;
    }
    if (closing < 0) {
      // A block that never closes is no block, and a run with no closing has none inside it either: go past the run.
      i = end;
      continue;
    }
    const content = lines
      .slice(i + 1, closing)
      .map((line) => line.slice(2))
      .join('\n');
    const toml = readToml(content);
    if (toml === undefined) return { status: 'unreadable', reason: REASON.notInForm };
    if (toml.toolUv) toolUv = true;
    for (const requirement of toml.dependencies) {
      const reading = readRequirement(requirement, manager);
      if (reading.kind === 'none') return { status: 'unreadable', reason: REASON.notInForm };
      if (reading.kind === 'other-source') otherSource = true;
      // A name whose range the hook does not read is vetted by the name alone: the uv installs it all the same.
      else pushOnce(packages, seen, spec('pypi', reading.name, reading.range));
    }
    i = closing + 1;
  }
  const out: InlineBlockRead = { status: 'ok', packages };
  if (toolUv) out.toolUv = true;
  if (otherSource) out.otherSource = true;
  return out;
}

/**
 * The packages the `# /// script` blocks of a Python file name (PEP 723). With a `\r` that no `\n` follows the text is read twice —
 * split at `\n` alone (the uv) and at any line break (the pipx with the `pip` engine) — and the answer is the union: a reading that
 * fails beside one that works leaves `incomplete`, which asks like a block that is not read, and a refusal still wins.
 */
export function inlineScriptBlock(text: string, manager = 'uv'): InlineBlockRead {
  const clean = text.startsWith('﻿') ? text.slice(1) : text;
  const first = readBlocksOf(linesAtLineFeed(clean), manager);
  if (!hasLoneCarriageReturn(clean)) return first;
  const second = readBlocksOf(linesAtAnyBreak(clean), manager);
  if (first.status === 'unreadable') return second.status === 'unreadable' ? first : { ...second, incomplete: first.reason };
  if (second.status === 'unreadable') return { ...first, incomplete: second.reason };
  const packages: PackageSpec[] = [];
  const seen = new Set<string>();
  for (const pkg of [...first.packages, ...second.packages]) pushOnce(packages, seen, pkg);
  const out: InlineBlockRead = { status: 'ok', packages };
  if (first.toolUv === true || second.toolUv === true) out.toolUv = true;
  if (first.otherSource === true || second.otherSource === true) out.otherSource = true;
  return out;
}

/**
 * The packages the inline script metadata of `file` — relative to `dir`, the directory the uv or the pipx looks for it in — names,
 * read through the same reader as a manifest (`under` bounds the links walked). Absent when there is no file; a block that is not
 * there or never closes is `ok` with no package.
 */
export function readInlineScript(dir: string, file: string, manager: string, under: string): ManifestRead {
  const shown = label(file);
  const none = { file: shown, packages: [], names: [], registries: [] };
  if (isNetworkPath(file)) return { ...none, status: 'unreadable', reason: REASON.network };
  const read = readManifestText(resolve(dir, file), under);
  if (read.status === 'absent') return { ...none, status: 'absent' };
  if (read.status === 'unreadable') return { ...none, status: 'unreadable', reason: read.reason };
  const block = inlineScriptBlock(read.text, manager);
  if (block.status === 'unreadable') return { ...none, status: 'unreadable', reason: block.reason };
  const out: ManifestRead = { file: shown, status: 'ok', packages: block.packages, names: block.packages.map((p) => p.name), registries: [] };
  if (block.incomplete !== undefined) out.incomplete = block.incomplete;
  if (block.toolUv === true) out.toolUv = true;
  if (block.otherSource === true) out.otherSource = true;
  return out;
}
