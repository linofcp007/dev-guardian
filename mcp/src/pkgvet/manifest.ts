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
  /** The registries / indexes the file itself names (a requirements file's `--index-url` and the like). */
  registries: string[];
  /** With `unreadable`: why, one of {@link MANIFEST_UNREADABLE_REASONS}. */
  reason?: string;
  /** With `ok`: a file this one includes was not read, and why — its packages are not in `packages`. */
  incomplete?: string;
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
function label(file: string): string {
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
    const parsed = parsePackageSpec('pypi', requirement, walk.manager);
    if (!('name' in parsed) || parsed.name.length > MAX_NAME_LENGTH) continue;
    if (parsed.range !== undefined && !pypiRange(parsed.range)) continue;
    pushOnce(found.packages, found.seen, spec('pypi', parsed.name, parsed.range));
  }
  return { status: 'ok' };
}

/**
 * The packages each requirements file of `files` — the values of a command's
 * `-r`, relative to `dir` — names, with those of the files it includes (three
 * levels, eight files in all for the command). One answer per file given, in
 * order: an include's packages are its includer's.
 */
export function readRequirements(dir: string, files: readonly string[], manager = 'pip'): ManifestRead[] {
  const walk: RequirementsWalk = { files: 0, visited: new Set<string>(), manager };
  return files.map((given): ManifestRead => {
    const file = label(given);
    if (isNetworkPath(given)) return { file, status: 'unreadable', packages: [], names: [], registries: [], reason: REASON.network };
    const found: RequirementsFound = { packages: [], registries: [], seen: new Set<string>() };
    const read = readRequirementFile(resolve(dir, given), dir, 0, walk, found);
    if (read.status === 'absent') return { file, status: 'absent', packages: [], names: [], registries: [] };
    if (read.status === 'unreadable') return { file, status: 'unreadable', packages: [], names: [], registries: [], reason: read.reason };
    const out: ManifestRead = { file, status: 'ok', packages: found.packages, names: found.packages.map((p) => p.name), registries: found.registries };
    if (found.incomplete !== undefined) out.incomplete = found.incomplete;
    return out;
  });
}
