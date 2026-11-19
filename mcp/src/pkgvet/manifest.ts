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
import { isSemverRange, npmProtocolReading, parsePackageSpec, readsFileValue } from './parseCommand.js';
import type { PackageSpec, PkgEcosystem } from './types.js';

type ManifestStatus = 'ok' | 'absent' | 'unreadable';

export interface ManifestRead {
  /** The file as the command names it — `package.json`, `reqs/dev.txt` — for the message. */
  file: string;
  status: ManifestStatus;
  /** The packages a registry would serve, each once, in the order of the file. */
  packages: PackageSpec[];
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
const MAX_RANGE_LENGTH = 100;
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
 * What a dependency's value asks the registry for: `undefined` for "the
 * default" (an empty value, `latest`), the range or tag, or `null` when the
 * value is no registry spec at all — a path, `file:`, `link:`, `workspace:`,
 * `catalog:`, a URL, a git repository, `user/repo`, an archive, or text.
 */
function npmRange(value: string, manager: string): string | undefined | null {
  const v = value.trim();
  if (v === '' || v === 'latest') return undefined;
  if (v.length > MAX_RANGE_LENGTH || readsFileValue(manager, v)) return null;
  if (DIST_TAG.test(v)) return v;
  return isSemverRange(v) ? v : null;
}

/**
 * A dependency entry as the packages a registry would serve: `"x": "npm:real@^1"` is `real` (an alias); for Yarn and bun
 * `"x": "npm:^1"` is `x` and `"x": "npm:1.0.0"` is both `x` and `1.0.0` ({@link npmProtocolReading}, the command line's own
 * rule). Empty when the value is no registry spec.
 */
function npmDependency(key: string, value: string, manager: string): PackageSpec[] {
  let name = key;
  let wanted = value.trim();
  let second: string | undefined;
  if (/^npm:/i.test(wanted)) {
    const real = wanted.slice(4);
    const reading = npmProtocolReading(manager, real);
    if (reading === 'alias') {
      const at = real.indexOf('@', real.startsWith('@') ? 1 : 0);
      name = at > 0 ? real.slice(0, at) : real;
      wanted = at > 0 ? real.slice(at + 1) : '';
    } else if (reading === 'both') {
      second = real;
      // The key is asked at that version or range; a word (a tag, a name) leaves it with none.
      wanted = isSemverRange(real) ? real : '';
    } else {
      // The key is the package and the rest its range; a rest that is no range still leaves the key vetted.
      wanted = npmRange(real, manager) === null ? '' : real;
    }
  }
  if (!validName('npm', name)) return [];
  const range = npmRange(wanted, manager);
  if (range === null) return [];
  const own = spec('npm', name, range);
  return second !== undefined && validName('npm', second) ? [own, spec('npm', second, undefined)] : [own];
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
  if (read.status === 'absent') return { file, status: 'absent', packages: [], registries: [] };
  if (read.status === 'unreadable') return { file, status: 'unreadable', packages: [], registries: [], reason: read.reason };
  let manifest: unknown;
  try {
    manifest = JSON.parse(read.text);
  } catch {
    return { file, status: 'unreadable', packages: [], registries: [], reason: REASON.notJson };
  }
  if (manifest === null || typeof manifest !== 'object' || Array.isArray(manifest)) {
    return { file, status: 'unreadable', packages: [], registries: [], reason: REASON.notManifest };
  }
  const packages: PackageSpec[] = [];
  const seen = new Set<string>();
  for (const section of NPM_SECTIONS) {
    const entries = (manifest as Record<string, unknown>)[section];
    if (entries === null || typeof entries !== 'object' || Array.isArray(entries)) continue;
    for (const [key, value] of Object.entries(entries as Record<string, unknown>)) {
      if (typeof value !== 'string') continue;
      for (const pkg of npmDependency(key, value, manager)) pushOnce(packages, seen, pkg);
    }
  }
  return { file, status: 'ok', packages, registries: [] };
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
    if (isNetworkPath(given)) return { file, status: 'unreadable', packages: [], registries: [], reason: REASON.network };
    const found: RequirementsFound = { packages: [], registries: [], seen: new Set<string>() };
    const read = readRequirementFile(resolve(dir, given), dir, 0, walk, found);
    if (read.status === 'absent') return { file, status: 'absent', packages: [], registries: [] };
    if (read.status === 'unreadable') return { file, status: 'unreadable', packages: [], registries: [], reason: read.reason };
    const out: ManifestRead = { file, status: 'ok', packages: found.packages, registries: found.registries };
    if (found.incomplete !== undefined) out.incomplete = found.incomplete;
    return out;
  });
}
