/**
 * Strict readers of the four lockfiles an npm-family manifest install is
 * driven by (`package-lock.json` / `npm-shrinkwrap.json`, `pnpm-lock.yaml`,
 * `yarn.lock`, `bun.lock`): text in, and out the entries the manager would
 * install — each with its name@version pair, where it is fetched from and,
 * when its URL names another package, that pair too.
 *
 * Pure: no file, no network. It is bundled into the hooks, which have no
 * dependencies, so the three line-based formats are read by hand (no YAML
 * library) — and that is why the readers are STRICT. A reader that returns
 * fewer pairs than the manager installs, and says nothing, is a malicious
 * version installed with the hook silent. So the rule in every format is:
 *
 *   - the lines that open an entry (its key) must ALL be recognised, in the
 *     form the manager writes; one that is not (a flow mapping, an anchor, a
 *     tab, another indentation) is counted in `unrecognised`, never skipped;
 *   - the lines INSIDE an entry are skipped, except the few the reader uses
 *     (`resolution`, `version`, `resolved`, …);
 *   - a file whose frame is not its format's (or whose format version is not
 *     one of those read) is `{ unread }`, with a reason in this file's words —
 *     never a piece of the file, which the hook repeats to the model.
 *
 * Hostile input: every regular expression here is anchored and runs on a
 * string of bounded length or without nested quantifiers; a line over
 * {@link MAX_LINE} characters is counted as not recognised without being
 * parsed; every pass over the text is linear in its size.
 */

import { parseJsonBounded } from '../platform/boundedJson.js';
import { isExactVersion, resolveVersion } from './versions.js';

export type LockFormat = 'package-lock' | 'pnpm-lock' | 'yarn-lock' | 'bun-lock';

/** A validated pair: a name the registry would accept and one exact version. */
export interface Pin {
  name: string;
  version: string;
}

export type Source =
  /** An explicit https URL of the public npm registry. */
  | { kind: 'public' }
  /** The format gives no URL: the manager asks the registry its own configuration names. */
  | { kind: 'unstated' }
  /** Any other http(s) URL. `url` stays in the process (it is compared with the user's registries); only `host` may leave it, and `''` when it is no DNS name of at most 80 characters. */
  | { kind: 'elsewhere'; host: string; url: string }
  /** A git repository, or another scheme: what is installed is not a registry version. */
  | { kind: 'git'; host: string };

export interface LockEntry {
  /** Absent when the entry has no valid name@version of its own (an entry that is only a URL). */
  pin?: Pin;
  source: Source;
  /** The pair a registry-shaped URL names, when it differs from `pin`. */
  fetched?: Pin;
}

export interface LockRead {
  format: LockFormat;
  /** In file order; entries equal in pin, source and fetched come out once. */
  entries: LockEntry[];
  /** Path, `link:`, `workspace:`, `file:`, `patch:`, `portal:` — the project's own code: never sent, never said. */
  local: number;
  /** Outside the form the manager writes, or with an invalid name or version: said. */
  unrecognised: number;
  /**
   * The version the lockfile pins for dependency `name` of the project in `rel` (the command's directory relative to
   * the lockfile's), when it records `range` letter for letter and the pinned version satisfies it; `null` otherwise.
   */
  resolutionOf(rel: string, name: string, range: string): string | null;
}

/** The manager's files, in the order it uses them. */
export const LOCKFILES: Record<'npm' | 'pnpm' | 'yarn' | 'bun', readonly string[]> = {
  npm: ['npm-shrinkwrap.json', 'package-lock.json'],
  pnpm: ['pnpm-lock.yaml'],
  yarn: ['yarn.lock'],
  bun: ['bun.lock'],
};

/** The format of a lockfile by its file name; `bun.lockb` (binary) has none. */
export function lockFormat(fileName: string): LockFormat | null {
  switch (fileName) {
    case 'package-lock.json':
    case 'npm-shrinkwrap.json':
      return 'package-lock';
    case 'pnpm-lock.yaml':
      return 'pnpm-lock';
    case 'yarn.lock':
      return 'yarn-lock';
    case 'bun.lock':
      return 'bun-lock';
    default:
      return null;
  }
}

/** The pairs to ask OSV about: the distinct pins of public, unstated and other-host entries (never git), plus each URL's own pair. */
export function askable(read: LockRead): Pin[] {
  const seen = new Set<string>();
  const out: Pin[] = [];
  for (const entry of read.entries) {
    if (entry.source.kind === 'git') continue;
    for (const pin of [entry.pin, entry.fetched]) {
      if (pin === undefined) continue;
      const key = `${pin.name}@${pin.version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(pin);
    }
  }
  return out;
}

/** `text` read as the lockfile of `format`; `{ unread }` (the reader's own words) when its frame is not that format's. */
export function readLock(format: LockFormat, text: string): LockRead | { unread: string } {
  switch (format) {
    case 'package-lock':
      return readPackageLock(text);
    case 'pnpm-lock':
      return readPnpm(text);
    case 'yarn-lock':
      return readYarn(text);
    case 'bun-lock':
      return readBun(text);
  }
}

// ───────────────────────────────────────────────────────── names, versions, hosts

/** The longest line a reader looks into (the longest of 17 real lockfiles is 4 196). */
const MAX_LINE = 65_536;
const MAX_NAME = 214;
const MAX_VERSION = 256;
/** The longest host the hook repeats. */
const MAX_HOST = 80;
const PUBLIC_HOSTS: ReadonlySet<string> = new Set(['registry.npmjs.org', 'registry.npmjs.com', 'registry.yarnpkg.com']);

/**
 * The registry's rule for a package name, old capitalised names included
 * (`JSONStream`). Not `manifest.ts#validName`: that reads a command-line word
 * and refuses a real name that ends like an archive (`lodash.zip`); here the
 * name comes out of a key, not out of a word.
 */
const NAME = /^(?:@[A-Za-z0-9~-][A-Za-z0-9._~-]*\/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function validName(name: string): boolean {
  return name.length <= MAX_NAME && NAME.test(name);
}

function validVersion(version: string): boolean {
  return version.length <= MAX_VERSION && VERSION.test(version) && isExactVersion('npm', version);
}

/** The pair, or `undefined` when the name or the version is not one the registry holds: nothing else of a lockfile may leave the reader. */
function makePin(name: string, version: string): Pin | undefined {
  return validName(name) && validVersion(version) ? { name, version } : undefined;
}

/** `host` when it is a DNS name of at most {@link MAX_HOST} characters, else `''` (an IPv6 literal, a name too long). */
function dnsName(host: string): string {
  const lower = host.toLowerCase();
  if (lower.length === 0 || lower.length > MAX_HOST) return '';
  for (const label of lower.split('.')) if (!DNS_LABEL.test(label)) return '';
  return lower;
}

/** Whether `range` is satisfied by the one version `version`, the way the manager checks a lockfile before it accepts it. */
function satisfies(range: string, version: string): boolean {
  try {
    return resolveVersion('npm', range, { versions: [version] }) === version;
  } catch {
    return false;
  }
}

const has = (o: object, key: string): boolean => Object.prototype.hasOwnProperty.call(o, key);
const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
/** `line` without the `\r` of a `\r\n` line end. */
const noCr = (line: string): string => (line.endsWith('\r') ? line.slice(0, -1) : line);
/** `s` without one pair of matching quotes. */
function unquote(s: string): string {
  if (s.length >= 2 && (s.startsWith("'") || s.startsWith('"')) && s.endsWith(s.charAt(0))) return s.slice(1, -1);
  return s;
}

// ───────────────────────────────────────────────────────── where an entry is fetched from

/** Where an entry comes from, and the pair its URL names. */
interface Located {
  source: Source;
  /** The pair a URL of the shape of a registry archive names (`…/<name>/-/<name>-<version>.tgz`). */
  named: Pin | undefined;
}

const LOCAL_SPEC = /^(?:file:|link:|workspace:|portal:|patch:)/;
const GIT_SPEC = /^(?:git\+|git:|git@|github:|gitlab:|bitbucket:|gist:|ssh:)/;
/** White space and control characters: the URL parser would drop or escape them, and no real lockfile holds one. */
const UNSAFE_URL = /[\u0000-\u0020\u007f-\u009f\u2028\u2029]/;
/** Where an entry whose URL cannot be read comes from: another source, said without a host. */
const UNKNOWN_ELSEWHERE: Located = { source: { kind: 'elsewhere', host: '', url: '' }, named: undefined };

function gitHost(spec: string): string {
  if (spec.startsWith('github:')) return 'github.com';
  if (spec.startsWith('gitlab:')) return 'gitlab.com';
  if (spec.startsWith('bitbucket:')) return 'bitbucket.org';
  if (spec.startsWith('gist:')) return 'gist.github.com';
  if (spec.startsWith('git@')) {
    const colon = spec.indexOf(':');
    return dnsName(spec.slice(4, colon < 0 ? undefined : colon));
  }
  try {
    return dnsName(new URL(spec.startsWith('git+') ? spec.slice(4) : spec).hostname);
  } catch {
    return '';
  }
}

/** The pair a URL path of the shape `/<name>/-/<name>-<version>.tgz` names (`@scope/name` or `@scope%2fname`), by string operations. */
function archivePair(pathname: string): Pin | undefined {
  if (!pathname.endsWith('.tgz')) return undefined;
  const cut = pathname.lastIndexOf('/-/');
  if (cut < 0) return undefined;
  const file = pathname.slice(cut + 3, -4);
  if (file.includes('/')) return undefined;
  const before = pathname.slice(0, cut);
  const lastSlash = before.lastIndexOf('/');
  let name = before.slice(lastSlash + 1).replace(/%2f/gi, '/');
  if (lastSlash > 0) {
    const scopeStart = before.lastIndexOf('/', lastSlash - 1);
    const scope = before.slice(scopeStart + 1, lastSlash);
    if (scope.startsWith('@') && !name.startsWith('@')) name = `${scope}/${name}`;
  }
  const bare = name.slice(name.lastIndexOf('/') + 1);
  if (!file.startsWith(`${bare}-`)) return undefined;
  return makePin(name, file.slice(bare.length + 1));
}

/**
 * The origin of a `resolved`, `tarball:`, registry element or version spec. `'local'` is the project's own code
 * (a path, `link:`, `workspace:`, …); `'bad'` a string no URL parser should be given.
 */
function locate(spec: string): Located | 'local' | 'bad' {
  if (spec.length === 0 || spec.length > MAX_LINE) return 'bad';
  if (LOCAL_SPEC.test(spec) || spec.startsWith('/') || spec.startsWith('./') || spec.startsWith('../')) return 'local';
  if (UNSAFE_URL.test(spec)) return 'bad';
  if (GIT_SPEC.test(spec)) return { source: { kind: 'git', host: gitHost(spec) }, named: undefined };
  let url: URL;
  try {
    url = new URL(spec);
  } catch {
    return 'bad';
  }
  const host = dnsName(url.hostname);
  const web = url.protocol === 'https:' || url.protocol === 'http:';
  if (!web || url.hostname === 'codeload.github.com' || url.pathname.endsWith('.git')) return { source: { kind: 'git', host }, named: undefined };
  // The public registry is an https URL of one of its hosts, no credentials, the default port: `https://registry.npmjs.org:x@evil.example/…` is evil.example.
  const isPublic = url.protocol === 'https:' && PUBLIC_HOSTS.has(url.hostname) && url.username === '' && url.password === '' && url.port === '';
  return { source: isPublic ? { kind: 'public' } : { kind: 'elsewhere', host, url: spec }, named: archivePair(url.pathname) };
}

// ───────────────────────────────────────────────────────── what a reader accumulates

interface Acc {
  entries: LockEntry[];
  seen: Set<string>;
  local: number;
  unrecognised: number;
}

const newAcc = (): Acc => ({ entries: [], seen: new Set(), local: 0, unrecognised: 0 });

function sourceKey(source: Source): string {
  switch (source.kind) {
    case 'elsewhere':
      return `elsewhere\u0000${source.host}\u0000${source.url}`;
    case 'git':
      return `git\u0000${source.host}`;
    default:
      return source.kind;
  }
}

/** One entry; equal in pin, source and fetched to one already read, it is not added again. */
function emit(acc: Acc, pin: Pin | undefined, located: Located | undefined): void {
  const source: Source = located === undefined ? { kind: 'unstated' } : located.source;
  // On the public registry an archive URL has the registry's shape; one that has not is not what the manager writes.
  if (source.kind === 'public' && located?.named === undefined) acc.unrecognised += 1;
  const named = located?.named;
  const fetched = named !== undefined && (pin === undefined || named.name !== pin.name || named.version !== pin.version) ? named : undefined;
  const key = `${pin === undefined ? '' : `${pin.name}@${pin.version}`}\u0000${sourceKey(source)}\u0000${fetched === undefined ? '' : `${fetched.name}@${fetched.version}`}`;
  if (acc.seen.has(key)) return;
  acc.seen.add(key);
  const entry: LockEntry = { source };
  if (pin !== undefined) entry.pin = pin;
  if (fetched !== undefined) entry.fetched = fetched;
  acc.entries.push(entry);
}

/** An entry whose origin is `spec` (`undefined`: the format states none); a local one is only counted, a URL no parser should read is counted as not recognised. */
function finish(acc: Acc, pin: Pin | undefined, spec: string | undefined): void {
  if (spec === undefined) {
    if (pin !== undefined) emit(acc, pin, undefined);
    return;
  }
  const where = locate(spec);
  if (where === 'local') {
    acc.local += 1;
  } else if (where === 'bad') {
    acc.unrecognised += 1;
    if (pin !== undefined) emit(acc, pin, UNKNOWN_ELSEWHERE);
  } else {
    emit(acc, pin, where);
  }
}

// ───────────────────────────────────────────────────────── package-lock.json

const DEPENDENCY_GROUPS = ['dependencies', 'devDependencies', 'optionalDependencies'] as const;

function readPackageLock(text: string): LockRead | { unread: string } {
  const parsed = parseJsonBounded(text);
  if (!parsed.ok) return { unread: parsed.reason === 'invalid' ? 'it is not valid JSON' : 'it holds more JSON values than dev-guardian reads' };
  const doc = parsed.value;
  if (!isRecord(doc)) return { unread: 'it is not a JSON object' };
  const version = doc['lockfileVersion'];
  if (version === undefined) return { unread: 'it has no lockfileVersion' };
  if (version !== 1 && version !== 2 && version !== 3) return { unread: 'its lockfileVersion is not 1, 2 or 3' };
  const acc = newAcc();
  // npm picks the tree by what is there, not by the number: `packages` whenever the file has it, `dependencies` when it has not (and npm 6 installs from it).
  readPackagesTree(acc, doc['packages']);
  readDependenciesTree(acc, doc['dependencies']);
  return {
    format: 'package-lock',
    entries: acc.entries,
    local: acc.local,
    unrecognised: acc.unrecognised,
    resolutionOf: (rel, name, range) => npmResolution(doc, rel, name, range),
  };
}

function readPackagesTree(acc: Acc, packages: unknown): void {
  if (packages === undefined) return;
  if (!isRecord(packages)) {
    acc.unrecognised += 1;
    return;
  }
  for (const [path, entry] of Object.entries(packages)) {
    if (path === '') continue;
    if (!isRecord(entry)) {
      acc.unrecognised += 1;
      continue;
    }
    const cut = path.lastIndexOf('node_modules/');
    // A key outside node_modules is a workspace member, `link: true` a link to one: the project's own code.
    if (entry['link'] === true || cut < 0) {
      acc.local += 1;
      continue;
    }
    const alias = entry['name'];
    const version = entry['version'];
    const resolved = entry['resolved'];
    if ((alias !== undefined && typeof alias !== 'string') || (typeof resolved === 'string' && resolved.length > MAX_LINE)) {
      acc.unrecognised += 1;
      continue;
    }
    const pin = typeof version === 'string' ? makePin(alias ?? path.slice(cut + 'node_modules/'.length), version) : undefined;
    const where = typeof resolved === 'string' && resolved !== '' ? resolved : undefined;
    if (pin === undefined) {
      // A directory or a link written as a URL is still the project's own.
      if (where !== undefined && locate(where) === 'local') acc.local += 1;
      else acc.unrecognised += 1;
      continue;
    }
    finish(acc, pin, where);
  }
}

/** The `dependencies` tree, nested ones included, walked without recursion (a hostile file may nest as deep as it likes). */
function readDependenciesTree(acc: Acc, tree: unknown): void {
  if (tree === undefined) return;
  if (!isRecord(tree)) {
    acc.unrecognised += 1;
    return;
  }
  const stack: Array<Iterator<[string, unknown]>> = [Object.entries(tree)[Symbol.iterator]()];
  for (let top = stack[stack.length - 1]; top !== undefined; top = stack[stack.length - 1]) {
    const next = top.next();
    if (next.done === true) {
      stack.pop();
      continue;
    }
    const [name, entry] = next.value;
    if (!isRecord(entry)) {
      acc.unrecognised += 1;
      continue;
    }
    treeEntry(acc, name, entry);
    const nested = entry['dependencies'];
    if (nested === undefined) continue;
    if (isRecord(nested)) stack.push(Object.entries(nested)[Symbol.iterator]());
    else acc.unrecognised += 1;
  }
}

function treeEntry(acc: Acc, key: string, entry: Record<string, unknown>): void {
  const version = entry['version'];
  const resolved = entry['resolved'];
  if (typeof version !== 'string' || version.length > MAX_LINE || (typeof resolved === 'string' && resolved.length > MAX_LINE)) {
    acc.unrecognised += 1;
    return;
  }
  const where = typeof resolved === 'string' && resolved !== '' ? resolved : undefined;
  let name = key;
  let exact = version;
  if (version.startsWith('npm:')) {
    // An alias: the entry is the real package.
    const rest = version.slice('npm:'.length);
    const at = rest.lastIndexOf('@');
    if (at <= 0) {
      acc.unrecognised += 1;
      return;
    }
    name = rest.slice(0, at);
    exact = rest.slice(at + 1);
  } else if (!validVersion(version)) {
    // A `version` that is no version is where the entry comes from: a URL, a git repository, `file:`.
    finish(acc, undefined, version);
    return;
  }
  const pin = makePin(name, exact);
  if (pin === undefined) acc.unrecognised += 1;
  else finish(acc, pin, where);
}

/** The version of the nearest node_modules, from the project up, when the project records `range` for `name`. */
function npmResolution(doc: Record<string, unknown>, rel: string, name: string, range: string): string | null {
  const packages = doc['packages'];
  if (!validName(name) || !isRecord(packages) || !has(packages, rel)) return null;
  const project = packages[rel];
  if (!isRecord(project)) return null;
  const recorded = DEPENDENCY_GROUPS.some((g) => {
    const group = project[g];
    return isRecord(group) && has(group, name) && group[name] === range;
  });
  if (!recorded) return null;
  for (let dir = rel; ; dir = dir.slice(0, Math.max(dir.lastIndexOf('/'), 0))) {
    const key = `${dir === '' ? '' : `${dir}/`}node_modules/${name}`;
    if (has(packages, key)) {
      const entry = packages[key];
      const pinned = isRecord(entry) && entry['link'] !== true ? entry['version'] : undefined;
      return typeof pinned === 'string' && validVersion(pinned) && satisfies(range, pinned) ? pinned : null;
    }
    if (dir === '') return null;
  }
}

// ───────────────────────────────────────────────────────── pnpm-lock.yaml

const SECTION_NAME = /^[A-Za-z][A-Za-z0-9_-]*$/;
const PNPM_VERSION_LINE = /^lockfileVersion: ['"]?(\d+)(?:\.\d+)?['"]?$/;
/** A plain YAML key: one word that does not start like a flow, an anchor, an alias, a tag, an explicit key or a block scalar. */
const PLAIN_KEY = /^[^\s'":&*!|>{[?#,%@`-]\S*$/;

/** The frame of a pnpm-lock.yaml: a lockfileVersion of 5, 6 or 9, only `name:` lines at column 0, each of `packages:` and `snapshots:` at most once and alone on its line. */
function pnpmFrame(lines: readonly string[]): { major: number } | { unread: string } {
  let major = -1;
  let keys = 0;
  let packages = 0;
  let snapshots = 0;
  for (const raw of lines) {
    const line = noCr(raw);
    const first = line.charCodeAt(0);
    if (line.length === 0 || first === 32 || first === 9) continue;
    if (line.length > MAX_LINE) return { unread: 'a line at column 0 is longer than 65 536 characters' };
    if (first === 35 || (line === '---' && keys === 0)) continue;
    const colon = line.indexOf(':');
    const name = colon > 0 ? line.slice(0, colon) : '';
    if (!SECTION_NAME.test(name)) return { unread: 'a line at column 0 is not a `name:` section' };
    keys += 1;
    if (name === 'lockfileVersion') {
      const m = PNPM_VERSION_LINE.exec(line);
      if (m === null || major !== -1) return { unread: 'its lockfileVersion line is not in the form pnpm writes' };
      major = Number(m[1]);
    } else if (name === 'packages' || name === 'snapshots') {
      if (line.trimEnd() !== `${name}:`) return { unread: `its \`${name}:\` section has something on its own line` };
      if ((name === 'packages' ? (packages += 1) : (snapshots += 1)) > 1) return { unread: `it has more than one \`${name}:\` section` };
    }
  }
  if (major === -1) return { unread: 'it has no lockfileVersion line' };
  if (major !== 5 && major !== 6 && major !== 9) return { unread: 'its lockfileVersion is not 5, 6 or 9' };
  return { major };
}

/** The key of an entry line (the line without its two spaces): `key:`, `'key':`, `"key":`, and `key: {}`; `null` for any other form. */
function pnpmKeyOf(rest: string): string | null {
  let s = rest.trimEnd();
  if (s.endsWith(' {}')) s = s.slice(0, -3);
  if (!s.endsWith(':')) return null;
  s = s.slice(0, -1);
  if (s.length === 0) return null;
  const quote = s.charAt(0);
  if (quote === "'") return s.length > 2 && s.endsWith("'") && !s.slice(1, -1).includes("'") ? s.slice(1, -1) : null;
  if (quote === '"') return s.length > 2 && s.endsWith('"') && !/["\\]/.test(s.slice(1, -1)) ? s.slice(1, -1) : null;
  return PLAIN_KEY.test(s) ? s : null;
}

/** The pair a key names (`/name/1.0.0_peers` in 5, `/name@1.0.0(peers)` in 6, `name@1.0.0(peers)` in 9); `'other'` for a key that is no registry pair (a tarball, a commit, a directory). */
function pnpmKeyPair(key: string, v5: boolean): Pin | 'other' | 'invalid' {
  const bare = key.startsWith('/') ? key.slice(1) : key;
  let name: string;
  let rest: string;
  if (v5) {
    let slash = bare.indexOf('/');
    if (bare.startsWith('@') && slash >= 0) slash = bare.indexOf('/', slash + 1);
    if (slash < 0) return 'other';
    name = bare.slice(0, slash);
    rest = bare.slice(slash + 1);
  } else {
    const at = bare.indexOf('@', 1);
    if (at < 0) return 'other';
    name = bare.slice(0, at);
    rest = bare.slice(at + 1);
  }
  const suffix = rest.indexOf(v5 ? '_' : '(');
  const version = suffix < 0 ? rest : rest.slice(0, suffix);
  const digit = version.charCodeAt(0);
  if (!(digit >= 48 && digit <= 57)) return 'other';
  return makePin(name, version) ?? 'invalid';
}

interface PnpmResolution {
  tarball?: string;
  repo?: string;
  commit?: string;
  directory?: string;
}

/** The `resolution: {…}` line, or `undefined` when it is not in the form pnpm writes (a block, a comment after it). */
function parsePnpmResolution(body: string): PnpmResolution | undefined {
  const t = body.trimEnd();
  if (!t.startsWith('resolution: {') || !t.endsWith('}')) return undefined;
  const out: PnpmResolution = {};
  for (const field of t.slice('resolution: {'.length, -1).split(', ')) {
    const at = field.indexOf(': ');
    if (at < 0) continue;
    const value = unquote(field.slice(at + 2));
    switch (field.slice(0, at)) {
      case 'tarball':
        out.tarball ??= value;
        break;
      case 'repo':
        out.repo ??= value;
        break;
      case 'commit':
        out.commit ??= value;
        break;
      case 'directory':
        out.directory ??= value;
        break;
      default:
    }
  }
  return out;
}

interface PnpmEntry {
  section: 'packages' | 'snapshots';
  key: string;
  /** `'broken'`: a `resolution` line not in the form pnpm writes (already counted). */
  resolution?: PnpmResolution | 'broken';
  /** The `name:` and `version:` of an entry whose key is no `name@version`. */
  name?: string;
  version?: string;
}

function finishPnpmEntry(acc: Acc, v5: boolean, e: PnpmEntry): void {
  if (e.resolution === 'broken') return;
  if (e.section === 'packages' && e.resolution === undefined) {
    acc.unrecognised += 1;
    return;
  }
  const res = e.resolution;
  if (res?.directory !== undefined) {
    acc.local += 1;
    return;
  }
  const pair = pnpmKeyPair(e.key, v5);
  if (e.section === 'snapshots') {
    // A snapshot of a non-registry package has its `packages:` entry, which says where it comes from.
    if (pair === 'invalid') acc.unrecognised += 1;
    else if (pair !== 'other') finish(acc, pair, undefined);
    return;
  }
  const git: Located | undefined = res?.repo !== undefined || res?.commit !== undefined ? { source: { kind: 'git', host: gitHost(res.repo ?? '') }, named: undefined } : undefined;
  const pin = pair === 'other' ? (e.name !== undefined && e.version !== undefined ? makePin(e.name, e.version) : undefined) : pair === 'invalid' ? undefined : pair;
  if (pair === 'invalid') {
    acc.unrecognised += 1;
  } else if (res?.tarball !== undefined) {
    finish(acc, pin, res.tarball);
  } else if (git !== undefined) {
    emit(acc, pin, git);
  } else if (pair === 'other') {
    acc.unrecognised += 1;
  } else {
    finish(acc, pin, undefined);
  }
}

/** One line of an entry's body, at exactly four spaces: the few the reader uses. */
function readPnpmBody(acc: Acc, e: PnpmEntry, body: string): void {
  if (body.startsWith('resolution:')) {
    if (e.resolution !== undefined) {
      acc.unrecognised += 1;
      return;
    }
    const parsed = parsePnpmResolution(body);
    if (parsed === undefined) acc.unrecognised += 1;
    e.resolution = parsed ?? 'broken';
  } else if (body.startsWith('name: ')) {
    e.name ??= unquote(body.slice('name: '.length).trimEnd());
  } else if (body.startsWith('version: ')) {
    e.version ??= unquote(body.slice('version: '.length).trimEnd());
  }
}

function readPnpm(text: string): LockRead | { unread: string } {
  const lines = text.split('\n');
  const frame = pnpmFrame(lines);
  if ('unread' in frame) return frame;
  const v5 = frame.major === 5;
  const acc = newAcc();
  let section: 'packages' | 'snapshots' | '' = '';
  const state: { cur: PnpmEntry | 'skip' | null } = { cur: null };
  const close = (): void => {
    const cur = state.cur;
    state.cur = null;
    if (cur !== null && cur !== 'skip') finishPnpmEntry(acc, v5, cur);
  };
  for (const raw of lines) {
    const line = noCr(raw);
    if (line.length === 0) continue;
    const first = line.charCodeAt(0);
    if (first !== 32 && first !== 9) {
      // Column 0: the frame has checked it. Only the section it opens matters here.
      if (first === 35 || line === '---') continue;
      close();
      const name = line.slice(0, line.indexOf(':'));
      section = name === 'packages' || name === 'snapshots' ? name : '';
      continue;
    }
    if (section === '') continue;
    if (line.length > MAX_LINE) {
      acc.unrecognised += 1;
      continue;
    }
    let indent = 0;
    while (line.charCodeAt(indent) === 32) indent += 1;
    if (indent === line.length) continue;
    const head = line.charCodeAt(indent);
    if (head === 9) {
      acc.unrecognised += 1;
    } else if (head === 35) {
      // a comment
    } else if (indent === 2) {
      close();
      const key = pnpmKeyOf(line.slice(2));
      if (key === null) {
        acc.unrecognised += 1;
        state.cur = 'skip';
      } else {
        state.cur = { section, key };
      }
    } else if (indent === 1 || indent === 3) {
      acc.unrecognised += 1;
    } else if (state.cur === null) {
      acc.unrecognised += 1;
    } else if (state.cur !== 'skip' && indent === 4 && section === 'packages') {
      readPnpmBody(acc, state.cur, line.slice(4));
    }
  }
  close();
  return {
    format: 'pnpm-lock',
    entries: acc.entries,
    local: acc.local,
    unrecognised: acc.unrecognised,
    resolutionOf: (rel, name, range) => pnpmResolution(lines, v5, rel, name, range),
  };
}

const PNPM_GROUPS: ReadonlySet<string> = new Set(['dependencies', 'devDependencies', 'optionalDependencies', 'specifiers']);

/** `name: value` of pnpm 5's one-line map entries (`'@babel/types': ^7.18.8`). */
function splitKeyValue(body: string): [string, string] | null {
  if (body.startsWith("'")) {
    const close = body.indexOf("'", 1);
    if (close < 0 || !body.startsWith(': ', close + 1)) return null;
    return [body.slice(1, close), unquote(body.slice(close + 3).trimEnd())];
  }
  const at = body.indexOf(': ');
  return at <= 0 ? null : [body.slice(0, at), unquote(body.slice(at + 2).trimEnd())];
}

const leadingSpaces = (line: string): number => {
  let n = 0;
  while (line.charCodeAt(n) === 32) n += 1;
  return n;
};

/**
 * The version pnpm pinned for `name` in the project `rel` (its importer, or the top of a file of one project) when the
 * recorded specifier is `range`. Read in the one layout pnpm writes: anything else is `null`, and the dependency goes
 * the registry's way.
 */
function pnpmResolution(lines: readonly string[], v5: boolean, rel: string, name: string, range: string): string | null {
  if (!validName(name)) return null;
  let from = 0;
  let to = lines.length;
  let indent = 0;
  const importers = lines.findIndex((l) => noCr(l) === 'importers:');
  if (importers >= 0) {
    const wanted = rel === '' ? '.' : rel;
    let found = -1;
    for (let i = importers + 1; i < lines.length && found < 0; i += 1) {
      const line = noCr(lines[i] ?? '').trimEnd();
      if (line.length > 0 && leadingSpaces(line) === 0) break;
      if (line === `  ${wanted}:` || line === `  '${wanted}':`) found = i;
    }
    if (found < 0) return null;
    from = found + 1;
    to = from;
    while (to < lines.length && (noCr(lines[to] ?? '').trim() === '' || leadingSpaces(noCr(lines[to] ?? '')) > 2)) to += 1;
    indent = 4;
  } else if (rel !== '') {
    return null;
  }
  const specifiers = new Map<string, string>();
  const versions = new Map<string, string>();
  let group: string | null = null;
  let current: string | null = null;
  for (let i = from; i < to; i += 1) {
    const line = noCr(lines[i] ?? '');
    const ind = leadingSpaces(line);
    if (ind === line.length || line.charCodeAt(ind) === 35 || ind < indent) continue;
    if (ind === indent) {
      const header = line.trimEnd();
      const label = header.endsWith(':') ? header.slice(ind, -1) : '';
      group = PNPM_GROUPS.has(label) ? label : null;
      current = null;
    } else if (group === null) {
      continue;
    } else if (ind === indent + 2) {
      const body = line.slice(ind);
      current = null;
      if (v5) {
        const kv = splitKeyValue(body);
        if (kv !== null && !(group === 'specifiers' ? specifiers : versions).has(kv[0])) (group === 'specifiers' ? specifiers : versions).set(kv[0], kv[1]);
      } else if (group !== 'specifiers') {
        current = pnpmKeyOf(body);
      }
    } else if (ind === indent + 4 && current !== null) {
      const body = line.slice(ind).trimEnd();
      if (body.startsWith('specifier: ') && !specifiers.has(current)) specifiers.set(current, unquote(body.slice('specifier: '.length)));
      else if (body.startsWith('version: ') && !versions.has(current)) versions.set(current, unquote(body.slice('version: '.length)));
    }
  }
  const pinned = versions.get(name);
  if (specifiers.get(name) !== range || pinned === undefined) return null;
  const peers = pinned.indexOf(v5 ? '_' : '(');
  const version = peers < 0 ? pinned : pinned.slice(0, peers);
  return validVersion(version) && satisfies(range, version) ? version : null;
}

// ───────────────────────────────────────────────────────── yarn.lock

const SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:/;

interface YarnBlock {
  /** The descriptors of the key (v1: each `name@range`, unquoted; Yarn 2+: as written between the quotes). */
  keys: string[];
  version?: string;
  resolved?: string;
  resolution?: string;
  /** A `version`, `resolved` or `resolution` line not in the form yarn writes, or written twice. */
  flawed: boolean;
  metadata: boolean;
}

/** `name@range` as a descriptor of a v1 key, with `alias@npm:real@range` read as the real package. */
function parseDescriptor(d: string): { name: string; range: string } | null {
  const at = d.indexOf('@', 1);
  if (at <= 0) return null;
  const name = d.slice(0, at);
  const range = d.slice(at + 1);
  if (!range.startsWith('npm:')) return { name, range };
  const rest = range.slice('npm:'.length);
  const inner = rest.indexOf('@', 1);
  return inner > 0 ? { name: rest.slice(0, inner), range: rest.slice(inner + 1) } : { name, range: rest };
}

/** The descriptors of a v1 key (`a@^1, "b@2 - 3"`); `null` when it is not in the form yarn writes. */
function splitDescriptors(inner: string): string[] | null {
  const out: string[] = [];
  let i = 0;
  while (i < inner.length) {
    if (inner.charCodeAt(i) === 34) {
      const end = inner.indexOf('"', i + 1);
      if (end < 0) return null;
      out.push(inner.slice(i + 1, end));
      i = end + 1;
    } else {
      let end = inner.indexOf(', ', i);
      if (end < 0) end = inner.length;
      out.push(inner.slice(i, end));
      i = end;
    }
    if (i < inner.length) {
      if (!inner.startsWith(', ', i)) return null;
      i += 2;
    }
  }
  return out.length > 0 && out.every((d) => d.length > 0 && !d.includes('\\')) ? out : null;
}

/**
 * The value of the 2-space field `field` of a block: `undefined` when the line is another key, `null` when it is this
 * one and not in the form yarn writes (v1: `field "value"`; Yarn 2+: `field: value` or `field: "value"`).
 */
function yarnField(line: string, berry: boolean, field: string): string | null | undefined {
  const head = berry ? `  ${field}:` : `  ${field}`;
  if (!line.startsWith(head)) return undefined;
  const after = line.charCodeAt(head.length);
  if (Number.isNaN(after)) return null;
  if (after !== 32) return undefined;
  const rest = line.slice(head.length + 1).trimEnd();
  if (rest.startsWith('"')) return rest.length >= 2 && rest.endsWith('"') ? rest.slice(1, -1) : null;
  return berry && rest.length > 0 && !/\s/.test(rest) ? rest : null;
}

/** The key of a column-0 line, or `null` when it is no key; `consumed` is set when the next line was part of it (`? "key"` and `:`). */
function yarnKey(line: string, next: string, berry: boolean): { keys: string[]; metadata: boolean; consumed: boolean } | null {
  if (berry) {
    let text: string;
    let consumed = false;
    if (line.startsWith('? ')) {
      if (noCr(next).trimEnd() !== ':') return null;
      text = line.slice(2).trim();
      consumed = true;
    } else {
      const t = line.trimEnd();
      if (!t.endsWith(':')) return null;
      text = t.slice(0, -1);
    }
    if (text === '__metadata') return { keys: [], metadata: true, consumed };
    if (text.startsWith('"')) {
      if (text.length < 2 || !text.endsWith('"')) return null;
      text = text.slice(1, -1);
    }
    return { keys: text.split(', '), metadata: false, consumed };
  }
  const t = line.trimEnd();
  if (!t.endsWith(':')) return null;
  const keys = splitDescriptors(t.slice(0, -1));
  return keys === null ? null : { keys, metadata: false, consumed: false };
}

/** Every block of a yarn.lock, handed to `onBlock`; the lines that open no block and are not inside one are counted. */
function scanYarn(lines: readonly string[], berry: boolean, acc: Acc, onBlock: (b: YarnBlock) => void): void {
  const state: { cur: YarnBlock | 'skip' | null } = { cur: null };
  const flush = (): void => {
    const cur = state.cur;
    state.cur = null;
    if (cur !== null && cur !== 'skip' && !cur.metadata) onBlock(cur);
  };
  for (let i = 0; i < lines.length; i += 1) {
    const line = noCr(lines[i] ?? '');
    if (line.length > MAX_LINE) {
      acc.unrecognised += 1;
      continue;
    }
    const first = line.charCodeAt(0);
    if (line.length === 0 || first === 35) continue;
    if (first !== 32 && first !== 9) {
      flush();
      const key = yarnKey(line, lines[i + 1] ?? '', berry);
      if (key === null) {
        acc.unrecognised += 1;
        state.cur = 'skip';
        continue;
      }
      if (key.consumed) i += 1;
      state.cur = { keys: key.keys, flawed: false, metadata: key.metadata };
      continue;
    }
    const block = state.cur;
    if (block === 'skip') continue;
    const trimmed = line.trimStart();
    if (trimmed.length === 0 || trimmed.charCodeAt(0) === 35) continue;
    if (block === null) {
      acc.unrecognised += 1;
      continue;
    }
    for (const field of berry ? (['version', 'resolution'] as const) : (['version', 'resolved'] as const)) {
      const value = yarnField(line, berry, field);
      if (value === undefined) continue;
      if (value === null || block[field] !== undefined) block.flawed = true;
      else block[field] = field === 'resolved' ? value.split('#', 1)[0] ?? '' : value;
      break;
    }
  }
  flush();
}

/** A block of a yarn.lock v1: the pair is the key's name and the block's `version`; the origin is `resolved`, or the range when it is not a registry range. */
function yarnClassicBlock(acc: Acc, b: YarnBlock): void {
  const counted = b.flawed || b.version === undefined;
  if (counted) acc.unrecognised += 1;
  if (b.version === undefined) return;
  const parsed = b.keys.map(parseDescriptor);
  const first = parsed[0];
  if (first === undefined || first === null || parsed.some((p) => p === null || p.name !== first.name)) {
    if (!counted) acc.unrecognised += 1;
    return;
  }
  const where = b.resolved ?? (SCHEME.test(first.range) ? first.range : undefined);
  const pin = makePin(first.name, b.version);
  if (pin !== undefined) {
    finish(acc, pin, where);
    return;
  }
  if (where !== undefined && locate(where) === 'local') acc.local += 1;
  else if (!counted) acc.unrecognised += 1;
}

const LOCAL_BERRY = /^(?:workspace|patch|link|portal|file):/;

/** A block of a yarn.lock of Yarn 2+: the pair is the `resolution` (`name@npm:version`), never the key. */
function yarnBerryBlock(acc: Acc, b: YarnBlock): void {
  // One count per block, however many things are wrong with it.
  let counted = b.flawed;
  const note = (): void => {
    if (!counted) acc.unrecognised += 1;
    counted = true;
  };
  if (counted) acc.unrecognised += 1;
  const resolution = b.resolution;
  const at = resolution === undefined ? -1 : resolution.indexOf('@', 1);
  if (resolution === undefined || at <= 0) {
    note();
    return;
  }
  const name = resolution.slice(0, at);
  const spec = resolution.slice(at + 1);
  if (LOCAL_BERRY.test(spec)) {
    acc.local += 1;
    return;
  }
  if (!spec.startsWith('npm:')) {
    // An https URL, a git repository: the version is the block's own.
    finish(acc, b.version === undefined ? undefined : makePin(name, b.version), spec);
    return;
  }
  const rest = spec.slice('npm:'.length);
  const cut = rest.indexOf('::');
  const pin = makePin(name, cut < 0 ? rest : rest.slice(0, cut));
  let where: string | undefined;
  if (cut >= 0) {
    for (const param of rest.slice(cut + 2).split('&')) {
      if (!param.startsWith('__archiveUrl=')) continue;
      try {
        where = decodeURIComponent(param.slice('__archiveUrl='.length));
      } catch {
        note();
      }
    }
  }
  if (pin === undefined) note();
  else finish(acc, pin, where);
}

function readYarn(text: string): LockRead | { unread: string } {
  const lines = text.split('\n');
  let berry = false;
  let classic = false;
  for (const raw of lines) {
    const line = noCr(raw);
    if (line.length > 40) continue;
    const t = line.trimEnd();
    if (t === '__metadata:') berry = true;
    else if (t === '# yarn lockfile v1') classic = true;
  }
  if (berry && classic) return { unread: 'it has both the header of a v1 lockfile and `__metadata:`' };
  if (!berry && !classic) return { unread: 'it has neither the `# yarn lockfile v1` header nor `__metadata:`' };
  const acc = newAcc();
  scanYarn(lines, berry, acc, (b) => (berry ? yarnBerryBlock(acc, b) : yarnClassicBlock(acc, b)));
  let index: Map<string, string> | undefined;
  /** descriptor → pinned version, built once from the blocks that are registry packages. */
  const pinnedBy = (): Map<string, string> => {
    if (index !== undefined) return index;
    const map = new Map<string, string>();
    scanYarn(lines, berry, newAcc(), (b) => {
      if (b.version === undefined || !validVersion(b.version)) return;
      if (berry && !(b.resolution ?? '').includes('@npm:')) return;
      for (const key of b.keys) if (!map.has(key)) map.set(key, b.version);
    });
    index = map;
    return map;
  };
  return {
    format: 'yarn-lock',
    entries: acc.entries,
    local: acc.local,
    unrecognised: acc.unrecognised,
    // yarn.lock lists no workspace member: found above the command's directory it covers nothing.
    resolutionOf: (rel, name, range) => {
      if (rel !== '' || !validName(name)) return null;
      const pinned = pinnedBy().get(berry ? `${name}@npm:${range}` : `${name}@${range}`);
      return pinned !== undefined && satisfies(range, pinned) ? pinned : null;
    },
  };
}

// ───────────────────────────────────────────────────────── bun.lock

interface BunLine {
  /** The key as written between its quotes. */
  key: string;
  /** The first element, decoded: `name@version`, `name@workspace:…`, `name@https://…`. */
  first: string;
  /** The second element when it is a string: the registry, `''` for the default. */
  second: string | undefined;
}

/** The index of the quote that closes the string opened at `start`, or -1. */
function stringEnd(line: string, start: number): number {
  for (let i = start + 1; i < line.length; i += 1) {
    const c = line.charCodeAt(i);
    if (c === 92) i += 1;
    else if (c === 34) return i;
  }
  return -1;
}

function stringAt(line: string, start: number, end: number): string | null {
  const raw = line.slice(start + 1, end);
  if (!raw.includes('\\')) return raw;
  try {
    const value: unknown = JSON.parse(`"${raw}"`);
    return typeof value === 'string' ? value : null;
  } catch {
    return null;
  }
}

/** An entry line of the form bun writes — `    "key": ["name@spec", "registry", {…}, "integrity"],` — and nothing else: the array must close at the end of the line, so two entries on one line, or one over several lines, are not read. */
function parseBunLine(line: string): BunLine | null {
  if (!line.startsWith('    "')) return null;
  const keyEnd = stringEnd(line, 4);
  if (keyEnd < 0 || !line.startsWith(': ["', keyEnd + 1)) return null;
  const firstStart = keyEnd + 4;
  const firstEnd = stringEnd(line, firstStart);
  if (firstEnd < 0) return null;
  const first = stringAt(line, firstStart, firstEnd);
  let i = firstEnd + 1;
  let second: string | undefined;
  if (line.startsWith(', "', i)) {
    const end = stringEnd(line, i + 2);
    if (end < 0) return null;
    second = stringAt(line, i + 2, end) ?? undefined;
    if (second === undefined) return null;
    i = end + 1;
  }
  let depth = 1;
  let inString = false;
  for (; i < line.length && depth > 0; i += 1) {
    const c = line.charCodeAt(i);
    if (inString) {
      if (c === 92) i += 1;
      else if (c === 34) inString = false;
    } else if (c === 34) {
      inString = true;
    } else if (c === 91 || c === 123) {
      depth += 1;
    } else if (c === 93 || c === 125) {
      depth -= 1;
    }
  }
  if (first === null || depth !== 0) return null;
  const tail = line.slice(i).trim();
  return tail === '' || tail === ',' ? { key: line.slice(5, keyEnd), first, second } : null;
}

/** The lines of the `packages` section that follows line `start`, up to its closing `  }`. */
function scanBun(lines: readonly string[], start: number, acc: Acc, onEntry: (e: BunLine) => void): void {
  for (let i = start + 1; i < lines.length; i += 1) {
    const line = noCr(lines[i] ?? '');
    if (line.length > MAX_LINE) {
      acc.unrecognised += 1;
      continue;
    }
    const t = line.trimEnd();
    if (t === '  }' || t === '  },') return;
    if (t.length === 0) continue;
    const entry = parseBunLine(line);
    if (entry === null) acc.unrecognised += 1;
    else onEntry(entry);
  }
}

function bunEntry(acc: Acc, e: BunLine): void {
  const at = e.first.indexOf('@', 1);
  if (at <= 0) {
    acc.unrecognised += 1;
    return;
  }
  const name = e.first.slice(0, at);
  const spec = e.first.slice(at + 1);
  if (spec.startsWith('workspace:')) {
    acc.local += 1;
  } else if (VERSION.test(spec)) {
    const pin = makePin(name, spec);
    if (pin === undefined) acc.unrecognised += 1;
    else finish(acc, pin, e.second === undefined || e.second === '' ? undefined : e.second);
  } else {
    // Not a registry version: where the entry comes from (a URL has no pair of its own).
    finish(acc, undefined, spec);
  }
}

const BUN_PACKAGES = '  "packages": {';

function readBun(text: string): LockRead | { unread: string } {
  const lines = text.split('\n');
  let version = '';
  let versions = 0;
  let start = -1;
  let sections = 0;
  for (let i = 0; i < lines.length; i += 1) {
    const line = noCr(lines[i] ?? '');
    if (line.startsWith('  "lockfileVersion": ')) {
      versions += 1;
      const value = line.slice('  "lockfileVersion": '.length).trimEnd();
      version = value.endsWith(',') ? value.slice(0, -1) : value;
    } else if (line.startsWith('  "packages":')) {
      if (line.trimEnd() !== BUN_PACKAGES) return { unread: 'its "packages" section does not open on a line of its own' };
      sections += 1;
      start = i;
    }
  }
  if (versions !== 1) return { unread: versions === 0 ? 'it has no lockfileVersion line' : 'it has more than one lockfileVersion line' };
  if (version !== '0' && version !== '1') return { unread: 'its lockfileVersion is not 0 or 1' };
  if (sections !== 1) return { unread: sections === 0 ? 'it has no `"packages": {` line' : 'it has more than one `"packages": {` section' };
  const acc = newAcc();
  scanBun(lines, start, acc, (e) => bunEntry(acc, e));
  let index: Map<string, string> | undefined;
  /** package key → pinned version, for the keys that are plain names (the hoisted copies). */
  const hoisted = (): Map<string, string> => {
    if (index !== undefined) return index;
    const map = new Map<string, string>();
    scanBun(lines, start, newAcc(), (e) => {
      const at = e.first.indexOf('@', 1);
      if (at > 0 && e.first.slice(0, at) === e.key && validName(e.key) && validVersion(e.first.slice(at + 1)) && !map.has(e.key)) map.set(e.key, e.first.slice(at + 1));
    });
    index = map;
    return map;
  };
  return {
    format: 'bun-lock',
    entries: acc.entries,
    local: acc.local,
    unrecognised: acc.unrecognised,
    resolutionOf: (rel, name, range) => {
      if (!validName(name) || !bunRecords(lines, rel, name, range)) return null;
      const pinned = hoisted().get(name);
      return pinned !== undefined && satisfies(range, pinned) ? pinned : null;
    },
  };
}

/** Whether the `workspaces` of the file has, for the project `rel`, a dependency `name` with exactly `range` — in the layout bun writes, line by line; any other layout says no. */
function bunRecords(lines: readonly string[], rel: string, name: string, range: string): boolean {
  const header = `    ${JSON.stringify(rel)}: {`;
  const item = `        ${JSON.stringify(name)}: ${JSON.stringify(range)}`;
  const state = { inWorkspaces: false, inProject: false, inGroup: false };
  for (const raw of lines) {
    const line = noCr(raw).trimEnd();
    if (!state.inWorkspaces) {
      state.inWorkspaces = line === '  "workspaces": {';
    } else if (line === '  }' || line === '  },') {
      return false;
    } else if (!state.inProject) {
      state.inProject = line === header;
    } else if (line === '    }' || line === '    },') {
      state.inProject = false;
    } else if (!state.inGroup) {
      state.inGroup = DEPENDENCY_GROUPS.some((g) => line === `      "${g}": {`);
    } else if (line === '      }' || line === '      },') {
      state.inGroup = false;
    } else if (line === item || line === `${item},`) {
      return true;
    }
  }
  return false;
}
