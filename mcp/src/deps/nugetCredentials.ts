/**
 * Whether a `dotnet restore` of the scanned repository would hand a NuGet
 * credential of the user's to a feed the repository chose.
 *
 * NuGet binds a credential to a feed's NAME, never to its URL, and a
 * repository's own `NuGet.config` can give a name any URL. Measured on the
 * .NET SDK 10.0.403 (Windows, 2026-10-27), with two local HTTP feeds that
 * answer 401 until a request carries credentials, and a temporary APPDATA,
 * HOME and NUGET_PACKAGES holding the "user's" configuration:
 *
 *   - a repository `NuGet.config` declaring the feed `corp` at the
 *     attacker's URL got the user's `corp` user name and password (from
 *     `%APPDATA%\NuGet\NuGet.Config`) on every request after the first 401;
 *     the user's own `corp` was never asked. The same with `<clear/>` before
 *     it; with the file in a project's directory below the solution's (the
 *     chain starts at each project's directory); with the credential in a
 *     drop-in (`%APPDATA%\NuGet\config\*.config`); and with it in
 *     `NuGetPackageSourceCredentials_corp` instead — no user-level source of
 *     that name needed. `<My_x0020_Feed>` under `packageSourceCredentials`
 *     is the feed `My Feed`, and the variable may spell it with the space.
 *   - names: feeds merge without case (a repository `CORP` replaced the
 *     user's `corp`), but the credential matched its feed's name WITH case
 *     (the repository's `CORP` got none). Compared here without case: a
 *     restore NuGet would have run without the credential is refused too,
 *     and a NuGet that matched otherwise is still held.
 *   - a repository `<config><add key="http_proxy" …/>` is not read by the
 *     restore: the user's feed on a non-loopback address (.NET never sends
 *     loopback through a proxy) was asked directly, and a proxy the user set
 *     in their own configuration won. Not a route; not checked.
 *
 * The chain, as `dotnet nuget config paths` lists it (same SDK; on Linux in
 * the `mcr.microsoft.com/dotnet/sdk:10.0` image, 10.0.403): one file per
 * directory from the project's up to the filesystem root, named
 * `nuget.config`, `NuGet.config` or `NuGet.Config` (Linux took the first of
 * those present; Windows any case — in the repository every one, in any
 * case, is read here, and above it each of the three names);
 * then the user's `NuGet.Config` and each `*.config` in the `config`
 * directory beside it (not below): `%APPDATA%\NuGet` on Windows,
 * `$DOTNET_CLI_HOME/.nuget/NuGet` or else `$HOME/.nuget/NuGet` on Linux
 * (`~/.config/NuGet` and `XDG_CONFIG_HOME` were not read); then the
 * machine's `*.config`: `%ProgramFiles(x86)%\NuGet\Config` on Windows,
 * `/etc/opt/NuGet/Config` on Linux (`XDG_DATA_HOME` was not read), and —
 * NuGet's source, not measured — `/Library/Application Support/NuGet/Config`
 * on macOS.
 *
 * The REPOSITORY is the git work tree holding the project, or the project
 * directory when there is none: a config at or below its root is the
 * repository's, every other one the user's. A name means, for the user, the
 * feed their own chain (from the repository root's parent) makes effective.
 * For every name a repository file makes effective from a project's
 * directory, when the user holds a credential for it — a
 * `packageSourceCredentials` entry in their chain, or a
 * `NuGetPackageSourceCredentials_<name>` variable in the environment the
 * restore gets — and the repository's URL is not on the same server (scheme,
 * host and port) as the user's, or the user has no feed of that name, the
 * restore is refused: a named gap, the feed and the repository file named,
 * never the credential. A local folder cannot receive a credential and is
 * let through; a `%VAR%` in the value is not expanded here and is treated as
 * any URL. Also refused: a repository value that is a network path
 * (`\\host\share`, `//host/…`, `file://host/…` — NuGet opening it, Windows
 * authenticates to the host; not measured with NuGet, the rule every
 * repository path is held to), and a configuration on either side that is
 * there and could not be read — what it declares is not known.
 */

import { readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { isNetworkPath, readSmallText } from '../hooks/configFile.js';
import {
  describeReadRefusal,
  isWithinDir,
  listProjectDirOrNull,
  projectEntryKindIn,
  readProjectText,
} from '../platform/projectFs.js';
import { urlHost } from './pipRequirements.js';

/** The largest NuGet configuration read; a real one is a few kilobytes. */
const MAX_CONFIG_BYTES = 1024 * 1024;

/** Where to find the user's and the machine's configuration (tests point every one at a temp directory). */
export interface NugetEnvironment {
  /** The restore's environment: `APPDATA`, `HOME`, `DOTNET_CLI_HOME`, `ProgramFiles(x86)`, `NuGetPackageSourceCredentials_*`. */
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  /** The home directory when the environment names none. */
  home?: string;
  /** The machine-wide configuration directory, or null for none. */
  machineConfigDir?: string | null;
}

export interface NugetRestoreRefusal {
  code: 'nuget_credential_rebound' | 'nuget_network_path' | 'nuget_config_unread';
  reason: string;
}

interface ParsedConfig {
  /** `packageSources`' `<add>` items in document order. */
  adds: Array<{ key: string; value: string }>;
  /** Whether `packageSources` holds a `<clear/>`. */
  clears: boolean;
  /** The feed names `packageSourceCredentials` holds an entry for, decoded. */
  credentialNames: string[];
  /** Every `value` attribute in the file, any section. */
  values: string[];
}

interface ConfigFile {
  path: string;
  repository: boolean;
  parsed: ParsedConfig;
}

interface Declared {
  key: string;
  value: string;
  file: ConfigFile;
}

type Unread = { unread: string };

function envValue(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const exact = env[name];
  if (exact !== undefined && exact !== '') return exact;
  const upper = name.toUpperCase();
  for (const [k, v] of Object.entries(env)) if (k.toUpperCase() === upper && v !== undefined && v !== '') return v;
  return undefined;
}

// ------------------------------------------------------------------ parsing

const ENTITIES: Record<string, string> = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };

function codePoint(n: number, fallback: string): string {
  return Number.isInteger(n) && n >= 0 && n <= 0x10ffff ? String.fromCodePoint(n) : fallback;
}

function decodeEntities(text: string): string {
  return text.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (whole, body: string) => {
    if (/^#x/i.test(body)) return codePoint(Number.parseInt(body.slice(2), 16), whole);
    if (body.startsWith('#')) return codePoint(Number.parseInt(body.slice(1), 10), whole);
    return ENTITIES[body.toLowerCase()] ?? whole;
  });
}

/** An XML name as `XmlConvert.DecodeName` reads it: `_x0020_` (or `_x00000020_`) is the character. */
function decodeXmlName(name: string): string {
  return name.replace(/_x([0-9a-f]{8}|[0-9a-f]{4})_/gi, (whole, hex: string) => codePoint(Number.parseInt(hex, 16), whole));
}

/**
 * A tag's attributes, the first of each name. A name is read from the start
 * of its run of name characters (`[\w.:-]`), past the digits, dots and
 * hyphens no name begins with: only a run's end can be followed by `=`, so a
 * search from each character inside the run read the rest of it again — a
 * tag of one 80 KB word took 6 s (measured), the square of its length.
 */
function attributes(text: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const m of text.matchAll(/(?<![\w.:-])[\d.-]*([A-Za-z_:][\w.:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')/g)) {
    const name = m[1]?.toLowerCase();
    if (name !== undefined && !out.has(name)) out.set(name, decodeEntities(m[2] ?? m[3] ?? ''));
  }
  return out;
}

/**
 * `text` up to its last `>`: no element can end after it, and a search for
 * one from every `<` beyond it read to the end of the text each time.
 */
function upToLastTagEnd(text: string): string {
  return text.slice(0, text.lastIndexOf('>') + 1);
}

/** A section's opening and closing tags, matched without case. */
interface SectionTags {
  open: RegExp;
  close: RegExp;
}

const PACKAGE_SOURCES: SectionTags = { open: /<packageSources\b/gi, close: /<\/packageSources\s*>/gi };
const PACKAGE_SOURCE_CREDENTIALS: SectionTags = {
  open: /<packageSourceCredentials\b/gi,
  close: /<\/packageSourceCredentials\s*>/gi,
};

/**
 * The bodies of every `<name>…</name>` section, matched without case (a
 * self-closing one has none): an opening tag ends at the first `>` after
 * it, its body at the first closing tag after that. Both are searched for
 * forward only — when none is left after one opening tag, none is after a
 * later one — where the expression this was searched both again from every
 * opening tag: 320 KB of `<packageSources>` alone took 2.3 s (measured), a
 * 1 MB configuration minutes.
 */
function sections(text: string, tags: SectionTags): string[] {
  const out: string[] = [];
  let tagEnd = -1;
  let close: { index: number; end: number } | null = null;
  let at = 0;
  for (;;) {
    tags.open.lastIndex = at;
    const open = tags.open.exec(text);
    if (open === null) break;
    const nameEnd = open.index + open[0].length;
    if (tagEnd < nameEnd) tagEnd = text.indexOf('>', nameEnd);
    if (tagEnd === -1) break;
    if (text.charAt(tagEnd - 1) === '/') {
      at = open.index + 1;
      continue;
    }
    if (close === null || close.index <= tagEnd) {
      tags.close.lastIndex = tagEnd + 1;
      const m = tags.close.exec(text);
      if (m === null) break;
      close = { index: m.index, end: m.index + m[0].length };
    }
    out.push(text.slice(tagEnd + 1, close.index));
    at = close.end;
  }
  return out;
}

/**
 * The parts of a NuGet configuration the check needs. Not an XML parser: it
 * reads more than NuGet would (section and element names without case, every
 * section of a name, an `<add>` before a `<clear/>` kept), so what it
 * misreads can only refuse a restore, never let one through. Comments are
 * dropped — a commented-out feed declares nothing.
 */
export function parseNugetConfig(raw: string): ParsedConfig {
  // `<!-{2}`, not the four characters: Semgrep's TypeScript parser (1.182.0)
  // reads `<!--` in a regular expression literal as an HTML comment, and
  // left the rest of this function unparsed — and unscanned.
  const text = raw.replace(/<!-{2}[\s\S]*?(?:-->|$)/g, '');
  const adds: ParsedConfig['adds'] = [];
  let clears = false;
  for (const body of sections(text, PACKAGE_SOURCES)) {
    for (const m of upToLastTagEnd(body).matchAll(/<(add|clear)\b([^>]*?)\/?>/gi)) {
      if ((m[1] ?? '').toLowerCase() === 'clear') {
        clears = true;
        continue;
      }
      const attrs = attributes(m[2] ?? '');
      const key = attrs.get('key')?.trim();
      if (key !== undefined && key !== '') adds.push({ key, value: (attrs.get('value') ?? '').trim() });
    }
  }
  const credentialNames: string[] = [];
  for (const body of sections(text, PACKAGE_SOURCE_CREDENTIALS)) {
    for (const m of upToLastTagEnd(body).matchAll(/<([A-Za-z_][\w.:-]*)\b[^>]*>/g)) {
      const name = m[1] ?? '';
      if (!['add', 'clear'].includes(name.toLowerCase())) credentialNames.push(decodeXmlName(name));
    }
  }
  const values = [...text.matchAll(/\bvalue\s*=\s*(?:"([^"]*)"|'([^']*)')/gi)].map((m) => decodeEntities(m[1] ?? m[2] ?? '').trim());
  return { adds, clears, credentialNames, values };
}

// ------------------------------------------------------------------ the chain

/** Whether a directory entry is a NuGet configuration as the directory walk finds one. */
const isConfigName = (name: string): boolean => name.toLowerCase() === 'nuget.config';

/** A drop-in directory of the user's or the machine's: listed outright — it is theirs, not the repository's. */
function listUserDir(dir: string): string[] | Unread {
  try {
    return readdirSync(dir).sort();
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    return code === 'ENOENT' || code === 'ENOTDIR' ? [] : { unread: `${dir} could not be listed` };
  }
}

function readUserConfig(path: string): ConfigFile | null | Unread {
  const r = readSmallText(path, MAX_CONFIG_BYTES);
  if (r.status === 'absent') return null;
  if (r.status === 'refused') return { unread: `${path}: ${describeReadRefusal(r.reason)}` };
  return { path, repository: false, parsed: parseNugetConfig(r.text) };
}

function machineConfigDir(nuget: NugetEnvironment, env: NodeJS.ProcessEnv, platform: NodeJS.Platform): string | null {
  if (nuget.machineConfigDir !== undefined) return nuget.machineConfigDir;
  if (platform === 'darwin') return '/Library/Application Support/NuGet/Config';
  if (platform !== 'win32') return '/etc/opt/NuGet/Config';
  const pf = envValue(env, 'ProgramFiles(x86)') ?? envValue(env, 'ProgramFiles');
  return pf === undefined ? null : join(pf, 'NuGet', 'Config');
}

/** The user's and the machine's configuration files, lowest priority first. */
function userChain(nuget: NugetEnvironment, repoRoot: string): ConfigFile[] | Unread {
  const env = nuget.env ?? process.env;
  const platform = nuget.platform ?? process.platform;
  const home = nuget.home ?? homedir();
  const userDir =
    platform === 'win32'
      ? join(envValue(env, 'APPDATA') ?? join(home, 'AppData', 'Roaming'), 'NuGet')
      : join(envValue(env, 'DOTNET_CLI_HOME') ?? envValue(env, 'HOME') ?? home, '.nuget', 'NuGet');
  const machineDir = machineConfigDir(nuget, env, platform);

  const paths: string[] = [];
  // A drop-in directory is listed; a NuGet.Config is probed by the names NuGet probes (Windows' is any case).
  const listed = (dir: string): Unread | null => {
    const names = listUserDir(dir);
    if ('unread' in names) return names;
    paths.push(...names.filter((n) => /\.config$/i.test(n)).map((n) => join(dir, n)));
    return null;
  };
  const probed = (dir: string): void => {
    paths.push(...(platform === 'win32' ? ['NuGet.Config'] : ['nuget.config', 'NuGet.config', 'NuGet.Config']).map((n) => join(dir, n)));
  };
  const failed = (machineDir !== null ? listed(machineDir) : null) ?? listed(join(userDir, 'config'));
  if (failed !== null) return failed;
  probed(userDir);
  // Above the repository: the user's own folders — a config there serves every repository below it.
  const above: string[] = [];
  for (let dir = dirname(resolve(repoRoot)); ; dir = dirname(dir)) {
    above.unshift(dir);
    if (dirname(dir) === dir) break;
  }
  for (const dir of above) probed(dir);

  const out: ConfigFile[] = [];
  for (const path of paths) {
    const file = readUserConfig(path);
    if (file === null) continue;
    if ('unread' in file) return file;
    out.push(file);
  }
  return out;
}

function repositoryConfigsIn(repoRoot: string, dir: string): ConfigFile[] | Unread {
  const rel = (p: string): string => relative(repoRoot, p).split(sep).join('/') || '.';
  if (projectEntryKindIn(repoRoot, dir) === 'absent') return [];
  const entries = listProjectDirOrNull(repoRoot, dir);
  // NuGet reads a config in a directory this walk cannot list (a link out of the repository): not known.
  if (entries === null) return { unread: `the directory ${rel(dir)} could not be listed` };
  const out: ConfigFile[] = [];
  for (const entry of entries.filter((e) => isConfigName(e.name)).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    const path = join(dir, entry.name);
    const r = readProjectText(repoRoot, path, MAX_CONFIG_BYTES);
    if (r.status === 'absent') continue;
    if (r.status === 'refused') return { unread: `${rel(path)} ${describeReadRefusal(r.reason)}` };
    out.push({ path, repository: true, parsed: parseNugetConfig(r.text) });
  }
  return out;
}

/** The repository's files from its root down to `start`, lowest priority (the root's) first. */
function repositoryChain(repoRoot: string, start: string, cache: Map<string, ConfigFile[] | Unread>): ConfigFile[] | Unread {
  const dirs: string[] = [];
  for (let dir = resolve(start); isWithinDir(repoRoot, dir); dir = dirname(dir)) {
    dirs.unshift(dir);
    if (relative(resolve(repoRoot), dir) === '' || dirname(dir) === dir) break;
  }
  const out: ConfigFile[] = [];
  for (const dir of dirs) {
    let files = cache.get(dir);
    if (files === undefined) {
      files = repositoryConfigsIn(repoRoot, dir);
      cache.set(dir, files);
    }
    if ('unread' in files) return files;
    out.push(...files);
  }
  return out;
}

/** The feeds a chain makes effective, by name without case: a `<clear/>` drops every lower-priority file's. */
function effectiveSources(files: readonly ConfigFile[]): Map<string, Declared> {
  const out = new Map<string, Declared>();
  for (const file of files) {
    if (file.parsed.clears) out.clear();
    for (const add of file.parsed.adds) out.set(add.key.toLowerCase(), { key: add.key, value: add.value, file });
  }
  return out;
}

// ------------------------------------------------------------------ judging

/** A network path a repository value names: `\\host\share`, `//host/…`, `file://host/…` (not `file:///`, not localhost). */
function isNetworkValue(value: string): boolean {
  if (isNetworkPath(value)) return true;
  const host = /^file:\/\/([^/\\]*)/i.exec(value)?.[1];
  return host !== undefined && host !== '' && host.toLowerCase() !== 'localhost';
}

/** Whether NuGet could send a credential to the feed: anything but a plain local folder. */
function mayCarryCredential(value: string): boolean {
  if (value.includes('%')) return true;
  if (/^file:/i.test(value)) return false;
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(value) || isNetworkPath(value);
}

/** The same server: the same text, or URLs of the same scheme, host and port — where the credential was meant to go. */
function sameServer(a: string, b: string): boolean {
  if (a === b) return true;
  try {
    const x = new URL(a);
    const y = new URL(b);
    return x.hostname !== '' && x.protocol === y.protocol && x.hostname === y.hostname && x.port === y.port;
  } catch {
    return false;
  }
}

/** The feed names the user holds a credential for, without case, each with where it is held. */
function heldCredentials(user: readonly ConfigFile[], env: NodeJS.ProcessEnv): Map<string, string> {
  const out = new Map<string, string>();
  for (const [name, value] of Object.entries(env)) {
    const m = /^NuGetPackageSourceCredentials_(.+)$/i.exec(name);
    if (m?.[1] !== undefined && value !== undefined && value !== '') out.set(m[1].toLowerCase(), `the variable ${name}`);
  }
  for (const file of user) {
    for (const name of file.parsed.credentialNames) {
      if (!out.has(name.toLowerCase())) out.set(name.toLowerCase(), file.path);
    }
  }
  return out;
}

/**
 * Why restoring from the directories in `starts` (each project's, the
 * solution's) would hand a credential of the user's to a feed the
 * repository rooted at `repoRoot` chose, or null when it would not — see the
 * module comment. A directory outside `repoRoot` is not judged: its chain
 * holds none of the repository's files.
 */
export function nugetRestoreRefusal(
  repoRoot: string,
  starts: readonly string[],
  nuget: NugetEnvironment = {},
): NugetRestoreRefusal | null {
  const env = nuget.env ?? process.env;
  const rel = (p: string): string => relative(repoRoot, p).split(sep).join('/') || p;
  const user = userChain(nuget, repoRoot);
  if ('unread' in user) {
    return {
      code: 'nuget_config_unread',
      reason: `not restored: your NuGet configuration ${user.unread}, so the feeds it binds a credential to could not be checked`,
    };
  }
  const cache = new Map<string, ConfigFile[] | Unread>();
  const chains: ConfigFile[][] = [];
  for (const start of [...new Set(starts.map((s) => resolve(s)))].sort()) {
    if (!isWithinDir(repoRoot, start)) continue;
    const chain = repositoryChain(repoRoot, start, cache);
    if ('unread' in chain) {
      return {
        code: 'nuget_config_unread',
        reason: `not restored: the repository's NuGet configuration ${chain.unread}, so the feeds it declares could not be checked`,
      };
    }
    chains.push(chain);
  }
  for (const file of new Set(chains.flat())) {
    const network = file.parsed.values.find(isNetworkValue);
    if (network !== undefined) {
      return {
        code: 'nuget_network_path',
        reason: `not restored: ${rel(file.path)} names a network path (${urlHost(network)}), which NuGet would open — and Windows authenticate to its host`,
      };
    }
  }
  const held = heldCredentials(user, env);
  if (held.size === 0) return null;
  const mine = effectiveSources(user);
  for (const chain of chains) {
    for (const [name, feed] of effectiveSources([...user, ...chain])) {
      if (!feed.file.repository || !mayCarryCredential(feed.value)) continue;
      const where = held.get(name);
      if (where === undefined) continue;
      const own = mine.get(name);
      if (own !== undefined && sameServer(own.value, feed.value)) continue;
      return {
        code: 'nuget_credential_rebound',
        reason:
          `not restored: ${rel(feed.file.path)} points the NuGet feed "${feed.key}" at ${urlHost(feed.value)}, and you hold a ` +
          `credential for a feed of that name (${where})${own !== undefined ? ' on another server' : ''} — NuGet binds a ` +
          'credential to the name, so the restore would send it there',
      };
    }
  }
  return null;
}
