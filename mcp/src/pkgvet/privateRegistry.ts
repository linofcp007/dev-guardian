/**
 * Could anything OTHER than "it does not exist" explain a 404 from the
 * public registry?
 *
 * The vetting may DENY a name the public registry has never heard of — that
 * is how a hallucinated dependency is caught before anyone squats it. But a
 * company's own packages are ALSO absent from the public registry, by
 * design, and so are a monorepo's own workspace packages. When this file
 * finds an explanation, "not on the public registry" stops being evidence
 * of anything: the verdict becomes `unknown` (with this file's answer as the
 * reason) and never `block`. Three kinds (the controller ruling's (d)-(f)):
 *
 *   - `registry`  — a custom registry / index / source is configured;
 *   - `auth`      — an npmjs credential is configured and the name is
 *                   scoped: a private scoped package answers 404 anonymously;
 *   - `workspace` — the name is a local workspace package (package.json
 *                   `workspaces`, `pnpm-workspace.yaml`, uv workspace members
 *                   or `[tool.uv.sources]`; composer path repositories are
 *                   already `repositories`).
 *
 * Where `registry` is looked for, per ecosystem:
 *
 *   - npm / pnpm / yarn / bun: `registry=` (all names) or `@scope:registry=`
 *     (that scope) in a project `.npmrc`, the user npmrc
 *     (`NPM_CONFIG_USERCONFIG` or `~/.npmrc`), npm's global npmrc when
 *     `npm_config_globalconfig` names it, and pnpm's global rc (XDG,
 *     `%LOCALAPPDATA%\pnpm\config\rc`, macOS); `NPM_CONFIG_REGISTRY`;
 *     yarn's `.yarnrc.yml` `npmRegistryServer` (global or under
 *     `npmScopes.<scope>`, project or `~`) and classic `.yarnrc`
 *     `registry`; bun's `bunfig.toml` (project or `~/.bunfig.toml`)
 *     `[install] registry` / `[install.scopes]`.
 *   - pip / uv / poetry: `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`,
 *     `UV_INDEX_URL`, `UV_EXTRA_INDEX_URL`, `UV_INDEX`, `UV_DEFAULT_INDEX`,
 *     `PIP_FIND_LINKS`, `PIP_NO_INDEX`; `pip.conf` / `pip.ini` (user, venv,
 *     `PIP_CONFIG_FILE`, and global: `/etc/pip.conf`,
 *     `/etc/xdg/pip/pip.conf`, `XDG_CONFIG_DIRS`, `%ProgramData%\pip\pip.ini`);
 *     `uv.toml` (`UV_CONFIG_FILE`, `~/.config/uv`, `%APPDATA%\uv`,
 *     `/etc/uv`, and the project); `[[tool.uv.index]]`,
 *     `[[tool.poetry.source]]`, `[[tool.pdm.source]]` or a `[tool.uv]`
 *     index URL in `pyproject.toml`.
 *   - Composer: a `repositories` entry in the project `composer.json` or the
 *     user's global `config.json`.
 *   - NuGet: any `nuget.config` (any casing) from the project up to the
 *     repository root, or the user-level one, with a package source that is
 *     not nuget.org.
 *
 * Round 2 additions: npm's DEFAULT global npmrc (`%APPDATA%\npm\etc\npmrc`,
 * or `<node prefix>/etc/npmrc` from `process.execPath`, or
 * `npm_config_prefix`); macOS pip (`~/Library/Application Support/pip`);
 * every `nuget.config` up to the filesystem root, as NuGet itself reads
 * them; and the hook's environment, matched case-insensitively —
 * `YARN_NPM_REGISTRY_SERVER`, `YARN_REGISTRY`, `BUN_CONFIG_REGISTRY`,
 * `npm_config_*registry*` (incl. `npm_config_@scope:registry`),
 * `PIP_*INDEX*`, `UV_*INDEX*`, `NUGET_*`.
 *
 * A configured value that IS the public registry (`registry.npmjs.org`,
 * `pypi.org/simple`, `api.nuget.org`) is not custom.
 *
 * Reads files only (node built-ins); never the network. A file reached through
 * a link to a network or device path is refused before it is opened
 * (`walkRoot`, follow-up Part Y), as the hook configuration is. A
 * configuration that is THERE but could not be read — refused that way, or not
 * a regular file, too large, no permission — is UNKNOWN, never absent: when
 * nothing else explains the 404 it is reported as `unreadable` (Part Y fix
 * round 1, controller ruling), so a missing name warns instead of being denied.
 */

import { lstatSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join, parse, relative, resolve } from 'node:path';
import { climbsOut, isRemoteOrDeviceTarget, readSmallText, walkLinksUnder, type TextRead } from '../hooks/configFile.js';
import { withCommentAt } from './strayAt.js';
import type { PkgEcosystem } from './types.js';

/**
 * What the lookups of one hook call (or one `vet_packages` call) share, so
 * that each file is read and each workspace walked once however many
 * packages are looked up (review I4: a 3000-directory workspace was walked
 * once PER PACKAGE, and 17 packages took 16.5 s — past the hook's 15 s).
 */
interface RegistryCache {
  /** A file's read, by path and the directory its links were walked below. */
  reads: Map<string, TextRead>;
  /** The package names under a workspace root, by manifest file name and root. */
  workspaces: Map<string, WorkspaceIndex>;
}

/** Every manifest name under a workspace root, the first path for each (breadth-first, like the walk it replaces). */
interface WorkspaceIndex {
  names: Map<string, string>;
  /** The first manifest or directory there that could not be read. */
  unread?: { path: string; what: UnreadKind };
  /** The walk stopped early: at {@link MAX_SCAN_DIRS} directories, or at the deadline. */
  cut?: 'size' | 'time';
}

/** A fresh cache for one call. */
export function registryCache(): RegistryCache {
  return { reads: new Map(), workspaces: new Map() };
}

export interface RegistryContext {
  projectDir?: string | undefined;
  /** User home. Defaults to `os.homedir()`. */
  homeDir?: string | undefined;
  /** Defaults to `process.env`. Tests pass an explicit object. */
  env?: Readonly<Record<string, string | undefined>> | undefined;
  /** System configuration root (`/etc`). Tests point it at a temp directory. */
  etcDir?: string | undefined;
  /** Defaults to `process.platform` (decides where npm's default global npmrc lives). */
  platform?: NodeJS.Platform | undefined;
  /** Defaults to `process.execPath`; on POSIX npm's global npmrc is `<its prefix>/etc/npmrc`. */
  nodeExecPath?: string | undefined;
  /** macOS's system `/Library` (pip's and NuGet's machine-wide configuration). Tests point it at a temp directory. */
  systemLibraryDir?: string | undefined;
  /** Shared by every lookup of one call; each lookup reads everything again without it. */
  cache?: RegistryCache | undefined;
  /**
   * Epoch ms past which a workspace walk stops. What it did not read is then
   * unknown, never absent: a name not found in it reads `unchecked`.
   */
  deadlineAt?: number | undefined;
  /**
   * The command the lookups are made for. Present, it decides which project files are obeyed: the bun's `bunfig.toml` and `.env`
   * files for a bun command, and the pairs (command by file) in which the manager does not obey a file it would otherwise be
   * said to. Absent (`vet_packages`, the lockfile and manifest lookups of tools), every file is read as before it existed.
   */
  command?: RegistryCommand | undefined;
}

/**
 * What a lookup needs of the install command (`InstallCommand` of `parseCommand.ts`, which this module does not import):
 * the manager as the parse names it, the form it was written in when it is one of the eight that were measured, whether the
 * install is global for certain, and the two things that stop the bun reading its `.env` files.
 */
export interface RegistryCommand {
  manager: string;
  registryForm?: string | undefined;
  global: boolean;
  envFileFlag: boolean;
  bunLauncher: boolean;
}

/**
 * Why a name missing from the PUBLIC registry is not evidence of anything:
 *
 *   - `registry` — a custom registry / index / source is configured (ruling (d));
 *   - `auth`     — an npmjs auth token is configured, and a PRIVATE scoped
 *                  package on npmjs answers 404 to an anonymous lookup (ruling (e));
 *   - `workspace`— the name is a local workspace package (ruling (f));
 *   - `unreadable` — nothing above was found, but a registry configuration
 *                  file or directory is THERE and was not read (a link to a
 *                  network or device path, a loop, not a regular file, too
 *                  large, no permission). It may name a private registry, so
 *                  it is unknown, never absent (Part Y fix round 1, controller
 *                  ruling).
 */
export type CustomRegistry = Explained | NotRead;

interface RegistryFields {
  /** Where it was found: a file path or an environment variable name. */
  source: string;
  url?: string;
  /** For `unreadable`: what `source` is (fix round 2) — named in the warning. */
  what?: UnreadKind;
  /** For `unchecked`: why the workspace at `source` was not read to its end — too many directories, or the deadline. */
  cut?: 'size' | 'time';
}

/**
 * A registry, credential or workspace that explains the 404 (the other two kinds below). `from` says whose word it is: `project` for a
 * file of the project (a folder up to the repository root, a file inside the project folder such as the `pip.conf` of its virtual
 * environment, a `.yarnrc.yml` above the root, a `.env`), `user` for the hook's environment, the command line and the files of the
 * user and of the machine. When a file of the project explains the 404 first the search goes on, and this is `user` if any of the
 * user's explains too. Required, so that no path leaves it unset and is read as `user`.
 */
interface Explained extends RegistryFields {
  /**
   * `unchecked` — nothing above was found, but a workspace was not read to its
   * end: it has more than {@link MAX_SCAN_DIRS} directories, or the vetting
   * deadline came first (review I4). `source` then says which.
   */
  kind: 'registry' | 'auth' | 'workspace';
  from: 'project' | 'user';
}

/** What could not be read or checked says nothing of whose word it is: it keeps every refusal, whoever's the file. */
interface NotRead extends RegistryFields {
  kind: 'unreadable' | 'unchecked';
  from?: undefined;
}

/** The most directories a workspace walk reads (exported for the warning's wording). */
export const MAX_WORKSPACE_DIRS = 3000;

/** What an unread path was: a registry configuration file, a workspace manifest, or a directory that could not be listed. */
type UnreadKind = 'configuration' | 'workspace manifest' | 'directory';

/** The public registry's host names, per ecosystem: exactly these, lower case. */
const PUBLIC_HOSTS: Record<PkgEcosystem, readonly string[]> = {
  npm: ['registry.npmjs.org', 'registry.npmjs.com', 'registry.yarnpkg.com'],
  pypi: ['pypi.org', 'pypi.python.org', 'files.pythonhosted.org'],
  packagist: ['packagist.org', 'repo.packagist.org'],
  nuget: ['api.nuget.org', 'www.nuget.org', 'nuget.org'],
};

/** Backslash, white space and control characters: a URL parser may read these differently from the package manager. */
const UNSAFE_TEXT = /[\\\s\u0000-\u001f\u007f]/;

/**
 * The scheme (`http`, `https` or `''` for `//host`), host and port of a value of the form
 * `[http: | https:]//host[:port][/…]`. The authority is the text up to the first `/`, `?` or `#`: a host and a
 * digits-only port (an empty one is the default, as parsers read it), so credentials (an `@`) never match.
 */
const URL_SHAPE = /^(?:(https?):)?\/\/([^/?#@:]+)(?::(\d*))?(?:[/?#]|$)/i;

/**
 * Whether `url` is the ecosystem's public registry, decided on the host the package manager would contact, read
 * from the TEXT (a hand-written reading, not `new URL`: the parser silently drops tabs and line breaks and turns
 * a backslash into a slash, which is how `https://pypi.org\@evil.example/` would pass). Only the host, in lower case,
 * and the scheme's own port — 443 for `https:` and `//host`, 80 for `http:` — are accepted; `http:` still counts
 * (for "does another registry explain a 404" it is the same registry, and for "does this scope keep its names off
 * the public registry" the package manager itself sends them there); credentials, another port and any other host do not.
 */
function isPublic(ecosystem: PkgEcosystem, url: string): boolean {
  const text = url.trim().replace(/^["']|["']$/g, '');
  if (UNSAFE_TEXT.test(text)) return false;
  const m = URL_SHAPE.exec(text);
  if (m === null) return false;
  const scheme = (m[1] ?? '').toLowerCase();
  const port = m[3];
  if (port !== undefined && port !== '' && port !== (scheme === 'http' ? '80' : '443')) return false;
  return PUBLIC_HOSTS[ecosystem].includes((m[2] ?? '').toLowerCase());
}

/** True when `url` is the ecosystem's own public registry (so naming it changes nothing). */
export function isPublicRegistryUrl(ecosystem: PkgEcosystem, url: string): boolean {
  return isPublic(ecosystem, url);
}

/**
 * The largest registry configuration file read. These reads run inside the
 * install hook's 15 s budget: a FIFO or a device where `.npmrc` belongs is
 * opened non-blocking and refused on its descriptor, never read, and an
 * absurd file is never read (Task 23 fix round 2, N1) — see
 * `hooks/configFile.ts`. A file refused here is UNKNOWN — see `unreadable`.
 */
const MAX_REGISTRY_CONFIG_BYTES = 1024 * 1024;

/** `path` lies strictly below `dir`. */
function isInside(dir: string, path: string): boolean {
  const rel = relative(dir, path);
  return rel !== '' && !climbsOut(rel) && !isAbsolute(rel);
}

/**
 * The directory below which `path`'s components are walked for a link to a
 * network or device path before anything is opened (`walkLinksUnder`, as for
 * the hook configuration — follow-up Part Y): the project when the file is in
 * it; the file's own directory when that is one of the project's ancestors (a
 * parent `.npmrc`, a `nuget.config` up to the root); the home directory when
 * the file is in there; otherwise the filesystem root (`/etc/pip.conf`,
 * `%ProgramData%\pip\pip.ini`). Never the project or the home directory
 * themselves, nor their ancestors: those are the user's layout, and a project
 * that lives on a share through a link must keep its configuration readable —
 * so listing one of them is `undefined`, no walk; so is a path that itself
 * names a share (a roaming profile's `%APPDATA%`), the user's setting rather
 * than a link to judge.
 */
function walkRoot(path: string, ctx: RegistryContext, under?: string): string | undefined {
  const abs = resolve(path);
  if (isRemoteOrDeviceTarget(abs)) return undefined;
  if (under !== undefined) return under;
  /** `dir` is `base` or one of its ancestors. */
  const holds = (dir: string, base: string): boolean => samePath(dir, base) || isInside(dir, base);
  const project = ctx.projectDir === undefined ? undefined : resolve(ctx.projectDir);
  const home = resolve(homeOf(ctx));
  if ((project !== undefined && holds(abs, project)) || holds(abs, home)) return undefined;
  if (project !== undefined && isInside(project, abs)) return project;
  const dir = dirname(abs);
  if (project !== undefined && holds(dir, project)) return dir;
  if (isInside(home, abs)) return home;
  return parse(abs).root;
}

/**
 * The first registry configuration path the current `customRegistryFor` call
 * found THERE but could not read. Reset at the start of each (synchronous)
 * call and read at its end: when nothing else explains a 404, this does.
 */
let firstUnread: { path: string; what: UnreadKind } | undefined;

function noteUnread(path: string, what: UnreadKind): void {
  firstUnread = firstUnread ?? { path, what };
}

/** The recorded unread path, cleared for the next call. */
function takeUnread(): { path: string; what: UnreadKind } | undefined {
  const unread = firstUnread;
  firstUnread = undefined;
  return unread;
}

/**
 * The first workspace the current `customRegistryFor` call could not read to
 * its end, and why; reset and read like {@link firstUnread}.
 */
let firstUnchecked: { root: string; cut: 'size' | 'time' } | undefined;

/** The recorded workspace, cleared for the next call. */
function takeUnchecked(): { root: string; cut: 'size' | 'time' } | undefined {
  const unchecked = firstUnchecked;
  firstUnchecked = undefined;
  return unchecked;
}

/**
 * A registry configuration file's text, or `undefined`. A link on the way to
 * a network or device path (`\\host\share`, `\\?\…`) — the file itself or a
 * directory above it, below {@link walkRoot} — refuses the file unopened: an
 * open through a link to an unreachable host waits on the network for minutes,
 * and a hook that dies at its 15 s timeout lets the install through unvetted.
 * A refused file is recorded ({@link noteUnread}); an absent one is not — and
 * so is one read from the call's cache, the same way as the first time.
 */
function read(path: string, ctx: RegistryContext, under?: string, what: UnreadKind = 'configuration'): string | undefined {
  const r = readRaw(path, ctx, under);
  if (r.status === 'refused') noteUnread(path, what);
  return r.status === 'ok' ? r.text : undefined;
}

/** {@link read} without the note: the whole read, from the call's cache when it is there. */
function readRaw(path: string, ctx: RegistryContext, under?: string): TextRead {
  const root = walkRoot(path, ctx, under);
  const key = `${path}\u0000${root ?? ''}`;
  let r = ctx.cache?.reads.get(key);
  if (r === undefined) {
    r = readSmallText(path, MAX_REGISTRY_CONFIG_BYTES, root);
    ctx.cache?.reads.set(key, r);
  }
  return r;
}

/**
 * The text of a `.env` file of the bun, by the same cache and the same bounded reader as {@link read}. A path that is not a regular
 * file (the folder of a Python virtual environment named `.env`, a FIFO) is no file: absent, and not noted. Anything else that is
 * there and is not read — too large, no permission, behind a link to the network — is configuration that was not read, as for the
 * other registry files. Never throws: an exception is "no `.env`".
 */
function readEnvFile(path: string, ctx: RegistryContext): string | undefined {
  try {
    const r = readRaw(path, ctx);
    if (r.status === 'refused' && r.reason !== 'not-a-regular-file') noteUnread(path, 'configuration');
    return r.status === 'ok' ? r.text : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Whether `path` exists, WITHOUT following a link at it: `lstat` never touches
 * a link's target, where `existsSync` would open a `.git` linked to a share.
 */
function present(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch {
    return false;
  }
}

/**
 * The entries of `dir` — none when it does not exist, and none, recorded as
 * unread ({@link noteUnread}), when a link on the way to it points at a network
 * or device path or it cannot be listed.
 */
function listDir(dir: string, ctx: RegistryContext): string[] {
  const under = walkRoot(dir, ctx);
  if (under !== undefined && !walkLinksUnder(under, dir).ok) {
    noteUnread(dir, 'directory');
    return [];
  }
  try {
    return readdirSync(dir);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code !== 'ENOENT' && code !== 'ENOTDIR') noteUnread(dir, 'directory');
    return [];
  }
}

function samePath(a: string, b: string): boolean {
  const norm = (p: string): string => resolve(p).replace(/[\\/]+$/, '');
  return process.platform === 'win32' ? norm(a).toLowerCase() === norm(b).toLowerCase() : norm(a) === norm(b);
}

/**
 * The project directory and its ancestors, nearest first — up to and
 * including the first one holding `.git`, and never the user's home (that
 * is read separately, as user-level configuration) or anything above it.
 */
function ancestors(ctx: RegistryContext): string[] {
  if (ctx.projectDir === undefined) return [];
  const stops = [ctx.homeDir, homedir()].filter((x): x is string => typeof x === 'string');
  const out: string[] = [];
  let dir = resolve(ctx.projectDir);
  for (let i = 0; i < 16; i += 1) {
    if (stops.some((s) => samePath(s, dir))) break;
    out.push(dir);
    if (present(join(dir, '.git'))) break;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return out;
}

/**
 * The root of the git repository the project directory is in — the first of {@link ancestors} that holds a `.git` (a
 * directory, or a file as in a worktree or a submodule) — or `undefined`: no repository, or one above the user's home,
 * 16 directories up or more. The same limits as the registry files', so both walks agree on the project.
 */
export function gitRepositoryRoot(ctx: RegistryContext): string | undefined {
  const top = ancestors(ctx).at(-1);
  return top !== undefined && present(join(top, '.git')) ? top : undefined;
}

function envOf(ctx: RegistryContext): Readonly<Record<string, string | undefined>> {
  return ctx.env ?? process.env;
}

function homeOf(ctx: RegistryContext): string {
  return ctx.homeDir ?? homedir();
}

function envValue(env: Readonly<Record<string, string | undefined>>, name: string): string | undefined {
  const v = env[name] ?? env[name.toLowerCase()];
  return v !== undefined && v.trim() !== '' ? v.trim() : undefined;
}

// ─────────────────────────────────────────────────────────────── npm

function npmScope(name: string): string | undefined {
  const m = /^@([^/]+)\//.exec(name);
  return m?.[1];
}

/**
 * An `.npmrc` value as npm, pnpm, Yarn 1 and bun read it: it ends at the first `;` or `#` outside quotes (an inline
 * comment), and one pair of surrounding quotes is taken off. A value with a backslash (ini escapes) is not cut: it
 * is handed over whole, and {@link isPublic} then reads it as another registry.
 */
function npmrcValue(raw: string): string {
  const value = raw.trim();
  if (value.includes('\\')) return value;
  let quote: string | undefined;
  let end = value.length;
  for (let i = 0; i < value.length; i += 1) {
    const ch = value.charAt(i);
    if (quote !== undefined) {
      if (ch === quote) quote = undefined;
    } else if (ch === '"' || ch === "'") quote = ch;
    else if (ch === ';' || ch === '#') {
      end = i;
      break;
    }
  }
  return withCommentAt(value.slice(0, end).trim().replace(/^(["'])(.*)\1$/, '$2'), value.slice(end));
}

/** What a registry value the reader cannot judge is read as: never the public registry (as `fromBunfig`'s). */
const UNREADABLE_VALUE = '(configured)';

/**
 * A `.yarnrc.yml` `npmRegistryServer` value, when it is a PLAIN SINGLE-LINE scalar; otherwise `(configured)`, which
 * is never the public registry. YAML has more spellings than a URL has: a doubled quote in a single-quoted scalar,
 * an escape in a double-quoted one, and a scalar continued on a more indented line all reach a host that the first
 * characters do not show (measured with Yarn 4.18.1). So:
 *   - quoted: the closing quote of the same kind ends the value, and only white space or a ` #` comment follows it;
 *     the content has no quote of that kind and no backslash;
 *   - unquoted: it does not start with a quote and ends at a ` #` comment;
 *   - and the next line that is neither blank nor a comment is not more indented than the key (a continuation).
 */
function yamlServer(lines: string[], at: number, keyIndent: number, raw: string): string {
  const next = lines.slice(at + 1).find((l) => l.trim() !== '' && !l.trim().startsWith('#'));
  if (next !== undefined && next.length - next.trimStart().length > keyIndent) return UNREADABLE_VALUE;
  const value = raw.trim();
  const quote = value.charAt(0);
  if (quote === '"' || quote === "'") {
    const close = value.indexOf(quote, 1);
    if (close < 0) return UNREADABLE_VALUE;
    const content = value.slice(1, close);
    const rest = value.slice(close + 1);
    if (content.includes('\\') || (rest.trim() !== '' && !/^\s+#/.test(rest))) return UNREADABLE_VALUE;
    return withCommentAt(content, rest);
  }
  const comment = value.search(/\s#/);
  return comment === -1 ? value.trim() : withCommentAt(value.slice(0, comment).trim(), value.slice(comment));
}

/** `.npmrc`: `registry=` and `@scope:registry=`. A key repeated in the file is read at its LAST line, as the managers do. */
function fromNpmrc(text: string, scope: string | undefined, all?: string[]): string | undefined {
  let found: string | undefined;
  let scoped: string | undefined;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith('#') || line.startsWith(';')) continue;
    const m = /^(@[^:=\s]+:)?registry\s*=\s*(.+)$/i.exec(line);
    if (m === null) continue;
    const lineScope = m[1]?.slice(1, -1);
    const url = npmrcValue(m[2] ?? '');
    all?.push(url);
    if (lineScope === undefined) found = url;
    else if (scope !== undefined && lineScope.toLowerCase() === scope.toLowerCase()) scoped = url;
  }
  return scoped ?? found;
}

/** yarn berry `.yarnrc.yml`: top-level `npmRegistryServer`, or `npmScopes.<scope>.npmRegistryServer`; the last of a repeated key. */
function fromYarnrcYml(text: string, scope: string | undefined, all?: string[]): string | undefined {
  let global: string | undefined;
  let scoped: string | undefined;
  let inScopes = false;
  let currentScope: string | undefined;
  const lines = text.split(/\r?\n/);
  for (const [at, raw] of lines.entries()) {
    if (raw.trim() === '' || raw.trim().startsWith('#')) continue;
    const indent = raw.length - raw.trimStart().length;
    const line = raw.trim();
    if (indent === 0) {
      inScopes = /^npmScopes\s*:/.test(line);
      currentScope = undefined;
      const m = /^npmRegistryServer\s*:\s*(.+)$/.exec(line);
      if (m !== null) global = yamlServer(lines, at, indent, m[1] ?? '');
      if (m !== null) all?.push(global ?? '');
      continue;
    }
    if (!inScopes) continue;
    const scopeKey = /^["']?@?([^"':]+)["']?\s*:\s*$/.exec(line);
    if (scopeKey !== null) {
      currentScope = scopeKey[1];
      continue;
    }
    const server = /^npmRegistryServer\s*:\s*(.+)$/.exec(line);
    if (server !== null) all?.push(yamlServer(lines, at, indent, server[1] ?? ''));
    if (server !== null && scope !== undefined && currentScope?.toLowerCase() === scope.toLowerCase()) {
      scoped = yamlServer(lines, at, indent, server[1] ?? '');
    }
  }
  return scoped ?? global;
}

/** yarn classic `.yarnrc`: `registry "url"` / `"@scope:registry" "url"`. */
function fromYarnrc(text: string, scope: string | undefined, all?: string[]): string | undefined {
  let found: string | undefined;
  let scoped: string | undefined;
  for (const raw of text.split(/\r?\n/)) {
    const m = /^\s*["']?(@[^:"']+:)?registry["']?\s+["']?([^"'\s]+)["']?/.exec(raw);
    if (m === null) continue;
    const lineScope = m[1]?.slice(1, -1);
    const value = withCommentAt(m[2] ?? '', raw.slice(m[0].length));
    all?.push(value);
    if (lineScope === undefined) found = value;
    else if (scope !== undefined && lineScope.toLowerCase() === scope.toLowerCase()) scoped = value;
  }
  return scoped ?? found;
}

/** bun `bunfig.toml`: `[install] registry = …` and `[install.scopes] <scope> = …`. */
function fromBunfig(text: string, scope: string | undefined, all?: string[]): string | undefined {
  let section = '';
  let found: string | undefined;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header !== null) {
      section = (header[1] ?? '').trim();
      continue;
    }
    const match = /https?:\/\/[^"'\s}]+/.exec(line);
    // An unquoted value ends at a space: what follows may be the rest of a credential written after a `#`.
    const unquoted = match !== null && !/["']/.test(line.charAt(match.index - 1));
    const url = match === null ? '(configured)' : withCommentAt(match[0], unquoted ? line.slice(match.index + match[0].length) : '');
    if (section === 'install' && /^registry\s*=/.test(line)) {
      all?.push(url);
      found = found ?? url;
    }
    if (section === 'install.scopes' && /^["']?@?[^"'=\s]+["']?\s*=/.test(line)) all?.push(url);
    if (section === 'install.scopes' && scope !== undefined) {
      const key = /^["']?@?([^"'=\s]+)["']?\s*=/.exec(line)?.[1];
      if (key !== undefined && key.toLowerCase() === scope.toLowerCase()) return url;
    }
  }
  return found;
}

/**
 * What a reader of the bun's files found: the value as the line gives it (an `http(s)` URL cut as {@link fromBunfig} cuts it, or
 * {@link UNREADABLE_VALUE}), and whether it explains a name missing from the public registry. A value of the new readers that is
 * not a URL (`$VARIABLE`, an unclosed quote) is only said, in the line: the bun may resolve it to the public registry.
 */
interface Found {
  url: string;
  explains: boolean;
}

/** `https://…` as the new readers take a value: a URL of the http(s) scheme as a whole word, anything else is not read. */
function urlOrConfigured(value: string): string {
  return /^https?:\/\/\S+$/i.test(value) ? value : UNREADABLE_VALUE;
}

/** The scope a header or key of `bunfig.toml` names, without its `@` and in lower case, or undefined when the text is no scope. */
function bunScopeKey(text: string): string | undefined {
  return /^@?[A-Za-z0-9._-]+$/.test(text) ? text.replace(/^@/, '').toLowerCase() : undefined;
}

/** The scope of a header `install.scopes."<s>"`, `install.scopes.'<s>'` or `install.scopes.<s>` (no `@`, no `.`): a subtable. */
function scopeOfSubtable(header: string): string | undefined {
  const quoted = /^install\.scopes\.(["'])([^"']+)\1$/.exec(header);
  if (quoted !== null) return bunScopeKey(quoted[2] ?? '');
  const bare = /^install\.scopes\.([A-Za-z0-9_-]+)$/.exec(header);
  return bare === null ? undefined : bunScopeKey(bare[1] ?? '');
}

/** The value of a `bunfig.toml` line, as {@link fromBunfig} reads it. */
function bunfigValue(line: string): string {
  const match = /https?:\/\/[^"'\s}]+/.exec(line);
  // An unquoted value ends at a space: what follows may be the rest of a credential written after a `#`.
  const unquoted = match !== null && !/["']/.test(line.charAt(match.index - 1));
  return match === null ? UNREADABLE_VALUE : withCommentAt(match[0], unquoted ? line.slice(match.index + match[0].length) : '');
}

/**
 * `bunfig.toml` for a bun command that is not global: a closed grammar of the two forms of {@link fromBunfig} and three more,
 * measured with the bun 1.4.4 — `install.registry = <v>` before any header, `url = <v>` under the exact header `[install.registry]`,
 * and `url = <v>` under `[install.scopes."<s>"]`, `[install.scopes.'<s>']` or `[install.scopes.<s>]` (the registry of scope `<s>`).
 * Other keys of those tables (`token`, `username`, `password`) are never read. The default registry is the FIRST of the forms in
 * the file; for a `scope` the first line that names it, else the default. A value of the new forms that is no URL is only said.
 * The two old forms keep their reading, `(configured)` included. Never throws: an exception is what the old reader answers.
 */
function bunfigFound(text: string, scope: string | undefined): Found | undefined {
  try {
    const wanted = scope?.toLowerCase();
    let section = '';
    let exact = '';
    let header = false;
    let found: Found | undefined;
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim();
      const head = /^\[([^\]]+)\]$/.exec(line);
      if (head !== null) {
        header = true;
        exact = head[1] ?? '';
        section = exact.trim();
        continue;
      }
      if (line === '' || line.startsWith('#')) continue;
      if (section === 'install' && /^registry\s*=/.test(line)) found = found ?? { url: bunfigValue(line), explains: true };
      else if (!header && /^install\.registry\s*=/.test(line)) found = found ?? newForm(bunfigValue(line));
      else if (exact === 'install.registry' && /^url\s*=/.test(line)) found = found ?? newForm(bunfigValue(line));
      else if (wanted !== undefined) {
        if (section === 'install.scopes') {
          const key = /^["']?@?([^"'=\s]+)["']?\s*=/.exec(line)?.[1];
          if (key !== undefined && key.toLowerCase() === wanted) return { url: bunfigValue(line), explains: true };
        } else if (/^url\s*=/.test(line) && scopeOfSubtable(exact) === wanted) return newForm(bunfigValue(line));
      }
    }
    return found;
  } catch {
    return undefined;
  }

  function newForm(url: string): Found {
    return { url, explains: url !== UNREADABLE_VALUE };
  }
}

/** The names of the registry variables of a `.env` the bun reads: the three, exactly. */
const BUN_ENV_NAMES: ReadonlySet<string> = new Set(['BUN_CONFIG_REGISTRY', 'NPM_CONFIG_REGISTRY', 'npm_config_registry']);

/**
 * The registry a `.env` of the bun gives, by a closed grammar read line by line (the text comes without its byte order mark, and
 * `\r\n` ends a line like `\n`): spaces, an optional `export `, the exact name of one of {@link BUN_ENV_NAMES}, spaces, `=`, spaces and
 * the value — unquoted (up to the first space, with no quote, backtick, backslash, `$` or `#`), in `"…"` (no `"`, `\` or `$` inside),
 * in `'…'` (no `'` inside) or in backticks (no backtick, `\` or `$` inside) — and then only spaces, or a space and a `#` comment.
 * An empty value does not count. A value of those names in any other form is {@link UNREADABLE_VALUE}. Any other line is ignored,
 * and so is every line inside a value that another variable opens with `"`, `'` or a backtick and does not close on its line, up to
 * the first line that holds that character (measured: the bun does not obey a registry line inside such a value). Of the values
 * that are not the public registry, `BUN_CONFIG_REGISTRY`'s last wins, else the last of the other two (measured). Nothing of the file
 * but that value is returned, and it is the value as written: a URL is judged and cut by the caller. Linear in the text.
 */
function bunEnvValue(text: string): string | undefined {
  let open: string | undefined;
  let bun: string | undefined;
  let other: string | undefined;
  for (const raw of text.split(/\r?\n/)) {
    if (open !== undefined) {
      if (raw.includes(open)) open = undefined;
      continue;
    }
    const assignment = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/.exec(raw);
    if (assignment === null) continue;
    const name = assignment[1] ?? '';
    const rest = assignment[2] ?? '';
    const first = rest.charAt(0);
    let value: string | undefined;
    if (first === '"' || first === "'" || first === '`') {
      const close = rest.indexOf(first, 1);
      if (close < 0) {
        open = first;
        value = UNREADABLE_VALUE;
      } else {
        const content = rest.slice(1, close);
        const bad = first !== "'" && (content.includes('\\') || content.includes('$'));
        value = bad || !endsCleanly(rest.slice(close + 1)) ? UNREADABLE_VALUE : content === '' ? undefined : urlOrConfigured(content);
      }
    } else {
      let end = 0;
      while (end < rest.length && rest.charAt(end) !== ' ' && rest.charAt(end) !== '\t') end += 1;
      const token = rest.slice(0, end);
      if (token === '' || token.startsWith('#')) value = undefined;
      else if (/["'`\\$#]/.test(token) || !endsCleanly(rest.slice(end))) value = UNREADABLE_VALUE;
      else value = urlOrConfigured(token);
    }
    if (!BUN_ENV_NAMES.has(name) || value === undefined) continue;
    if (value !== UNREADABLE_VALUE && isPublic('npm', value)) continue;
    if (name === 'BUN_CONFIG_REGISTRY') bun = value;
    else other = value;
  }
  return bun ?? other;

  /** What follows a value: only spaces, or a space and a `#` comment. */
  function endsCleanly(tail: string): boolean {
    const t = tail.trimStart();
    return t === '' || (t !== tail && t.startsWith('#'));
  }
}

/** The modes of the bun's `.env` files: `NODE_ENV` when it is `development` or `test`, `production` for any other value, set or not. */
function bunMode(ctx: RegistryContext): 'development' | 'test' | 'production' {
  const v = envOf(ctx)['NODE_ENV'];
  return v === 'development' || v === 'test' ? v : 'production';
}

/** The `.env` files of one folder the bun reads, highest precedence first: `.env.<mode>.local`, `.env.local` (not in `test`), `.env.<mode>`, `.env`. */
function bunEnvNames(mode: string): string[] {
  return [`.env.${mode}.local`, ...(mode === 'test' ? [] : ['.env.local']), `.env.${mode}`, '.env'];
}

/** Whether one entry of `workspaces` lists the folder `rel` (below the root, written with `/`), or the reader cannot tell. */
function judgeWorkspaceEntry(entry: unknown, rel: string): 'yes' | 'no' | 'unknown' {
  if (typeof entry !== 'string' || entry === '' || entry.startsWith('!') || entry.startsWith('./')) return 'unknown';
  // A trailing `/` is not the exact path of the folder (not measured): not judged.
  if (entry.endsWith('/') && !entry.endsWith('/*') && !entry.endsWith('/**')) return 'unknown';
  let body = entry;
  let kind: 'exact' | 'star' | 'globstar' = 'exact';
  if (entry.endsWith('/**')) {
    body = entry.slice(0, -3);
    kind = 'globstar';
  } else if (entry.endsWith('/*')) {
    body = entry.slice(0, -2);
    kind = 'star';
  }
  if (body === '' || /[*?[\]{}()!+@\\]/.test(body) || body.split('/').some((seg) => seg === '' || seg === '.' || seg === '..')) return 'unknown';
  if (kind === 'exact') return body === rel ? 'yes' : 'no';
  if (!rel.startsWith(`${body}/`)) return 'no';
  return kind === 'globstar' || !rel.slice(body.length + 1).includes('/') ? 'yes' : 'no';
}

/** Whether the `workspaces` of a `package.json` list the folder `rel`: yes, no, or the reader cannot tell (an entry it does not judge and none that lists). */
function workspacesList(packageJson: string | undefined, rel: string): 'yes' | 'no' | 'unknown' {
  if (packageJson === undefined) return 'no';
  try {
    const w = (JSON.parse(packageJson) as { workspaces?: unknown }).workspaces;
    const entries: unknown = Array.isArray(w) ? w : w !== null && typeof w === 'object' ? (w as { packages?: unknown }).packages : undefined;
    if (!Array.isArray(entries)) return 'no';
    const verdicts = (entries as unknown[]).map((e) => judgeWorkspaceEntry(e, rel));
    return verdicts.includes('yes') ? 'yes' : verdicts.includes('unknown') ? 'unknown' : 'no';
  } catch {
    return 'no';
  }
}

/**
 * The folders whose `.env` files the bun reads for this command, and whether what they say can explain a missing name. Only for a
 * bun command that is not global, has no `--env-file` / `--no-env-file`, and is not a launcher (`bunx`, `bun x`, `bun create`, `bun c`:
 * `bun x` measured not to read any, the others by the bun's documentation); `undefined` for any other.
 *
 * One folder, never above the repository root nor the home directory: the root of the bun — the nearest folder, from that of the nearest
 * `package.json`, whose `workspaces` list that folder (an exact path, `<prefix>/*` one level below, `<prefix>/**` at any depth below);
 * else that folder; with no `package.json`, the command's. A root with an entry the reader does not judge and no entry that lists
 * the folder gives both its `.env` files and the folder's, only to be said: none explains a name (the refusal stays).
 */
function bunEnvPlan(ctx: RegistryContext): { dirs: string[]; explains: boolean } | undefined {
  const cmd = ctx.command;
  if (cmd === undefined || cmd.manager !== 'bun' || cmd.global || cmd.envFileFlag || cmd.bunLauncher) return undefined;
  try {
    const near = ancestors(ctx);
    const first = near.findIndex((dir) => present(join(dir, 'package.json')));
    const base = near[first < 0 ? 0 : first];
    if (base === undefined) return undefined;
    if (first < 0) return { dirs: [base], explains: true };
    let unsure: string | undefined;
    for (const dir of near.slice(first + 1)) {
      const listed = workspacesList(read(join(dir, 'package.json'), ctx, undefined, 'workspace manifest'), relative(dir, base).split(/[\\/]/).join('/'));
      if (listed === 'yes') return { dirs: [dir], explains: true };
      if (listed === 'unknown' && unsure === undefined) unsure = dir;
    }
    return unsure === undefined ? { dirs: [base], explains: true } : { dirs: [unsure, base], explains: false };
  } catch {
    return undefined;
  }
}

/** What a `.env` file gives as {@link Found}: its value, which explains when it is a URL and the folders' plan lets it. */
function envFound(text: string, explainsAllowed: boolean): Found | undefined {
  const value = bunEnvValue(text);
  if (value === undefined) return undefined;
  return { url: value, explains: explainsAllowed && value !== UNREADABLE_VALUE };
}

/**
 * Reads one registry URL for `scope` — or, with `all` given, ALSO pushes every
 * registry URL the file names (default and per scope), for {@link npmUserRegistries}.
 */
type NpmParser = (text: string, scope: string | undefined, all?: string[]) => string | undefined;

/** A configuration file; `user` is false for a file in the project's directories or above its repository root. */
interface NpmConfigFile {
  path: string;
  parse: NpmParser;
  user: boolean;
}

/** An npmjs credential in an npmrc (`//registry.npmjs.org/:_authToken=`, `_auth=`, …) or `.yarnrc.yml`. */
const NPM_AUTH =
  /^\s*(?:\/\/registry\.(?:npmjs\.org|yarnpkg\.com)\/:)?_(?:authToken|auth|password)\s*=|^\s*npmAuth(?:Token|Ident)\s*:/m;

/**
 * Every npm-family configuration file that can apply, nearest first:
 * project ancestors (`.npmrc`, `.yarnrc.yml`, `.yarnrc`, `bunfig.toml`),
 * then user (`NPM_CONFIG_USERCONFIG` or `~/.npmrc`, `~/.yarnrc.yml`,
 * `~/.yarnrc`, `~/.bunfig.toml`), pnpm's global rc (XDG, `%LOCALAPPDATA%`,
 * macOS), and npm's global npmrc when `npm_config_globalconfig` names it.
 */
function npmConfigFiles(ctx: RegistryContext): NpmConfigFile[] {
  const env = envOf(ctx);
  const home = homeOf(ctx);
  const files: NpmConfigFile[] = [];
  const near = ancestors(ctx);
  for (const dir of near) {
    files.push(
      { path: join(dir, '.npmrc'), parse: fromNpmrc, user: false },
      { path: join(dir, '.yarnrc.yml'), parse: fromYarnrcYml, user: false },
      { path: join(dir, '.yarnrc'), parse: fromYarnrc, user: false },
      { path: join(dir, 'bunfig.toml'), parse: fromBunfig, user: false },
    );
  }
  // Yarn Berry reads `.yarnrc.yml` in EVERY ancestor up to the filesystem
  // root — past the repository root and the home directory (follow-up Part Y).
  const top = near[near.length - 1];
  if (top !== undefined) {
    for (let dir = dirname(top), i = 0; i < 64; dir = dirname(dir), i += 1) {
      files.push({ path: join(dir, '.yarnrc.yml'), parse: fromYarnrcYml, user: false });
      if (dirname(dir) === dir) break;
    }
  }
  const xdg = envValue(env, 'XDG_CONFIG_HOME') ?? join(home, '.config');
  const localAppData = envValue(env, 'LOCALAPPDATA') ?? join(home, 'AppData', 'Local');
  files.push(
    { path: envValue(env, 'NPM_CONFIG_USERCONFIG') ?? join(home, '.npmrc'), parse: fromNpmrc, user: true },
    { path: join(home, '.yarnrc.yml'), parse: fromYarnrcYml, user: true },
    { path: join(home, '.yarnrc'), parse: fromYarnrc, user: true },
    { path: join(home, '.bunfig.toml'), parse: fromBunfig, user: true },
    { path: join(xdg, '.bunfig.toml'), parse: fromBunfig, user: true },
    { path: join(xdg, 'pnpm', 'rc'), parse: fromNpmrc, user: true },
    { path: join(localAppData, 'pnpm', 'config', 'rc'), parse: fromNpmrc, user: true },
    { path: join(home, 'Library', 'Preferences', 'pnpm', 'rc'), parse: fromNpmrc, user: true },
  );
  const globalConfig = envValue(env, 'NPM_CONFIG_GLOBALCONFIG');
  if (globalConfig !== undefined) files.push({ path: globalConfig, parse: fromNpmrc, user: true });
  // npm's DEFAULT global npmrc, read even when nothing names it:
  // `<prefix>/etc/npmrc`, the prefix being `%APPDATA%\npm` on Windows and the
  // node installation's prefix (`<prefix>/bin/node`) elsewhere — or
  // `npm_config_prefix` when set.
  const prefix =
    envValue(env, 'NPM_CONFIG_PREFIX') ??
    ((ctx.platform ?? process.platform) === 'win32'
      ? join(envValue(env, 'APPDATA') ?? join(home, 'AppData', 'Roaming'), 'npm')
      : dirname(dirname(ctx.nodeExecPath ?? process.execPath)));
  files.push({ path: join(prefix, 'etc', 'npmrc'), parse: fromNpmrc, user: true });
  return files;
}

/**
 * Environment variables that point a package manager at a registry, matched
 * case-insensitively on the name. The first whose value is not the public
 * registry (or is not a URL at all — `UV_INDEX_STRATEGY`) counts.
 * `*NO_INDEX*` counts only when truthy. For NuGet, only a variable that names
 * a source, a feed or a configuration file (`NUGET_*SOURCE*`, `NUGET_*FEED*`,
 * `NUGET_*CONFIG*`) or a source's credentials
 * (`NuGetPackageSourceCredentials_<name>`): `NUGET_PACKAGES` (the package
 * cache) or `NUGET_XMLDOC_MODE` explain nothing (follow-up Part Y).
 */
const ENV_REGISTRY: Record<PkgEcosystem, RegExp> = {
  npm: /^(?:YARN_NPM_REGISTRY_SERVER|YARN_REGISTRY|BUN_CONFIG_REGISTRY|npm_config_.*registry.*)$/i,
  pypi: /^(?:(?:PIP|UV)_.*INDEX.*|PIP_FIND_LINKS|UV_FIND_LINKS)$/i,
  packagist: /^$/,
  nuget: /^(?:NUGET_\w*(?:SOURCE|FEED|CONFIG)\w*|NUGET_FALLBACK_PACKAGES|NuGetPackageSourceCredentials_.+)$/i,
};

function envRegistry(ecosystem: PkgEcosystem, ctx: RegistryContext): CustomRegistry | null {
  for (const [key, raw] of Object.entries(envOf(ctx))) {
    if (raw === undefined || raw.trim() === '' || !ENV_REGISTRY[ecosystem].test(key)) continue;
    const value = raw.trim();
    if (/NO_INDEX/i.test(key)) {
      if (/^(?:1|true|yes|on)$/i.test(value)) return { kind: 'registry', source: key, from: 'user' };
      continue;
    }
    if (value.split(/\s+/).some((u) => !isPublic(ecosystem, u.replace(/^[^=]+=(?=https?:)/, '')))) {
      return { kind: 'registry', source: key, url: value, from: 'user' };
    }
  }
  return null;
}

/** A configuration file as the lookup of a 404 and the line of the project read it: the parser, or the bun's own reader. */
interface RegistryFile extends NpmConfigFile {
  /** Replaces `parse`: the closed reader of the bun's `bunfig.toml`, or of a `.env`. */
  found?: (text: string, scope: string | undefined) => Found | undefined;
  /** A `.env` of the bun: read by {@link readEnvFile}. */
  env?: true;
}

/** `parse` kept only for the registry of a SCOPE: a global `bun add` obeys no project default registry (N8), and still obeys a scope's. */
function scopeOnly(parse: NpmParser): NpmParser {
  return (text, scope) => {
    if (scope === undefined) return undefined;
    const url = parse(text, scope);
    return url !== undefined && url !== parse(text, undefined) ? url : undefined;
  };
}

/** The files of a bun command that is not global, which reads the new forms of `bunfig.toml` and the `.env` files. */
function isBunProject(ctx: RegistryContext): boolean {
  return ctx.command?.manager === 'bun' && !ctx.command.global;
}

/**
 * {@link npmConfigFiles}, as the command reads them. For a bun command that is not global: the closed grammar of `bunfig.toml` in the
 * project, and the `.env` files of the one folder of {@link bunEnvPlan} before that folder's `.npmrc` (measured: the `.env` wins).
 * For a global `bun add`: the project's `.npmrc` and `bunfig.toml` give a scope's registry only (pair N8). Any other command, and
 * no command, the files as they were.
 */
function registryFiles(ctx: RegistryContext): RegistryFile[] {
  const base = npmConfigFiles(ctx);
  const cmd = ctx.command;
  const bun = isBunProject(ctx);
  const noDefault = cmd?.global === true && cmd.registryForm === 'bun add';
  if (!bun && !noDefault) return base;
  const plan = bun ? bunEnvPlan(ctx) : undefined;
  const out: RegistryFile[] = [];
  for (const f of base) {
    const name = basename(f.path);
    if (f.user) {
      out.push(f);
    } else if (noDefault && (name === '.npmrc' || name === 'bunfig.toml')) {
      out.push({ ...f, parse: scopeOnly(f.parse) });
    } else if (bun && name === 'bunfig.toml') {
      out.push({ ...f, found: bunfigFound });
    } else {
      if (plan !== undefined && name === '.npmrc' && plan.dirs.some((d) => samePath(d, dirname(f.path)))) {
        for (const envName of bunEnvNames(bunMode(ctx))) {
          out.push({ path: join(dirname(f.path), envName), parse: () => undefined, user: false, env: true, found: (text) => envFound(text, plan.explains) });
        }
      }
      out.push(f);
    }
  }
  return out;
}

function npmRegistry(name: string, ctx: RegistryContext): CustomRegistry | null {
  const scope = npmScope(name);
  const fromEnv = envRegistry('npm', ctx);
  if (fromEnv !== null) return fromEnv;
  let authSource: string | undefined;
  let userAuth: string | undefined;
  // The first explanation found. One of the project's does not end the search: the user's own may explain the 404 as well, and
  // then it is the user's word (`from`), which keeps the warning for a malicious name the public registry took down.
  let first: Explained | null = null;
  for (const file of registryFiles(ctx)) {
    const text = file.env === true ? readEnvFile(file.path, ctx) : read(file.path, ctx);
    if (text === undefined) continue;
    const url = file.found === undefined ? file.parse(text, scope) : undefined;
    const hit: Found | undefined = file.found === undefined ? (url === undefined ? undefined : { url, explains: true }) : file.found(text, scope);
    if (hit !== undefined && hit.explains && !isPublic('npm', hit.url)) {
      first = first ?? { kind: 'registry', source: file.path, url: hit.url, from: file.user ? 'user' : 'project' };
      if (file.user) return first.from === 'user' ? first : { ...first, from: 'user' };
      continue;
    }
    if (file.env !== true && NPM_AUTH.test(text)) {
      authSource = authSource ?? file.path;
      if (file.user) userAuth = userAuth ?? file.path;
    }
  }
  // Ruling (e): a private SCOPED package on npmjs answers 404 to an
  // anonymous request, so with credentials configured a scoped 404 proves
  // nothing. npmjs has no private unscoped packages.
  const credential = scope !== undefined && userAuth !== undefined;
  if (first !== null) return credential && first.from === 'project' ? { ...first, from: 'user' } : first;
  if (scope !== undefined && authSource !== undefined) return { kind: 'auth', source: authSource, from: userAuth !== undefined ? 'user' : 'project' };
  const local = npmWorkspacePackage(name, ctx);
  return local === undefined ? null : { kind: 'workspace', source: local, from: 'project' };
}

/**
 * The registry the npm-family configuration gives `name`'s SCOPE in
 * particular — `@scope:registry=` in an npmrc, `npmScopes` in `.yarnrc.yml`,
 * `[install.scopes]` in `bunfig.toml`, `npm_config_@scope:registry` — when it
 * is not the public one, and whose word that is: the `project`'s (a file in
 * one of its directories, up to the repository root) or the `user`'s (the
 * home directory, the machine, the environment). `null` for an unscoped name
 * and for a scope with no registry of its own: the default registry
 * (`registry=`) is every name's, not a scope's.
 *
 * The install hook asks before it looks up a scoped name a MANIFEST gives it:
 * the package manager fetches such a package from that registry and never
 * asks the public one for it, so neither does the hook — the names of a
 * project's private packages stay where the package manager keeps them.
 * Never throws: a configuration that cannot be read answers `null`.
 */
export function npmScopeRegistry(
  name: string,
  ctx: RegistryContext = {},
): { scope: string; source: string; url: string; from: 'project' | 'user' } | null {
  return npmScopeRegistryOf(ctx)(name);
}

type ScopeRegistry = { scope: string; source: string; url: string; from: 'project' | 'user' } | null;

/**
 * {@link npmScopeRegistry} prepared for many names: what a call costs apart
 * from the name — the environment, the list of configuration files with whose
 * word each is, and their texts — is done ONCE, on the first scoped name, and
 * each scope is answered from it once. A lockfile names hundreds of scopes, and
 * the preparation (file-system calls, a read and a parse per file) cost about a
 * millisecond a scope. The answers are those of the one-name function: the
 * environment first, then the first file that names the scope; never throws.
 */
export function npmScopeRegistryOf(ctx: RegistryContext = {}): (name: string) => ScopeRegistry {
  interface Prepared {
    env: Array<{ key: string; lower: string; value: string }>;
    files: Array<{ path: string; text: string; parse: (text: string, scope: string | undefined) => string | undefined; project: boolean }>;
  }
  let prepared: Prepared | null | undefined;
  const prepare = (): Prepared | null => {
    try {
      const env = Object.entries(envOf(ctx)).map(([key, raw]) => ({ key, lower: key.toLowerCase(), value: raw?.trim() ?? '' }));
      const near = ancestors(ctx);
      const files: Prepared['files'] = [];
      for (const { path, parse } of npmConfigFiles(ctx)) {
        const text = read(path, ctx);
        if (text === undefined) continue;
        files.push({ path, text, parse, project: near.some((dir) => samePath(dir, dirname(path))) });
      }
      return { env, files };
    } catch {
      // unknown reads as none: the name is then looked up like any other
      return null;
    }
  };
  const answers = new Map<string, ScopeRegistry>();
  return (name) => {
    const scope = npmScope(name);
    if (scope === undefined) return null;
    const known = answers.get(scope);
    if (known !== undefined) return known;
    if (prepared === undefined) prepared = prepare();
    const answer = prepared === null ? null : answerFor(scope, prepared);
    answers.set(scope, answer);
    return answer;
  };

  function answerFor(scope: string, from: Prepared): ScopeRegistry {
    try {
      const wanted = `npm_config_@${scope.toLowerCase()}:registry`;
      for (const { key, lower, value } of from.env) {
        if (value !== '' && lower === wanted && !isPublic('npm', value)) return { scope, source: key, url: value, from: 'user' };
      }
      for (const file of from.files) {
        const url = file.parse(file.text, scope);
        // The scope's own line — not the default registry, which every name gets.
        if (url === undefined || url === file.parse(file.text, undefined) || isPublic('npm', url)) continue;
        return { scope, source: file.path, url, from: file.project ? 'project' : 'user' };
      }
    } catch {
      // unknown reads as none
    }
    return null;
  }
}

/**
 * The project files each manager obeys for the DEFAULT registry, in the order tried within one directory
 * (measured 2026-11-18: npm 11, pnpm 10, bun 1.4, Yarn 1.22 and 4.18 — the word `yarn` does not tell the two Yarns
 * apart, so it counts the files of both).
 */
const PROJECT_DEFAULT_FILES: Record<string, ReadonlyArray<{ name: string; parse: NpmParser }>> = {
  npm: [{ name: '.npmrc', parse: fromNpmrc }],
  npx: [{ name: '.npmrc', parse: fromNpmrc }],
  pnpm: [{ name: '.npmrc', parse: fromNpmrc }],
  bun: [
    { name: '.npmrc', parse: fromNpmrc },
    { name: 'bunfig.toml', parse: fromBunfig },
  ],
  yarn: [
    { name: '.npmrc', parse: fromNpmrc },
    { name: '.yarnrc.yml', parse: fromYarnrcYml },
    { name: '.yarnrc', parse: fromYarnrc },
  ],
};

/**
 * EVERY project file that sets the default registry for `manager` (`npm`, `npx`, `pnpm`, `bun` or `yarn`) to one that
 * is not the public registry, each with the value as its parser returns it (the LAST line of a repeated key): the
 * nearest directory first and, within a directory, in the order of {@link PROJECT_DEFAULT_FILES}. The managers do not
 * agree on which file wins (measured 2026-11-19: the workspace root's for npm and bun, the member's for pnpm and Yarn,
 * and in one directory `bunfig.toml` over `.npmrc` for bun, `.npmrc` over `.yarnrc` for Yarn 1), so none is chosen:
 * a file that sets the public registry is no entry, and does not hide another. The directories are the ones the
 * manager reads: beside the nearest `package.json` from `ctx.projectDir` up (the directory itself when there is
 * none), and at a workspace root above it (a `package.json` with `workspaces`; for pnpm also a
 * `pnpm-workspace.yaml`); Yarn also reads a plain directory above, up to the repository root. Never the home directory
 * or above it.
 *
 * `[]` for another manager, no such file, only the public registry, files that only give registries to scopes, files
 * that cannot be read; never throws.
 */
export function npmProjectDefaultRegistry(manager: string, ctx: RegistryContext = {}): Array<{ source: string; url: string }> {
  const found: Array<{ source: string; url: string }> = [];
  try {
    const files = Object.hasOwn(PROJECT_DEFAULT_FILES, manager) ? PROJECT_DEFAULT_FILES[manager] : undefined;
    if (files === undefined) return found;
    const near = ancestors(ctx);
    const first = near.findIndex((dir) => present(join(dir, 'package.json')));
    const from = first < 0 ? 0 : first;
    const envDirs = manager === 'bun' ? bunEnvPlan(ctx)?.dirs : undefined;
    for (const dir of near.slice(from)) {
      const isBase = dir === near[from];
      const obeyed =
        isBase ||
        manager === 'yarn' ||
        hasWorkspaces(read(join(dir, 'package.json'), ctx, undefined, 'workspace manifest')) ||
        (manager === 'pnpm' && present(join(dir, 'pnpm-workspace.yaml')));
      // The `.env` files of the bun come first in their folder (measured: they win), and only for a command that reads them.
      if (envDirs?.some((d) => samePath(d, dir)) === true) {
        for (const name of bunEnvNames(bunMode(ctx))) {
          const source = join(dir, name);
          const text = readEnvFile(source, ctx);
          const url = text === undefined ? undefined : bunEnvValue(text);
          if (url !== undefined) found.push({ source, url });
        }
      }
      if (!obeyed) continue;
      for (const { name, parse } of files) {
        const source = join(dir, name);
        const text = read(source, ctx);
        // The bun reads the new forms of its `bunfig.toml` for the line, with or without a command.
        const url = text === undefined ? undefined : manager === 'bun' && name === 'bunfig.toml' ? bunfigFound(text, undefined)?.url : parse(text, undefined);
        if (url !== undefined && !isPublic('npm', url)) found.push({ source, url });
      }
    }
  } catch {
    // unknown reads as none for the files not yet read: fail-open, what was found stays
  }
  return found;
}

/**
 * The registry URL as it is compared with a lockfile's: an `http(s)` URL's
 * origin and path with a trailing slash, no credentials, query or fragment;
 * `undefined` for anything else (a variable left unexpanded, `(configured)`)
 * and for the public registry. "Public" is decided on the PARSED host, not by
 * {@link isPublic}: exact host, no credentials, the default port — and, stricter than it, https only
 * (for the lockfile comparison, `http://registry.npmjs.org/` is another origin).
 */
function userRegistryUrl(raw: string): string | undefined {
  let u: URL;
  try {
    u = new URL(raw.trim().replace(/^["']|["']$/g, ''));
  } catch {
    return undefined;
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return undefined;
  const publicHost = PUBLIC_HOSTS.npm.includes(u.hostname);
  if (publicHost && u.protocol === 'https:' && u.username === '' && u.password === '' && u.port === '') return undefined;
  const path = u.pathname.endsWith('/') ? u.pathname : `${u.pathname}/`;
  return `${u.origin}${path}`;
}

/** The environment variables that name an npm-family registry — strictly: `npm_config_replace_registry_host` is a setting, not a URL. */
const ENV_USER_REGISTRY = /^(?:npm_config_(?:@[^:]+:)?registry|YARN_NPM_REGISTRY_SERVER|YARN_REGISTRY|BUN_CONFIG_REGISTRY)$/i;

/**
 * Whether the environment names the default registry of an npm-family manager (`NPM_CONFIG_REGISTRY`,
 * `YARN_NPM_REGISTRY_SERVER`, `YARN_REGISTRY`, `BUN_CONFIG_REGISTRY`): the manager obeys it before any file of the
 * project, whatever the value. A scope's own variable (`npm_config_@scope:registry`) is not the default.
 */
export function npmEnvNamesDefaultRegistry(ctx: RegistryContext = {}): boolean {
  try {
    return Object.entries(envOf(ctx)).some(([key, value]) => ENV_USER_REGISTRY.test(key) && !key.includes('@') && (value ?? '').trim() !== '');
  } catch {
    return false;
  }
}

/**
 * Every registry URL the USER's npm-family configuration names — `registry=`
 * and `@scope:registry=` of the user npmrc and npm's global one, the
 * environment, `~/.yarnrc.yml`, `~/.bunfig.toml` (and the user-level classic
 * `.yarnrc` and pnpm's rc) — without the public registry. NEVER a file of the
 * project, nor a `.yarnrc.yml` above its repository root: a package fetched
 * from one of these URLs is the user's own choice, and a project file must not
 * be able to add one (it would silence the hook's line about another origin).
 * Same files and parsers as {@link npmScopeRegistry}. A configuration that
 * cannot be read names none; never throws.
 */
export function npmUserRegistries(ctx: RegistryContext = {}): string[] {
  const urls = new Set<string>();
  const add = (raw: string): void => {
    const url = userRegistryUrl(raw);
    if (url !== undefined) urls.add(url);
  };
  try {
    for (const [key, value] of Object.entries(envOf(ctx))) {
      if (value !== undefined && ENV_USER_REGISTRY.test(key)) add(value);
    }
    for (const { path, parse, user } of npmConfigFiles(ctx)) {
      if (!user) continue;
      const text = read(path, ctx);
      if (text === undefined) continue;
      const named: string[] = [];
      parse(text, undefined, named);
      named.forEach(add);
    }
  } catch {
    // unknown reads as none: nothing is then silenced
  }
  return [...urls];
}

// ─────────────────────────────────────────────────────── workspaces

const SKIP_DIRS = new Set(['node_modules', '.git', '.venv', 'venv', '__pycache__', 'vendor', 'dist', 'build', 'target']);
const MAX_SCAN_DIRS = MAX_WORKSPACE_DIRS;
const MAX_SCAN_DEPTH = 5;

/**
 * Every `file` under `root` (depth-limited, never into node_modules,
 * vendor, virtualenvs or dot-directories), indexed by the package name
 * `nameOf` reads from it — the first manifest breadth-first for each name.
 * Glob patterns in the workspace declaration are deliberately NOT
 * interpreted: any manifest under a workspace root with the name counts as
 * local — a false "local" only turns a deny into a warning.
 *
 * Built once per root and call (`ctx.cache`), then looked up per package: it
 * was walked once PER PACKAGE, up to 3000 directories each time (review I4).
 * A walk that stops early — at {@link MAX_SCAN_DIRS} directories, or at
 * `ctx.deadlineAt` — says so (`cut`), so a name it did not reach is unknown,
 * never absent.
 */
function workspaceIndex(
  root: string,
  file: string,
  nameOf: (text: string) => string | undefined,
  ctx: RegistryContext,
): WorkspaceIndex {
  const key = `${file}\u0000${root}`;
  const cached = ctx.cache?.workspaces.get(key);
  if (cached !== undefined) return cached;
  const index: WorkspaceIndex = { names: new Map() };
  const queue: Array<{ dir: string; depth: number }> = [{ dir: root, depth: 0 }];
  for (let at = 0; at < queue.length; at += 1) {
    if (at >= MAX_SCAN_DIRS) {
      index.cut = 'size';
      break;
    }
    if (ctx.deadlineAt !== undefined && Date.now() > ctx.deadlineAt) {
      index.cut = 'time';
      break;
    }
    const next = queue[at];
    if (next === undefined) break;
    const manifest = join(next.dir, file);
    const r = readSmallText(manifest, MAX_REGISTRY_CONFIG_BYTES, walkRoot(manifest, ctx, root));
    if (r.status === 'refused') index.unread = index.unread ?? { path: manifest, what: 'workspace manifest' };
    else if (r.status === 'ok') {
      const name = nameOf(r.text);
      if (name !== undefined && !index.names.has(name)) index.names.set(name, manifest);
    }
    if (next.depth >= MAX_SCAN_DEPTH) continue;
    let entries: string[] = [];
    try {
      entries = readdirSync(next.dir, { withFileTypes: true })
        .filter((e) => e.isDirectory() && !e.name.startsWith('.') && !SKIP_DIRS.has(e.name))
        .map((e) => e.name);
    } catch {
      continue;
    }
    for (const e of entries) queue.push({ dir: join(next.dir, e), depth: next.depth + 1 });
  }
  ctx.cache?.workspaces.set(key, index);
  return index;
}

/** The manifest of `wanted` under `root`, or `undefined` — noting what the walk could not read. */
function findManifest(
  root: string,
  file: string,
  nameOf: (text: string) => string | undefined,
  wanted: string,
  ctx: RegistryContext,
): string | undefined {
  const index = workspaceIndex(root, file, nameOf, ctx);
  const hit = index.names.get(wanted);
  if (hit !== undefined) return hit;
  if (index.unread !== undefined) noteUnread(index.unread.path, index.unread.what);
  if (index.cut !== undefined) firstUnchecked = firstUnchecked ?? { root, cut: index.cut };
  return undefined;
}

/** A `package.json`'s `name`. */
function npmManifestName(text: string): string | undefined {
  try {
    const name = (JSON.parse(text) as { name?: unknown }).name;
    return typeof name === 'string' ? name : undefined;
  } catch {
    return undefined;
  }
}

/** A `pyproject.toml`'s `[project] name`, normalised (PEP 503). */
function pyprojectName(text: string): string | undefined {
  const project = /^\s*\[project\]\s*$([\s\S]*?)(?=^\s*\[|(?![\s\S]))/m.exec(text)?.[1] ?? '';
  const n = /^\s*name\s*=\s*["']([^"']+)["']/m.exec(project)?.[1];
  return n === undefined ? undefined : pep503(n);
}

function hasWorkspaces(packageJson: string | undefined): boolean {
  if (packageJson === undefined) return false;
  try {
    const w = (JSON.parse(packageJson) as { workspaces?: unknown }).workspaces;
    if (Array.isArray(w)) return w.length > 0;
    return w !== null && typeof w === 'object' && Array.isArray((w as { packages?: unknown }).packages);
  } catch {
    return false;
  }
}

/** Ruling (f), npm/pnpm/yarn/bun: a package.json named `name` under a workspace root. */
function npmWorkspacePackage(name: string, ctx: RegistryContext): string | undefined {
  for (const dir of ancestors(ctx)) {
    const isRoot =
      hasWorkspaces(read(join(dir, 'package.json'), ctx, undefined, 'workspace manifest')) || present(join(dir, 'pnpm-workspace.yaml'));
    if (!isRoot) continue;
    const hit = findManifest(dir, 'package.json', npmManifestName, name, ctx);
    if (hit !== undefined) return hit;
  }
  return undefined;
}

const pep503 = (n: string): string => n.trim().toLowerCase().replace(/[-_.]+/g, '-');

/** Ruling (f), uv: a `[tool.uv.workspace]` member named `name`, or a `[tool.uv.sources]` entry for it. */
function uvWorkspacePackage(name: string, ctx: RegistryContext): string | undefined {
  const wanted = pep503(name);
  for (const dir of ancestors(ctx)) {
    const path = join(dir, 'pyproject.toml');
    const text = read(path, ctx);
    if (text === undefined) continue;
    const sources = /^\s*\[tool\.uv\.sources\]\s*$([\s\S]*?)(?=^\s*\[|(?![\s\S]))/m.exec(text)?.[1] ?? '';
    for (const m of sources.matchAll(/^\s*["']?([A-Za-z0-9._-]+)["']?\s*=/gm)) {
      if (pep503(m[1] ?? '') === wanted) return path;
    }
    if (!/^\s*\[tool\.uv\.workspace\]/m.test(text)) continue;
    const hit = findManifest(dir, 'pyproject.toml', pyprojectName, wanted, ctx);
    if (hit !== undefined) return hit;
  }
  return undefined;
}

// ────────────────────────────────────────────────────────────── PyPI

/** `index-url`, `extra-index-url`, `find-links` (any spelling) or `no-index` in a pip config file. */
function fromPipConf(text: string): string | undefined {
  for (const raw of text.split(/\r?\n/)) {
    const m = /^\s*(index[-_]url|extra[-_]index[-_]url|find[-_]links)\s*[=:]\s*(\S+)/i.exec(raw);
    if (m !== null && !isPublic('pypi', m[2] ?? '')) return m[2];
    if (/^\s*no[-_]index\s*[=:]\s*(?:true|1|yes|on)\s*$/i.test(raw)) return 'no-index';
  }
  return undefined;
}

/**
 * The kind of an index a `uv.toml` or a `pyproject.toml` names. The tables of an array (`[[index]]`, `[[tool.uv.index]]`,
 * `[[tool.poetry.source]]` by priority, `[[tool.pdm.source]]`) count whatever their URL; the keys (`index-url`, `extra-index-url`,
 * `find-links`) count when their value is not the public index.
 */
type IndexKind =
  | 'uv-top'
  | 'uv-pip'
  | 'uv-index'
  | 'uv-index-default'
  | 'tool-uv'
  | 'tool-uv-pip'
  | 'tool-uv-index'
  | 'tool-uv-index-default'
  | 'poetry-none'
  | 'poetry-primary'
  | 'poetry-supplemental'
  | 'poetry-explicit'
  | 'poetry-other'
  | 'pdm';

interface IndexEntry {
  kind: IndexKind;
  url: string;
}

/** A table of an array, its header's name and its lines, as read so far. */
interface ArrayTable {
  name: string;
  body: string[];
}

/** The first `http(s)` URL of the lines of a table of an array, else {@link UNREADABLE_VALUE}. */
function arrayUrl(body: string[]): string {
  return /https?:\/\/[^"'\s]+/.exec(body.join('\n'))?.[0] ?? UNREADABLE_VALUE;
}

/** The value of `index-url`, `extra-index-url` or `find-links` on a line (a `"`, `'`, space or `]` ends it), unless it is the public index. */
function indexKeyValue(line: string, onlyIndexUrl = false): string | undefined {
  const m = /^\s*(index-url|extra-index-url|find-links)\s*=\s*["']?([^"'\s\]]+)/.exec(line);
  if (m === null || (onlyIndexUrl && m[1] !== 'index-url')) return undefined;
  return isPublic('pypi', m[2] ?? '') ? undefined : m[2];
}

/**
 * Every index a table-aware reading of a TOML file names, in the order of the file. `arrays` maps the name of an array of tables to the
 * kind of an entry (given its lines); `keys` maps a table's name to the kind of the index keys under it (`onlyIndexUrl`: just `index-url`),
 * and `top` is the kind of the keys before any header (`uv.toml`). A header that is not one of them ends the table before it.
 */
function indexEntries(
  text: string,
  arrays: Readonly<Record<string, (body: string[]) => IndexKind>>,
  keys: Readonly<Record<string, { kind: IndexKind; onlyIndexUrl?: true }>>,
  top?: IndexKind,
): IndexEntry[] {
  const out: IndexEntry[] = [];
  let table: ArrayTable | undefined;
  let keyed: { kind: IndexKind; onlyIndexUrl?: true } | undefined = top === undefined ? undefined : { kind: top };
  const flush = (): void => {
    const kind = table === undefined ? undefined : arrays[table.name]?.(table.body);
    if (table !== undefined && kind !== undefined) out.push({ kind, url: arrayUrl(table.body) });
    table = undefined;
  };
  for (const line of text.split(/\r?\n/)) {
    const array = /^\s*\[\[\s*([^\][]+?)\s*\]\]/.exec(line);
    const plain = array === null ? /^\s*\[\s*([^\][]+?)\s*\]/.exec(line) : null;
    if (array !== null || plain !== null) {
      flush();
      const name = (array ?? plain)?.[1] ?? '';
      if (array !== null) {
        table = { name, body: [] };
        keyed = undefined;
      } else {
        keyed = Object.hasOwn(keys, name) ? keys[name] : top === undefined ? undefined : { kind: top };
      }
      continue;
    }
    if (table !== undefined) {
      table.body.push(line);
      continue;
    }
    if (keyed === undefined) continue;
    const value = indexKeyValue(line, keyed.onlyIndexUrl === true);
    if (value !== undefined) out.push({ kind: keyed.kind, url: value });
  }
  flush();
  return out;
}

const hasDefault = (body: string[]): boolean => body.some((l) => /^\s*default\s*=\s*true\b/.test(l));
/** The priority of a `[[tool.poetry.source]]`: none, one of the three measured, or another word. */
function poetryKind(body: string[]): IndexKind {
  const p = body.map((l) => /^\s*priority\s*=\s*["']([^"']*)["']/.exec(l)?.[1]).find((v) => v !== undefined);
  if (p === undefined) return 'poetry-none';
  return p === 'primary' || p === 'supplemental' || p === 'explicit' ? (`poetry-${p}` as IndexKind) : 'poetry-other';
}

/** The indexes of a `uv.toml`: the keys on top and in any other table, `[pip]` apart, and `[[index]]`. */
function uvTomlEntries(text: string): IndexEntry[] {
  return indexEntries(
    text,
    { index: (body) => (hasDefault(body) ? 'uv-index-default' : 'uv-index') },
    { pip: { kind: 'uv-pip' } },
    'uv-top',
  );
}

/** The indexes of a `pyproject.toml`: `[tool.uv]`, `[tool.uv.pip]` (`index-url`), `[[tool.uv.index]]`, `[[tool.poetry.source]]` and `[[tool.pdm.source]]`. */
function pyprojectEntries(text: string): IndexEntry[] {
  return indexEntries(
    text,
    {
      'tool.uv.index': (body) => (hasDefault(body) ? 'tool-uv-index-default' : 'tool-uv-index'),
      'tool.poetry.source': poetryKind,
      'tool.pdm.source': () => 'pdm',
    },
    { 'tool.uv': { kind: 'tool-uv' }, 'tool.uv.pip': { kind: 'tool-uv-pip', onlyIndexUrl: true } },
  );
}

/**
 * The pairs (command by project file) in which the manager does not obey the file, measured 2026-11-20 (uv 0.13.8, poetry 2.5.1, pipx
 * 1.18.16, pip 23.0.1), by the form the command was written in: the kinds of index that then explain nothing. Outside this table a
 * project file counts, as it did (a pair nobody measured, a form the parse does not tell).
 */
const NOT_OBEYED: Readonly<Record<string, ReadonlySet<IndexKind>>> = {
  'uv add': new Set<IndexKind>(['uv-pip', 'poetry-primary']),
  'uv pip install': new Set<IndexKind>(['poetry-primary']),
  'pipx install': new Set<IndexKind>(['uv-top', 'tool-uv', 'tool-uv-index', 'tool-uv-index-default', 'poetry-primary']),
  'pipx run': new Set<IndexKind>(['uv-top', 'tool-uv']),
  'poetry add': new Set<IndexKind>(['poetry-explicit', 'uv-top', 'tool-uv', 'tool-uv-index-default']),
  'pip install': new Set<IndexKind>(['uv-top', 'tool-uv', 'tool-uv-index', 'tool-uv-index-default', 'poetry-primary']),
};

/** The URL of the first entry of a PROJECT file that explains a 404 for the command: `[tool.uv.pip]` only for `uv pip install`, and not the pairs of {@link NOT_OBEYED}. */
function explainingIndex(entries: readonly IndexEntry[], ctx: RegistryContext): string | undefined {
  const form = ctx.command?.registryForm;
  const skipped = form === undefined ? undefined : (Object.hasOwn(NOT_OBEYED, form) ? NOT_OBEYED[form] : undefined);
  return entries.find((e) => (e.kind === 'tool-uv-pip' ? form === 'uv pip install' : skipped?.has(e.kind) !== true))?.url;
}

/** The URL of the first entry of a file of the user or of the machine: every kind but `[tool.uv.pip]`, which only a project's `pyproject.toml` has. */
function anyIndex(entries: readonly IndexEntry[]): string | undefined {
  return entries.find((e) => e.kind !== 'tool-uv-pip')?.url;
}

/** `path` is inside one of the project's directories (up to the repository root): the `pip.conf` of the virtual environment of the project, say. */
function insideProject(path: string, ctx: RegistryContext): boolean {
  return ancestors(ctx).some((dir) => isInside(dir, resolve(path)));
}

function pypiRegistry(name: string, ctx: RegistryContext): CustomRegistry | null {
  const env = envOf(ctx);
  const fromEnv = envRegistry('pypi', ctx);
  if (fromEnv !== null) return fromEnv;

  // The first explanation found. A file of the project does not end the search: the user's own may explain the 404 too, and then
  // it is the user's word (`from`).
  const state: { first: Explained | null } = { first: null };
  const take = (found: Explained): Explained | null => {
    state.first = state.first ?? found;
    return found.from === 'user' ? { ...state.first, from: 'user' } : null;
  };

  // pip: explicit file, user (XDG, ~/.pip, %APPDATA%), venv, and global
  // (/etc/pip.conf, /etc/xdg/pip/pip.conf and XDG_CONFIG_DIRS, %ProgramData%).
  const home = homeOf(ctx);
  const etc = ctx.etcDir ?? '/etc';
  const confs: string[] = [];
  const explicit = envValue(env, 'PIP_CONFIG_FILE');
  if (explicit !== undefined) confs.push(explicit);
  const xdg = envValue(env, 'XDG_CONFIG_HOME') ?? join(home, '.config');
  confs.push(
    join(xdg, 'pip', 'pip.conf'),
    join(home, '.pip', 'pip.conf'),
    join(home, 'Library', 'Application Support', 'pip', 'pip.conf'),
  );
  const appdata = envValue(env, 'APPDATA') ?? join(home, 'AppData', 'Roaming');
  confs.push(join(appdata, 'pip', 'pip.ini'), join(home, 'pip', 'pip.ini'));
  // pip's "site" configuration lives in the environment's prefix: a venv's,
  // or a conda environment's (`$CONDA_PREFIX`).
  for (const prefix of [envValue(env, 'VIRTUAL_ENV'), envValue(env, 'CONDA_PREFIX')]) {
    if (prefix !== undefined) confs.push(join(prefix, 'pip.conf'), join(prefix, 'pip.ini'));
  }
  confs.push(join(etc, 'pip.conf'), join(etc, 'xdg', 'pip', 'pip.conf'));
  confs.push(join(ctx.systemLibraryDir ?? '/Library', 'Application Support', 'pip', 'pip.conf'));
  for (const d of (envValue(env, 'XDG_CONFIG_DIRS') ?? '').split(':').filter(Boolean)) confs.push(join(d, 'pip', 'pip.conf'));
  const programData = envValue(env, 'ProgramData') ?? envValue(env, 'PROGRAMDATA');
  if (programData !== undefined) confs.push(join(programData, 'pip', 'pip.ini'));
  for (const path of confs) {
    const text = read(path, ctx);
    const url = text === undefined ? undefined : fromPipConf(text);
    // The `pip.conf` of a virtual environment inside the project is the project's (EC-9); the others are the user's or the machine's.
    if (url !== undefined) {
      const done = take({ kind: 'registry', source: path, url, from: insideProject(path, ctx) ? 'project' : 'user' });
      if (done !== null) return done;
    }
  }

  // uv: UV_CONFIG_FILE, user (XDG / %APPDATA%) and system uv.toml.
  const uvConfs: string[] = [];
  const uvExplicit = envValue(env, 'UV_CONFIG_FILE');
  if (uvExplicit !== undefined) uvConfs.push(uvExplicit);
  uvConfs.push(join(xdg, 'uv', 'uv.toml'), join(appdata, 'uv', 'uv.toml'), join(etc, 'uv', 'uv.toml'));
  for (const path of uvConfs) {
    const text = read(path, ctx);
    const url = text === undefined ? undefined : anyIndex(uvTomlEntries(text));
    if (url !== undefined) {
      const done = take({ kind: 'registry', source: path, url, from: 'user' });
      if (done !== null) return done;
    }
  }

  for (const dir of ancestors(ctx)) {
    const uvToml = join(dir, 'uv.toml');
    const uvText = read(uvToml, ctx);
    const uvUrl = uvText === undefined ? undefined : explainingIndex(uvTomlEntries(uvText), ctx);
    if (uvUrl !== undefined) take({ kind: 'registry', source: uvToml, url: uvUrl, from: 'project' });
    const pyproject = join(dir, 'pyproject.toml');
    const text = read(pyproject, ctx);
    if (text === undefined) continue;
    const url = explainingIndex(pyprojectEntries(text), ctx);
    if (url !== undefined) take({ kind: 'registry', source: pyproject, url, from: 'project' });
    break; // the nearest pyproject.toml is the project; its parents are not
  }
  if (state.first !== null) return state.first;
  const local = uvWorkspacePackage(name, ctx);
  return local === undefined ? null : { kind: 'workspace', source: local, from: 'project' };
}

// ────────────────────────────────────────────────────────── Composer

function hasRepositories(text: string | undefined): boolean {
  if (text === undefined) return false;
  try {
    const doc = JSON.parse(text) as { repositories?: unknown };
    const r = doc.repositories;
    if (Array.isArray(r)) return r.length > 0;
    return r !== null && typeof r === 'object' && Object.keys(r).length > 0;
  } catch {
    return false;
  }
}

function composerRegistry(ctx: RegistryContext): CustomRegistry | null {
  for (const dir of ancestors(ctx)) {
    const path = join(dir, 'composer.json');
    const text = read(path, ctx);
    if (text === undefined) continue;
    if (hasRepositories(text)) return { kind: 'registry', source: path, from: 'project' };
    break;
  }
  const env = envOf(ctx);
  const home = homeOf(ctx);
  const composerHome = envValue(env, 'COMPOSER_HOME');
  const globals = composerHome !== undefined
    ? [join(composerHome, 'config.json')]
    : [join(home, '.composer', 'config.json'), join(home, '.config', 'composer', 'config.json'), join(envValue(env, 'APPDATA') ?? join(home, 'AppData', 'Roaming'), 'Composer', 'config.json')];
  for (const path of globals) if (hasRepositories(read(path, ctx))) return { kind: 'registry', source: path, from: 'user' };
  return null;
}

// ───────────────────────────────────────────────────────────── NuGet

function nugetConfigIn(dir: string, ctx: RegistryContext): string | undefined {
  const hit = listDir(dir, ctx).find((f) => f.toLowerCase() === 'nuget.config');
  return hit === undefined ? undefined : join(dir, hit);
}

/** Every package source in a NuGet config that is not nuget.org. */
function customNugetSources(text: string): string[] {
  const sources = /<packageSources>([\s\S]*?)<\/packageSources>/i.exec(text)?.[1] ?? '';
  const out: string[] = [];
  for (const m of sources.matchAll(/<add\b[^>]*\bvalue\s*=\s*"([^"]+)"/gi)) {
    const url = m[1] ?? '';
    if (url !== '' && !isPublic('nuget', url)) out.push(url);
  }
  return out;
}

/** A source that is a folder on this machine: not a URL, not a UNC share. */
function isLocalFolderSource(source: string): boolean {
  return !/^[a-z][a-z0-9+.-]*:\/\//i.test(source) && !/^[\\/]{2}/.test(source);
}

/**
 * Whether a local folder feed holds `id` — flat (`<id>.<version>.nupkg`) or
 * hierarchical (`<id>/`), any casing. `%VAR%` in the folder is expanded, and
 * a relative folder is taken from the config file's directory.
 */
function localFeedHas(folder: string, configPath: string, id: string, ctx: RegistryContext): boolean {
  const env = envOf(ctx);
  const expanded = folder.replace(/%([^%]+)%/g, (whole, name: string) => envValue(env, name) ?? whole);
  // A config written on Windows (`…\NuGetPackages\`) names the same folder
  // on Linux and macOS, where NuGet reads its backslashes as separators.
  const portable = (ctx.platform ?? process.platform) === 'win32' ? expanded : expanded.replace(/\\/g, '/');
  const dir = resolve(dirname(configPath), portable.replace(/[\\/]+$/, ''));
  const lower = id.toLowerCase();
  return listDir(dir, ctx).some((entry) => {
    const e = entry.toLowerCase();
    return e === lower || nupkgIds(e).includes(lower);
  });
}

/** A NuGet version: `1`, `1.2.3.4`, `1.0.0-beta.1`, `1.0.0+build.5`. */
const NUGET_VERSION = /^\d+(?:\.\d+){0,3}(?:-[0-9a-z-]+(?:\.[0-9a-z-]+)*)?(?:\+[0-9a-z-]+(?:\.[0-9a-z-]+)*)?$/i;

/**
 * The package ids a `<id>.<version>.nupkg` file name can mean: every split
 * where `<id>.` is followed by a NuGet version (fix round 2:
 * `Foo.2FA.1.0.0.nupkg` is `Foo.2FA`, not `Foo`; fix round 3: `foo.2.1.0.0` is
 * `foo` 2.1.0.0 and `foo.2` 1.0.0 and `foo.2.1` 0.0 — a false "held" only
 * turns a deny into a warning).
 */
function nupkgIds(file: string): string[] {
  const m = /^(.+)\.nupkg$/i.exec(file);
  if (m === null) return [];
  const parts = (m[1] ?? '').split('.');
  const ids: string[] = [];
  for (let i = 1; i < parts.length; i += 1) {
    if (NUGET_VERSION.test(parts.slice(i).join('.'))) ids.push(parts.slice(0, i).join('.'));
  }
  return ids;
}

function nugetRegistry(name: string, ctx: RegistryContext): CustomRegistry | null {
  const fromEnv = envRegistry('nuget', ctx);
  if (fromEnv !== null) return fromEnv;
  // NuGet reads every nuget.config from the project up to the filesystem
  // root — past `.git` and past the home directory — so this walk does too.
  const files: string[] = [];
  if (ctx.projectDir !== undefined) {
    let dir = resolve(ctx.projectDir);
    for (let i = 0; i < 64; i += 1) {
      const f = nugetConfigIn(dir, ctx);
      if (f !== undefined) files.push(f);
      const parent = dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  }
  const env = envOf(ctx);
  const home = homeOf(ctx);
  const appdata = envValue(env, 'APPDATA') ?? join(home, 'AppData', 'Roaming');
  for (const dir of [join(appdata, 'NuGet'), join(home, '.nuget', 'NuGet'), join(home, '.config', 'NuGet')]) {
    const f = nugetConfigIn(dir, ctx);
    if (f !== undefined) files.push(f);
  }
  // Every `*.config` in the additional user-wide directories and the
  // machine-wide ones, as NuGet reads them (follow-up Part Y).
  const userDirs = [join(appdata, 'NuGet', 'config'), join(home, '.nuget', 'config'), join(home, '.config', 'NuGet', 'config')];
  const machineDirs = [
    join(ctx.etcDir ?? '/etc', 'opt', 'NuGet', 'Config'),
    join(ctx.systemLibraryDir ?? '/Library', 'Application Support', 'NuGet', 'Config'),
  ];
  const programFilesX86 = envValue(env, 'ProgramFiles(x86)');
  if (programFilesX86 !== undefined) machineDirs.push(join(programFilesX86, 'NuGet', 'Config'));
  const machineWide = new Set<string>();
  for (const dir of [...userDirs, ...machineDirs]) {
    for (const f of listDir(dir, ctx).filter((e) => /\.config$/i.test(e)).sort()) {
      files.push(join(dir, f));
      if (machineDirs.includes(dir)) machineWide.add(join(dir, f));
    }
  }
  for (const path of files) {
    const text = read(path, ctx);
    if (text === undefined) continue;
    for (const url of customNugetSources(text)) {
      // A machine-wide config's LOCAL folder — Visual Studio's
      // Microsoft.VisualStudio.Offline.config is one on every VS machine —
      // explains a 404 only for a package it holds (fix round 1, M2).
      if (machineWide.has(path) && isLocalFolderSource(url) && !localFeedHas(url, path, name, ctx)) continue;
      return { kind: 'registry', source: path, url, from: insideProject(path, ctx) ? 'project' : 'user' };
    }
  }
  return null;
}

/**
 * The custom registry that would serve `name`, or `null` when only the
 * public registry is configured.
 */
export function customRegistryFor(
  ecosystem: PkgEcosystem,
  name: string,
  ctx: RegistryContext = {},
): CustomRegistry | null {
  firstUnread = undefined;
  firstUnchecked = undefined;
  let found: CustomRegistry | null;
  try {
    switch (ecosystem) {
      case 'npm':
        found = npmRegistry(name, ctx);
        break;
      case 'pypi':
        found = pypiRegistry(name, ctx);
        break;
      case 'packagist':
        found = composerRegistry(ctx);
        break;
      case 'nuget':
        found = nugetRegistry(name, ctx);
        break;
      default:
        found = null;
    }
  } catch {
    found = null;
  }
  // Nothing explains the 404 — unless a workspace was not read to its end (it
  // may hold the package: review I4), or a configuration that is there could
  // not be read: it may name a private registry (Part Y fix round 1).
  const unread = takeUnread();
  const unchecked = takeUnchecked();
  if (found !== null) return found;
  if (unchecked !== undefined) return { kind: 'unchecked', source: unchecked.root, cut: unchecked.cut };
  return unread !== undefined ? { kind: 'unreadable', source: unread.path, what: unread.what } : null;
}
