/**
 * Deciding how — and whether — a declared server may be started, before
 * anything is spawned.
 *
 * ## Remote entries (fix rounds 3, 4 and 5)
 *
 * `allow_remote` gates every way an entry's CONFIGURATION says it reaches
 * another machine, not only the `url` shape. An entry is remote when:
 *
 *   - it has a URL (`url`, `serverUrl`, `httpUrl`) and no command — even at
 *     localhost: it is a network transport, and a local port may be a tunnel;
 *   - a UNC or device-namespace path appears ANYWHERE in its command, an
 *     argument or an `env` value, as a substring (`\\host\share\x.exe`,
 *     `cmd /c "… type \\host\share\x"`, `-r\\host\…`, `/config:\\host\…`,
 *     `@\\host\…`, `\\?\…`, `\\.\…`, `//host/share/…`): touching it contacts
 *     that host over SMB, which sends the user's NTLM credentials to it;
 *   - a URL with a host appears anywhere in the command, an argument or an
 *     `env` value — `npx mcp-remote https://…`, `supergateway`, `mcp-proxy`,
 *     `--import=file://host/x.mjs`, `NODE_OPTIONS`, `DOCKER_HOST=tcp://…`, a
 *     database URL. Every `scheme://` and every special scheme followed by
 *     `:` (`http`, `https`, `ws`, `wss`, `ftp`, with or without `//`:
 *     `https:evil.example` is a URL to WHATWG) is parsed with WHATWG `URL`,
 *     and one that does not parse is remote. `file:///x` (no host) is local,
 *     and so is a LOOPBACK URL — see below;
 *   - any token of its command line — the command, an argument, a word inside
 *     a `-c` / `/c` string, split on whitespace, quotes, shell operators and
 *     `=` — is `ssh`, `sshpass`, `plink`, `kubectl` or `oc`;
 *   - a `docker`, `podman` or `nerdctl` token is followed by `-H`/`--host`,
 *     `--context` (anything but `default`), `--remote`, `--connection` or
 *     `--url`; or its global flags (before the first non-flag) hold `-c`
 *     (anything but `default`) or podman's `-r`; or its `env` sets
 *     `DOCKER_CONTEXT` or `CONTAINER_CONNECTION`. `-c` and `-r` are read only
 *     among the global flags: after the image, `sh -c` is a shell's.
 *
 * ### Loopback (fix round 5)
 *
 * `DATABASE_URL=postgres://localhost/app` does not need `allow_remote`. A URL
 * is exempt only when its PARSED hostname is exactly `localhost`, a
 * `127.x.x.x` dotted quad or `[::1]` — never a prefix (`localhost.evil.com`,
 * `127.0.0.1.evil.com`), never `[::ffff:127.0.0.1]` or a DNS name that
 * resolves to loopback — AND it is written so that no other parser can read
 * another host from it: no `\` anywhere (WHATWG reads it as a slash where
 * other parsers do not); at most one `@` before the path, with an exact
 * loopback host written after it (`postgres://user:pw@localhost/db` is
 * local, `http://a@localhost@other/` is not — with several `@` the last
 * decides for some parsers); and no query string on a scheme other than
 * http(s)/ws(s) (libpq takes a host from `?host=`). A multi-host URL
 * (`mongodb://a:1,b:2/`) does not parse, or parses to a hostname that is not
 * loopback: remote either way. WHATWG's own normalisation counts for
 * http(s): `http://127.1` and `http://0x7f000001` are 127.0.0.1. Every URL
 * in a string is checked; a loopback one is skipped, never the end of the
 * scan. Each value is first read as URL parsers read it — TAB and newline
 * deleted anywhere, C0 controls and spaces trimmed from both ends — and a
 * loopback URL whose host the gate stopped reading at a space, a quote or a
 * control character, before any `/`, `?` or `#`, is not exempt: WHATWG
 * reads on past them as userinfo (`http://127.0.0.1:80 @other/` is other).
 *
 * The limit: loopback is where a TUNNEL starts. `ssh -L 5432:db.internal:5432`,
 * `kubectl port-forward`, a local proxy or a VPN client listening on
 * 127.0.0.1 make a loopback URL reach another machine, and nothing in an
 * entry's configuration says so. The gate sees the tunnel only when the entry
 * itself starts it (`ssh`, `kubectl` in its command line).
 *
 * The first cut matched a UNC path only at the start of an argument or after
 * `=`, and URLs only for http(s)/ws(s): the review started `cmd /c "echo
 * started> marker & type \\host\share\x"`, which wrote the marker and tried
 * SMB (fix round 4).
 *
 * This is a TEXTUAL gate on the shapes a configuration can take, not a
 * sandbox. A program that looks local still reaches the network by itself
 * once started — `npx` downloads the package, a server calls its own API, a
 * script builds a URL at run time — and nothing here sees that; SECURITY.md
 * says so. It applies on every platform.
 *
 * ## Resolving a command without touching the network (C1)
 *
 * On Windows, `cross-spawn` resolves the command with `which.sync` over
 * `PATHEXT`, and `CreateProcess` runs synchronously: a UNC command blocked
 * this whole process from the first second (measured: zero timer ticks until
 * a kill at 1500 s). So on Windows the command is resolved HERE, with async
 * `stat` calls over the LOCAL entries of the launch environment's `PATH`
 * (UNC and device entries are skipped and named), and the absolute path is
 * what gets spawned; `cross-spawn` then has one local file to confirm. A UNC
 * command allowed as remote is first checked for reachability from a
 * short-lived child process, killed at the deadline, so neither this
 * process's event loop nor its thread pool waits on SMB; only a reachable one
 * is spawned. On POSIX the child's own `execvp` searches `PATH`, after the
 * fork, so there is nothing to resolve here.
 *
 * The limit, documented beside the process-tree ones in
 * `stdioTransport.ts`: a `PATH` entry that LOOKS local but reaches the
 * network — a mapped drive letter (`Z:\tools`), a junction or symlink to a
 * UNC share — is still `stat`ed. The stat runs in the thread pool, bounded by
 * the deadline, so it cannot block the event loop; it can still send an SMB
 * request, and while a share does not answer, a thread-pool thread waits.
 */

import { spawn } from 'node:child_process';
import { stat } from 'node:fs/promises';
import { delimiter, extname, isAbsolute, resolve } from 'node:path';
import type { McpServerEntry } from '../agentaudit/mcpServers.js';
import { isRemoteOrDeviceTarget } from '../hooks/configFile.js';

/**
 * A special scheme (WHATWG: one whose URLs always have a host) followed by
 * `:`, anywhere: `https:evil.example` reaches evil.example as surely as
 * `https://evil.example` (fix round 5, I-4). `file` is left to
 * {@link ANY_SCHEME_WITH_SLASHES}: `file:x` has no host.
 */
const SPECIAL_SCHEME = /(?:https?|wss?|ftp):/gi;
/** Any `scheme://`; what follows is a host only when WHATWG parses one. */
const ANY_SCHEME_WITH_SLASHES = /[a-z][a-z0-9+.-]*:\/\//gi;
/** Where a URL written into a command line or an env value ends. */
const URL_END = /[\s"'<>|`]/;
/**
 * A UNC or device path anywhere: `\\host\…`, `\\?\…`, `\\.\…`, or
 * `//host/…` not preceded by `:` or `/` (a URL's `://`, `file:///`).
 */
const UNC_ANYWHERE = /\\\\[^\\\s"'<>|]+\\|(?<![:/])\/\/[^/\s"'<>|]+\//;

/** Schemes whose query string no client takes a host from. */
const QUERY_SAFE_SCHEMES = new Set(['http:', 'https:', 'ws:', 'wss:']);

/** The text from `start` to the end of the URL written there. */
function urlAt(text: string, start: number): string {
  const rest = text.slice(start);
  const end = rest.search(URL_END);
  return end < 0 ? rest : rest.slice(0, end);
}

/**
 * `url` names only this machine (fix round 5, LOOPBACK): its PARSED hostname
 * is exactly `localhost`, a `127.x.x.x` dotted quad or `[::1]` — never a
 * prefix of a longer name — and nothing in how it is written lets another
 * parser read another host:
 *
 *   - no `\` anywhere: WHATWG reads it as `/` in a special scheme, other
 *     parsers (Python's `urlsplit`) do not — `http://localhost\@other/`;
 *   - at most ONE `@` before the path, and the text after it is itself an
 *     exact loopback host: with several, the last decides for some parsers
 *     and not for others. Credentials are fine — `postgres://user:pw@localhost/db`
 *     is the most common DATABASE_URL there is;
 *   - no query on a scheme whose clients take a host from one (libpq's
 *     `?host=` / `?hostaddr=`).
 *
 * WHATWG's own normalisation counts where there is no userinfo:
 * `http://127.1` and `http://0x7f000001` are 127.0.0.1. `[::ffff:127.0.0.1]`
 * and a DNS name that resolves to loopback are not exempt.
 */
function isLoopbackName(name: string): boolean {
  const host = name.toLowerCase();
  const quad = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  return host === 'localhost' || host === '[::1]' || (quad !== null && quad.slice(1).every((o) => Number(o) <= 255));
}

/** No `\`, at most one `@` and a loopback host after it, no query where one names a host: see above. */
function unambiguous(url: URL, written: string): boolean {
  if (written.includes('\\')) return false;
  const afterScheme = written.slice(written.indexOf(':') + 1).replace(/^\/*/, '');
  const authority = afterScheme.split('/')[0] ?? '';
  const at = authority.indexOf('@');
  if (at >= 0) {
    if (authority.indexOf('@', at + 1) >= 0) return false;
    // The host as written after the `@`, with its port: nothing else may follow.
    const host = /^(\[[^\]]*\]|[^:]*)(?::\d*)?$/.exec(authority.slice(at + 1))?.[1];
    if (host === undefined || !isLoopbackName(host)) return false;
  }
  return QUERY_SAFE_SCHEMES.has(url.protocol) || !written.includes('?');
}

/** How a reason names a URL: scheme and host. `origin` is "null" for a non-special scheme (fix round 5, minor 2). */
function hostLabel(url: URL): string {
  return `${url.protocol}//${url.host}`;
}

/** A `url` entry as a reason names it. */
function urlLabel(url: string): string {
  try {
    return hostLabel(new URL(url));
  } catch {
    return 'a URL that does not parse';
  }
}

/**
 * Why `text` reaches another machine through a URL or a UNC path, or null.
 * EVERY URL in it is checked: a loopback one is skipped, never the end of
 * the scan.
 */
function remoteInText(raw: string): string | null {
  const text = asUrlParsersRead(raw);
  if (UNC_ANYWHERE.test(raw) || UNC_ANYWHERE.test(text)) return 'names a network or device path';
  const starts = new Set<number>();
  for (const m of text.matchAll(SPECIAL_SCHEME)) starts.add(m.index);
  for (const m of text.matchAll(ANY_SCHEME_WITH_SLASHES)) starts.add(m.index);
  for (const start of [...starts].sort((a, b) => a - b)) {
    const written = urlAt(text, start);
    let url: URL;
    try {
      url = new URL(written);
    } catch {
      return `names a URL that does not parse (${JSON.stringify(written.slice(0, 80))})`;
    }
    if (url.hostname === '') continue;
    if (isLoopbackName(url.hostname)) {
      const cutInAuthority = start + written.length < text.length && authorityOpen(written);
      if (!cutInAuthority && unambiguous(url, written)) continue;
      return (
        `names ${hostLabel(url)} written so that another client may read another host ` +
        '(a backslash, several @, a host after the @ that is not loopback as written, a query on a ' +
        'non-HTTP scheme, or a space, quote or control character inside its host)'
      );
    }
    return `names ${hostLabel(url)} (a proxy, a client or a source on another machine)`;
  }
  return null;
}

/**
 * A value as a URL parser reads it (final review): WHATWG deletes ASCII TAB
 * and newline ANYWHERE in its input, and strips leading and trailing C0
 * controls and spaces — so does Python's `urlsplit` for the first. The gate
 * cut `http://127.0.0.1:80<TAB>@other.example/` at the TAB and exempted the
 * loopback it saw; the server read other.example.
 */
function asUrlParsersRead(value: string): string {
  return value.replace(/[\t\n\r]/g, '').replace(/^[\u0000- ]+|[\u0000- ]+$/g, '');
}

/**
 * The authority of `written` is still open where the gate stopped reading
 * it: no `/`, `?` or `#` after the scheme. A parser that does not stop where
 * the gate did — WHATWG reads on past a space or a quote as userinfo, so
 * `http://127.0.0.1:80 @other.example/` is other.example — can find another
 * host there, so such a URL is never exempt. One whose path has begun can
 * gain nothing but path.
 */
function authorityOpen(written: string): boolean {
  const afterScheme = written.slice(written.indexOf(':') + 1).replace(/^\/*/, '');
  return !/[/?#]/.test(afterScheme);
}

/** A command's own name: `C:\…\ssh.exe` → `ssh`. */
function commandName(command: string): string {
  const base = command.replace(/\\/g, '/').split('/').pop() ?? command;
  return base.replace(/\.(exe|cmd|bat|com)$/i, '').toLowerCase();
}

/** Commands that run the server on, or reach into, another machine, wherever they appear. */
const REMOTE_COMMANDS = new Set(['ssh', 'sshpass', 'plink', 'kubectl', 'oc']);
/** Container engines: remote when told to use another engine. */
const ENGINES = new Set(['docker', 'podman', 'nerdctl']);
/** An engine flag naming another engine, wherever it appears after the engine. */
const ENGINE_FLAG = /^(?:-H.*|--host|--remote|--connection|--url)$/;

/**
 * Every token of the command line (fix round 5, minor 1): the command, the
 * arguments, and the words inside a `-c` / `/c` string — split on
 * whitespace, quotes, shell operators and `=`, so `cd x&&ssh host`,
 * `$(kubectl …)` and `ProxyCommand=ssh` all show their command.
 */
function commandTokens(command: string, args: readonly string[]): string[] {
  return [command, ...args].flatMap((s) => s.split(/[\s"'`&|;()<>=]+/)).filter((t) => t !== '');
}

/** An engine told to use another engine (see the module doc), or null. */
function remoteEngine(tokens: readonly string[], env: Readonly<Record<string, unknown>>): string | null {
  let seen: string | null = null;
  for (let i = 0; i < tokens.length; i += 1) {
    const name = commandName(tokens[i] ?? '');
    if (!ENGINES.has(name)) continue;
    seen = name;
    // Global flags come first, and `-c <context>` and podman's `-r` mean
    // what they say only there: after the image, `sh -c` is a shell's.
    for (let j = i + 1; j < tokens.length && (tokens[j] ?? '').startsWith('-'); j += 1) {
      const flag = tokens[j] ?? '';
      if (flag === '-r') return `${name} is told to use a remote engine (-r)`;
      if (flag === '-c' || flag === '--context') {
        const value = tokens[j + 1] ?? '';
        if (value !== 'default') return `${name} is told to use the context '${value}'`;
        j += 1;
      }
    }
    for (let j = i + 1; j < tokens.length; j += 1) {
      const flag = tokens[j] ?? '';
      if (ENGINE_FLAG.test(flag)) return `${name} is told to use another engine (${flag.startsWith('-H') ? '-H' : flag})`;
      if (flag === '--context' && (tokens[j + 1] ?? '') !== 'default') {
        return `${name} is told to use the context '${tokens[j + 1] ?? ''}'`;
      }
    }
  }
  if (seen === null) return null;
  for (const key of ['DOCKER_CONTEXT', 'CONTAINER_CONNECTION']) {
    const value = env[key];
    if (typeof value === 'string' && value !== '' && value !== 'default') {
      return `${seen} is told to use the ${key === 'DOCKER_CONTEXT' ? 'context' : 'connection'} '${value}' (${key})`;
    }
  }
  return null;
}

/**
 * Why an entry's configuration reaches another machine, or null when it
 * looks local — a textual gate, not a sandbox (see the module doc).
 */
export function remoteReasonOf(entry: McpServerEntry): string | null {
  if (entry.command === undefined) {
    if (entry.url !== undefined) return `remote server at ${urlLabel(entry.url)}`;
    return null;
  }
  const command = entry.command;
  if (isRemoteOrDeviceTarget(command)) {
    return 'its command is on a network or device path (starting it contacts that host)';
  }
  const args = entry.args ?? [];
  const tokens = commandTokens(command, args);
  for (const t of tokens) {
    const name = commandName(t);
    if (REMOTE_COMMANDS.has(name)) return `its command line runs ${name} (the server runs on, or reaches into, another machine)`;
  }
  const engine = remoteEngine(tokens, entry.env ?? {});
  if (engine !== null) return engine;
  const envValues = Object.entries(entry.env ?? {}).flatMap(([k, v]) => (typeof v === 'string' ? [[k, v] as const] : []));
  const parts: Array<{ where: string; text: string }> = [
    { where: 'its command line', text: command },
    ...args.map((text) => ({ where: 'its command line', text })),
    ...envValues.map(([k, text]) => ({ where: `its env ${k}`, text })),
  ];
  for (const { where, text } of parts) {
    const why = remoteInText(text);
    if (why !== null) return `${where} ${why}`;
  }
  return null;
}

export type Resolved = { ok: true; command: string } | { ok: false; reason: string };

/** The value of `name` in `env`, whatever its case (Windows environment names are case-insensitive). */
function envValue(env: Record<string, string>, name: string): string | undefined {
  const key = Object.keys(env).find((k) => k.toUpperCase() === name);
  return key === undefined ? undefined : env[key];
}

async function isFile(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
}

function raceDeadline<T>(p: Promise<T>, deadline: number, onTimeout: T): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<T>((done) => {
    timer = setTimeout(() => done(onTimeout), Math.max(0, deadline - Date.now()));
    timer.unref();
  });
  return Promise.race([p, timeout]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}

/**
 * Whether `path` (a UNC command) can be read, asked of a child process that
 * is killed at `deadline`: the wait on SMB happens there, not here.
 */
function reachableFromChild(path: string, deadline: number): Promise<boolean> {
  return new Promise((done) => {
    const child = spawn(process.execPath, ['-e', 'process.exit(require("fs").statSync(process.argv[1]).isFile() ? 0 : 1)', path], {
      stdio: 'ignore',
      windowsHide: true,
    });
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      done(false);
    }, Math.max(0, deadline - Date.now()));
    timer.unref();
    child.on('error', () => {
      clearTimeout(timer);
      done(false);
    });
    child.on('exit', (code) => {
      clearTimeout(timer);
      done(code === 0);
    });
  });
}

/**
 * The command to spawn for `command` under `env` (the launch environment),
 * with `cwd` for a relative one — resolved without any synchronous file-system
 * or network access. See the module doc.
 */
export async function resolveCommand(
  command: string,
  env: Record<string, string>,
  cwd: string,
  deadline: number,
): Promise<Resolved> {
  if (isRemoteOrDeviceTarget(command)) {
    const reachable = await reachableFromChild(command, deadline);
    return reachable
      ? { ok: true, command }
      : { ok: false, reason: 'its command is on a network path that could not be reached within its time budget' };
  }
  if (process.platform !== 'win32') return { ok: true, command };

  const exts = (envValue(env, 'PATHEXT') ?? process.env['PATHEXT'] ?? '.COM;.EXE;.BAT;.CMD')
    .split(';')
    .filter((e) => e !== '');
  const withExts = (base: string): string[] => (extname(base) !== '' ? [base, ...exts.map((e) => base + e)] : exts.map((e) => base + e));

  let candidates: string[];
  const skipped: string[] = [];
  if (/[\\/]/.test(command) || isAbsolute(command)) {
    candidates = withExts(resolve(cwd, command));
  } else {
    const dirs = (envValue(env, 'PATH') ?? '').split(delimiter).filter((d) => d !== '');
    candidates = [];
    for (const dir of dirs) {
      if (isRemoteOrDeviceTarget(dir)) {
        skipped.push(dir);
        continue;
      }
      candidates.push(...withExts(resolve(dir, command)));
    }
  }
  const search = (async (): Promise<string | null> => {
    for (const c of candidates) if (await isFile(c)) return c;
    return null;
  })();
  const found = await raceDeadline<string | null | 'timeout'>(search, deadline, 'timeout');
  if (found === 'timeout') return { ok: false, reason: `resolving '${command}' did not finish within its time budget` };
  if (found === null) {
    return {
      ok: false,
      reason:
        `could not start the server: '${command}' was not found on PATH` +
        (skipped.length > 0 ? ` (network PATH entries were not searched: ${skipped.join(', ')})` : ''),
    };
  }
  return { ok: true, command: found };
}
