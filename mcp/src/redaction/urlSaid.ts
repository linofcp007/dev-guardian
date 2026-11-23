/**
 * How a tool says a URL or a network path it READ from a file (a lockfile, a `.npmrc`, a requirements file, a
 * `.mcp.json`, the repository's git configuration) or from a program's error line: the one rule, so that no credential
 * written in such a URL ends in the transcript, on the screen, in the database or in a report.
 *
 * The text is decided by how a URL parser reads it (`new URL`, the WHATWG one: it deletes TAB, CR and LF anywhere,
 * strips spaces and C0 controls at both ends, and reads the authority of a special scheme written with one, two or no
 * slash, or with a backslash). A user part is never said; an `@` that is not a user part (a credential written with an
 * unencoded `/`, `?`, `#` or `\` makes the parser read the START of it as the host) says no host at all; a text with an
 * `@` that the parser does not read as a URL says `(unparseable URL)`. Only a text with no `@` (and a reader's cut-off
 * part with none), a loose version, an `npm:` alias, the scp form of git with the name `git`, and a URL whose only `@`
 * are the scope of its own package or an empty user part come out as written.
 *
 * It rests on {@link strayAt} (`pkgvet/strayAt.ts`), which says whether a parsed URL has an `@` outside its credentials.
 * Nothing in `pkgvet/`, `hooks/` or `platform/gitSafety.ts` imports this module: the hooks' bundle does not carry it.
 */

import { isLooseVersion } from '../deps/versionCompare.js';
import { strayAt } from '../pkgvet/strayAt.js';

/** What a reason says in place of a host that cannot be told from a piece of a credential. */
const HOST_NOT_SHOWN = '(host not shown)';
const UNPARSEABLE = '(unparseable URL)';

// ── the grammar of where a URL starts and ends in a text (one grammar; `mcpaudit/launch.ts` imports it) ──────────────

/**
 * A special scheme (WHATWG: one whose URLs always have a host) followed by
 * `:`, anywhere: `https:evil.example` reaches evil.example as surely as
 * `https://evil.example` (fix round 5, I-4). `file` is left to
 * {@link ANY_SCHEME_WITH_SLASHES}: `file:x` has no host.
 */
export const SPECIAL_SCHEME = /(?:https?|wss?|ftp):/gi;
/** Any `scheme://`; what follows is a host only when WHATWG parses one. */
export const ANY_SCHEME_WITH_SLASHES = /[a-z][a-z0-9+.-]*:\/\//gi;
/** Where a URL written into a command line, an env value or an error line ends. */
export const URL_END = /[\s"'<>|`]/;
/**
 * A UNC or device path anywhere: `\\host\…`, `\\?\…`, `\\.\…`, or
 * `//host/…` not preceded by `:` or `/` (a URL's `://`, `file:///`).
 */
export const UNC_ANYWHERE = /\\\\[^\\\s"'<>|]+\\|(?<![:/])\/\/[^/\s"'<>|]+\//;

/**
 * A value as a URL parser reads it (final review): WHATWG deletes ASCII TAB
 * and newline ANYWHERE in its input, and strips leading and trailing C0
 * controls and spaces — so does Python's `urlsplit` for the first. The gate
 * cut `http://127.0.0.1:80<TAB>@other.example/` at the TAB and exempted the
 * loopback it saw; the server read other.example.
 */
export function asUrlParsersRead(value: string): string {
  return value.replace(/[\t\n\r]/g, '').replace(/^[\u0000- ]+|[\u0000- ]+$/g, '');
}

// ── one URL ──────────────────────────────────────────────────────────────────────────────────────────────────────────

interface UrlSaidOptions {
  /** `whole`: the URL as it is said without its credentials. `hostPort`: only `scheme://host[:port]`, never what was written. */
  form: 'whole' | 'hostPort';
  /** The package the URL serves, when known: the `@` that opens its own scope is not a sign of a stray one. */
  ownName?: string;
  /** What the reader cut off after the value (a comment, a `;`, a space): an `@` in it says no host. */
  cutOff?: string;
}

/** `npm:(@scope/)?name@version`, the scope and the name with no `:`, `\`, `@`, `/` or space, the version with no `/`, `\`, `:`, `@` or space. */
const NPM_ALIAS = /^npm:(?:@[^:\\@/\s]+\/)?[^:\\@/\s]+@[^/\\:@\s]+$/;
/** The scp form of git with the name `git`: one `@`, a host with no `:`, `/`, `\` or space, and a path with no `@` or space. */
const SCP_GIT = /^git@[^:/\\\s@]+:[^@\s]*$/;
/** The scp form with another name (a login for ssh; for npm's `hosted-git-info` it may be a credential). */
const SCP_OTHER = /^[^:/\\\s@]+@([^:/\\\s@]+:[^@\s]*)$/;
const NETWORK_BEGIN = /^(?:\/\/|\\\\)/;

/** The scheme of a parsed URL, as `scheme` (no colon). */
const schemeOf = (url: URL): string => url.protocol.replace(/:$/, '');

/**
 * `written`, said as the rule above decides (the order is the rule: the first that holds). `hostPort` never gives back
 * the text it received: only a host with its port, the label of a text with no host, or `(unparseable URL)`.
 */
export function urlSaid(written: string, opts: UrlSaidOptions): string {
  const whole = opts.form === 'whole';
  const hasAt = written.includes('@');
  const cutAt = (opts.cutOff ?? '').includes('@');
  // 1. As written: only these, and only in the whole form.
  if (whole && !cutAt && (!hasAt || isLooseVersion(written) || NPM_ALIAS.test(written) || SCP_GIT.test(written))) return written;
  // 2. The scp form with another name: the host and the path, without the name.
  if (whole && !cutAt) {
    const scp = SCP_OTHER.exec(written);
    if (scp?.[1] !== undefined) return scp[1];
  }
  // 3. The parser reads a host.
  let url: URL | null = null;
  try {
    url = new URL(written);
  } catch {
    url = null;
  }
  if (url !== null && url.hostname !== '') {
    if (strayAt(url, opts.ownName) || cutAt) return `${schemeOf(url)}://${HOST_NOT_SHOWN}`;
    if (!whole) return `${url.protocol}//${url.host}`;
    if (url.username !== '' || url.password !== '') {
      url.username = '';
      url.password = '';
      return url.href;
    }
    return written;
  }
  // 4. The parser reads the text with no host and there is no `@` (`file:///x`).
  if (url !== null && !hasAt && !cutAt) return whole ? written : `${url.protocol}//`;
  // 5. A network path the parser does not read, with an `@` in it or in what was cut off.
  const trimmed = asUrlParsersRead(written);
  if (url === null && (hasAt || cutAt) && NETWORK_BEGIN.test(trimmed)) return `${trimmed.slice(0, 2)}${HOST_NOT_SHOWN}`;
  // 6. Everything else with an `@`, or a text that does not parse in the host form.
  return UNPARSEABLE;
}

// ── the URLs in a free text ──────────────────────────────────────────────────────────────────────────────────────────

const SCHEME_CHAR = /[A-Za-z0-9+.-]/;
const LETTER = /[A-Za-z]/;
/** The special schemes, longest first at the same end: `https` before `http`. */
const SPECIAL = ['https', 'http', 'wss', 'ws', 'ftp'];

/**
 * Where a URL starts in `t[from, to)` (one word: no character of {@link URL_END} in it), or -1: the leftmost of a
 * `scheme://` ({@link ANY_SCHEME_WITH_SLASHES}), a special scheme and `:` ({@link SPECIAL_SCHEME}) and a network path
 * ({@link UNC_ANYWHERE}). Found by scanning for the `:` and looking back over the scheme's characters, so no pattern
 * backtracks over a long word: the cost is linear in the text.
 */
function urlStartIn(t: string, from: number, to: number): number {
  let best = -1;
  for (let colon = t.indexOf(':', from); colon >= 0 && colon < to; colon = t.indexOf(':', colon + 1)) {
    let first = colon;
    while (first > from && SCHEME_CHAR.test(t.charAt(first - 1))) first -= 1;
    while (first < colon && !LETTER.test(t.charAt(first))) first += 1;
    if (first === colon) continue;
    if (t.startsWith('//', colon + 1)) {
      best = first;
      break;
    }
    const run = t.slice(first, colon).toLowerCase();
    const special = SPECIAL.find((name) => run.endsWith(name));
    if (special !== undefined) {
      best = colon - special.length;
      break;
    }
  }
  const unc = t.slice(from, to).search(UNC_ANYWHERE);
  if (unc >= 0 && (best < 0 || from + unc < best)) best = from + unc;
  return best;
}

/** How a URL says it begins: `scheme://` or the network path's `//` or `\\`. */
function beginOf(url: string): string {
  return NETWORK_BEGIN.test(url) ? url.slice(0, 2) : `${url.slice(0, url.indexOf(':')).toLowerCase()}://`;
}

/**
 * The URLs in a free text (an error line, a JSON key, a message), each said by {@link urlSaid} in the whole form. The
 * text is read without TAB, CR and LF. A URL starts where {@link urlStartIn} finds a start and ends at the first
 * character of {@link URL_END} or the end of the text; a start inside a URL already read is skipped (a word holds one
 * URL). When the rest of the text after the end of a URL holds an `@`, everything from the start of that URL to the end
 * of the word that holds the LAST `@` of the text is said as `scheme://(host not shown)` — a cut at a space must not
 * leave the rest of a credential in sight — and reading goes on after that word. The last `@` is found once. A text
 * with no URL comes out as it was; one with a URL comes out built from the text without TAB, CR and LF.
 */
export function urlsSaidIn(text: string): string {
  const t = text.replace(/[\t\n\r]/g, '');
  const lastAt = t.lastIndexOf('@');
  const n = t.length;
  let out = '';
  let copied = 0;
  let found = false;
  let i = 0;
  while (i < n) {
    if (URL_END.test(t.charAt(i))) {
      i += 1;
      continue;
    }
    let end = i;
    while (end < n && !URL_END.test(t.charAt(end))) end += 1;
    const start = urlStartIn(t, i, end);
    if (start < 0) {
      i = end;
      continue;
    }
    found = true;
    const url = t.slice(start, end);
    let stop = end;
    let said: string;
    if (lastAt >= end) {
      stop = lastAt;
      while (stop < n && !URL_END.test(t.charAt(stop))) stop += 1;
      said = `${beginOf(url)}${HOST_NOT_SHOWN}`;
    } else {
      said = urlSaid(url, { form: 'whole' });
    }
    out += t.slice(copied, start) + said;
    copied = stop;
    i = stop;
  }
  return found ? out + t.slice(copied) : text;
}

// ── git configuration keys ───────────────────────────────────────────────────────────────────────────────────────────

/** The sections whose keys take a URL as their subsection: `http.<url>.<variable>`, `credential.<url>.<variable>`. */
const URL_SECTIONS = ['http', 'credential'];

/**
 * Git configuration keys (`<section>.<subsection>.<variable>`) with the subsection said by {@link urlSaid}: a key such
 * as `http.https://U:T@H/.extraheader` names the repository's own setting that dev-guardian did not apply, and its URL
 * holds the credential the repository wrote there. A key with no URL subsection comes out as it was; repeats collapse.
 */
export function gitKeysSaid(keys: readonly string[]): string[] {
  const said = keys.map((key) => {
    const first = key.indexOf('.');
    const last = key.lastIndexOf('.');
    if (first < 0 || last <= first || !URL_SECTIONS.includes(key.slice(0, first).toLowerCase())) return key;
    return `${key.slice(0, first + 1)}${urlSaid(key.slice(first + 1, last), { form: 'whole' })}${key.slice(last)}`;
  });
  return [...new Set(said)];
}
