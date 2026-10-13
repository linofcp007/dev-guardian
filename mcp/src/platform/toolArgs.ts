/**
 * What a tool hands a program as an argument, checked where it enters the
 * tool — the tools' half of the "BatBadBut" fix (review 10, finding 3).
 *
 * WP-CLI, WPScan and Lighthouse are batch files on Windows (`wp.bat`, a gem's
 * `wpscan.bat`, npm's `lighthouse.cmd`), and a `"` in a slug, a URL or a path
 * handed to one closed its quotes when `cmd.exe` read the line a second time.
 * `runners/spawn.ts` now refuses any such argument for every caller; each
 * tool also takes only what its value can be:
 *
 *   - a URL is parsed with WHATWG's `URL` — http or https only — and the
 *     program gets the RE-SERIALISED `href`, never the text it came as: a
 *     `"` is `%22` there, a line break is gone, a space is `%20`. The URL a
 *     site names itself (WordPress's `home` option, read by WP-CLI) is held
 *     to the same rule;
 *   - a path holds no `"` and no control character (a Windows path never
 *     holds a `"`; a path that does is not one);
 *   - a WordPress plugin slug and an API token are their own short alphabets.
 */

/**
 * `text` as an http(s) URL, parsed and re-serialised (`URL.href`); null when
 * it is not one.
 */
export function httpUrl(text: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(text);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
  return parsed.href;
}

/** Why `value` cannot be a path a program is handed — `"`, or a control character; null when it can. */
export function pathArgProblem(name: string, value: string): string | null {
  if (value.includes('"')) return `${name} holds a double quote, which no path holds`;
  if (/[\u0000-\u001F\u007F]/.test(value)) return `${name} holds a control character, which no path holds`;
  return null;
}

/**
 * A WordPress plugin slug: what WordPress's `sanitize_title_with_dashes` keeps
 * of a plugin's name — letters, digits, `_` and `-` (a local plugin's folder
 * may be capitalised). Nothing `cmd.exe` reads as syntax.
 */
export const WP_PLUGIN_SLUG = /^[A-Za-z0-9_-]{1,200}$/;

/** An API token (WPScan's are 43 letters and digits): letters, digits, `_`, `-` and `.`. */
export const API_TOKEN = /^[A-Za-z0-9_.-]{1,512}$/;
