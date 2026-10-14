/**
 * Claude Code's own settings can switch every dev-guardian hook off without
 * touching dev-guardian's configuration: `"disableAllHooks": true` in
 * `.claude/settings.json` / `.claude/settings.local.json` (project or user
 * level), an `env` block that sets the hook dispatcher's own switches —
 * `GUARDIAN_HOOKS=off`, `GUARDIAN_HOOKS_BASH_BLOCK=0|false`,
 * `GUARDIAN_PKG_VET=0`, and with any value `NODE_OPTIONS` and
 * `GUARDIAN_PKG_VET_DEADLINE_MS` — or an `enabledPlugins` entry that turns the
 * plugin itself off (`"dev-guardian@<marketplace>": false`, follow-up Part Y).
 * An assistant writes those files routinely (to allow a
 * command, say), so the Write/Edit guard cannot refuse them wholesale. It
 * refuses exactly one thing: an edit whose RESULT sets one of those keys that
 * the file did not already set (final review M5). A key the user already set
 * stays set through any later edit; `env` `PATH`, `HOME` and `USERPROFILE`
 * are asked about ({@link newlyAsked}); anything else — permissions, other env
 * vars, other hooks — is never refused.
 *
 * Pure functions, `node:` built-ins only: the hook dispatcher loads the
 * compiled copy from `mcp/dist/hooks/` in an install with no `node_modules`.
 */

/**
 * `.claude/settings.json` or `.claude/settings.local.json`, anywhere — and,
 * given Claude Code's `CLAUDE_CONFIG_DIR` (`configDir`), the same two files
 * directly in that directory, which are then the user's settings (review
 * round 2: `~/.claude-conta2/settings.json` was not guarded). Both paths are
 * compared as given — the caller resolves them (`guardedPath`) — with either
 * separator, and case-insensitively on Windows.
 */
export function isClaudeSettingsPath(path: string, configDir?: string): boolean {
  if (/(?:^|[\\/])\.claude[\\/]settings(?:\.local)?\.json$/i.test(path)) return true;
  if (configDir === undefined || configDir.trim() === '') return false;
  const fold = process.platform === 'win32';
  const m = (fold ? /^(.*)[\\/](settings(?:\.local)?\.json)$/i : /^(.*)\/(settings(?:\.local)?\.json)$/).exec(path);
  if (m === null) return false;
  const norm = (p: string): string => {
    const t = p.replace(/\\/g, '/').replace(/\/+$/, '');
    return fold ? t.toLowerCase() : t;
  };
  return norm(m[1] ?? '') === norm(configDir);
}

/** The env switches the dispatcher reads, and the values that turn a hook off. */
const ENV_SWITCHES: ReadonlyArray<{ name: string; off: ReadonlyArray<string> }> = [
  { name: 'GUARDIAN_HOOKS', off: ['off'] },
  { name: 'GUARDIAN_HOOKS_BASH_BLOCK', off: ['0', 'false'] },
  { name: 'GUARDIAN_PKG_VET', off: ['0'] },
];

/**
 * Variables that switch a hook off whatever their value (review of 3.4.0,
 * finding 4): `NODE_OPTIONS` runs code in every hook before it starts
 * (`--import=data:…,process.exit(0)` made the dispatcher silent on `rm -rf
 * /`), and `GUARDIAN_PKG_VET_DEADLINE_MS` sets how long package vetting may
 * take (`1` turned the deny of a malicious package into a note). A new value
 * is a new switch.
 */
const ENV_ANY_VALUE = ['NODE_OPTIONS', 'GUARDIAN_PKG_VET_DEADLINE_MS'];

/**
 * Variables that decide which program a hook runs or which home it reads its
 * user configuration from — `PATH` finds the `node` every hook entry starts —
 * so a new value is the user's to confirm: asked, never denied.
 */
const ENV_ASKED = ['PATH', 'HOME', 'USERPROFILE'];

/** A plugin id that names dev-guardian, under any marketplace (`dev-guardian@<marketplace>`). */
const OUR_PLUGIN = /dev-guardian/i;

/** An object of the lenient reading ({@link readLenient}): its entries in order, a key that repeats kept every time. */
class LenientObject {
  constructor(readonly entries: ReadonlyArray<readonly [string, Lenient]>) {}
}
type Lenient = null | boolean | number | string | Lenient[] | LenientObject;

/** The deepest nesting {@link readLenient} reads; a settings file is a few levels deep. */
const MAX_LENIENT_DEPTH = 64;

/**
 * `text` read as JSON the lenient way a settings reader may: `//` and `/* *\/`
 * comments and trailing commas allowed (JSONC), and a key that repeats kept
 * every time — JSON.parse keeps the last, another reader may keep the first,
 * and either may be the one Claude Code acts on (review of 3.4.0, finding 4).
 * A key's escapes are decoded (`"disableAllHooks"` is `disableAllHooks`).
 * `undefined` when it is no such text. One pass, linear.
 */
function readLenient(text: string): Lenient | undefined {
  let i = 0;
  const n = text.length;
  const NUMBER = /-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
  const skip = (): void => {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 32 || c === 9 || c === 10 || c === 13) i += 1;
      else if (c === 47 && text.charCodeAt(i + 1) === 47) {
        const end = text.indexOf('\n', i);
        i = end < 0 ? n : end + 1;
      } else if (c === 47 && text.charCodeAt(i + 1) === 42) {
        const end = text.indexOf('*/', i + 2);
        if (end < 0) throw new Error('unterminated comment');
        i = end + 2;
      } else return;
    }
  };
  const string = (): string => {
    let j = i + 1;
    while (j < n && text.charCodeAt(j) !== 34) j += text.charCodeAt(j) === 92 ? 2 : 1;
    if (j >= n) throw new Error('unterminated string');
    const value: unknown = JSON.parse(text.slice(i, j + 1));
    i = j + 1;
    return String(value);
  };
  const value = (depth: number): Lenient => {
    if (depth > MAX_LENIENT_DEPTH) throw new Error('too deep');
    skip();
    const c = text.charAt(i);
    if (c === '"') return string();
    if (c === '{' || c === '[') {
      const object = c === '{';
      i += 1;
      const entries: Array<readonly [string, Lenient]> = [];
      const items: Lenient[] = [];
      for (;;) {
        skip();
        if (text.charAt(i) === (object ? '}' : ']')) {
          i += 1;
          return object ? new LenientObject(entries) : items;
        }
        if (object) {
          if (text.charAt(i) !== '"') throw new Error('a key expected');
          const key = string();
          skip();
          if (text.charAt(i) !== ':') throw new Error('a colon expected');
          i += 1;
          entries.push([key, value(depth + 1)]);
        } else items.push(value(depth + 1));
        skip();
        if (text.charAt(i) === ',') i += 1;
        else if (text.charAt(i) !== (object ? '}' : ']')) throw new Error('a comma expected');
      }
    }
    for (const [word, literal] of [['true', true], ['false', false], ['null', null]] as const) {
      if (text.startsWith(word, i)) {
        i += word.length;
        return literal;
      }
    }
    NUMBER.lastIndex = i;
    const m = NUMBER.exec(text);
    if (m === null) throw new Error('a value expected');
    i += m[0].length;
    return Number(m[0]);
  };
  try {
    const v = value(0);
    skip();
    return i === n ? v : undefined;
  } catch {
    return undefined;
  }
}

/** Whether a setting's value may be read as "on" — any value JavaScript takes as true; `"false"` among them. */
function truthy(v: Lenient): boolean {
  return v instanceof LenientObject || Array.isArray(v) || Boolean(v);
}

/** A scalar's text, as the environment would hold it; none for an object or an array. */
function scalar(v: Lenient): string | undefined {
  return v instanceof LenientObject || Array.isArray(v) ? undefined : String(v);
}

/** What a settings file's switches add up to: the labels that switch a hook off, and those to ask about. */
interface Found {
  off: string[];
  ask: string[];
}

/** One `env` entry, judged. Names match case-insensitively (Windows env is). */
function judgeEnv(key: string, value: Lenient, found: Found): void {
  const name = key.toUpperCase();
  const text = scalar(value);
  if (text === undefined) return;
  const sw = ENV_SWITCHES.find((s) => s.name === name);
  if (sw !== undefined && sw.off.includes(text)) found.off.push(`env ${sw.name}=${text}`);
  if (ENV_ANY_VALUE.includes(name)) found.off.push(`env ${name}=${text}`);
  if (ENV_ASKED.includes(name)) found.ask.push(`env ${name}=${text}`);
}

/**
 * From the settings read leniently. `disableAllHooks` with any value that may
 * read as true (`"true"`, `1`, …), and an `enabledPlugins` entry naming
 * dev-guardian with any value but `true` (`"false"`, `0`, …), count: which form
 * Claude Code honours is its parser's business, and an ambiguous one is taken
 * as the switch (review of 3.4.0, finding 4).
 */
function fromObject(settings: LenientObject): Found {
  const found: Found = { off: [], ask: [] };
  for (const [key, value] of settings.entries) {
    if (key === 'disableAllHooks' && truthy(value)) found.off.push('disableAllHooks: true');
    else if (key === 'env' && value instanceof LenientObject) {
      for (const [name, v] of value.entries) judgeEnv(name, v, found);
    } else if (key === 'enabledPlugins' && value instanceof LenientObject) {
      for (const [id, enabled] of value.entries) {
        if (enabled !== true && OUR_PLUGIN.test(id)) found.off.push(`enabledPlugins ${id}=false`);
      }
    }
  }
  return found;
}

/**
 * The same settings, by pattern, for text that is not a JSON object (a
 * fragment of an edit that could not be applied), its `\uXXXX` escapes read as
 * what they spell. The labels match {@link fromObject}'s, so the two can be
 * compared.
 */
const TEXT_PATTERNS: ReadonlyArray<{ label: string; re: RegExp }> = [
  { label: 'disableAllHooks: true', re: /"disableAllHooks"\s*:\s*(?:true\b|"[^"\n]|-?(?:[1-9]|0\.\d*[1-9])|[[{])/ },
  { label: 'env GUARDIAN_HOOKS=off', re: /"GUARDIAN_HOOKS"\s*:\s*"off"/i },
  { label: 'env GUARDIAN_HOOKS_BASH_BLOCK=0', re: /"GUARDIAN_HOOKS_BASH_BLOCK"\s*:\s*(?:"0"|0\b)/i },
  { label: 'env GUARDIAN_HOOKS_BASH_BLOCK=false', re: /"GUARDIAN_HOOKS_BASH_BLOCK"\s*:\s*(?:"false"|false\b)/i },
  { label: 'env GUARDIAN_PKG_VET=0', re: /"GUARDIAN_PKG_VET"\s*:\s*(?:"0"|0\b)/i },
];

/** A variable set to any value, by pattern: its name, and its value as a JSON literal. */
const ENV_VALUE = /"(NODE_OPTIONS|GUARDIAN_PKG_VET_DEADLINE_MS|PATH|HOME|USERPROFILE)"\s*:\s*("(?:[^"\\\n]|\\.)*"|-?\d[\d.eE+-]*|true|false|null)/gi;

/**
 * An `enabledPlugins` entry turning dev-guardian off, by pattern: a quoted key
 * naming dev-guardian under a marketplace set to anything but `true`. In a
 * Claude Code settings file only `enabledPlugins` has such keys, and an edit
 * fragment may not show the `enabledPlugins` around it.
 */
const PLUGIN_OFF = /"([^"\n]*dev-guardian[^"\n]*)"\s*:\s*(?!true\b)(?:false\b|null\b|-?\d|")/gi;

function fromText(raw: string): Found {
  const text = raw.includes('\\u') ? raw.replace(/\\u([0-9A-Fa-f]{4})/g, (_, hex: string) => String.fromCharCode(parseInt(hex, 16))) : raw;
  const found: Found = { off: TEXT_PATTERNS.filter((p) => p.re.test(text)).map((p) => p.label), ask: [] };
  for (const m of text.matchAll(PLUGIN_OFF)) found.off.push(`enabledPlugins ${m[1] ?? ''}=false`);
  for (const m of text.matchAll(ENV_VALUE)) {
    let value: unknown;
    try {
      value = JSON.parse(m[2] ?? '');
    } catch {
      continue;
    }
    // In a fragment, `"path": …` is anything's path: only the upper-case name is the variable.
    const name = m[1] ?? '';
    if (ENV_ANY_VALUE.includes(name.toUpperCase()) || name === name.toUpperCase()) judgeEnv(name, value as Lenient, found);
  }
  return found;
}

/** {@link fromObject} of `content` read leniently, or {@link fromText} when it is no JSON object. */
function settingsFound(content: string): Found {
  const text = content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
  const read = readLenient(text);
  return read instanceof LenientObject ? fromObject(read) : fromText(text);
}

/**
 * The hook-loosening settings `content` sets, as labels (`disableAllHooks:
 * true`, `env GUARDIAN_PKG_VET=0`, `env NODE_OPTIONS=…`, …). Read as JSON — the
 * lenient way: comments, trailing commas, a repeated key kept every time — when
 * it is an object (a leading byte-order mark allowed), matched by pattern
 * otherwise.
 */
export function hookLooseningSettings(content: string): string[] {
  return settingsFound(content).off;
}

/** The loosening settings `after` sets that `before` did not. `before` undefined = a new file. */
export function newlyLoosened(before: string | undefined, after: string): string[] {
  const had = new Set(before === undefined ? [] : hookLooseningSettings(before));
  return hookLooseningSettings(after).filter((label) => !had.has(label));
}

/**
 * The settings `after` sets, and `before` did not, that are the user's to
 * confirm rather than refused: `env` `PATH`, `HOME` or `USERPROFILE`
 * ({@link ENV_ASKED}).
 */
export function newlyAsked(before: string | undefined, after: string): string[] {
  const had = new Set(before === undefined ? [] : settingsFound(before).ask);
  return settingsFound(after).ask.filter((label) => !had.has(label));
}

/**
 * Claude Code's Edit applied to `content`: `oldString` replaced by `newString`
 * (every occurrence with `replaceAll`). `undefined` when `oldString` is not
 * there, i.e. the edit cannot be reproduced.
 */
export function applyEdit(content: string, oldString: string, newString: string, replaceAll = false): string | undefined {
  if (oldString === '') return undefined;
  if (replaceAll) return content.includes(oldString) ? content.split(oldString).join(newString) : undefined;
  const at = content.indexOf(oldString);
  return at < 0 ? undefined : content.slice(0, at) + newString + content.slice(at + oldString.length);
}
