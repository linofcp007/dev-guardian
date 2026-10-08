/**
 * Tells — text in a blind copy that tells the model it is looking at a
 * deliberately vulnerable app, a benchmark, or a known corpus. A tell does
 * not change what the code does, but it changes how a model reads it ("this
 * is the intentional challenge flaw"), so a blind copy must carry none — in
 * its comments, its strings, its identifiers or its file names.
 *
 * What counts, matched case-insensitively everywhere:
 *   - {@link GENERAL_TELLS} and {@link ATTACK_TELLS} as raw text — words no
 *     ordinary application needs (`intentional`, `vulnerab…`, `OWASP`,
 *     `benchmark`, a corpus or author name, `cheat`, `malicious`, …) and the
 *     attack classes (`XXE`, `SQLi`, `injection`, `attack`, …);
 *   - every identifier-like token split on camelCase, snake_case and digit
 *     boundaries ({@link tokenParts}), each part judged by {@link PART_RULES}
 *     — so `xssFilter`, `sqlInjectionX` and `is_unsafe` are tells although
 *     `\bxss\b` never matches them.
 * Except: {@link ALLOWLIST} (real API words a reviewer must see — the CSP
 * keywords `'unsafe-inline'`, `'unsafe-eval'`, `'unsafe-hashes'`), and
 * random key material (a long token with digits and both cases).
 *
 * How a tell goes, never moving a line:
 *   - a comment carrying one is emptied ({@link neutraliseTellComments});
 *   - in code, strings and data files, every tell-bearing token is renamed by
 *     the SAME deterministic map ({@link rewriteToken}): the same identifier
 *     becomes the same replacement in every file — imports, exports, the
 *     module specifier strings that name it and the file names that embed it
 *     ({@link rewritePath}) — so the code still reads coherently;
 *   - "on purpose" (a phrase, not a token) becomes "as designed".
 * {@link findTells} is the check `corpora.ts` runs on a finished copy: any
 * survivor and the copy is refused.
 */

export const GENERAL_TELLS: readonly RegExp[] = [
  /intention/i,
  /vulnerab/i,
  /\bvuln/i,
  /exploit/i,
  /challenge/i,
  /\bctf\b|fbctf/i,
  /juice/i,
  /owasp/i,
  /hacking[\s_-]?instructor/i,
  /dvwa/i,
  /\bdamn\b/i,
  /vampi/i,
  /benchmark/i,
  /kimminich/i,
  /\bpwn/i,
  /on purpose/i,
  /deliberate/i,
  /should[\s_-]+(?:never|always)[\s_-]+happen/i,
  // review round 2
  /cheat/i,
  /hackable/i,
  /unsafe/i,
  /prompt[\s_-]*injection/i,
  /malicious/i,
  /leaked/i,
];

export const ATTACK_TELLS: readonly RegExp[] = [
  /\b(?:xxe|ssti|sqli|rce|lfi|rfi|idor|ssrf|xss|csrf|redos|bola)\b/i,
  /\bcwe-\d+/i,
  /\binjection\b/i,
  /\btraversal\b/i,
  /\binsecure\b/i,
  /\battacks?\b/i,
  /\bbackdoor\b/i,
];

/** Kept as-is: real API words a reviewer of the code must see. Matched case-insensitively. */
export const ALLOWLIST: readonly RegExp[] = [
  // CSP source expressions — the very thing an XSS verdict on a CSP header turns on (Juice Shop routes/userProfile.ts)
  /unsafe-(?:inline|eval|hashes)\b/i,
];

const RAW_TELLS: readonly RegExp[] = [...GENERAL_TELLS, ...ATTACK_TELLS];

/**
 * A tell part and what it becomes. First match wins: `exact` compares the
 * whole part, `prefix` its start, `contains` anywhere. The replacement takes
 * the part's case (`XSS` → `MARKUP`, `Xss` → `Markup`, `xss` → `markup`).
 */
export const PART_RULES: ReadonlyArray<{ match: 'exact' | 'prefix' | 'contains'; word: string; to: string }> = [
  { match: 'exact', word: 'xss', to: 'markup' },
  { match: 'exact', word: 'xxe', to: 'entity' },
  { match: 'exact', word: 'ssti', to: 'tmpl' },
  { match: 'exact', word: 'sqli', to: 'query' },
  { match: 'exact', word: 'rce', to: 'remote' },
  { match: 'exact', word: 'lfi', to: 'localfile' },
  { match: 'exact', word: 'rfi', to: 'remotefile' },
  { match: 'exact', word: 'idor', to: 'objref' },
  { match: 'exact', word: 'bola', to: 'objref' },
  { match: 'exact', word: 'ssrf', to: 'outbound' },
  { match: 'exact', word: 'csrf', to: 'formtoken' },
  { match: 'exact', word: 'redos', to: 'pattern' },
  { match: 'exact', word: 'ctf', to: 'score' },
  { match: 'exact', word: 'cwe', to: 'ref' },
  { match: 'exact', word: 'damn', to: 'very' },
  { match: 'contains', word: 'dvwa', to: 'app' },
  { match: 'contains', word: 'vampi', to: 'shelf' },
  { match: 'contains', word: 'intention', to: 'planned' },
  { match: 'contains', word: 'challenge', to: 'event' },
  { match: 'contains', word: 'juice', to: 'shop' },
  { match: 'contains', word: 'owasp', to: 'promo' },
  { match: 'contains', word: 'benchmark', to: 'site' },
  { match: 'contains', word: 'kimminich', to: 'owner' },
  { match: 'contains', word: 'exploit', to: 'event' },
  { match: 'contains', word: 'malicious', to: 'unusual' },
  { match: 'prefix', word: 'vuln', to: 'item' },
  { match: 'prefix', word: 'inject', to: 'input' },
  { match: 'prefix', word: 'travers', to: 'walk' },
  { match: 'prefix', word: 'insecure', to: 'plain' },
  { match: 'prefix', word: 'backdoor', to: 'side' },
  { match: 'prefix', word: 'attack', to: 'action' },
  { match: 'prefix', word: 'hackable', to: 'storage' },
  { match: 'prefix', word: 'hacking', to: 'testing' },
  { match: 'prefix', word: 'hacker', to: 'user' },
  { match: 'prefix', word: 'hack', to: 'patch' },
  { match: 'prefix', word: 'cheat', to: 'anomaly' },
  { match: 'prefix', word: 'unsafe', to: 'raw' },
  { match: 'prefix', word: 'leak', to: 'shared' },
  { match: 'prefix', word: 'pwn', to: 'reach' },
  { match: 'prefix', word: 'deliberate', to: 'planned' },
];

/** The parts of a token: `sqlInjectionX` → `sql`, `Injection`, `X`; `is_unsafe` → `is`, `_`, `unsafe`; `XMLParser` → `XML`, `Parser`. */
export function tokenParts(token: string): string[] {
  return token.match(/[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+|[^A-Za-z0-9]+/g) ?? [];
}

/** Key material, not words: a long token with digits and both cases (base64, keys). */
function isKeyMaterial(token: string): boolean {
  return token.length >= 24 && /[0-9]/.test(token) && /[a-z]/.test(token) && /[A-Z]/.test(token);
}

function ruleFor(part: string): (typeof PART_RULES)[number] | undefined {
  const l = part.toLowerCase();
  return PART_RULES.find((r) => (r.match === 'exact' ? l === r.word : r.match === 'prefix' ? l.startsWith(r.word) : l.includes(r.word)));
}

/** `word` in the case of `like`: `XSS` → `MARKUP`, `Xss` and `SQLi` → `Markup`/`Query`, `xss` → `markup`. */
function inCase(like: string, word: string): string {
  if (like.length > 1 && like === like.toUpperCase() && like !== like.toLowerCase()) return word.toUpperCase();
  if (/^[A-Z]/.test(like)) return `${word[0]?.toUpperCase() ?? ''}${word.slice(1)}`;
  return word;
}

/**
 * An `exact` rule matching the whole token: `SQLi` splits into `SQ` + `Li`,
 * so a mixed-case acronym is judged whole before it is judged by parts.
 */
function wholeTokenRule(token: string): (typeof PART_RULES)[number] | undefined {
  if (!/^[A-Za-z]+$/.test(token)) return undefined;
  const l = token.toLowerCase();
  return PART_RULES.find((r) => r.match === 'exact' && r.word === l);
}

/** The tell parts of a token (empty when it carries none). */
export function tokenTellParts(token: string): string[] {
  if (isKeyMaterial(token)) return [];
  if (wholeTokenRule(token) !== undefined) return [token];
  return tokenParts(token).filter((p) => ruleFor(p) !== undefined);
}

/**
 * A token with every tell part replaced — a pure function of the token, so
 * the same identifier becomes the same name everywhere it is written.
 */
export function rewriteToken(token: string): string {
  if (isKeyMaterial(token)) return token;
  const whole = wholeTokenRule(token);
  if (whole !== undefined) return inCase(token, whole.to);
  const parts = tokenParts(token);
  if (!parts.some((p) => ruleFor(p) !== undefined)) return token;
  return parts
    .map((p) => {
      const r = ruleFor(p);
      return r === undefined ? p : inCase(p, r.to);
    })
    .join('');
}

const TOKEN = /[A-Za-z0-9_$]+/g;

/** `fn` applied to the parts of `s` outside the allowlisted words, which stay as they are. */
function outsideAllowlist(s: string, fn: (piece: string) => string): string {
  const keep: Array<[number, number]> = [];
  for (const re of ALLOWLIST) for (const m of s.matchAll(new RegExp(re.source, 'gi'))) keep.push([m.index, m.index + m[0].length]);
  if (keep.length === 0) return fn(s);
  keep.sort((a, b) => a[0] - b[0]);
  let out = '';
  let at = 0;
  for (const [a, b] of keep) {
    if (a < at) continue;
    out += fn(s.slice(at, a)) + s.slice(a, b);
    at = b;
  }
  return out + fn(s.slice(at));
}

/** Allowlisted words blanked (same length, no line moved), for detection. */
function maskAllowlist(s: string): string {
  return outsideAllowlist(s, (piece) => `\u0000${piece}\u0000`)
    .split('\u0000')
    .map((piece, i) => (i % 2 === 1 ? piece : piece.replace(/[^\r\n]/g, ' ')))
    .join('');
}

/** Every tell-bearing token in `piece` renamed, and "on purpose" made "as designed". */
function rewritePiece(piece: string, log?: (from: string, to: string) => void): string {
  return outsideAllowlist(piece, (p) =>
    p
      .replace(/\bon purpose\b/gi, (m) => (m[0] === 'O' ? 'As designed' : 'as designed'))
      .replace(TOKEN, (tok) => {
        const to = rewriteToken(tok);
        if (to !== tok) log?.(tok, to);
        return to;
      }),
  );
}

/** A path with every tell-bearing token of every segment renamed (the same map as in the code). */
export function rewritePath(rel: string): string {
  return rewritePiece(rel);
}

/** Every tell in `text`, raw or by token, outside the allowlist — as the matched words, with offsets. */
function tellMatches(text: string): Array<{ offset: number; word: string }> {
  const masked = maskAllowlist(text);
  const out: Array<{ offset: number; word: string }> = [];
  for (const re of RAW_TELLS) for (const m of masked.matchAll(new RegExp(re.source, 'gi'))) out.push({ offset: m.index, word: m[0] });
  for (const m of masked.matchAll(TOKEN)) {
    const parts = tokenTellParts(m[0]);
    if (parts.length > 0 && !out.some((o) => o.offset >= m.index && o.offset < m.index + m[0].length)) out.push({ offset: m.index, word: m[0] });
  }
  return out.sort((a, b) => a.offset - b.offset);
}

/** The tells in `text` (raw words, and tokens with a tell part), outside the allowlist. */
export function tellsIn(text: string): string[] {
  return tellMatches(text).map((m) => m.word);
}

export type SourceLang = 'js' | 'php' | 'python';
export type FileKind = SourceLang | 'prose' | 'binary';

/** How a file is read for tells: as code of a language, as prose (data, docs), or not at all. */
export function fileKindOf(rel: string): FileKind {
  if (/\.(ts|tsx|js|jsx|mjs|cjs|mts|cts)$/i.test(rel)) return 'js';
  if (/\.php$/i.test(rel)) return 'php';
  if (/\.py$/i.test(rel)) return 'python';
  if (/\.(db|sqlite|png|jpe?g|gif|ico|zip|gz|pdf|woff2?|ttf|bin)$/i.test(rel)) return 'binary';
  return 'prose';
}

export interface Span {
  /** Offset of the opening delimiter. */
  start: number;
  /** Offset just past the closing delimiter (or the end of the line, for a line comment). */
  end: number;
  /** Length of the opening and closing delimiters. */
  open: number;
  close: number;
}

export interface CommentSpan extends Span {
  kind: 'line' | 'block' | 'doc';
}

/** Whether a `/` after `before` (the line so far) opens a regex literal rather than dividing. */
function regexMayStart(before: string): boolean {
  const t = before.trimEnd();
  if (t === '') return true;
  if (/(?:^|[^\w$])(?:return|typeof|case|in|of|void|delete|throw|new)$/.test(t)) return true;
  return /[(,=:[!&|?{};+\-*%<>~^]$/.test(t);
}

function lineStart(text: string, i: number): number {
  return text.lastIndexOf('\n', i - 1) + 1;
}

function lineEnd(text: string, i: number): number {
  let j = i;
  while (j < text.length && text[j] !== '\n' && text[j] !== '\r') j += 1;
  return j;
}

/**
 * The comments and the string literals of `text`: line and block comments
 * for JS/TS and PHP, `#` comments and docstrings (a triple-quoted string that
 * is a statement of its own, at bracket depth 0) for Python; quoted strings,
 * template literals (with their `${…}` holes) and Python's other
 * triple-quoted strings. Regex literals are skipped, so a `//` inside one, or
 * inside a URL in a string, is not a comment. A scanner, not a parser: good
 * enough for the copies it is used on, and the line count is asserted after
 * every use.
 */
export function scanSpans(text: string, lang: SourceLang): { comments: CommentSpan[]; strings: Span[] } {
  const comments: CommentSpan[] = [];
  const strings: Span[] = [];
  const n = text.length;
  let depth = 0;
  let i = 0;
  while (i < n) {
    const c = text[i] ?? '';
    const two = text.slice(i, i + 2);
    if (lang === 'python') {
      if (c === '#') {
        const e = lineEnd(text, i);
        comments.push({ start: i, end: e, open: 1, close: 0, kind: 'line' });
        i = e;
        continue;
      }
      const three = text.slice(i, i + 3);
      if (three === "'''" || three === '"""') {
        const close = text.indexOf(three, i + 3);
        const end = close === -1 ? n : close + 3;
        const before = text.slice(lineStart(text, i), i);
        const prefixOnly = /^[ \t]*[rRuUbBfF]{0,2}$/.test(before);
        const span = { start: i, end, open: 3, close: close === -1 ? 0 : 3 };
        if (prefixOnly && depth === 0) comments.push({ ...span, kind: 'doc' });
        else strings.push(span);
        i = end;
        continue;
      }
    } else {
      if (two === '//' || (lang === 'php' && c === '#' && text[i + 1] !== '[')) {
        const e = lineEnd(text, i);
        comments.push({ start: i, end: e, open: c === '#' ? 1 : 2, close: 0, kind: 'line' });
        i = e;
        continue;
      }
      if (two === '/*') {
        const close = text.indexOf('*/', i + 2);
        const end = close === -1 ? n : close + 2;
        comments.push({ start: i, end, open: 2, close: close === -1 ? 0 : 2, kind: 'block' });
        i = end;
        continue;
      }
      if (c === '`' && lang === 'js') {
        // a template literal; `${ … }` holes are skipped by brace counting
        let j = i + 1;
        let hole = 0;
        while (j < n) {
          const t = text[j];
          if (t === '\\') j += 2;
          else if (hole === 0 && t === '`') break;
          else if (t === '$' && text[j + 1] === '{') {
            hole += 1;
            j += 2;
          } else {
            if (hole > 0 && t === '{') hole += 1;
            else if (hole > 0 && t === '}') hole -= 1;
            j += 1;
          }
        }
        strings.push({ start: i, end: Math.min(n, j + 1), open: 1, close: j < n ? 1 : 0 });
        i = j + 1;
        continue;
      }
      if (c === '/' && lang === 'js' && regexMayStart(text.slice(lineStart(text, i), i))) {
        let j = i + 1;
        let inClass = false;
        while (j < n && text[j] !== '\n') {
          const r = text[j];
          if (r === '\\') j += 2;
          else {
            if (r === '[') inClass = true;
            else if (r === ']') inClass = false;
            else if (r === '/' && !inClass) break;
            j += 1;
          }
        }
        i = j + 1;
        continue;
      }
    }
    if (c === '"' || c === "'") {
      // a one-line string (PHP's may span lines: honour that)
      let j = i + 1;
      while (j < n && text[j] !== c && (lang === 'php' || text[j] !== '\n')) j += text[j] === '\\' ? 2 : 1;
      strings.push({ start: i, end: Math.min(n, j + 1), open: 1, close: j < n ? 1 : 0 });
      i = j + 1;
      continue;
    }
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if ((c === ')' || c === ']' || c === '}') && depth > 0) depth -= 1;
    i += 1;
  }
  return { comments, strings };
}

/** The comments of `text` ({@link scanSpans}). */
export function commentSpans(text: string, lang: SourceLang): CommentSpan[] {
  return scanSpans(text, lang).comments;
}

/** The text of a comment without its delimiters. */
function commentText(text: string, s: Span): string {
  return text.slice(s.start + s.open, s.end - s.close);
}

/**
 * `text` with every comment that carries a tell emptied: a line comment is
 * removed together with the blanks before it; a block comment or docstring
 * keeps its delimiters and its line breaks and nothing else. A run of
 * whole-line comments on adjacent lines is one comment: emptying only the
 * line with the tell would leave the rest of its sentence behind. No line is
 * added or removed. Returns the new text and how many comment spans were
 * emptied.
 */
export function neutraliseTellComments(text: string, lang: SourceLang): { text: string; emptied: number } {
  const all = commentSpans(text, lang);
  const wholeLine = (s: CommentSpan): boolean => s.kind === 'line' && /^[ \t]*$/.test(text.slice(lineStart(text, s.start), s.start));
  const groups: CommentSpan[][] = [];
  for (const s of all) {
    const last = groups[groups.length - 1];
    const prev = last?.[last.length - 1];
    const adjacent =
      prev !== undefined && wholeLine(prev) && wholeLine(s) && /^\r?\n$/.test(text.slice(prev.end, lineStart(text, s.start)));
    if (last !== undefined && adjacent) last.push(s);
    else groups.push([s]);
  }
  const spans = groups.filter((g) => g.some((s) => tellMatches(commentText(text, s)).length > 0)).flat();
  if (spans.length === 0) return { text, emptied: 0 };
  let out = '';
  let at = 0;
  for (const s of spans) {
    if (s.kind === 'line') {
      let cut = s.start;
      const ls = lineStart(text, s.start);
      while (cut > Math.max(at, ls) && (text[cut - 1] === ' ' || text[cut - 1] === '\t')) cut -= 1;
      out += text.slice(at, cut);
    } else {
      const inner = text.slice(s.start + s.open, s.end - s.close).replace(/[^\r\n]/g, '');
      out += text.slice(at, s.start) + text.slice(s.start, s.start + s.open) + inner + text.slice(s.end - s.close, s.end);
    }
    at = s.end;
  }
  out += text.slice(at);
  return { text: out, emptied: spans.length };
}

/** What a scrub renamed: code identifiers apart from words inside strings, for the collision check. */
export interface ScrubLog {
  code: Map<string, string>;
  strings: Map<string, string>;
}

export function newScrubLog(): ScrubLog {
  return { code: new Map(), strings: new Map() };
}

/**
 * The last step of every blind copy's code file: comments carrying a tell
 * emptied, then every tell-bearing token renamed — in code, string literals
 * and regex literals alike, by the one map ({@link rewriteToken}). The
 * strings are display text and module specifiers here; the copy is read,
 * never run. Quotes stay and no line moves.
 */
export function scrubCode(text: string, lang: SourceLang, log?: ScrubLog): string {
  const t = neutraliseTellComments(text, lang).text;
  const { comments, strings } = scanSpans(t, lang);
  const marks = [
    ...comments.map((s) => ({ start: s.start, end: s.end, kind: 'comment' as const })),
    ...strings.map((s) => ({ start: s.start, end: s.end, kind: 'string' as const })),
  ].sort((a, b) => a.start - b.start);
  let out = '';
  let at = 0;
  const code = (piece: string): string => rewritePiece(piece, (f, to) => log?.code.set(f, to));
  for (const m of marks) {
    if (m.start < at) continue;
    out += code(t.slice(at, m.start));
    const body = t.slice(m.start, m.end);
    out += m.kind === 'comment' ? body : rewritePiece(body, (f, to) => log?.strings.set(f, to));
    at = m.end;
  }
  return out + code(t.slice(at));
}

/** The last step of every data or text file: every tell-bearing token renamed by the same map. */
export function scrubProse(text: string, log?: ScrubLog): string {
  return rewritePiece(text, (f, to) => log?.strings.set(f, to));
}

/** The identifier-like tokens of the code regions of `text` (not comments, not strings). */
export function codeTokens(text: string, lang: SourceLang): Set<string> {
  const { comments, strings } = scanSpans(text, lang);
  const marks = [...comments, ...strings].sort((a, b) => a.start - b.start);
  const out = new Set<string>();
  let at = 0;
  const take = (piece: string): void => {
    for (const m of piece.matchAll(TOKEN)) out.add(m[0]);
  };
  for (const m of marks) {
    if (m.start < at) continue;
    take(text.slice(at, m.start));
    at = m.end;
  }
  take(text.slice(at));
  return out;
}

export interface Tell {
  /** 1-based line; 0 for the file's path. */
  line: number;
  tell: string;
  where: 'code' | 'string' | 'comment' | 'prose' | 'path';
}

function lineOfOffset(starts: readonly number[], offset: number): number {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if ((starts[mid] ?? 0) <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

/**
 * The tells in one file of a blind copy, its path included: raw words and
 * identifier parts, in comments, string literals and code alike.
 */
export function findTells(rel: string, text: string | null): Tell[] {
  const out: Tell[] = tellsIn(rel).map((tell) => ({ line: 0, tell, where: 'path' as const }));
  const kind = fileKindOf(rel);
  if (text === null || kind === 'binary') return out;
  const starts = [0];
  for (let i = 0; i < text.length; i += 1) if (text[i] === '\n') starts.push(i + 1);
  const matches = tellMatches(text);
  if (kind === 'prose') {
    for (const m of matches) out.push({ line: lineOfOffset(starts, m.offset), tell: m.word, where: 'prose' });
    return out;
  }
  const { comments, strings } = scanSpans(text, kind);
  const within = (spans: readonly Span[], o: number): boolean => spans.some((s) => o >= s.start && o < s.end);
  for (const m of matches) {
    const where = within(comments, m.offset) ? 'comment' : within(strings, m.offset) ? 'string' : 'code';
    out.push({ line: lineOfOffset(starts, m.offset), tell: m.word, where });
  }
  return out;
}
