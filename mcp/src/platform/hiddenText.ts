/**
 * What a text hides from the person reviewing it and not from the model
 * reading it: invisible code points, letters of another script that read as
 * Latin ones, compatibility forms, encoded blobs — shared by
 * `audit_mcp_tools` (`mcpaudit/`, over what a server serves) and `scan_skill`
 * (`skillaudit/`, over a package on disk), so the two never disagree about
 * what is hidden. Which invisible code points belong where they are is
 * `invisibleChars.ts`'s.
 *
 * Pure functions. No I/O.
 */

import { isLegitimateInvisible, subdivisionFlagTags } from './invisibleChars.js';

/**
 * Code points that render as nothing, or reorder what does: Unicode's own
 * `Default_Ignorable_Code_Point` and `Bidi_Control` classes, plus the
 * interlinear annotation controls U+FFF9–FFFB (format characters that are in
 * neither). Fix round 3, I4: the first cut listed ranges by hand and missed
 * variation selectors (U+FE00–FE0F, U+E0100–E01EF — a whole smuggling
 * alphabet), U+061C, U+00AD, U+034F, the Hangul fillers, U+180B–180F,
 * U+206A–206F, U+FFF9–FFFB and U+1D173–1D17A.
 */
const INVISIBLE = /[\p{Default_Ignorable_Code_Point}\p{Bidi_Control}\u{FFF9}-\u{FFFB}]/u;
const INVISIBLE_ALL = /[\p{Default_Ignorable_Code_Point}\p{Bidi_Control}\u{FFF9}-\u{FFFB}]/gu;

type InvisibleKind =
  | 'tag characters'
  | 'variation selectors'
  | 'bidi controls'
  | 'zero-width and other invisible characters';

function invisibleKind(code: number): InvisibleKind | null {
  const ch = String.fromCodePoint(code);
  if (!INVISIBLE.test(ch)) return null;
  if (code >= 0xe0000 && code <= 0xe007f) return 'tag characters';
  if ((code >= 0xfe00 && code <= 0xfe0f) || (code >= 0xe0100 && code <= 0xe01ef)) return 'variation selectors';
  if (/\p{Bidi_Control}/u.test(ch)) return 'bidi controls';
  return 'zero-width and other invisible characters';
}

interface InvisibleScan {
  kinds: InvisibleKind[];
  count: number;
  /** What the tag characters spell, mapped back to ASCII ('' when none). */
  decodedTags: string;
  /** What a run of variation selectors spells as bytes (VS1–16 = 0–15, VS17–256 = 16–255), when readable. */
  decodedSelectors: string;
  /** UTF-16 index of the first reported code point. */
  index: number;
  /** The first reported code point. */
  first: number;
}

function readable(text: string): boolean {
  if (text.length === 0) return false;
  let printable = 0;
  for (const ch of text) {
    const c = ch.codePointAt(0) ?? 0;
    if (c >= 0x20 && c !== 0x7f && c !== 0xfffd) printable += 1;
  }
  return printable / [...text].length >= 0.9;
}

/** The invisible code points of `text` that do not belong where they are, or null when there are none. */
export function scanInvisible(text: string): InvisibleScan | null {
  // Most text has none: one linear test before the per-code-point walk.
  if (!INVISIBLE.test(text)) return null;
  const points = [...text].map((ch) => ch.codePointAt(0) ?? 0);
  const flagTags = subdivisionFlagTags(points);
  const kinds = new Set<InvisibleKind>();
  let count = 0;
  let decodedTags = '';
  const selectorBytes: number[] = [];
  let index = -1;
  let first = 0;
  let offset = 0;
  for (let i = 0; i < points.length; i += 1) {
    const code = points[i] ?? 0;
    const kind = invisibleKind(code);
    if (kind !== null && !flagTags.has(i) && !isLegitimateInvisible(code, points[i - 1], points[i + 1])) {
      kinds.add(kind);
      count += 1;
      if (index < 0) {
        index = offset;
        first = code;
      }
      if (kind === 'tag characters' && code >= 0xe0020 && code <= 0xe007e) decodedTags += String.fromCharCode(code - 0xe0000);
      if (code >= 0xfe00 && code <= 0xfe0f) selectorBytes.push(code - 0xfe00);
      else if (code >= 0xe0100 && code <= 0xe01ef) selectorBytes.push(code - 0xe0100 + 16);
    }
    offset += code > 0xffff ? 2 : 1;
  }
  if (count === 0) return null;
  const selectors = selectorBytes.length >= 4 ? Buffer.from(selectorBytes).toString('utf8') : '';
  return { kinds: [...kinds], count, decodedTags, decodedSelectors: readable(selectors) ? selectors : '', index, first };
}

/** Replace every invisible code point with a visible `\u{…}` escape, so output never re-carries it. */
export function escapeInvisible(text: string): string {
  let out = '';
  for (const ch of text) {
    const code = ch.codePointAt(0);
    out += code !== undefined && invisibleKind(code) !== null ? `\\u{${code.toString(16).toUpperCase()}}` : ch;
  }
  return out;
}

/**
 * Letters of other scripts that read as Latin ones: Cyrillic and Greek
 * capitals and small letters with a Latin twin. `Іgnоrе` (three of them)
 * reads as "Ignore" and matches no ASCII pattern.
 */
const CONFUSABLES: Record<string, string> = {
  // Cyrillic
  а: 'a', А: 'A', В: 'B', е: 'e', Е: 'E', ё: 'e', Ё: 'E', К: 'K', к: 'k', М: 'M', Н: 'H', о: 'o', О: 'O',
  р: 'p', Р: 'P', с: 'c', С: 'C', Т: 'T', у: 'y', У: 'Y', х: 'x', Х: 'X', і: 'i', І: 'I', ї: 'i', Ї: 'I',
  ј: 'j', Ј: 'J', ѕ: 's', Ѕ: 'S', ԁ: 'd', ԛ: 'q', ԝ: 'w', Ԝ: 'W', һ: 'h', Һ: 'H', ү: 'y', Ү: 'Y', ɡ: 'g',
  // Greek
  Α: 'A', Β: 'B', Ε: 'E', Ζ: 'Z', Η: 'H', Ι: 'I', Κ: 'K', Μ: 'M', Ν: 'N', Ο: 'O', Ρ: 'P', Τ: 'T', Υ: 'Y',
  Χ: 'X', ο: 'o', ν: 'v', ρ: 'p', ι: 'i', κ: 'k', υ: 'u', χ: 'x', α: 'a',
};

/**
 * What the text reads as: NFKC (full-width `Ｉｇｎｏｒｅ` → `Ignore`, and the
 * other compatibility forms) with look-alike letters folded to Latin. The
 * text rules run on this too (fix round 3, I4).
 */
export function readAs(text: string): string {
  let out = '';
  for (const ch of text.normalize('NFKC')) out += CONFUSABLES[ch] ?? ch;
  return out;
}

/**
 * What the model reads where a reviewer sees something else: {@link readAs}
 * with every invisible code point dropped first — a soft hyphen or a
 * zero-width space inside `ig­nore` splits the word for a pattern and for no
 * reader. Line breaks are kept, so a line of this is the same line of the
 * original. Plain ASCII is returned as it is.
 */
export function asTheModelReads(text: string): string {
  if (/^[\u0000-\u007f]*$/.test(text)) return text;
  return readAs(text.replace(INVISIBLE_ALL, ''));
}

/**
 * The first word of four letters or more that mixes Latin letters with
 * Cyrillic or Greek look-alikes (`pаypal`, `Іgnоrе`), or null. A word wholly
 * in one script is ordinary text in that language; a unit like `μs` is too
 * short, and a Greek letter with no Latin twin (μ, λ) is not a look-alike.
 */
export function mixedScriptWord(text: string): { word: string; index: number } | null {
  for (const m of text.matchAll(/[\p{L}\p{M}]{4,}/gu)) {
    const word = m[0];
    let latin = false;
    let lookAlike = false;
    let otherForeign = false;
    for (const ch of word) {
      if (/\p{Script=Latin}/u.test(ch)) latin = true;
      else if (/[\p{Script=Cyrillic}\p{Script=Greek}]/u.test(ch)) {
        if (CONFUSABLES[ch] !== undefined) lookAlike = true;
        else otherForeign = true;
      }
    }
    if (latin && lookAlike && !otherForeign) return { word, index: m.index };
  }
  return null;
}

/**
 * A base64 (or base64url) run long enough to hold a payload. Both cases and
 * a digit are required, so a lowercase hex digest — a common, harmless long
 * token in a description — is not one.
 */
const BASE64_RUN = /[A-Za-z0-9+/_-]{100,}={0,2}/g;

interface EncodedBlob {
  /** UTF-16 index of the run in the text. */
  index: number;
  length: number;
  /** The decoded text when it is mostly printable, else null. */
  decodedText: string | null;
}

/** Every base64 run of the text (the first `limit`), each decoded when it reads as text. */
export function encodedBlobs(text: string, limit = Number.POSITIVE_INFINITY): EncodedBlob[] {
  const out: EncodedBlob[] = [];
  for (const m of text.matchAll(BASE64_RUN)) {
    if (out.length >= limit) break;
    const run = m[0];
    if (!/[A-Z]/.test(run) || !/[a-z]/.test(run) || !/[0-9]/.test(run)) continue;
    const decoded = Buffer.from(run.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    let printable = 0;
    for (const ch of decoded) {
      const code = ch.codePointAt(0) ?? 0;
      if ((code >= 0x20 && code < 0x7f) || code === 0x0a || code === 0x0d || code === 0x09) printable += 1;
    }
    const isText = decoded.length > 0 && printable / decoded.length >= 0.9;
    out.push({ index: m.index, length: run.length, decodedText: isText ? decoded : null });
  }
  return out;
}

/** The first base64 run of the text, or null. */
export function findEncodedBlob(text: string): EncodedBlob | null {
  return encodedBlobs(text, 1)[0] ?? null;
}
