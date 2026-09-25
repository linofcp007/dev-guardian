/**
 * Minimal JSONC (JSON-with-Comments) support for `audit_agent_config`.
 *
 * Coordinator review, round 1: `.vscode/mcp.json` and VS Code / Cursor
 * settings legitimately carry `//` and `/* *\/` comments and trailing
 * commas — real, editable-by-hand config, not malformed JSON — and the
 * original reader reported the whole file as an unreadable parse error the
 * moment either appeared.
 *
 * No dependency is pulled in for this: both passes below are small,
 * string-aware character scanners (never a regex over the whole text,
 * which cannot tell a `//` inside a string from a real comment). Two
 * separate passes rather than one combined scanner, because each is small
 * enough to read and test on its own:
 *   1. strip comments, copying string contents through untouched;
 *   2. on the comment-free result, drop a comma that has nothing but
 *      whitespace between it and a closing `}`/`]`, again never touching
 *      a comma inside a string.
 *
 * `parseJsonc` runs both, then `JSON.parse`s the result — so a file with no
 * comments or trailing commas at all (ordinary strict JSON, which every
 * other config source here still is) passes through unchanged and behaves
 * exactly as `JSON.parse` on its own would.
 */

/** Strips `//` line comments and `/* *\/` block comments, leaving string contents untouched. */
function stripComments(text: string): string {
  let out = '';
  let i = 0;
  const n = text.length;
  let inString = false;

  while (i < n) {
    const ch = text[i];
    if (inString) {
      out += ch;
      if (ch === '\\' && i + 1 < n) {
        out += text[i + 1];
        i += 2;
        continue;
      }
      if (ch === '"') inString = false;
      i += 1;
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
      i += 1;
      continue;
    }
    if (ch === '/' && text[i + 1] === '/') {
      i += 2;
      while (i < n && text[i] !== '\n') i += 1;
      continue; // the newline itself (if any) is copied on the next iteration
    }
    if (ch === '/' && text[i + 1] === '*') {
      i += 2;
      while (i < n && !(text[i] === '*' && text[i + 1] === '/')) i += 1;
      i += 2; // skip the closing `*/`; harmless if i now overshoots n
      continue;
    }
    out += ch;
    i += 1;
  }
  return out;
}

/** Drops a `,` followed only by whitespace and then `}` or `]`, leaving string contents untouched. */
function stripTrailingCommas(text: string): string {
  let out = '';
  let i = 0;
  const n = text.length;
  let inString = false;

  while (i < n) {
    const ch = text[i];
    if (inString) {
      out += ch;
      if (ch === '\\' && i + 1 < n) {
        out += text[i + 1];
        i += 2;
        continue;
      }
      if (ch === '"') inString = false;
      i += 1;
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
      i += 1;
      continue;
    }
    if (ch === ',') {
      let j = i + 1;
      while (j < n && /\s/.test(text[j] ?? '')) j += 1;
      const next = text[j];
      if (next === '}' || next === ']') {
        i += 1; // drop the comma, keep scanning from what follows
        continue;
      }
    }
    out += ch;
    i += 1;
  }
  return out;
}

/** Strips comments and trailing commas from JSONC text, leaving strict-JSON input unchanged. */
export function stripJsonc(text: string): string {
  return stripTrailingCommas(stripComments(text));
}

/** `JSON.parse(stripJsonc(text))` — throws exactly when the stripped result is still not valid JSON. */
export function parseJsonc(text: string): unknown {
  return JSON.parse(stripJsonc(text));
}
