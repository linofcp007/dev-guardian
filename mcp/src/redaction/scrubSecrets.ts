/**
 * Source text with every line that holds a detected secret replaced — for
 * the excerpts dev-guardian quotes back to a model: the LLM scan's briefs
 * (`llmscan/briefs.ts`, where this began) and `suggest_fix`'s surrounding
 * source (review 3.6.1, finding 7).
 *
 * The detector is the hooks' (`hooks/secretScan.ts`), run with
 * `skipPlaceholders: false`: redaction keeps what a warning skips — a
 * documented example key, a passphrase with spaces (review 8, items 10-11)
 * — because here a false positive costs a line and a miss leaks a secret.
 */

import { scanForSecrets } from '../hooks/secretScan.js';

/**
 * A line of a private key's body: base64 (8 characters or more), quoted or
 * not, with a trailing `,` or `+` and `\r\n` escapes, as a key is written in
 * code; or a PEM header line of an encrypted key.
 */
function isKeyBodyLine(line: string): boolean {
  if (/^\s*(Proc-Type|DEK-Info):/.test(line)) return true;
  const content = line.replace(/\\[rn]/g, '').replace(/^[\s'"`]+|[\s'"`,+]+$/g, '');
  return /^[A-Za-z0-9+/=]{8,}$/.test(content);
}

/**
 * `text` with every line that holds a detected secret replaced by
 * `‹rule line n›` (n counted from `firstLine`). The detector reports where a
 * secret is, never its extent, so the whole line goes; a private key's body
 * goes with its header: the lines below it that look like a key's body, up
 * to the END line. A key on ONE line (a string with `\r\n` escapes, as OWASP
 * Juice Shop keeps its own) has no body below it — taking every line "up to
 * the END line" there removed the rest of the excerpt (measured: 179 lines).
 * The line count is kept: line i of the result is line i of `text`.
 */
export function scrubSecrets(text: string, firstLine = 1): string {
  const hits = scanForSecrets(text, { skipPlaceholders: false });
  if (hits.length === 0) return text;
  const lines = text.split(/\r?\n/);
  const rulesByLine = new Map<number, string[]>();
  const keyBody = new Set<number>();
  for (const h of hits) {
    const at = h.line - 1;
    rulesByLine.set(at, [...(rulesByLine.get(at) ?? []), h.ruleId]);
    if (h.ruleId !== 'private-key-block') continue;
    if ((lines[at] ?? '').includes('-----END')) continue;
    for (let i = at + 1; i < lines.length; i += 1) {
      const line = lines[i] ?? '';
      if (line.includes('-----END')) {
        keyBody.add(i);
        break;
      }
      if (!isKeyBodyLine(line)) break;
      keyBody.add(i);
    }
  }
  return lines
    .map((line, i) => {
      const rules = rulesByLine.get(i);
      if (rules === undefined) return keyBody.has(i) ? '‹private key body removed›' : line;
      const indent = /^\s*/.exec(line)?.[0] ?? '';
      return `${indent}‹${rules.join(', ')} line ${String(firstLine + i)}›`;
    })
    .join('\n');
}
