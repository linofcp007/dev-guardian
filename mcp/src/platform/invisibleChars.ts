/**
 * Which invisible code points belong where they are — shared by
 * `audit_mcp_tools` (`mcpaudit/rules.ts`, which reports the others as
 * smuggling) and `platform/untrustedText.ts` (which escapes the others before
 * repository text is shown). One definition, so the two never disagree about
 * what an emoji sequence, a keycap, a CJK variation selector or a
 * subdivision flag is.
 */

const PICTOGRAPHIC = /\p{Extended_Pictographic}/u;
const IDEOGRAPHIC = /\p{Ideographic}/u;

/**
 * The invisible code points that belong where they are: one VS15/VS16 after
 * an emoji (❤️) or on a keycap (1️⃣), a zero-width joiner inside an emoji
 * sequence (👨‍👩‍👧), and one ideographic variation selector after a CJK
 * ideograph (葛󠄀). Anything else invisible is reported.
 */
export function isLegitimateInvisible(code: number, prev: number | undefined, next: number | undefined): boolean {
  const prevCh = prev === undefined ? '' : String.fromCodePoint(prev);
  const nextCh = next === undefined ? '' : String.fromCodePoint(next);
  if (code === 0xfe0e || code === 0xfe0f) {
    return PICTOGRAPHIC.test(prevCh) || (/[0-9#*]/.test(prevCh) && next === 0x20e3);
  }
  if (code === 0x200d) {
    const prevIsEmoji = PICTOGRAPHIC.test(prevCh) || prev === 0xfe0f || (prev !== undefined && prev >= 0x1f3fb && prev <= 0x1f3ff);
    return prevIsEmoji && PICTOGRAPHIC.test(nextCh);
  }
  if (code >= 0xe0100 && code <= 0xe01ef) return IDEOGRAPHIC.test(prevCh);
  return false;
}

/**
 * The only tag sequences Unicode recommends for general interchange (RGI):
 * the England, Scotland and Wales flags — 🏴 U+1F3F4, the tag letters of
 * `gbeng`/`gbsct`/`gbwls`, and CANCEL TAG U+E007F (fix round 4). Any other
 * use of tag characters, a flag or not, stays reported.
 */
const RGI_SUBDIVISION_FLAGS = new Set(['gbeng', 'gbsct', 'gbwls']);

export function subdivisionFlagTags(points: readonly number[]): Set<number> {
  const exempt = new Set<number>();
  for (let i = 0; i < points.length; i += 1) {
    if (points[i] !== 0x1f3f4) continue;
    let j = i + 1;
    let tag = '';
    for (let c = points[j]; c !== undefined && c >= 0xe0020 && c <= 0xe007e; c = points[j]) {
      tag += String.fromCharCode(c - 0xe0000);
      j += 1;
    }
    if (points[j] === 0xe007f && RGI_SUBDIVISION_FLAGS.has(tag)) {
      for (let k = i + 1; k <= j; k += 1) exempt.add(k);
    }
  }
  return exempt;
}
