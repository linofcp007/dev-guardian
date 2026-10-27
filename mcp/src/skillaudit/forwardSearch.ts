/**
 * Searches that never go back, for the shapes a backtracking expression
 * reads again from every starting point: `KEYWORD[^|;&\n]*?TAIL` restarts its
 * run at every keyword and reads it to the end of the command each time, so a
 * line of keywords costs the square of its length — `curl ` 32 000 times took
 * 2.2 s here, and a skill's file may be a 2 MB line (review of the 3.7.0
 * self-scan, measured).
 *
 * The answer for each keyword is the same as the expression's: the first
 * match of the tail at or after the keyword, if it starts before the end of
 * the command (the next `|`, `;`, `&` or line break — a tail may begin on
 * that character, as the expression's lazy run may stop on it). What changes
 * is that the tail and the command's end are each searched for once and
 * reused while later keywords do not pass them.
 */

/**
 * `re`'s first match (a `g` expression) at or after a position, searched for
 * again only when a position passes it — positions asked in increasing order
 * read `text` about once.
 */
export function forwardSearch(text: string, re: RegExp): (from: number) => RegExpExecArray | null {
  let searchedFrom = Number.POSITIVE_INFINITY;
  let found: RegExpExecArray | null = null;
  return (from: number): RegExpExecArray | null => {
    if (from < searchedFrom || (found !== null && found.index < from)) {
      re.lastIndex = from;
      found = re.exec(text);
      searchedFrom = from;
    }
    return found;
  };
}

/** What ends a simple command for the searches here. */
const COMMAND_END = /[|;&\n]/g;

/** One match of `KEYWORD[^|;&\n]*?TAIL`: where it starts, its text, and the tail's own match (its groups). */
interface KeywordTailMatch {
  index: number;
  text: string;
  tail: RegExpExecArray;
}

/**
 * Every match `KEYWORD[^|;&\n]*?TAIL` (with `g`) makes in `text`, in order —
 * `keyword` and `tail` each a `g` expression of its own, with the flags the
 * whole one had. Linear in `text` when the tail's own search is.
 */
export function keywordThenTail(text: string, keyword: RegExp, tail: RegExp): KeywordTailMatch[] {
  const out: KeywordTailMatch[] = [];
  const commandEnd = forwardSearch(text, COMMAND_END);
  const nextTail = forwardSearch(text, tail);
  keyword.lastIndex = 0;
  for (let k = keyword.exec(text); k !== null; k = keyword.exec(text)) {
    const end = k.index + k[0].length;
    const t = nextTail(end);
    // No tail after this keyword: none after a later one either.
    if (t === null) break;
    if (t.index > (commandEnd(end)?.index ?? text.length)) {
      keyword.lastIndex = k.index + 1;
      continue;
    }
    const stop = t.index + t[0].length;
    out.push({ index: k.index, text: text.slice(k.index, stop), tail: t });
    keyword.lastIndex = Math.max(stop, k.index + 1);
  }
  return out;
}

/**
 * Every match `KEYWORD(?![^|;&\n]*VETO)[^|;&\n]*` (with `g`) makes in `text`:
 * each keyword whose command holds no match of `veto` after it, through the
 * end of that command. `keyword` and `veto` are `g` expressions.
 */
export function keywordWithoutVeto(text: string, keyword: RegExp, veto: RegExp): Array<{ index: number; text: string }> {
  const out: Array<{ index: number; text: string }> = [];
  const commandEnd = forwardSearch(text, COMMAND_END);
  const nextVeto = forwardSearch(text, veto);
  keyword.lastIndex = 0;
  for (let k = keyword.exec(text); k !== null; k = keyword.exec(text)) {
    const end = k.index + k[0].length;
    const stop = commandEnd(end)?.index ?? text.length;
    const v = nextVeto(end);
    if (v !== null && v.index <= stop) {
      keyword.lastIndex = k.index + 1;
      continue;
    }
    out.push({ index: k.index, text: text.slice(k.index, stop) });
    keyword.lastIndex = Math.max(stop, k.index + 1);
  }
  return out;
}
