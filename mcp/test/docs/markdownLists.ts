/**
 * A structural check of the list layout of a generated page, for the rules
 * markdownlint applies to `docs/` here (`.markdownlint.jsonc`): MD005, MD007
 * (indent 2), MD032, MD009, MD012 and MD047 — plus the shapes that markdownlint
 * accepts and that take a line away from its record on the page (a line at
 * column 0 inside the list of a section, a nested list glued to a paragraph of
 * the item).
 *
 * It models only what `renderKnownLimitsDoc` writes: `#` headings, paragraphs,
 * `- ` items at indentation 0 or 2 and continuation lines indented by two
 * spaces. A text with a shape outside that — a code fence, an ordered or a
 * `*` / `+` item, a `-` followed by more than one space or a tab, a heading
 * inside an item — is refused with "not modelled", never passed in silence.
 * No markdownlint, no `npx`, no network: a pure function over the text.
 */

/** A problem is `"<line>: <rule> <what>"`; a shape this check does not model is `"<line>: not modelled <what>"`. */
export function listProblems(text: string): string[] {
  if (text === '') return [];
  const problems: string[] = [];
  const say = (n: number, rule: string, what: string): void => {
    problems.push(`${String(n + 1)}: ${rule} ${what}`);
  };
  if (!text.endsWith('\n')) say(text.split('\n').length - 1, 'MD047', 'the text does not end with a newline');
  const lines = text.replace(/\n$/, '').split('\n');
  const last = lines.length - 1;
  const ITEM = /^( *)- /;
  let inList = false; // a top-level list is open in this section
  for (const [n, line] of lines.entries()) {
    const prev = n > 0 ? lines[n - 1] : undefined;
    if (/[ \t]$/.test(line)) say(n, 'MD009', 'trailing whitespace');
    if (line === '' && (prev === '' || n === last)) say(n, 'MD012', 'two blank lines in a row, or a blank line at the end');
    if (line === '') continue;

    // The shapes this check does not model.
    if (/^ *(```|~~~)/.test(line)) {
      say(n, 'not modelled', 'a code fence');
      continue;
    }
    if (/^ *\d+[.)] /.test(line)) {
      say(n, 'not modelled', 'an ordered list item');
      continue;
    }
    if (/^ *[*+]( |$)/.test(line)) {
      say(n, 'not modelled', 'a list item that starts with "*" or "+"');
      continue;
    }
    if (/^ *-(\t| {2})/.test(line)) {
      say(n, 'not modelled', 'a "-" followed by more than one space or by a tab');
      continue;
    }
    if (/^ +#{1,6}( |$)/.test(line)) {
      say(n, 'not modelled', 'a heading inside a list item');
      continue;
    }

    if (/^#{1,6}( |$)/.test(line)) {
      if (inList && prev !== '') say(n, 'MD032', 'a list is not followed by a blank line');
      inList = false;
      continue;
    }
    const item = ITEM.exec(line);
    const indent = /^ */.exec(line)?.[0].length ?? 0;
    if (item !== null) {
      const at = item[1]?.length ?? 0;
      if (at !== 0 && at !== 2) say(n, 'MD007', `an item indented by ${String(at)}`);
      if (at === 0) {
        if (!inList && prev !== '') say(n, 'MD032', 'a list is not preceded by a blank line');
        inList = true;
        continue;
      }
      // A nested item: inside an open top-level item, right after the first line of the item, another nested item or a blank line.
      if (!inList) {
        if (at === 2) say(n, 'MD007', 'a nested item outside a top-level item');
      } else if (prev !== '' && !ITEM.test(prev ?? '')) say(n, 'MD032', 'a nested list is not preceded by a blank line');
      continue;
    }
    // A text line.
    if (indent === 0) {
      if (inList) say(n, 'MD005', 'a line at column 0 inside the list of the section (it ends the list)');
      continue;
    }
    if (!inList) say(n, 'MD007', 'an indented line outside a list');
    else if (/^ {2}- /.test(prev ?? '')) say(n, 'MD032', 'a nested list is not followed by a blank line');
  }
  return problems;
}
