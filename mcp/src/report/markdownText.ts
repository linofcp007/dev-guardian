/**
 * Untrusted text in the Markdown reports (`report_export`, the OWASP
 * coverage section): a finding's title, rule id, file path and tool, a CVE's
 * package fields, a model's verdict. All of it is the scanned repository's —
 * a project's own `.semgrep.yml` message, a file name, an imported SARIF
 * log's tool name, a lock file's package name, words the repository steered a
 * model to write — so none of it may end a table, close a code span, or open
 * a heading, a link, an image or raw HTML in a report a stakeholder opens
 * (review 3.6.1, finding 3: only a title's `|` was escaped).
 *
 * Every helper makes the text one line first: a newline is what ended a
 * table row or started a heading.
 */

/** Longest untrusted text one report line carries. */
const MD_INLINE_MAX = 2_000;

const oneLine = (s: string): string => {
  const one = s.replace(/\s+/g, ' ').trim();
  return one.length > MD_INLINE_MAX ? `${one.slice(0, MD_INLINE_MAX)}…` : one;
};

/**
 * Model-written text (a verdict's decisive line and reasoning, a hunt
 * finding's title) as inline markdown: one line, and no markup a viewer
 * would act on — an image, a link, raw HTML or emphasis prints as the
 * characters they are.
 */
export function mdInline(s: string): string {
  return oneLine(s).replace(/[\\`*_[\]<>|!~#&]/g, (c) => `\\${c}`);
}

/**
 * A table cell of the repository's text: one line, its `|` escaped so the
 * row keeps its width, and no backtick, `<`, `[`, `]` or `!` left to open a
 * code span, raw HTML, a link or an image. Emphasis is left alone: it changes
 * how a cell looks, not what it does — and `deps_audit` stays readable.
 */
export function mdCell(s: string): string {
  return oneLine(s).replace(/[\\`|<>[\]!]/g, (c) => `\\${c}`);
}

/** Text as an inline code span outside a table: one line, and no backtick to close the span early. */
export function mdCode(s: string): string {
  return `\`${oneLine(s).replace(/`/g, "'")}\``;
}

/**
 * Text as an inline code span inside a table cell: {@link mdCode}, with `|`
 * escaped — GitHub's tables split a row on `|` before reading code spans, and
 * honour `\|` inside one. Empty text is an empty cell, not two backticks.
 */
export function mdCodeCell(s: string): string {
  const one = oneLine(s);
  return one === '' ? '' : `\`${one.replace(/`/g, "'").replace(/\|/g, '\\|')}\``;
}
