/**
 * The lines of a text, one at a time — never an array of them.
 *
 * `text.split(/\r?\n/)` makes one string per line, all at once: a 30 MiB
 * `yarn.lock` of newlines became an array of 31 million strings and took the
 * server past its heap limit, although the read itself was bounded (review
 * of 3.0, W2E). Iterating keeps one line alive at a time; the caller stops as
 * soon as it has its answer.
 */
/** Each line of `text` without its `\n` or `\r\n`; a trailing newline yields no empty last line. */
export function* textLines(text) {
    let start = 0;
    while (start < text.length) {
        const nl = text.indexOf('\n', start);
        const end = nl < 0 ? text.length : nl;
        const line = text.slice(start, end > start && text.charCodeAt(end - 1) === 13 ? end - 1 : end);
        yield line;
        if (nl < 0)
            return;
        start = nl + 1;
    }
}
//# sourceMappingURL=textLines.js.map