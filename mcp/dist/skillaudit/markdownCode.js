/**
 * The code inside an instruction file.
 *
 * A third-party skill is read by the model as instructions, so a fenced
 * ```bash``` block or an inline `curl … | bash` in its SKILL.md is what the
 * model runs — the same as the line in `scripts/setup.sh` that the code rules
 * already score. This module splits a text file (Markdown and the other
 * `DOC_EXT` formats) into the two views the pattern pass needs:
 *
 *   - `code`: every line of a fenced block (any info string, or none) and
 *     every inline code span, each with the line number it sits on in the
 *     file — the `code`-target rules run over these;
 *   - `prose`: the file's lines with fenced blocks and inline code spans
 *     blanked out — the `prose`-target rules run over these, so a command is
 *     scored once, by the rule for the shape it was written in.
 *
 * Deliberately more permissive than a Markdown renderer: a fence is accepted
 * at any indentation and behind `>` quote markers, because an attacker picks
 * the spelling a renderer would ignore and the model still reads. An
 * unclosed fence runs to the end of the file, as CommonMark says.
 *
 * Shell line continuations inside a fenced block (`… \` + newline) are
 * joined into one logical line, reported at the line it starts on: an
 * install one-liner is routinely wrapped that way, and the pipe to the shell
 * is then on a line of its own.
 *
 * Pure functions. No I/O.
 */
const FENCE_OPEN = /^[ \t>]*(`{3,}|~{3,})(.*)$/;
const CONTINUATION = /\\[ \t]*$/;
export function splitMarkdown(content) {
    const lines = content.split(/\r?\n/);
    const code = [];
    const prose = [];
    let fence = null;
    let blocks = 0;
    // A continued fenced line still waiting for the line that ends it.
    let pending = null;
    for (let i = 0; i < lines.length; i += 1) {
        const line = lines[i] ?? '';
        const lineNo = i + 1;
        if (fence) {
            if (isClosingFence(line, fence)) {
                if (pending)
                    code.push(pending);
                pending = null;
                fence = null;
            }
            else {
                const block = blocks - 1;
                code.push({ line: lineNo, text: line, kind: 'fenced', block });
                const continues = CONTINUATION.test(line);
                if (pending) {
                    const joined = {
                        line: pending.line,
                        text: `${pending.text.replace(CONTINUATION, '')} ${line.trim()}`,
                        kind: 'fenced',
                        block,
                    };
                    if (continues) {
                        pending = joined;
                    }
                    else {
                        code.push(joined);
                        pending = null;
                    }
                }
                else if (continues) {
                    pending = { line: lineNo, text: line, kind: 'fenced', block };
                }
            }
            prose.push('');
            continue;
        }
        const open = FENCE_OPEN.exec(line);
        const run = open?.[1];
        // A backtick fence's info string may not contain a backtick — that is an
        // inline span (```x``` on one line), handled below.
        if (open && run && !(run.startsWith('`') && (open[2] ?? '').includes('`'))) {
            fence = { char: run.charAt(0), length: run.length };
            blocks += 1;
            prose.push('');
            continue;
        }
        const spans = inlineSpans(line);
        for (const s of spans)
            code.push({ line: lineNo, text: s.text, kind: 'inline', block: null });
        prose.push(blank(line, spans));
    }
    if (pending)
        code.push(pending);
    return { code, prose };
}
function isClosingFence(line, fence) {
    const m = /^[ \t>]*(`{3,}|~{3,})[ \t]*$/.exec(line);
    const run = m?.[1];
    return run !== undefined && run.charAt(0) === fence.char && run.length >= fence.length;
}
/**
 * CommonMark code spans on one line: a run of N backticks opens, the next run
 * of exactly N closes, and an unmatched run is literal text. One leading and
 * one trailing space are stripped when both are present.
 */
function inlineSpans(line) {
    const out = [];
    let i = 0;
    while (i < line.length) {
        if (line[i] !== '`') {
            i += 1;
            continue;
        }
        let n = 0;
        while (line[i + n] === '`')
            n += 1;
        const openEnd = i + n;
        let j = openEnd;
        let close = -1;
        while (j < line.length) {
            if (line[j] !== '`') {
                j += 1;
                continue;
            }
            let m = 0;
            while (line[j + m] === '`')
                m += 1;
            if (m === n) {
                close = j;
                break;
            }
            j += m;
        }
        if (close === -1) {
            i = openEnd;
            continue;
        }
        let text = line.slice(openEnd, close);
        if (text.length >= 2 && text.startsWith(' ') && text.endsWith(' ') && text.trim() !== '') {
            text = text.slice(1, -1);
        }
        out.push({ start: i, end: close + n, text });
        i = close + n;
    }
    return out;
}
function blank(line, spans) {
    if (spans.length === 0)
        return line;
    let out = '';
    let at = 0;
    for (const s of spans) {
        out += `${line.slice(at, s.start)} `;
        at = s.end;
    }
    return out + line.slice(at);
}
//# sourceMappingURL=markdownCode.js.map