/**
 * Splitting a list of file arguments across several invocations of one tool.
 *
 * A scanner handed thousands of changed files cannot take them on one command
 * line: Windows' `CreateProcess` caps a command line at 32 767 characters, and
 * POSIX `ARG_MAX` is large but finite. `review-scan.sh` used to hand the list
 * to `xargs`, whose batches (~19.8 KB on Git Bash) each ran Semgrep with the
 * SAME `--output`, so every batch overwrote the last and the review reported
 * whichever batch happened to finish last. The fix is two halves, and this
 * module is the first: split the list below a fixed budget, in order, losing
 * nothing. The caller gives each batch its own report file and validates each
 * one (see `semgrepReport.ts`).
 *
 * The budget is 24 000 characters for the WHOLE command line — command,
 * fixed arguments and the batch — which leaves room below Windows' limit for
 * the quoting `CreateProcess` needs and for an absolute executable path.
 */
/** Longest command line a batch may produce, in characters. */
export const ARG_CHAR_BUDGET = 24_000;
/**
 * Characters `arg` occupies on a Windows command line: the argument, the
 * separating space, and — when it holds whitespace or a quote — the two
 * surrounding quotes plus one escape per embedded quote. POSIX `execve` needs
 * none of that, so this over-counts there, which is the safe direction.
 */
function argCost(arg) {
    const quotes = (arg.match(/"/g) ?? []).length;
    const needsQuoting = arg.length === 0 || /[\s"]/.test(arg);
    return arg.length + 1 + (needsQuoting ? 2 : 0) + quotes;
}
/** Length of `command args…` once quoted for a command line. */
export function commandLineLength(command, args) {
    return args.reduce((n, a) => n + argCost(a), argCost(command));
}
/**
 * Consecutive batches of `items`, each fitting `maxChars` together with the
 * command and `fixedArgs`. Order is kept and nothing is dropped: an item too
 * long to fit any batch gets one of its own rather than being skipped — the
 * invocation may then fail, and the caller reports that failure, which is the
 * honest outcome; silently not scanning a file is not.
 */
export function batchArgs(items, options) {
    const budget = options.maxChars ?? ARG_CHAR_BUDGET;
    const base = commandLineLength(options.command ?? 'x'.repeat(260), options.fixedArgs);
    const batches = [];
    let current = [];
    let used = base;
    for (const item of items) {
        const cost = argCost(item);
        if (current.length > 0 && used + cost > budget) {
            batches.push(current);
            current = [];
            used = base;
        }
        current.push(item);
        used += cost;
    }
    if (current.length > 0)
        batches.push(current);
    return batches;
}
//# sourceMappingURL=argBatches.js.map