/**
 * Invoke nuclei and report whether the run itself succeeded. All I/O, no
 * decisions: this module spawns the process and reports the outcome. Reading
 * `outputPath` and turning its JSONL into findings is `normalizeNuclei.ts`'s
 * job, kept in a separate pure module so nothing here both reads output AND
 * decides what it means — the split every other pure/impure pair in
 * `dast/` holds, because every fabrication defect in this project's history
 * was born in a layer that did both at once.
 *
 * Mirrors `surface/scanSemgrep.ts`'s shape: a pure `build*Args` helper tested
 * on its own, and a thin wrapper over `runProcess` whose only job is
 * translating a `ProcessRunResult` into a verdict. The exit-code handling
 * differs from Semgrep's on purpose — see `interpretRun`.
 */
import { dirname } from 'node:path';
import { runProcess } from '../runners/processRunner.js';
/**
 * Requests per second nuclei is allowed to send. nuclei's own built-in
 * default (150) is tuned for scanning the public internet at scale; this
 * tool's default target is someone's local or internal app, which needs a
 * far gentler ceiling, so this is deliberately conservative rather than
 * reusing nuclei's own default.
 */
export const DEFAULT_NUCLEI_RATE_LIMIT = 10;
/**
 * Tag families excluded from every nuclei run regardless of `allowIntrusive`.
 * The design's non-goals rule out injection and fuzzing payloads from this
 * tool entirely — real fuzzing stays behind nuclei's own `-dast` mode, which
 * this integration never enables (design doc §7) — so `dos` and `fuzz` are
 * never on the table. `allowIntrusive` only ever widens the envelope to admit
 * `intrusive`-tagged templates; it must never touch these two.
 */
const ALWAYS_EXCLUDED_TAGS = ['dos', 'fuzz'];
function excludedTags(allowIntrusive) {
    return allowIntrusive
        ? [...ALWAYS_EXCLUDED_TAGS]
        : [...ALWAYS_EXCLUDED_TAGS, 'intrusive'];
}
/**
 * Pure argument construction — this is where every safety flag lives, so it
 * is tested directly rather than through a real process run.
 *
 * `-no-interactsh` is unconditional, independent of `allowIntrusive` or
 * anything else: out-of-band probes make the TARGET call a third-party
 * interactsh server, an exfiltration channel out of a scanner that may be
 * pointed at the user's internal network. No envelope setting removes it.
 */
export function buildNucleiArgs(opts) {
    return [
        '-target', opts.targetUrl,
        '-jsonl',
        '-output', opts.outputPath,
        '-silent',
        '-no-interactsh',
        '-exclude-tags', excludedTags(opts.allowIntrusive).join(','),
        '-rate-limit', String(DEFAULT_NUCLEI_RATE_LIMIT),
    ];
}
export async function invokeNuclei(opts) {
    const run = await runProcess({
        command: opts.binaryPath,
        args: buildNucleiArgs(opts),
        // nuclei targets a URL, not a filesystem tree, so the working directory
        // has no bearing on what gets scanned; `outputPath`'s own directory is
        // used only because it is a real, already-relevant path handed to us,
        // rather than reaching for ambient process state.
        cwd: dirname(opts.outputPath),
        timeoutMs: opts.timeoutMs,
        signal: opts.signal,
    });
    return interpretRun(run);
}
/**
 * `outcome === 'completed'` is exactly exit code 0 (`processRunner.ts`
 * downgrades anything else to `failed` / `timed_out` / etc). Unlike Semgrep,
 * nuclei carries no "non-zero exit means it found something" convention to
 * special-case: a maintainer-confirmed reproduction
 * (projectdiscovery/nuclei#5086) shows exit 0 whether or not templates
 * matched, on Linux, macOS and Windows alike. So a non-zero exit here is
 * always a genuine run problem — bad flags, a template that failed to load,
 * the target refusing the connection at the transport level before any
 * template ran — never "found something", and `outcome === 'completed'` is
 * the only success path.
 */
export function interpretRun(run) {
    if (run.outcome === 'completed')
        return { ok: true };
    const firstLine = run.stderr.split(/\r?\n/).find((l) => l.trim().length > 0);
    return { ok: false, reason: firstLine ?? `nuclei ${run.outcome}` };
}
//# sourceMappingURL=nuclei.js.map