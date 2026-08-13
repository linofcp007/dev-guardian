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
/**
 * Environment variables the nuclei child is allowed to see, matched
 * case-insensitively (Windows spells `PATH` as `Path`, and a case-sensitive
 * list would drop it on exactly one platform).
 *
 * Everything here is needed to LOCATE and RUN the binary, or to let it find
 * its own template cache — nothing is here to configure a scan. In
 * particular, nuclei is deliberately never handed the caller's Authorization
 * header, so the variable `scan_dast`'s `auth_header_env` names must not
 * reach it either.
 *
 * The proxy variables are the one judgement call: they are standard for any
 * network tool, and omitting them turns a working scan behind a corporate
 * proxy into a mysterious failure. A proxy URL can itself embed credentials,
 * so this is not a claim that the child environment is secret-free — only
 * that the credential THIS TOOL was handed is not in it.
 */
const NUCLEI_ENV_ALLOWLIST = new Set([
    // Locating and executing the binary.
    'path', 'pathext', 'comspec', 'systemroot', 'windir', 'systemdrive',
    // Where nuclei keeps its config and template cache.
    'home', 'homedrive', 'homepath', 'userprofile', 'xdg_config_home',
    'appdata', 'localappdata',
    // Scratch space.
    'temp', 'tmp', 'tmpdir',
    // Locale and time, so timestamps and any parsing behave as the user expects.
    'lang', 'lc_all', 'tz',
    // Network egress.
    'http_proxy', 'https_proxy', 'no_proxy',
    // The CA bundle Go's crypto/x509 reads on Linux. These are filesystem
    // paths, not secrets, so allowing them doesn't weaken the scrub above --
    // and without them, a host with a non-default trust store (a container
    // image with its own bundle, or the corporate MITM proxy http_proxy/
    // https_proxy above already supports) fails TLS, including nuclei's own
    // template-update fetch.
    'ssl_cert_file', 'ssl_cert_dir',
]);
/**
 * Build the child environment for the nuclei spawn from a source environment
 * (normally `process.env`). Pure, so the allowlist is testable without
 * spawning anything.
 *
 * Exact name matches only, never prefixes or substrings: `PATH_TO_VAULT_TOKEN`
 * is not `PATH`. An unset name is omitted rather than defined as `undefined`,
 * because the two differ once the object is spread.
 */
export function nucleiEnv(source) {
    const out = {};
    for (const [name, value] of Object.entries(source)) {
        if (value === undefined)
            continue;
        if (!NUCLEI_ENV_ALLOWLIST.has(name.toLowerCase()))
            continue;
        out[name] = value;
    }
    return out;
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
        // An allowlisted environment, and `extendEnv: false` so it REPLACES the
        // parent's rather than being merged over it. Without the second half the
        // first is decorative: execa extends `process.env` by default, and the
        // child would inherit the value of whatever variable `auth_header_env`
        // named — a credential this tool goes out of its way never to put on
        // nuclei's command line.
        env: nucleiEnv(process.env),
        extendEnv: false,
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