/**
 * Git hardening: the environment every git process dev-guardian starts in —
 * or on — a scanned project runs with (review 3.0, W2E-git).
 *
 * A scanned project is input, and so is its `.git/`. A repository delivered
 * with its own `.git/` (an archive, a ZIP download, a shared folder) can name
 * programs for git to run, and git runs them:
 *
 *   - `core.fsmonitor` — on `status`, `ls-files` (even `--others`),
 *     `diff --name-only HEAD`, `check-ignore`;
 *   - hooks in `.git/hooks` — `post-index-change` on a plain `status`,
 *     `post-checkout` and `reference-transaction` on `worktree add`, and
 *     `prepare-commit-msg`, `post-commit`, `reference-transaction` on a
 *     commit made WITH `--no-verify`;
 *   - a filter driver (`filter.<d>.clean|smudge|process`, mapped by
 *     `.gitattributes`) on checkout, and its clean half on `status` and
 *     `diff HEAD` of a stat-dirty file;
 *   - a textconv driver (`diff.<d>.textconv`) on `git log -p` — the exact
 *     `git log -p -U0 --full-history --all` gitleaks runs in git mode;
 *   - `gpg.program` with `log.showSignature` — on that same `git log -p`,
 *     for any commit that carries a signature;
 *   - `core.sshCommand`, `core.askPass`, `core.gitProxy`, credential
 *     helpers, `remote.<n>.receivepack` — on a push; `remote.<n>.uploadpack`
 *     — on a partial clone's lazy fetch of a missing object.
 *
 * Measured before this module existed: `scan_sast` ran a repository's
 * `core.fsmonitor` five times through Semgrep 1.176.1's own `git ls-files`,
 * and `scan_secrets` ran its textconv driver through gitleaks 8.30.1.
 *
 * Git reads configuration from the ENVIRONMENT (`GIT_CONFIG_COUNT`,
 * `GIT_CONFIG_KEY_<n>`, `GIT_CONFIG_VALUE_<n>`; git 2.31+) at "command"
 * scope, which comes after — and so overrides — every file, the repository's
 * own included. Every git a scanner or a package manager starts inherits it,
 * which a `-c` on dev-guardian's own command line could never reach. The
 * user's own `GIT_CONFIG_COUNT` entries are kept: ours are appended after
 * them. Two layers:
 *
 *   1. STATIC, on every process ({@link staticGitSafety}): `core.fsmonitor`
 *      off, `core.hooksPath` at a path that cannot exist (a path BENEATH a
 *      regular file — the Node executable on Windows, `/dev/null`
 *      elsewhere), the `ext::` transport refused, signatures never verified
 *      by `git log`, no automatic gc or maintenance, and `GIT_PAGER`,
 *      `GIT_EDITOR` and `GIT_SEQUENCE_EDITOR` set to no-ops.
 *   2. PER REPOSITORY ({@link gitSafetyFor}): the repository's own
 *      command-naming keys — from `local` and `worktree` scope, which
 *      includes every file those pull in through `include.path` /
 *      `includeIf` (git reports an included entry at its includer's scope;
 *      measured) — read with `git config --get-regexp`, which runs nothing,
 *      and each overridden: with the user's own value for that key when their
 *      system or global configuration has one, otherwise with a neutral one
 *      (see {@link neutralValue} for what each value was measured to do).
 *
 * Reading the configuration can fail in a way the child's own read would not
 * (a timeout, a key that is not UTF-8 and so cannot be named in an
 * environment variable, a git too old for `GIT_CONFIG_COUNT`). Then the
 * result is REFUSED: nothing is run, and the caller reports why — never a
 * run that merely hoped the repository had nothing to neutralise.
 *
 * This file uses Node built-ins only: the hook (`hooks/guardian-hook.mjs`)
 * and the CLI import it from `dist/`, where no `node_modules` exists.
 * `test/unit/platform/gitSpawnSites.test.ts` fails when a git spawn anywhere
 * in `src/`, `cli/` or `hooks/` bypasses it.
 */
import { spawn, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
/** The git executable, for callers that describe a git spawn as data (`runProcess`). */
export const GIT_COMMAND = 'git';
/** How long reading a repository's configuration may take. */
const PROBE_TIMEOUT_MS = 10_000;
/** More output than this from `git config --get-regexp` is refused, not truncated. */
const PROBE_MAX_BYTES = 1024 * 1024;
/** More command-naming keys than this in one repository is refused (each one is two environment variables). */
const MAX_REPOSITORY_KEYS = 200;
/**
 * Where git looks for hooks: a path BENEATH a regular file, which no one can
 * create without replacing that file. On Windows, beneath the Node executable
 * (`C:/Program Files/nodejs/node.exe/no-git-hooks` — measured: no hook runs);
 * elsewhere beneath `/dev/null`. Never `/dev/null` on Windows: there it is
 * `C:\dev\null`, a directory any user may create at the drive root. Never a
 * relative path: git resolves that against the work tree, which is the
 * repository's.
 */
export function noHooksPath(platform = process.platform, execPath = process.execPath) {
    if (platform === 'win32')
        return `${execPath.replace(/\\/g, '/')}/no-git-hooks`;
    return '/dev/null/no-git-hooks';
}
/**
 * The static overrides: what every git process dev-guardian starts gets,
 * whatever the repository. `diff.submodule=short`: a repository's own
 * `diff.submodule=diff` makes `git log -p` — gitleaks' — diff INSIDE each
 * submodule, running the submodule's textconv driver (measured); `short`
 * (git's default) prints the commit ids alone.
 */
function staticConfig(hooksPath) {
    return [
        ['core.fsmonitor', 'false'],
        ['core.hooksPath', hooksPath],
        ['protocol.ext.allow', 'never'],
        ['log.showSignature', 'false'],
        ['gc.auto', '0'],
        ['maintenance.auto', 'false'],
        ['diff.submodule', 'short'],
    ];
}
/**
 * Pager and editors, as environment variables: `GIT_PAGER` outranks
 * `pager.<cmd>` and `core.pager`, `GIT_EDITOR` outranks `core.editor`,
 * `GIT_SEQUENCE_EDITOR` outranks `sequence.editor`. `:` is git's own "no
 * editor"; `cat` its own "no pager". Git only pages to a terminal and only
 * opens an editor when asked for a message it was not given — neither is
 * reachable from a dev-guardian spawn (measured) — so these are depth, not
 * the fix.
 */
const STATIC_VARS = { GIT_PAGER: 'cat', GIT_EDITOR: ':', GIT_SEQUENCE_EDITOR: ':' };
/**
 * `safety` without the `core.hooksPath` redirect — for the one child whose
 * JOB is to install hooks where git says they go (`precommit_install`'s
 * `pre-commit install`, which refuses outright when `core.hooksPath` is set:
 * "Cowardly refusing to install hooks with `core.hooksPath` set" — measured,
 * pre-commit 4.6.0). Everything else stays. That child's git calls —
 * `rev-parse --show-cdup`, `--is-inside-git-dir`, `--git-common-dir`,
 * `config core.hooksPath` (measured with GIT_TRACE) — write no index and run
 * no hook.
 */
export function withoutHooksPath(safety) {
    return { ...safety, config: safety.config.filter(([key]) => key !== 'core.hooksPath') };
}
/** The static layer alone: for a process that reaches no repository dev-guardian can name. */
export function staticGitSafety(platform = process.platform) {
    return { config: staticConfig(noHooksPath(platform)), vars: STATIC_VARS, notApplied: [], refused: null };
}
/**
 * Every configuration key that names a command git may run — from git's own
 * documentation (`git help --config`), limited to what a git started by
 * dev-guardian, a scanner or a package manager can reach — plus the static
 * layer's own keys (so a repository that sets them is named), plus the
 * sentinel {@link PROBE_KEY}. POSIX ERE, matched against git's canonical key
 * (section and name lower-cased, subsection as written).
 *
 * Deliberately absent, because no dev-guardian path runs the command that
 * reads them: `difftool.*`, `mergetool.*`, `guitool.*`, `diff.tool`,
 * `merge.tool`, `sendemail.*`, `imap.tunnel`, `web.browser`, `browser.*`,
 * `man.*`, `help.browser`, `instaweb.*`, `interactive.diffFilter` (`add -p`),
 * `trailer.*.cmd` (`commit --trailer`; a plain `commit -m` runs none —
 * measured), `submodule.*.update` (`submodule update`), `gc.recentObjectsHook`
 * (gc — and automatic gc is off, static). `uploadpack.packObjectsHook` is
 * honoured by git only from protected (system, global, command-line)
 * configuration, never a repository's.
 *
 * Also the keys that decide where and how a git sends the user's credentials
 * over HTTP — each measured to apply from a repository's own configuration
 * (review 3.0, W2E-git round 2): `http[.<url>].extraHeader` (a header on every
 * request), `.proxy` and `remote.<n>.proxy` (every request through a host of
 * the repository's choosing), `.sslVerify`, `.sslCAInfo`, `.sslCAPath` (a
 * certificate the repository chose — a man in the middle of the user's
 * token), `.cookieFile` and `.saveCookies` (cookies sent from, and WRITTEN
 * to, a path of its choosing), `.followRedirects`. `url.<base>.insteadOf` and
 * `pushInsteadOf` cannot be overridden from the environment; `create_fix_pr`'s
 * push refuses a URL they rewrite (`fixpr/pr.ts`).
 */
export const COMMAND_KEYS_REGEX = '^(' +
    [
        'filter\\..+\\.(clean|smudge|process)',
        'diff\\..+\\.(textconv|command)',
        'diff\\.external',
        'merge\\..+\\.driver',
        'core\\.(sshcommand|askpass|gitproxy|alternaterefscommand|fsmonitor|hookspath|pager|editor)',
        'sequence\\.editor',
        'pager\\..+',
        'credential\\.(.+\\.)?helper',
        'gpg\\.(program|.+\\.program|ssh\\.defaultkeycommand)',
        'alias\\..+',
        'remote\\..+\\.(uploadpack|receivepack|proxy)',
        'http\\.(.+\\.)?(extraheader|proxy|sslverify|sslcainfo|sslcapath|cookiefile|savecookies|followredirects)',
        'devguardian\\.envprobe',
    ].join('|') +
    ')$';
/**
 * A key dev-guardian passes to its own `git config` read and expects back at
 * `command` scope. Absent, the git on PATH did not read `GIT_CONFIG_COUNT`
 * (older than 2.31) — and would not read the overrides either.
 */
export const PROBE_KEY = 'devguardian.envprobe';
/** Scopes whose values are the user's own. Everything else (`local`, `worktree`, …) is the repository's. */
const TRUSTED_SCOPES = new Set(['system', 'global', 'command']);
/** Whether a `git config --show-scope` scope is the repository's own (not the user's). */
export function isRepositoryScope(scope) {
    return !TRUSTED_SCOPES.has(scope);
}
const STRICT_UTF8 = new TextDecoder('utf-8', { fatal: true });
/**
 * `git config --show-scope -z --get-regexp` output: `scope NUL key LF value
 * NUL`, repeated; `key NUL` (no LF) for a key with no value. A key that is
 * not UTF-8 cannot be named in an environment variable git will match, so it
 * is a refusal, not a key to skip.
 */
export function parseConfigListing(bytes) {
    const entries = [];
    const tokens = [];
    let start = 0;
    for (let i = 0; i < bytes.length; i++) {
        if (bytes[i] === 0) {
            tokens.push(bytes.subarray(start, i));
            start = i + 1;
        }
    }
    for (let i = 0; i + 1 < tokens.length; i += 2) {
        const scopeBytes = tokens[i];
        const kv = tokens[i + 1];
        if (scopeBytes === undefined || kv === undefined)
            break;
        const lf = kv.indexOf(0x0a);
        const keyBytes = lf < 0 ? kv : kv.subarray(0, lf);
        let key;
        try {
            key = STRICT_UTF8.decode(keyBytes);
        }
        catch {
            return {
                refused: `the repository's git configuration has a key that is not UTF-8 (${JSON.stringify(keyBytes.toString('latin1'))}), ` +
                    'which cannot be overridden from the environment',
            };
        }
        let value = null;
        if (lf >= 0) {
            try {
                value = STRICT_UTF8.decode(kv.subarray(lf + 1));
            }
            catch {
                value = null;
            }
        }
        entries.push({ scope: scopeBytes.toString('utf8'), key, value });
    }
    return { entries };
}
const FILTER_KEY = /^filter\.(.+)\.(clean|smudge|process)$/;
const CREDENTIAL_HELPER = /^credential\.(?:.+\.)?helper$/;
/** Neutralised by the static layer — overridden whatever the repository says; only named. */
const STATIC_KEYS = new Set(['core.fsmonitor', 'core.hookspath', 'core.pager', 'core.editor', 'sequence.editor']);
/**
 * The value that disables `key` when the user has none of their own — each
 * one measured (git 2.52.0.windows.1; git 2.39.5 in `node:22`):
 *
 *   - `filter.<d>.clean|smudge|process` = `''`: the driver is not run and the
 *     content passes through unchanged (with `filter.<d>.required` forced
 *     false: `required` plus an empty command makes git die instead);
 *   - `diff.<d>.textconv` = `cat`: identity. An EMPTY textconv is not
 *     "unset" — git dies ("unable to read files to diff"). `cat` resolves
 *     through Git for Windows' own `usr/bin` even when PATH holds only
 *     `Git\cmd` (measured); where it cannot resolve, git dies loudly;
 *   - `diff.<d>.command`, `diff.external`, `merge.<d>.driver` = `''`: git
 *     dies ("cannot spawn"), loudly. No dev-guardian path asks for what reads
 *     them: every diff it runs is `--name-only`/`--name-status`, gitleaks'
 *     `git log -p` runs no external diff without `--ext-diff` (measured),
 *     and nothing merges;
 *   - `core.sshCommand` = `ssh` (or the user's `GIT_SSH`, quoted);
 *     `core.askPass`, `core.alternateRefsCommand`,
 *     `gpg.ssh.defaultKeyCommand`, `alias.<x>` = `''`; `gpg.program` and
 *     `gpg.openpgp.program` = `gpg`, `gpg.x509.program` = `gpgsm`,
 *     `gpg.ssh.program` = `ssh-keygen` — git's own defaults;
 *   - `http[.<url>].proxy`, `remote.<n>.proxy` = the user's own proxy
 *     variable (`https_proxy`, `http_proxy`, `all_proxy`, as git reads them),
 *     else `''`: git reads those variables only when no `http.proxy` is set,
 *     and an empty one means no proxy at all (measured) — so this is what the
 *     user's git would have done without the repository's setting;
 *   - `http[.<url>].sslVerify` = `true`; `.sslCAInfo`, `.sslCAPath` = `''`,
 *     which fails the TLS handshake — loudly, nothing reaches the server
 *     (measured: schannel and OpenSSL); `.cookieFile` = `''`;
 *     `.saveCookies` = `false`; `.followRedirects` = `initial`, git's default.
 *
 * A URL-specific `http.<url>.<name>` is always overridden under its OWN key:
 * git keeps the most specific match per URL, so a generic `http.<name>`
 * appended after it loses (measured).
 */
export function neutralValue(key, env) {
    if (FILTER_KEY.test(key))
        return '';
    if (/^diff\..+\.textconv$/.test(key))
        return 'cat';
    if (key === 'core.sshcommand') {
        const gitSsh = envValue(env, 'GIT_SSH');
        return gitSsh !== undefined && gitSsh !== '' ? shellQuote(gitSsh) : 'ssh';
    }
    if (key === 'gpg.program' || key === 'gpg.openpgp.program')
        return 'gpg';
    if (key === 'gpg.x509.program')
        return 'gpgsm';
    if (key === 'gpg.ssh.program')
        return 'ssh-keygen';
    const http = HTTP_KEY.exec(key);
    if (http !== null) {
        const name = http[2] ?? '';
        if (name === 'proxy')
            return envProxy(env, http[1]);
        if (name === 'sslverify')
            return 'true';
        if (name === 'savecookies')
            return 'false';
        if (name === 'followredirects')
            return 'initial';
        return '';
    }
    if (/^remote\..+\.proxy$/.test(key))
        return envProxy(env, undefined);
    return '';
}
/** `http.<name>` or `http.<url>.<name>` for the HTTP keys the policy handles: [, url, name]. */
const HTTP_KEY = /^http\.(?:(.+)\.)?(extraheader|proxy|sslverify|sslcainfo|sslcapath|cookiefile|savecookies|followredirects)$/;
/**
 * The proxy the user's own environment names, as git reads it when no
 * `http.proxy` is configured: for an `https` URL `HTTPS_PROXY` then
 * `https_proxy`, for `http` `http_proxy`, then `ALL_PROXY`, `all_proxy` — the
 * later one winning. `''` when there is none. For a key that names no URL
 * (`http.proxy`, `remote.<n>.proxy` — one value for every URL), the first the
 * user set of `https_proxy`, `HTTPS_PROXY`, `http_proxy`, `all_proxy`,
 * `ALL_PROXY`.
 */
function envProxy(env, url) {
    const exact = (name) => {
        const v = env[name];
        return v === undefined || v === '' ? undefined : v;
    };
    const all = exact('all_proxy') ?? exact('ALL_PROXY');
    if (url === undefined)
        return exact('https_proxy') ?? exact('HTTPS_PROXY') ?? exact('http_proxy') ?? all ?? '';
    const primary = /^http:\/\//i.test(url) ? exact('http_proxy') : (exact('https_proxy') ?? exact('HTTPS_PROXY'));
    return primary ?? all ?? '';
}
/** A POSIX single-quoted word: `core.sshCommand` goes through a shell, `GIT_SSH` does not. */
function shellQuote(s) {
    return `'${s.replace(/'/g, `'\\''`)}'`;
}
/** The overrides one repository's listing calls for. */
function neutraliseListing(entries, env) {
    const trusted = entries.filter((e) => TRUSTED_SCOPES.has(e.scope));
    const untrusted = entries.filter((e) => !TRUSTED_SCOPES.has(e.scope) && e.key !== PROBE_KEY);
    const probeSeen = entries.some((e) => e.scope === 'command' && e.key === PROBE_KEY);
    const config = [];
    const vars = {};
    const notApplied = new Set();
    const drivers = new Set();
    const extraHeaders = new Set();
    let credentials = false;
    const trustedValue = (key) => {
        let v = null;
        for (const e of trusted)
            if (e.key === key)
                v = e.value;
        return v;
    };
    for (const { key } of untrusted) {
        notApplied.add(key);
        if (STATIC_KEYS.has(key) || /^pager\./.test(key))
            continue;
        if (CREDENTIAL_HELPER.test(key)) {
            credentials = true;
            continue;
        }
        const http = HTTP_KEY.exec(key);
        if (http?.[2] === 'extraheader') {
            extraHeaders.add(key);
            continue;
        }
        if (http !== null) {
            // The user's own value for this very key, else for its generic form
            // (what would have applied to that URL without the repository's key).
            const mine = trustedValue(key) ?? (http[1] !== undefined ? trustedValue(`http.${http[2] ?? ''}`) : null);
            config.push([key, mine ?? neutralValue(key, env)]);
            continue;
        }
        if (key === 'core.gitproxy') {
            // First match wins for core.gitProxy, so an appended override loses;
            // GIT_PROXY_COMMAND (empty: no proxy) outranks every entry. A user's own
            // GIT_PROXY_COMMAND already does.
            if (envValue(env, 'GIT_PROXY_COMMAND') === undefined)
                vars['GIT_PROXY_COMMAND'] = '';
            continue;
        }
        if (/^remote\..+\.(uploadpack|receivepack)$/.test(key)) {
            // The FIRST value wins for these ("more than one uploadpack given,
            // using the first" — measured), so no appended override can replace
            // them. uploadpack is reached by a partial clone's lazy fetch, which
            // GIT_NO_LAZY_FETCH refuses; receivepack only by a push, and
            // dev-guardian's one push passes --receive-pack itself.
            if (key.endsWith('.uploadpack'))
                vars['GIT_NO_LAZY_FETCH'] = '1';
            continue;
        }
        const mine = trustedValue(key);
        const value = mine ?? neutralValue(key, env);
        config.push([key, value]);
        const filter = FILTER_KEY.exec(key);
        if (filter?.[1] !== undefined && mine === null)
            drivers.add(filter[1]);
    }
    for (const driver of drivers)
        config.push([`filter.${driver}.required`, 'false']);
    for (const key of extraHeaders) {
        // An empty value resets the list — under the repository's OWN key: git
        // keeps the most specific match per URL, so a generic reset loses to a
        // URL-specific header (measured). Then the user's own headers that
        // applied to that URL are replayed under the same key: those set for
        // exactly it, and the generic ones — never a header set for another URL.
        config.push([key, '']);
        for (const e of trusted) {
            if ((e.key === key || e.key === 'http.extraheader') && e.value !== null)
                config.push([key, e.value]);
        }
    }
    if (credentials) {
        // An empty helper resets the list (git's documented idiom): the
        // repository's helpers go, and the user's own are replayed after, in order.
        config.push(['credential.helper', '']);
        for (const e of trusted) {
            if (CREDENTIAL_HELPER.test(e.key) && e.value !== null)
                config.push([e.key, e.value]);
        }
    }
    return { config, vars, notApplied: [...notApplied].sort(), probeSeen };
}
function probeArgs(dir) {
    // safe.directory=*: read the configuration even of a repository git would
    // refuse for its ownership, so a scanner that passes its own
    // safe.directory finds it neutralised all the same.
    return ['-c', 'safe.directory=*', '-C', dir, 'config', '--includes', '--show-scope', '-z', '--get-regexp', COMMAND_KEYS_REGEX];
}
/**
 * The environment the probe runs with: the child's own, minus `GIT_CONFIG`
 * (which makes `git config` — and only `git config` — read one file instead
 * of the repository's), plus the static layer and the sentinel.
 */
function probeEnv(base, platform) {
    const env = { ...base };
    for (const name of Object.keys(env))
        if (sameName(name, 'GIT_CONFIG', platform))
            delete env[name];
    const stat = staticGitSafety(platform);
    return applyGitSafety({ ...stat, config: [...stat.config, [PROBE_KEY, '1']] }, env, platform);
}
/**
 * Why the environment's own `GIT_CONFIG_COUNT` rules out appending to it, or
 * null. Git reads it with `strtoul` and dies on anything after the digits
 * ("bogus count in GIT_CONFIG_COUNT").
 */
function countProblem(env, platform) {
    const raw = envValue(env, 'GIT_CONFIG_COUNT', platform) ?? '';
    const t = raw.trim();
    if (t === '' || /^\+?\d+$/.test(t))
        return null;
    return `GIT_CONFIG_COUNT in the environment is ${JSON.stringify(raw)}, not a number, and git refuses to run with it`;
}
/**
 * Git's own refusals to read a configuration at all — measured: `git status`
 * dies with the same message — so no git can run a command it names: a bad
 * line, a bad include, an include cycle, a `.git` file pointing at no
 * repository (a broken submodule). Any other failure of the read is a
 * refusal of ours.
 */
const GIT_CANNOT_READ = /cannot change to|bad config line|bad numeric config value|exceeded maximum include depth|not a git repository/i;
function interpretExit(status, stdout, stderr, dir) {
    if (status === 0)
        return { kind: 'listing', bytes: stdout };
    // Exit 1: nothing matched — not even the sentinel, so GIT_CONFIG_COUNT was not read.
    if (status === 1)
        return { kind: 'listing', bytes: Buffer.alloc(0) };
    if (status === 3)
        return { kind: 'none' };
    if (status === 128 && GIT_CANNOT_READ.test(stderr))
        return { kind: 'none' };
    return {
        kind: 'refused',
        message: `could not read the git configuration of ${dir}: git config exited ${status ?? 'on a signal'}${firstLine(stderr) !== '' ? ` (${firstLine(stderr)})` : ''}`,
    };
}
function combine(probes, env, platform) {
    const base = staticGitSafety(platform);
    const config = [...base.config];
    const vars = { ...base.vars };
    const notApplied = new Set();
    const refusals = [];
    // A pair another repository's reading already added is not added again;
    // within one reading, every pair stands (an empty reset and a replay of the
    // same value are both meaningful there).
    const seen = new Set();
    for (const { dir, probe, submodule } of probes) {
        if (probe.kind === 'refused')
            refusals.push(probe.message);
        if (probe.kind !== 'listing')
            continue;
        const parsed = parseConfigListing(probe.bytes);
        if ('refused' in parsed) {
            refusals.push(`${parsed.refused} (${dir})`);
            continue;
        }
        const n = neutraliseListing(parsed.entries, env);
        if (!n.probeSeen) {
            refusals.push('the git on PATH does not take configuration from the environment (GIT_CONFIG_COUNT needs git 2.31 or later), ' +
                "so a scanned repository's own git configuration could not be kept from running commands");
            continue;
        }
        if (n.notApplied.length > MAX_REPOSITORY_KEYS) {
            refusals.push(`the git configuration of ${dir} names ${n.notApplied.length} commands, more than ${MAX_REPOSITORY_KEYS}`);
            continue;
        }
        const earlier = new Set(seen);
        for (const pair of n.config) {
            const id = `${pair[0]}\0${pair[1]}`;
            if (earlier.has(id))
                continue;
            seen.add(id);
            config.push(pair);
        }
        Object.assign(vars, n.vars);
        for (const k of n.notApplied)
            notApplied.add(submodule === undefined ? k : `${k} (submodule ${submodule})`);
    }
    return {
        config,
        vars,
        notApplied: [...notApplied].sort(),
        refused: refusals.length > 0 ? [...new Set(refusals)].join('; ') : null,
    };
}
/**
 * The safety one `git config --show-scope -z --get-regexp` listing calls
 * for — what {@link gitSafetyFor} computes for a directory once git has
 * answered. Pure: the policy, testable without a git.
 */
export function safetyFromListing(dir, listing, env = process.env, platform = process.platform) {
    return combine([{ dir, probe: { kind: 'listing', bytes: listing } }], env, platform);
}
/**
 * The static layer plus, for each of `dirs`, the neutralisation its
 * repository's own configuration calls for — read in `dir` exactly as a git
 * started there would read it — and, the same way, for every initialised
 * submodule of that repository, nested ones included ({@link gitlinks}). `dirs`
 * that are not in a repository add nothing.
 *
 * Submodules, because git goes into them: a `status` or a `diff` against the
 * work tree runs a `status` inside each initialised submodule, whose OWN
 * configuration (`.git/modules/<name>/config`, or an in-tree `sub/.git/`)
 * names its own filter and textconv drivers. Measured (review 3.0, W2E-git
 * round 2): a superproject `git status --porcelain` ran a clean filter
 * defined only in the submodule, and so did one with an old-style in-tree
 * `.git`. The environment reaches that inner git — git keeps
 * `GIT_CONFIG_COUNT` for a submodule (unlike for a local transport) — so the
 * submodule's command keys are simply added to the overrides.
 */
export async function gitSafetyFor(dirs, opts = {}) {
    const platform = opts.platform ?? process.platform;
    const env = opts.env ?? process.env;
    const problem = countProblem(env, platform);
    if (problem !== null)
        return { ...staticGitSafety(platform), refused: problem };
    const walk = {
        git: opts.git ?? GIT_COMMAND,
        env: probeEnv(env, platform),
        timeoutMs: opts.timeoutMs ?? PROBE_TIMEOUT_MS,
        reuseMs: opts.reuseMs ?? PROBE_REUSE_MS,
        read: [],
        visited: new Set(),
        submodules: 0,
    };
    for (const dir of new Set(dirs))
        await walkAsync(walk, dir, dir, 0);
    return combine(walk.read, env, platform);
}
/** {@link gitSafetyFor}, synchronously — for the CLI, the hook and the synchronous readers. */
export function gitSafetyForSync(dirs, opts = {}) {
    const platform = opts.platform ?? process.platform;
    const env = opts.env ?? process.env;
    const problem = countProblem(env, platform);
    if (problem !== null)
        return { ...staticGitSafety(platform), refused: problem };
    const walk = {
        git: opts.git ?? GIT_COMMAND,
        env: probeEnv(env, platform),
        timeoutMs: opts.timeoutMs ?? PROBE_TIMEOUT_MS,
        reuseMs: opts.reuseMs ?? PROBE_REUSE_MS,
        read: [],
        visited: new Set(),
        submodules: 0,
    };
    for (const dir of new Set(dirs))
        walkSync(walk, dir, dir, 0);
    return combine(walk.read, env, platform);
}
/** More initialised submodules than this, every level together, is refused, not read. */
const MAX_SUBMODULES = 64;
/** Submodules of submodules are followed this deep; a deeper one is refused. */
const MAX_SUBMODULE_DEPTH = 8;
/** What {@link walkAsync} and {@link walkSync} do with one directory's gitlinks. */
function nextSubmodules(walk, dir, depth, links) {
    if (links.kind === 'refused') {
        walk.read.push({ dir, probe: { kind: 'refused', message: links.message } });
        return [];
    }
    const next = [];
    for (const sub of links.dirs) {
        if (walk.visited.has(sub))
            continue;
        walk.visited.add(sub);
        walk.submodules += 1;
        if (walk.submodules > MAX_SUBMODULES || depth + 1 > MAX_SUBMODULE_DEPTH) {
            walk.read.push({
                dir: sub,
                probe: {
                    kind: 'refused',
                    message: `${dir} has initialised submodules past what dev-guardian reads (${MAX_SUBMODULES} in all, ` +
                        `${MAX_SUBMODULE_DEPTH} levels deep), so their git configuration could not be kept from running commands`,
                },
            });
            return [];
        }
        next.push(sub);
    }
    return next;
}
async function walkAsync(walk, root, dir, depth) {
    walk.visited.add(dir);
    const probe = await probeAsync(walk.git, dir, walk.env, walk.timeoutMs, walk.reuseMs);
    walk.read.push(depth === 0 ? { dir, probe } : { dir, probe, submodule: relativeLabel(root, dir) });
    if (probe.kind !== 'listing')
        return;
    const links = await gitlinksAsync(walk.git, dir, walk.env, walk.timeoutMs, walk.reuseMs);
    for (const sub of nextSubmodules(walk, dir, depth, links))
        await walkAsync(walk, root, sub, depth + 1);
}
function walkSync(walk, root, dir, depth) {
    walk.visited.add(dir);
    const probe = probeSync(walk.git, dir, walk.env, walk.timeoutMs, walk.reuseMs);
    walk.read.push(depth === 0 ? { dir, probe } : { dir, probe, submodule: relativeLabel(root, dir) });
    if (probe.kind !== 'listing')
        return;
    const links = gitlinksSync(walk.git, dir, walk.env, walk.timeoutMs, walk.reuseMs);
    for (const sub of nextSubmodules(walk, dir, depth, links))
        walkSync(walk, root, sub, depth + 1);
}
function relativeLabel(root, dir) {
    const rel = relative(root, dir).split('\\').join('/');
    return rel === '' ? '.' : rel;
}
/**
 * `git ls-files -z --stage -- :/` — the whole index, from wherever `dir` is in
 * the work tree (runs nothing: no work-tree file is read, and fsmonitor is
 * off) — keeping each gitlink (mode 160000) whose directory holds a `.git`,
 * file (an absorbed submodule's pointer into `.git/modules/…`) or directory
 * (an old-style in-tree repository): exactly the submodules a `git status`
 * goes into. A gitlink path that is not UTF-8 cannot be followed, so it is a
 * refusal; git failing to read the index (no repository, a damaged index —
 * which a `status` fails on too) is no submodule.
 */
function gitlinkArgs(dir) {
    return ['-c', 'safe.directory=*', '-C', dir, 'ls-files', '-z', '--stage', '--', ':/'];
}
/** The index listing is every file in the repository; more than this is refused. */
const GITLINK_LISTING_MAX_BYTES = 512 * 1024 * 1024;
function parseGitlinks(dir, status, stdout) {
    if (status !== 0)
        return { kind: 'dirs', dirs: [] };
    const dirs = [];
    let start = 0;
    for (let i = 0; i <= stdout.length; i++) {
        if (i < stdout.length && stdout[i] !== 0)
            continue;
        const entry = stdout.subarray(start, i);
        start = i + 1;
        // `<mode> <object> <stage>\t<path>`
        if (entry.length < 8 || entry.toString('latin1', 0, 7) !== '160000 ')
            continue;
        const tab = entry.indexOf(0x09);
        if (tab < 0)
            continue;
        let path;
        try {
            path = STRICT_UTF8.decode(entry.subarray(tab + 1));
        }
        catch {
            return { kind: 'refused', message: `${dir} has a submodule whose path is not UTF-8, which dev-guardian cannot follow` };
        }
        const abs = resolve(dir, path);
        if (!dirs.includes(abs) && existsSync(join(abs, '.git')))
            dirs.push(abs);
    }
    return { kind: 'dirs', dirs };
}
function gitlinksError(error, dir, timeoutMs) {
    if (error.code === 'ENOENT')
        return { kind: 'dirs', dirs: [] };
    if (error.code === 'ETIMEDOUT')
        return { kind: 'refused', message: `listing the submodules of ${dir} took longer than ${timeoutMs} ms` };
    if (error.code === 'ENOBUFS') {
        return { kind: 'refused', message: `the index of ${dir} lists more than ${GITLINK_LISTING_MAX_BYTES} bytes of files; its submodules were not read` };
    }
    return { kind: 'refused', message: `could not list the submodules of ${dir}: ${error.message}` };
}
const gitlinkCache = new Map();
function cachedGitlinks(key, reuseMs) {
    const hit = gitlinkCache.get(key);
    if (hit === undefined || Date.now() - hit.at > reuseMs)
        return null;
    return hit.links;
}
function rememberGitlinks(key, links) {
    if (links.kind === 'refused')
        return links;
    if (gitlinkCache.size >= PROBE_CACHE_MAX)
        gitlinkCache.clear();
    gitlinkCache.set(key, { at: Date.now(), links });
    return links;
}
function gitlinksSync(git, dir, env, timeoutMs, reuseMs) {
    const key = probeCacheKey(git, dir, env);
    const hit = cachedGitlinks(key, reuseMs);
    if (hit !== null)
        return hit;
    const r = spawnSync(git, gitlinkArgs(dir), {
        env,
        timeout: timeoutMs,
        maxBuffer: GITLINK_LISTING_MAX_BYTES,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
    });
    if (r.error !== undefined)
        return gitlinksError(r.error, dir, timeoutMs);
    return rememberGitlinks(key, parseGitlinks(dir, r.status, Buffer.isBuffer(r.stdout) ? r.stdout : Buffer.alloc(0)));
}
async function gitlinksAsync(git, dir, env, timeoutMs, reuseMs) {
    const key = probeCacheKey(git, dir, env);
    const hit = cachedGitlinks(key, reuseMs);
    if (hit !== null)
        return hit;
    const r = await collect(git, gitlinkArgs(dir), { env, timeoutMs, maxBuffer: GITLINK_LISTING_MAX_BYTES });
    if (r.error !== undefined)
        return gitlinksError(r.error, dir, timeoutMs);
    return rememberGitlinks(key, parseGitlinks(dir, r.status, r.stdout));
}
/**
 * A reading of one directory's configuration is reused for {@link PROBE_REUSE_MS}:
 * a scan asks git a dozen questions in a burst, and each reading is a
 * process (about 40 ms on Windows, 4 ms in a Linux container — measured).
 * Keyed on the git, the directory and every environment variable that
 * decides which configuration git reads, so a different environment is a
 * different reading. Only an answer is reused, never a refusal. The window
 * is the read-then-use gap the module comment names, made two seconds long:
 * a writer who can change `.git/config` inside it could as well inside the
 * other. Measured on the hostile fixture (Windows, git 2.52): one reading
 * per git call without it — `scan_secrets` 12 for 12 git calls, `review_pr`
 * 25 for 26 — and 5, 2 (`scan_sast`) and 5 with it.
 */
const PROBE_REUSE_MS = 2_000;
const PROBE_CACHE_MAX = 64;
const probeCache = new Map();
function probeCacheKey(git, dir, env) {
    const relevant = Object.keys(env)
        .filter((k) => /^(GIT_|HOME$|USERPROFILE$|XDG_CONFIG_HOME$|PATH$|PROGRAMDATA$|APPDATA$)/i.test(k))
        .sort()
        .map((k) => `${k}=${env[k] ?? ''}`);
    return JSON.stringify([git, dir, relevant]);
}
function cachedProbe(key, reuseMs) {
    const hit = probeCache.get(key);
    if (hit === undefined)
        return null;
    if (Date.now() - hit.at > reuseMs) {
        probeCache.delete(key);
        return null;
    }
    return hit.probe;
}
function rememberProbe(key, probe) {
    if (probe.kind === 'refused')
        return probe;
    if (probeCache.size >= PROBE_CACHE_MAX)
        probeCache.clear();
    probeCache.set(key, { at: Date.now(), probe });
    return probe;
}
/** Forget every reading — for a test that rewrites a repository's configuration between two runs. */
export function forgetGitConfigReads() {
    probeCache.clear();
    gitlinkCache.clear();
}
function probeSync(git, dir, env, timeoutMs, reuseMs) {
    const key = probeCacheKey(git, dir, env);
    return cachedProbe(key, reuseMs) ?? rememberProbe(key, probeSyncUncached(git, dir, env, timeoutMs));
}
async function probeAsync(git, dir, env, timeoutMs, reuseMs) {
    const key = probeCacheKey(git, dir, env);
    return cachedProbe(key, reuseMs) ?? rememberProbe(key, await probeAsyncUncached(git, dir, env, timeoutMs));
}
function probeSyncUncached(git, dir, env, timeoutMs) {
    const r = spawnSync(git, probeArgs(dir), {
        env,
        timeout: timeoutMs,
        maxBuffer: PROBE_MAX_BYTES,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
    });
    if (r.error !== undefined)
        return probeError(r.error, dir, timeoutMs);
    return interpretExit(r.status, Buffer.isBuffer(r.stdout) ? r.stdout : Buffer.alloc(0), String(r.stderr ?? ''), dir);
}
async function probeAsyncUncached(git, dir, env, timeoutMs) {
    const r = await collect(git, probeArgs(dir), { env, timeoutMs, maxBuffer: PROBE_MAX_BYTES });
    if (r.error !== undefined)
        return probeError(r.error, dir, timeoutMs);
    return interpretExit(r.status, r.stdout, r.stderr.toString('utf8'), dir);
}
function probeError(error, dir, timeoutMs) {
    if (error.code === 'ENOENT')
        return { kind: 'none' };
    if (error.code === 'ETIMEDOUT') {
        return { kind: 'refused', message: `reading the git configuration of ${dir} took longer than ${timeoutMs} ms` };
    }
    if (error.code === 'ENOBUFS') {
        return { kind: 'refused', message: `the git configuration of ${dir} is larger than ${PROBE_MAX_BYTES} bytes of command settings` };
    }
    return { kind: 'refused', message: `could not read the git configuration of ${dir}: ${error.message}` };
}
/**
 * `base` with `safety` applied: its overrides appended after the user's own
 * `GIT_CONFIG_COUNT` entries, and its variables set. A `GIT_CONFIG_COUNT`
 * that is not a number makes every git die ("bogus count") — so the result
 * is left for git to refuse, never repaired.
 */
export function applyGitSafety(safety, base, platform = process.platform) {
    const env = { ...base };
    for (const [name, value] of Object.entries(safety.vars))
        setVar(env, name, value, platform);
    if (countProblem(env, platform) !== null)
        return env;
    const countName = Object.keys(env).find((name) => sameName(name, 'GIT_CONFIG_COUNT', platform));
    const trimmed = (countName === undefined ? '' : (env[countName] ?? '')).trim();
    let n = trimmed === '' ? 0 : Number(trimmed);
    for (const [key, value] of safety.config) {
        setVar(env, `GIT_CONFIG_KEY_${n}`, key, platform);
        setVar(env, `GIT_CONFIG_VALUE_${n}`, value, platform);
        n += 1;
    }
    setVar(env, countName ?? 'GIT_CONFIG_COUNT', String(n), platform);
    return env;
}
/**
 * `-e NAME=value` arguments for `docker run`: the same overrides for a git
 * inside a container, counted from zero (the container's environment is
 * dev-guardian's to write), with the container's own no-hooks path.
 */
export function dockerGitEnvArgs(safety) {
    const hooks = noHooksPath('linux');
    const config = safety.config.map(([k, v]) => (k === 'core.hooksPath' ? [k, hooks] : [k, v]));
    const args = [];
    config.forEach(([k, v], i) => {
        args.push('-e', `GIT_CONFIG_KEY_${i}=${k}`, '-e', `GIT_CONFIG_VALUE_${i}=${v}`);
    });
    args.push('-e', `GIT_CONFIG_COUNT=${config.length}`);
    for (const [name, value] of Object.entries(safety.vars))
        args.push('-e', `${name}=${value}`);
    return args;
}
/**
 * The `--receive-pack` for a push to a repository ON THIS MACHINE (a path, a
 * `file://` URL): `git -c <every override> receive-pack`. Git starts a local
 * transport's receive-pack with `GIT_CONFIG_COUNT` and `GIT_CONFIG_PARAMETERS`
 * REMOVED from its environment (git's `local_repo_env` — measured: the
 * destination's own hooks ran under a hardened push), so the environment
 * cannot reach it; its command line can — git runs it through its shell,
 * words quoted here. `safety` is for the destination repository
 * ({@link gitSafetyFor} of it). Null when a key cannot be written as a
 * `-c key=value` word (one holding `=`): the caller refuses the push.
 * Never for a network remote, whose receive-pack is the server's command.
 */
export function localReceivePackCommand(safety) {
    const words = [GIT_COMMAND];
    for (const [key, value] of safety.config) {
        if (key.includes('='))
            return null;
        words.push('-c', shellQuote(`${key}=${value}`));
    }
    words.push('receive-pack');
    return words.join(' ');
}
/** `note` wording for a result that read a repository with some of its own git configuration not applied. */
export function describeNotApplied(keys) {
    if (keys.length === 0)
        return null;
    const shown = keys.slice(0, 6).join(', ');
    const more = keys.length > 6 ? ` and ${keys.length - 6} more` : '';
    return (`the repository's own git configuration was not applied for ${shown}${more} — ` +
        'dev-guardian never runs a command a scanned repository configures (files were read as stored in git)');
}
const DEFAULT_MAX_BUFFER = 100_000_000;
const DEFAULT_TIMEOUT_MS = 60_000;
/** `git -C dir …args`, hardened for `dir`'s repository. Never throws. */
export async function execGit(dir, args, opts = {}) {
    const r = await execGitBuffer(dir, args, opts);
    return { ...r, stdout: r.stdout.toString('utf8') };
}
/** {@link execGit}, with stdout as bytes (`cat-file blob`). */
export async function execGitBuffer(dir, args, opts = {}) {
    const safety = await gitSafetyFor([dir, ...(opts.alsoRepos ?? [])], opts);
    if (safety.refused !== null)
        return refusedResult(safety, Buffer.alloc(0));
    const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const maxBuffer = opts.maxBuffer ?? DEFAULT_MAX_BUFFER;
    const r = await collect(opts.git ?? GIT_COMMAND, ['-C', dir, ...args], {
        env: applyGitSafety(safety, opts.env ?? process.env, opts.platform ?? process.platform),
        timeoutMs,
        maxBuffer,
    });
    return {
        status: r.error === undefined ? r.status : null,
        stdout: r.stdout,
        stderr: r.stderr.toString('utf8'),
        failure: r.error === undefined ? null : execFailure(r.error, timeoutMs, maxBuffer),
        notApplied: safety.notApplied,
    };
}
/** {@link execGit}, synchronously. */
export function execGitSync(dir, args, opts = {}) {
    const safety = gitSafetyForSync([dir, ...(opts.alsoRepos ?? [])], opts);
    if (safety.refused !== null)
        return refusedResult(safety, '');
    const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const maxBuffer = opts.maxBuffer ?? DEFAULT_MAX_BUFFER;
    const r = spawnSync(opts.git ?? GIT_COMMAND, ['-C', dir, ...args], {
        env: applyGitSafety(safety, opts.env ?? process.env, opts.platform ?? process.platform),
        encoding: 'utf8',
        timeout: timeoutMs,
        maxBuffer,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
    });
    return {
        status: r.error === undefined ? r.status : null,
        stdout: typeof r.stdout === 'string' ? r.stdout : '',
        stderr: typeof r.stderr === 'string' ? r.stderr : '',
        failure: r.error === undefined ? null : execFailure(r.error, timeoutMs, maxBuffer),
        notApplied: safety.notApplied,
    };
}
function refusedResult(safety, empty) {
    const message = `dev-guardian did not run git: ${safety.refused ?? ''}`;
    return { status: null, stdout: empty, stderr: message, failure: { code: 'refused', message }, notApplied: safety.notApplied };
}
function execFailure(error, timeoutMs, maxBuffer) {
    if (error.code === 'ENOENT')
        return { code: 'not-found', message: 'git is not installed' };
    if (error.code === 'ETIMEDOUT')
        return { code: 'timeout', message: `git took longer than ${timeoutMs} ms` };
    if (error.code === 'ENOBUFS')
        return { code: 'too-large', message: `git printed more than ${maxBuffer} bytes` };
    return { code: 'spawn', message: `git failed to run (${error.code ?? error.message})` };
}
/** spawn, collect both streams, kill on timeout or oversize; never rejects. */
function collect(command, args, opts) {
    return new Promise((resolveRun) => {
        let settled = false;
        const out = [];
        const err = [];
        let outBytes = 0;
        let errBytes = 0;
        let error;
        const finish = (status) => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timer);
            resolveRun({ status, stdout: Buffer.concat(out), stderr: Buffer.concat(err), ...(error !== undefined ? { error } : {}) });
        };
        const fail = (code, message) => {
            if (error === undefined)
                error = Object.assign(new Error(message), { code });
            child.kill('SIGKILL');
        };
        const child = spawn(command, args, { env: opts.env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
        const timer = setTimeout(() => fail('ETIMEDOUT', `timed out after ${opts.timeoutMs} ms`), opts.timeoutMs);
        child.stdout.on('data', (chunk) => {
            outBytes += chunk.length;
            if (outBytes > opts.maxBuffer)
                fail('ENOBUFS', 'stdout maxBuffer exceeded');
            else
                out.push(chunk);
        });
        child.stderr.on('data', (chunk) => {
            errBytes += chunk.length;
            if (errBytes <= 1024 * 1024)
                err.push(chunk);
        });
        child.on('error', (e) => {
            error ??= e;
            finish(null);
        });
        child.on('close', (code) => finish(code));
    });
}
function setVar(env, name, value, platform) {
    // Windows names are case-insensitive: a `Git_Config_Count` left beside a
    // `GIT_CONFIG_COUNT` gives the child two entries and no defined winner.
    for (const other of Object.keys(env))
        if (other !== name && sameName(other, name, platform))
            delete env[other];
    env[name] = value;
}
function envValue(env, name, platform = process.platform) {
    for (const key of Object.keys(env))
        if (sameName(key, name, platform))
            return env[key];
    return undefined;
}
function sameName(a, b, platform) {
    return platform === 'win32' ? a.toUpperCase() === b.toUpperCase() : a === b;
}
function firstLine(text) {
    return text.split(/\r?\n/).find((l) => l.trim().length > 0)?.trim() ?? '';
}
//# sourceMappingURL=gitSafety.js.map