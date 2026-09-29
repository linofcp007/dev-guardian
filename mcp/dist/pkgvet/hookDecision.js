/**
 * The PreToolUse hook's decision for one Bash/PowerShell command: deny,
 * warn, note, or stay silent. Kept here (compiled to `mcp/dist/pkgvet/`)
 * rather than in `hooks/guardian-hook.mjs` so it is unit-testable; the hook
 * itself only calls it and emits the answer.
 *
 *   - **deny** a malicious package, always; and a package the public
 *     registry does not have ONLY when the whole command, comments
 *     stripped, is ONE plain install statement with allowlisted flags
 *     (controller ruling, round 2 — `confidentShape` in `parseCommand.ts`;
 *     `InstallCommand.uncertain` is empty exactly then) AND no custom
 *     registry, npmjs auth token (scoped names) or local workspace package
 *     explains the 404 (`privateRegistry.ts`). Blocking a missing name buys
 *     little — the install would 404 anyway — and a false deny blocks real
 *     work. That deny carries an escape hatch ({@link escapeHatch}, named per
 *     tool and shell); a malicious one does not;
 *   - **warn** (additionalContext) on a missing name that was not denied
 *     ("not found on the public registry — if it is private or local,
 *     ignore this"), a version < 72 h old, install scripts, typosquat
 *     suspicion, an unpublished exact version, and known vulnerabilities
 *     only on an EXACT pin (for a range the installed version is unknown);
 *   - **note** — one line — for anything that could not be vetted (offline,
 *     timeout, HTTP error, rate limit). The command runs; the note says it
 *     was NOT verified, never that it was;
 *   - **silent** when every package came back `ok`, and for every command
 *     that installs nothing by name — which never touches the network.
 *
 * All network work shares one budget ({@link HOOK_BUDGET_MS}, 3 s): the
 * install commands of a compound line are vetted in parallel under it.
 */
import { parseInstallCommands } from './parseCommand.js';
import { loadPopularIndex } from './popular.js';
import { registryCache } from './privateRegistry.js';
import { buildPopularIndex, normalizePackageName } from './typosquat.js';
import { HOOK_BUDGET_MS, vetPackages } from './vet.js';
import { isExactVersion } from './versions.js';
/** The vetting deadline's default: well under Claude Code's 15 s hook timeout. */
export const DEFAULT_DEADLINE_MS = 8000;
/** The most `GUARDIAN_PKG_VET_DEADLINE_MS` may raise it to: past the hook's 15 s, the command runs with no verdict. */
const MAX_DEADLINE_MS = 14_000;
/**
 * The one deadline on a hook call's vetting (review I4), in ms from the start
 * of the call: `GUARDIAN_PKG_VET_DEADLINE_MS` (0-14000), else 8000. Local
 * work — reading registry configuration, walking a workspace — used to run
 * unbounded before the 3 s network budget: 17 packages in a 3000-directory
 * monorepo took 16.5 s, and Claude Code kills a hook at 15 s.
 */
export function vetDeadlineMs(env) {
    const raw = env['GUARDIAN_PKG_VET_DEADLINE_MS']?.trim();
    if (raw === undefined || !/^\d+$/.test(raw))
        return DEFAULT_DEADLINE_MS;
    return Math.min(Number(raw), MAX_DEADLINE_MS);
}
function label(r) {
    return r.version !== undefined ? `${r.name}@${r.version}` : r.name;
}
function firstLine(r) {
    return r.reasons[0] ?? 'no reason recorded';
}
/** The most packages one hook call looks up; the rest are named as not vetted. */
export const MAX_VETTED_PACKAGES = 50;
/** How much of a command is read for installs — the shell guard reads the same 512 KB. */
const MAX_PARSED_LENGTH = 512 * 1024;
/**
 * The install commands to vet, bounded (fix round 2): every package that
 * repeats one already seen (same ecosystem, name and range) is dropped, and
 * past {@link MAX_VETTED_PACKAGES} the rest are counted, not looked up — 60 KB
 * of `npm i x; ` once took ~57 s through the hook, past its 15 s timeout. A
 * command over 512 KB is read from its start only, and then no command may be
 * denied for a missing name: its last word may have been cut in half.
 */
function boundedInstalls(command, shell, isPopular) {
    const cut = command.length > MAX_PARSED_LENGTH;
    const parsed = parseInstallCommands(cut ? command.slice(0, MAX_PARSED_LENGTH) : command, { shell });
    const key = (pkg) => `${pkg.ecosystem}\0${pkg.name.toLowerCase()}\0${pkg.range ?? ''}`;
    const seen = new Set();
    const unique = [];
    for (const c of parsed) {
        for (const pkg of c.packages) {
            if (seen.has(key(pkg)))
                continue;
            seen.add(key(pkg));
            unique.push(pkg);
        }
    }
    // The names NOT on the popular list first (fix round 3): 50 popular names
    // in front of a malicious one must not push it past the cap.
    const chosen = new Set([...unique.filter((p) => !isPopular(p)), ...unique.filter(isPopular)].slice(0, MAX_VETTED_PACKAGES).map(key));
    const commands = [];
    for (const c of parsed) {
        const packages = c.packages.filter((pkg) => chosen.delete(key(pkg)));
        if (packages.length === 0)
            continue;
        const uncertain = cut ? [...c.uncertain, 'the command is over 512 KB and only its start was read'] : c.uncertain;
        commands.push({ ...c, packages, uncertain });
    }
    return { commands, notVetted: Math.max(0, unique.length - MAX_VETTED_PACKAGES), cut };
}
/** Whether a package is on its ecosystem's popular list — the lists `vet_packages` itself uses. */
function popularTest(opts) {
    const indexes = new Map();
    return (pkg) => {
        let index = indexes.get(pkg.ecosystem);
        if (index === undefined) {
            const override = opts.popular?.[pkg.ecosystem];
            index =
                override === null
                    ? null
                    : override !== undefined
                        ? buildPopularIndex(pkg.ecosystem, override)
                        : opts.popularDir === undefined
                            ? loadPopularIndex(pkg.ecosystem)
                            : loadPopularIndex(pkg.ecosystem, opts.popularDir);
            indexes.set(pkg.ecosystem, index);
        }
        return index !== null && index.set.has(normalizePackageName(pkg.ecosystem, pkg.name));
    };
}
/** The note for a command read only to its first 512 KB. */
const CUT_NOTE = 'dev-guardian: installs past the first 512 KB of this command were not looked for — not verified.';
/**
 * `null` when there is nothing to say: no install command, or every package
 * vetted clean.
 */
export async function decideInstallCommand(command, opts) {
    const shell = opts.shell ?? 'bash';
    const { commands, notVetted, cut } = boundedInstalls(command, shell, popularTest(opts));
    // A cut command whose start installs nothing still says what was not read.
    if (commands.length === 0)
        return cut ? { context: CUT_NOTE } : null;
    const env = opts.env ?? process.env;
    const offline = env['GUARDIAN_OFFLINE'] === '1';
    const budgetMs = opts.budgetMs ?? HOOK_BUDGET_MS;
    // One deadline for the whole call, and one cache, shared by every command
    // of the line (review I4).
    const deadlineAt = opts.deadlineAt ?? (opts.startedAt ?? Date.now()) + vetDeadlineMs(env);
    const cache = registryCache();
    const batches = await Promise.all(commands.map((c) => vetPackages(c.packages, {
        budgetMs,
        offline,
        deadlineAt,
        now: opts.now ?? Date.now(),
        registry: {
            projectDir: opts.cwd,
            homeDir: opts.homeDir,
            env,
            etcDir: opts.etcDir,
            platform: opts.platform,
            nodeExecPath: opts.nodeExecPath,
            systemLibraryDir: opts.systemLibraryDir,
            cache,
        },
        commandRegistries: c.registries,
        ...(opts.fetchImpl !== undefined ? { fetchImpl: opts.fetchImpl } : {}),
        ...(opts.popularDir !== undefined ? { popularDir: opts.popularDir } : {}),
        ...(opts.popular !== undefined ? { popular: opts.popular } : {}),
    })));
    const denies = [];
    const warnings = [];
    const unverified = [];
    let malicious = false;
    let missingIn;
    commands.forEach((cmd, i) => {
        for (const r of batches[i] ?? []) {
            const d = decideOne(r, cmd.uncertain);
            if (d.deny !== undefined)
                denies.push(d.deny);
            if (d.malicious === true)
                malicious = true;
            else if (d.deny !== undefined)
                missingIn = missingIn ?? cmd.manager;
            if (d.warn !== undefined)
                warnings.push(d.warn);
            if (d.unverified !== undefined)
                unverified.push(d.unverified);
        }
    });
    if (denies.length > 0) {
        return {
            deny: `dev-guardian blocked this install: ${denies.join(' ')} ` +
                'Check the package name against the project documentation or the registry before installing anything. ' +
                // Controller ruling (round 2): a missing-name deny carries its own
                // escape hatch — a registry flag, or an inline prefix, takes the
                // command out of the confident shape, so the agent can always
                // proceed. A MALICIOUS package gets no such hint.
                (malicious ? 'If this package is genuinely intended, ask the user to install it themselves.' : escapeHatch(missingIn ?? '', shell)),
        };
    }
    const lines = [];
    if (warnings.length > 0) {
        lines.push('⚠️ dev-guardian package vetting — review before relying on these:');
        for (const w of warnings)
            lines.push(`  • ${w}`);
    }
    if (unverified.length > 0)
        lines.push(`dev-guardian could not vet ${unverified.join(', ')} — not verified.`);
    if (notVetted > 0) {
        lines.push(`dev-guardian: ${notVetted} more packages in this command were not vetted (only the first ${MAX_VETTED_PACKAGES} are) — not verified.`);
    }
    if (cut)
        lines.push(CUT_NOTE);
    return lines.length > 0 ? { context: lines.join('\n') } : null;
}
const NOT_FOUND = 'not found on the public registry — if it is private or local, ignore this.';
/** The flag that names a registry, per package manager (`InstallCommand.manager`). */
const REGISTRY_FLAG = {
    npm: '`--registry <url>`',
    pnpm: '`--registry <url>`',
    bun: '`--registry <url>`',
    pip: '`--index-url <url>`',
    'uv-pip': '`--index-url <url>`',
    uv: '`--index <url>`',
    poetry: '`--source <name>`',
    dotnet: '`--source <url>`',
};
/** Tools with no registry flag to name one with (Yarn classic has one, Berry has not; neither form can be told apart here). */
const NO_REGISTRY_FLAG = {
    yarn: 'Yarn Berry has no registry flag',
    composer: 'composer has no registry flag',
};
/**
 * The missing-name deny's own escape hatch (controller ruling, round 2): a way
 * to re-run the install that takes it out of the plain shape, so the agent can
 * always proceed. It names what the tool really has — a registry flag, or
 * (composer, Yarn Berry) none — and an inline `GUARDIAN_PKG_VET=0`, spelled
 * for the shell: a `VAR=x` prefix for bash, `$env:` for PowerShell. Neither
 * touches the hook's own switch; a malicious version is still denied.
 */
export function escapeHatch(manager, shell = 'bash') {
    const prefix = shell === 'powershell'
        ? "run `$env:GUARDIAN_PKG_VET = '0'` before it, in the same command"
        : 'prefix the command with `GUARDIAN_PKG_VET=0`';
    const flag = REGISTRY_FLAG[manager];
    if (flag !== undefined)
        return `If this package is private or local, re-run the install with an explicit ${flag}, or ${prefix}.`;
    const none = NO_REGISTRY_FLAG[manager];
    return `If this package is private or local, ${prefix}${none !== undefined ? ` (${none})` : ''}.`;
}
const CHECK_KEYS = [
    'exists',
    'malicious',
    'vulnerabilities',
    'publish_age',
    'install_scripts',
    'typosquat',
];
function sentence(text) {
    return /[.?!]$/.test(text) ? text : `${text}.`;
}
/**
 * One package's contribution to the hook's answer.
 *
 *   - malicious (OSV `MAL-` on the version, npm takedown placeholder) → deny, always;
 *   - missing from the public registry → deny ONLY when the vetting found
 *     nothing to explain it (it is `block`, not `unknown`) AND the command
 *     has the confident shape (`uncertain` is empty); otherwise the ruling's
 *     "not found … ignore this" warning, with the reason;
 *   - every other `warn` check, except known vulnerabilities on a version
 *     the user did not pin exactly (M4: for a range or a bare name the
 *     installed version is not known here — the tool still reports them);
 *   - checks that could not run → the one-line "not verified" note.
 */
function decideOne(r, uncertain) {
    if (r.checks.malicious.status === 'fail') {
        const why = Object.values(r.checks)
            .filter((c) => c.status === 'fail' && c.detail !== undefined)
            .map((c) => c.detail ?? '')
            .join('; ');
        return { deny: `'${label(r)}': ${sentence(why)}`, malicious: true };
    }
    if (r.not_on_public_registry === true) {
        if (r.verdict === 'block' && uncertain.length === 0) {
            return { deny: `'${label(r)}': ${sentence(r.checks.exists.detail ?? firstLine(r))}` };
        }
        const didYouMean = r.similar_to !== undefined ? ` Did you mean '${r.similar_to}'?` : '';
        const why = r.verdict === 'block' ? `not denied: ${uncertain.join('; ')}` : (r.checks.exists.detail ?? '');
        return { warn: `'${label(r)}': ${NOT_FOUND}${didYouMean} (${why})` };
    }
    const pinned = isExactVersion(r.ecosystem, r.requested);
    const warns = CHECK_KEYS.filter((key) => key !== 'vulnerabilities' || pinned)
        .map((key) => r.checks[key])
        .filter((c) => c.status === 'warn' && c.detail !== undefined)
        .map((c) => c.detail ?? '');
    if (r.requested_version_unpublished === true) {
        warns.push(`requested version ${r.requested ?? ''} is not published — possibly a hallucinated version`);
    }
    if (warns.length > 0)
        return { warn: `${label(r)}: ${warns.slice(0, 3).join('; ')}` };
    const unknownCheck = Object.values(r.checks).find((c) => c.status === 'unknown' && c.detail !== undefined);
    if (unknownCheck !== undefined)
        return { unverified: `${label(r)} (${unknownCheck.detail ?? ''})` };
    return {};
}
//# sourceMappingURL=hookDecision.js.map