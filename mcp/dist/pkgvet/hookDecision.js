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
 *     work. That deny carries an escape hatch ({@link ESCAPE_HATCH}); a
 *     malicious one does not;
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
import { HOOK_BUDGET_MS, vetPackages } from './vet.js';
import { isExactVersion } from './versions.js';
function label(r) {
    return r.version !== undefined ? `${r.name}@${r.version}` : r.name;
}
function firstLine(r) {
    return r.reasons[0] ?? 'no reason recorded';
}
/**
 * `null` when there is nothing to say: no install command, or every package
 * vetted clean.
 */
export async function decideInstallCommand(command, opts) {
    const commands = parseInstallCommands(command).filter((c) => c.packages.length > 0);
    if (commands.length === 0)
        return null;
    const env = opts.env ?? process.env;
    const offline = env['GUARDIAN_OFFLINE'] === '1';
    const budgetMs = opts.budgetMs ?? HOOK_BUDGET_MS;
    const batches = await Promise.all(commands.map((c) => vetPackages(c.packages, {
        budgetMs,
        offline,
        now: opts.now ?? Date.now(),
        registry: {
            projectDir: opts.cwd,
            homeDir: opts.homeDir,
            env,
            etcDir: opts.etcDir,
            platform: opts.platform,
            nodeExecPath: opts.nodeExecPath,
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
    commands.forEach((cmd, i) => {
        for (const r of batches[i] ?? []) {
            const d = decideOne(r, cmd.uncertain);
            if (d.deny !== undefined)
                denies.push(d.deny);
            if (d.malicious === true)
                malicious = true;
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
                // escape hatch — an explicit registry flag takes the command out of
                // the confident shape, so the agent can always proceed. A MALICIOUS
                // package gets no such hint.
                (malicious ? 'If this package is genuinely intended, ask the user to install it themselves.' : ESCAPE_HATCH),
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
    return lines.length > 0 ? { context: lines.join('\n') } : null;
}
const NOT_FOUND = 'not found on the public registry — if it is private or local, ignore this.';
export const ESCAPE_HATCH = 'If this package is private or local, re-run the install with an explicit --registry / --index-url / --source, or set GUARDIAN_PKG_VET=0.';
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