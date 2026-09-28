/**
 * cosign checks of a container image's supply chain, for `scan_containers`.
 *
 * Two different questions, never confused with each other:
 *
 *   - **verify** (a signer identity AND an OIDC issuer were given): a real
 *     `cosign verify` — the signature is checked against Sigstore's trust
 *     root and the certificate's identity against the one named. A rejection
 *     is a high finding (`cosign-verify` / `image-signature-not-verified`).
 *     The run records the signer (`ToolRun.signer`): a rejection for one
 *     signer is re-measured only by a verification for the same one.
 *   - **detect** (no signer given): only whether a signature and a signed
 *     SLSA provenance attestation EXIST. Absence is a low (`image-unsigned`)
 *     or info (`image-no-provenance`) finding. A signature that exists is
 *     `present_unverified`: anyone can sign an image, so its existence says
 *     nothing about WHO signed it, and the answer says so.
 *
 * ---- What cosign cannot be taken at its word on (measured, v3.1.3) ----
 *
 * cosign swallows some registry failures and prints the same thing it
 * prints for "nothing there". Measured against the fake registry in
 * `test/helpers/fakeOciRegistry.ts`, with a failure injected:
 *
 *   - `cosign tree` ignores any error but 404 on the legacy `.sig` / `.att`
 *     tags: a `.sig` answering 500 prints "No Supply Chain Security Related
 *     Artifacts found", exit 0, nothing on stderr (cli/tree.go, the
 *     `if err == nil` around each legacy fetch). Its referrers call fails
 *     loudly ("getting referrers", exit 1); a referrer it cannot fetch is a
 *     line on stderr and the listing goes on without it.
 *   - `cosign download signature` / `download attestation` try the bundles
 *     first and ignore a failure there (`if err == nil && len > 0`), then
 *     read the legacy tag — which fails loudly ("remote image: GET …").
 *   - `cosign verify` falls back to legacy signatures when the referrers
 *     call fails, or when a bundle does not parse, and then says "no
 *     signatures found", exit 10 — for an image signed with a v3 bundle.
 *   - `cosign verify`'s exit 12 ("no matching signatures") joins ONE error
 *     per signature (pkg/cosign/verify.go, `strings.Join(…, "\n ")`), a
 *     transient failure on the expected signer's signature included.
 *
 * So nothing here is "absent" or "rejected" on one call's word:
 *
 *   - a signature is absent only when `tree` (loud on referrers) lists none
 *     AND `download signature` (loud on the `.sig` tag) says "no signatures
 *     associated"; provenance only when `tree` lists no SLSA referrer AND
 *     `download attestation` (loud on the `.att` tag) finds neither v1 nor
 *     v0.2;
 *   - verify's "no signatures found" is a rejection only when those same two
 *     calls agree there is none; exit 12, 13 or 1 only when every error it
 *     folded is a verdict about the signature (another identity or issuer,
 *     no certificate, a signature or log entry that does not verify) and
 *     none is a network or registry failure.
 *
 * Everything else is `unknown` and the check `failed` — never a pass.
 *
 * ---- The image cosign checks ----
 *
 * `cosign triangulate --type digest` pins the tag to a digest first, and
 * every later call checks that digest: without it each call resolved the
 * tag on its own, and a tag that moved between two calls made them disagree
 * about two images. The response names the digest. Trivy resolves the tag
 * separately, and on a multi-arch index this is the index's digest — a
 * signature on the per-platform images only reads as absent; both are said.
 * `triangulate` is deprecated and goes in cosign 4: without it the checks
 * run on the tag, and the answer says the digest was not pinned.
 *
 * cosign older than 3.0 is not used at all: its `tree` does not list OCI
 * referrers unless asked (`--experimental-oci11`), and every v3 signature
 * and every GitHub build-provenance attestation is one — measured: cosign
 * 2.6.5 on a signed `ghcr.io/sigstore/cosign/cosign:v3.1.3` prints "No …
 * Artifacts found", exit 0.
 */
import { compareSemver } from '../platform/semverCompare.js';
import { runProcess } from './processRunner.js';
import { makeFinding } from './scannerParsers/index.js';
import { extractVersion } from './toolProbe.js';
/** Findings of a real `cosign verify`. */
export const COSIGN_VERIFY_TOOL_NAME = 'cosign-verify';
/** Findings of the existence check (`cosign tree` + the downloads). */
export const COSIGN_TREE_TOOL_NAME = 'cosign-tree';
/** Each cosign call's own budget; cosign's own default `--timeout` is 3 min too. */
export const COSIGN_TIMEOUT_MS = 180_000;
/** The oldest cosign whose `tree` lists OCI referrers by default. */
export const COSIGN_MIN_VERSION = '3.0.0';
/** Whether this cosign can be used — see the module comment for why 2.x cannot. */
export function readinessFromProbe(r) {
    if (r.outcome !== 'completed') {
        return { ok: false, status: 'failed', reason: `\`cosign version\` did not complete: ${firstError(r.stderr) ?? r.outcome.replace(/_/g, ' ')}` };
    }
    const version = extractVersion(`${r.stdout}\n${r.stderr}`);
    if (version === null)
        return { ok: false, status: 'failed', reason: '`cosign version` printed no version this can read' };
    const cmp = compareSemver(version, COSIGN_MIN_VERSION);
    if (cmp === null || cmp < 0) {
        return {
            ok: false,
            status: 'skipped',
            reason: `outdated: cosign ${version} is older than ${COSIGN_MIN_VERSION} — its \`cosign tree\` does not list OCI ` +
                'referrers, where every cosign v3 signature and every GitHub provenance attestation lives, so it would ' +
                'report a signed image as unsigned. Install cosign 3 (install_toolchain { tools: ["cosign"] }).',
        };
    }
    return { ok: true, version };
}
const DIGEST_REF = /^(\S+)@(sha256:[0-9a-f]{64})$/;
export function classifyTriangulate(r) {
    if (r.outcome === 'completed') {
        const m = DIGEST_REF.exec(r.stdout.trim());
        if (m?.[2] !== undefined)
            return { kind: 'digest', ref: m[0], digest: m[2] };
        return { kind: 'error', detail: 'cosign triangulate printed no digest reference' };
    }
    if (/unknown command "triangulate"/.test(r.stderr)) {
        return {
            kind: 'tag_only',
            reason: 'this cosign has no `triangulate` (removed in cosign 4), so the digest was not pinned: each call resolved the tag itself',
        };
    }
    return { kind: 'error', detail: firstError(r.stderr) ?? `cosign triangulate ${r.outcome.replace(/_/g, ' ')}` };
}
/** Signing bundles and cosign's own OCI 1.1 signature artifacts. */
const SIGNATURE_TYPES = new Set([
    'https://sigstore.dev/cosign/sign/v1',
    'application/vnd.dev.cosign.artifact.sig.v1+json',
]);
/** What `cosign verify` prints as `critical.type` for an image signature, legacy or v3. */
const VERIFIED_SIGNATURE_TYPES = new Set(['cosign container image signature', 'https://sigstore.dev/cosign/sign/v1']);
/** SLSA provenance, any version (`https://slsa.dev/provenance/v0.2`, `…/v1`). */
const PROVENANCE_TYPE = /^https:\/\/slsa\.dev\/provenance\//;
/** `cosign tree` prints a bundle's predicate-type annotation, and predicate types are URIs. */
const PREDICATE_TYPE = /^https?:\/\//;
const BUNDLE_TYPE = /^application\/vnd\.dev\.sigstore\.bundle/;
/** The predicate types `download attestation` is asked for, newest first. */
export const PROVENANCE_PREDICATE_TYPES = ['https://slsa.dev/provenance/v1', 'https://slsa.dev/provenance/v0.2'];
const TREE_HEADER = /Supply Chain Security Related artifacts for an image:/;
const TREE_NONE = /No Supply Chain Security Related Artifacts found for image/;
const TREE_SIGNATURES = /Signatures for an image tag:/;
const TREE_ATTESTATIONS = /Attestations for an image tag:/;
const TREE_SBOMS = /SBOMs for an image tag:/;
const TREE_REFERRER = /(\S+) artifacts via OCI referrer:/;
const TREE_FETCH_ERROR = /^Error fetching (?:artifact|layers for artifact) /;
/**
 * `cosign tree`'s listing, or null when it is not one: no header, or a
 * header with neither an artifact line nor cosign's "nothing found" line
 * after it (cosign stopped part-way, or printed a format this was not
 * written for).
 */
export function parseCosignTree(stdout, stderr) {
    const lines = stdout.split(/\r?\n/);
    if (!lines.some((l) => TREE_HEADER.test(l)))
        return null;
    const listing = {
        signature: false,
        legacyAttestations: false,
        referrerTypes: [],
        attestationBundleTypes: [],
        ambiguousBundles: false,
        fetchErrors: stderr.split(/\r?\n/).filter((l) => TREE_FETCH_ERROR.test(l.trim())),
    };
    let recognised = false;
    for (const line of lines) {
        if (TREE_NONE.test(line)) {
            recognised = true;
        }
        else if (TREE_SIGNATURES.test(line)) {
            recognised = true;
            listing.signature = true;
        }
        else if (TREE_ATTESTATIONS.test(line)) {
            recognised = true;
            listing.legacyAttestations = true;
        }
        else if (TREE_SBOMS.test(line)) {
            recognised = true;
        }
        else {
            const type = TREE_REFERRER.exec(line)?.[1];
            if (type === undefined)
                continue;
            recognised = true;
            listing.referrerTypes.push(type);
            if (SIGNATURE_TYPES.has(type))
                listing.signature = true;
            else if (BUNDLE_TYPE.test(type))
                listing.ambiguousBundles = true;
            else if (PREDICATE_TYPE.test(type) && !listing.attestationBundleTypes.includes(type))
                listing.attestationBundleTypes.push(type);
        }
    }
    return recognised ? listing : null;
}
/** An incomplete listing: a referrer cosign could not fetch, or a bundle it could not classify. */
function incomplete(tree) {
    return tree.fetchErrors.length > 0 || tree.ambiguousBundles;
}
/**
 * What the listing says about an image signature: `present`; `attestation_only`
 * (no `cosign sign`, but a signed attestation `cosign verify` would accept);
 * `unknown` (the listing is incomplete); or `confirm` — it lists none, which
 * `cosign tree` also prints when the `.sig` tag failed, so a loud call decides.
 */
export function signatureFromTree(tree) {
    if (tree.signature)
        return 'present';
    if (incomplete(tree))
        return 'unknown';
    if (tree.attestationBundleTypes.length > 0)
        return 'attestation_only';
    return 'confirm';
}
/** `present` when a SLSA provenance referrer is listed; otherwise `confirm` (the `.att` tag and v0.2/v1 need reading). */
export function provenanceFromTree(tree) {
    return tree.referrerTypes.some((t) => PROVENANCE_TYPE.test(t)) ? 'present' : 'confirm';
}
// ---------------------------------------------------------------------------
// The loud calls: `download signature`, `download attestation`
// ---------------------------------------------------------------------------
/** `cosign download signature`: output is a signature; "no signatures associated" is none; anything else did not answer. */
export function classifySignatureDownload(r) {
    if (r.outcome === 'output_too_large')
        return 'present';
    if (r.outcome === 'completed')
        return r.stdout.trim().length > 0 ? 'present' : 'unknown';
    if (r.outcome === 'failed' && /no signatures associated/.test(r.stderr))
        return 'absent';
    return 'unknown';
}
/**
 * One `cosign download attestation --predicate-type=<type>`. cosign prints
 * only attestations of that type, so any output — even past the stdout cap —
 * means one exists; its own "no attestations with predicate type" error means
 * none does. Anything else did not answer.
 */
export function classifyAttestationDownload(r) {
    if (r.outcome === 'output_too_large')
        return 'present';
    if (r.outcome === 'completed')
        return r.stdout.trim().length > 0 ? 'present' : 'unknown';
    if (r.outcome === 'failed' && /no attestations with predicate type/.test(r.stderr))
        return 'absent';
    return 'unknown';
}
/** Another identity or issuer than the one asked for. */
const IDENTITY_MISMATCH = /none of the expected identities matched|no matching CertificateIdentity found|expected (?:SAN|issuer) value/;
/** A verdict about the signature itself — the same on every retry. */
const SIGNATURE_VERDICT = new RegExp([
    IDENTITY_MISMATCH.source,
    'no certificate found on signature',
    'transparency log certificate does not match',
    'failed to verify log inclusion',
    'invalid signature',
    'signature verification failed',
    'failed to verify signature',
].join('|'));
/** A network, registry or Sigstore-service failure — the question was not answered. */
const TRANSIENT = /dial tcp|i\/o timeout|timeout|deadline exceeded|connection (?:reset|refused)|\bEOF\b|TLS handshake|TOOMANYREQUESTS|too many requests|UNKNOWN:|UNAVAILABLE|unexpected status|status code|no such host|temporar|rate limit|GET https?:|remote image|fetching |getting |setting up clients/i;
const BAD_REGEXP = /error parsing regexp/;
/**
 * The errors cosign folded into one "no matching …" message: the lines of
 * its first `Error:` block, prefix removed — one per signature or bundle
 * (a multi-line error contributes several lines, each judged on its own).
 */
function foldedErrors(stderr) {
    const lines = stderr.split(/\r?\n/);
    const start = lines.findIndex((l) => l.startsWith('Error: '));
    if (start < 0)
        return [];
    const block = [];
    for (let i = start; i < lines.length; i++) {
        const line = lines[i] ?? '';
        if (i > start && (line.startsWith('error during command execution:') || line.startsWith('Error: ')))
            break;
        const text = (i === start ? line.slice('Error: '.length) : line)
            .replace(/^\s*no matching (?:signatures|attestations):\s*/, '')
            .trim();
        if (text.length > 0)
            block.push(text);
    }
    return block;
}
/** How a `cosign verify` ended — see the module comment for what each exit can hide. */
export function classifyVerify(r) {
    if (r.outcome === 'completed')
        return { verdict: 'verified', ...verifiedPayloads(r.stdout) };
    if (r.outcome !== 'failed')
        return { verdict: 'error', detail: `cosign verify ${r.outcome.replace(/_/g, ' ')}` };
    const detail = firstError(r.stderr) ?? `cosign verify exited ${r.exitCode ?? '(no exit code)'}`;
    if (r.exitCode === 10)
        return { verdict: 'no_signature_claimed', detail };
    const folded = foldedErrors(r.stderr);
    const judged = folded.length > 0 &&
        !BAD_REGEXP.test(r.stderr) &&
        folded.every((e) => SIGNATURE_VERDICT.test(e) && !TRANSIENT.test(e.replace(/got subjects \[[^\]]*\]/, '')));
    if (!judged)
        return { verdict: 'error', detail };
    if (r.exitCode === 13 || folded.every((e) => /no certificate found on signature/.test(e))) {
        return { verdict: 'rejected', reason: 'no_certificate', detail };
    }
    if ((r.exitCode === 12 || r.exitCode === 1) && folded.some((e) => IDENTITY_MISMATCH.test(e))) {
        const mismatch = folded.find((e) => IDENTITY_MISMATCH.test(e)) ?? detail;
        return { verdict: 'rejected', reason: 'no_matching_signature', detail: clip(r.exitCode === 1 ? mismatch : detail) };
    }
    return { verdict: 'error', detail };
}
/** What `cosign verify` accepted (`critical.type` of each payload) and over which digest. */
function verifiedPayloads(stdout) {
    const types = [];
    let digest;
    let parsed;
    try {
        // One JSON array on one line; cosign may print a blank line first.
        parsed = JSON.parse(stdout.split(/\r?\n/).find((l) => l.trimStart().startsWith('[')) ?? '');
    }
    catch {
        return { types };
    }
    if (!Array.isArray(parsed))
        return { types };
    for (const item of parsed) {
        const critical = isRecord(item) && isRecord(item['critical']) ? item['critical'] : null;
        if (critical === null)
            continue;
        const type = critical['type'];
        if (typeof type === 'string' && !types.includes(type))
            types.push(type);
        const image = critical['image'];
        const d = isRecord(image) ? image['docker-manifest-digest'] : undefined;
        if (typeof d === 'string' && digest === undefined)
            digest = d;
    }
    return digest !== undefined ? { types, digest } : { types };
}
function isRecord(v) {
    return typeof v === 'object' && v !== null && !Array.isArray(v);
}
/**
 * `cosign verify`'s argv. Each value is passed inside its own flag
 * (`--certificate-identity=<value>`), so no value can be read as another
 * option whatever it starts with; the reference is last.
 */
export function verifyArgs(ref, policy) {
    const args = ['verify'];
    if (policy.identity !== undefined)
        args.push(`--certificate-identity=${policy.identity}`);
    if (policy.identityRegexp !== undefined)
        args.push(`--certificate-identity-regexp=${policy.identityRegexp}`);
    if (policy.issuer !== undefined)
        args.push(`--certificate-oidc-issuer=${policy.issuer}`);
    if (policy.issuerRegexp !== undefined)
        args.push(`--certificate-oidc-issuer-regexp=${policy.issuerRegexp}`);
    args.push(ref);
    return args;
}
/**
 * The signer, one spelling per policy: JSON of the fields given, in a fixed
 * order. Recorded as `ToolRun.signer` and part of a verification's target —
 * JSON, not `key=value` joined by a separator, so no value can forge the
 * boundary between two fields.
 */
export function canonicalSignerPolicy(policy) {
    const out = {};
    if (policy.identity !== undefined)
        out['identity'] = policy.identity;
    if (policy.identityRegexp !== undefined)
        out['identity_regexp'] = policy.identityRegexp;
    if (policy.issuer !== undefined)
        out['issuer'] = policy.issuer;
    if (policy.issuerRegexp !== undefined)
        out['issuer_regexp'] = policy.issuerRegexp;
    return JSON.stringify(out);
}
/**
 * A warning for each signer regexp not anchored at both ends. cosign matches
 * a regexp anywhere in the certificate's value (Go RE2 `MatchString`), so
 * `https://github.com/org/app/` also accepts
 * `https://github.com/attacker/x/.github/workflows/y.yml@refs/heads/https://github.com/org/app/`
 * — a branch name is the attacker's to choose.
 */
export function unanchoredSignerRegexps(policy) {
    const anchored = (re) => re.startsWith('^') && (/(?<!\\)\$$/.test(re) || re.endsWith('\\z'));
    const out = [];
    for (const [field, re] of [
        ['signer_identity_regexp', policy.identityRegexp],
        ['signer_issuer_regexp', policy.issuerRegexp],
    ]) {
        if (re === undefined || anchored(re))
            continue;
        out.push(`${field} ${JSON.stringify(re)} is not anchored (^…$): cosign accepts any certificate whose value merely ` +
            'CONTAINS a match — a workflow in another repository, on a branch named to include it, passes. Anchor it ' +
            'at both ends.');
    }
    return out;
}
/** The first `Error: …` line cosign printed, without the prefix, bounded. */
function firstError(stderr) {
    for (const raw of stderr.split(/\r?\n/)) {
        const line = raw.trim();
        if (line.startsWith('Error: '))
            return clip(line.slice('Error: '.length));
    }
    const first = stderr
        .split(/\r?\n/)
        .map((l) => l.trim())
        .find((l) => l.length > 0 && !l.startsWith('Command "triangulate" is deprecated'));
    return first === undefined ? null : clip(first);
}
function clip(text) {
    return text.length > 400 ? `${text.slice(0, 399)}…` : text;
}
/** What to do about an unverified signature — the same words everywhere. */
export const UNVERIFIED_NOTE = 'A signature exists, but its signer was NOT verified: anyone can sign an image. Pass signer_identity ' +
    '(or signer_identity_regexp) and signer_issuer (or signer_issuer_regexp) to verify who signed it.';
/** Why an image cosign cannot find is often not a typo. */
const REGISTRY_ONLY_NOTE = 'cosign reads the image and its signatures from the registry, never from the local Docker daemon: an image ' +
    'built locally and never pushed cannot be checked (push it, or scan the pushed reference).';
/** The response's summary when cosign did not run at all. */
export function skippedSummary(image, reason) {
    return { image, checked: null, check: 'skipped', signature: 'unknown', provenance: 'unknown', note: `Not checked: ${reason}.` };
}
async function cosign(args, ctx) {
    return runProcess({
        command: 'cosign',
        args,
        cwd: ctx.cwd,
        env: ctx.env,
        timeoutMs: COSIGN_TIMEOUT_MS,
        ...(ctx.signal !== undefined ? { signal: ctx.signal } : {}),
        ...(ctx.onLog !== undefined ? { onLog: ctx.onLog } : {}),
    });
}
/** Whether this cosign can be used (`cosign version`) — see {@link readinessFromProbe}. */
export async function cosignReadiness(ctx) {
    return readinessFromProbe(await cosign(['version'], ctx));
}
/**
 * Pins `image` to a digest (`triangulate`), or explains why it could not:
 * the tag-only fallback, or — when the registry has no such image — the
 * failed check, returned as such.
 */
async function pin(image, pass, ctx, extra) {
    const r = await cosign(['triangulate', '--type', 'digest', image], ctx);
    const res = classifyTriangulate(r);
    if (res.kind === 'digest') {
        return {
            ref: res.ref,
            checked: res.ref,
            scope: `cosign checked ${res.ref}, the digest the tag named when this scan pinned it; Trivy resolved the tag on ` +
                'its own, so if the tag moved in between they looked at different images. On a multi-arch index this is ' +
                "the index's digest: a signature on the per-platform images only reads as unsigned.",
        };
    }
    if (res.kind === 'tag_only') {
        return {
            ref: image,
            checked: null,
            scope: `The digest was not pinned: ${res.reason}. On a multi-arch index a signature on the per-platform images only reads as unsigned.`,
        };
    }
    const why = `cosign could not find it in its registry — ${res.detail}. ${REGISTRY_ONLY_NOTE}`;
    return {
        // Each name spelled out: history/runNames.test.ts reads bookkeeping names from the source.
        run: pass === 'cosign-verify'
            ? { name: 'cosign-verify', status: 'failed', reason: `image ${image}: ${why}`, target: image, ...extra }
            : { name: 'cosign-tree', status: 'failed', reason: `image ${image}: ${why}`, target: image, ...extra },
        findings: [],
        summary: {
            image,
            checked: null,
            check: pass === 'cosign-verify' ? 'verify' : 'detect',
            signature: 'unknown',
            provenance: pass === 'cosign-verify' ? 'not_checked' : 'unknown',
            note: `Not checked: ${why}`,
        },
        cancelled: r.outcome === 'cancelled',
    };
}
function isCheck(p) {
    return 'run' in p;
}
/** `cosign tree` then, when it lists nothing, `cosign download signature`. */
async function signatureEvidence(ref, ctx) {
    const treeRun = await cosign(['tree', ref], ctx);
    const tree = treeRun.outcome === 'completed' ? parseCosignTree(treeRun.stdout, treeRun.stderr) : null;
    if (tree === null) {
        const why = treeRun.outcome === 'completed'
            ? 'its output was not a listing this version of dev-guardian can read'
            : (firstError(treeRun.stderr) ?? `cosign tree ${treeRun.outcome.replace(/_/g, ' ')}`);
        return { state: 'unknown', attestationTypes: [], tree: null, treeWhy: why, why: `cosign tree did not complete — ${why}`, cancelled: treeRun.outcome === 'cancelled' };
    }
    const fromTree = signatureFromTree(tree);
    const base = { attestationTypes: tree.attestationBundleTypes, tree };
    if (fromTree === 'present' || fromTree === 'attestation_only')
        return { ...base, state: fromTree, cancelled: false };
    if (fromTree === 'unknown') {
        const why = tree.fetchErrors.length > 0 ? `cosign tree could not fetch ${tree.fetchErrors.length} referrer(s)` : 'cosign tree listed a Sigstore bundle of no known type';
        return { ...base, state: 'unknown', why, cancelled: false };
    }
    if (ctx.signal?.aborted === true)
        return { ...base, state: 'unknown', why: 'cancelled', cancelled: true };
    const dl = await cosign(['download', 'signature', ref], ctx);
    const answer = classifySignatureDownload(dl);
    if (answer === 'unknown') {
        return { ...base, state: 'unknown', why: `cosign download signature did not answer — ${firstError(dl.stderr) ?? dl.outcome}`, cancelled: dl.outcome === 'cancelled' };
    }
    return { ...base, state: answer, cancelled: false };
}
/** `cosign verify` of `image` against `policy`. */
export async function verifyImage(image, policy, ctx) {
    const signer = canonicalSignerPolicy(policy);
    const pinned = await pin(image, 'cosign-verify', ctx, { signer });
    if (isCheck(pinned))
        return pinned;
    const warnings = unanchoredSignerRegexps(policy);
    const r = await cosign(verifyArgs(pinned.ref, policy), ctx);
    let v = classifyVerify(r);
    let cancelled = r.outcome === 'cancelled';
    const who = describePolicy(policy);
    const run = (outcome, reason) => ({
        name: 'cosign-verify',
        status: outcome,
        reason: `image ${image} (${pinned.checked ?? 'tag not pinned'}): ${reason}`,
        target: image,
        signer,
    });
    const note = (text) => [text, pinned.scope, ...warnings].join(' ');
    // "no signatures found" is a rejection only when the loud calls agree.
    if (v.verdict === 'no_signature_claimed') {
        const claim = v.detail;
        const evidence = await signatureEvidence(pinned.ref, ctx);
        cancelled = cancelled || evidence.cancelled;
        if (evidence.state === 'absent') {
            v = { verdict: 'rejected', reason: 'no_signature', detail: claim };
        }
        else if (evidence.state === 'unknown') {
            v = { verdict: 'error', detail: `cosign verify said "${claim}", which could not be confirmed: ${evidence.why ?? 'unknown'}` };
        }
        else {
            const t = evidence.tree;
            const seen = t !== null && t.referrerTypes.length > 0
                ? `cosign tree lists ${t.referrerTypes.join(', ')}`
                : t?.signature === true
                    ? 'cosign tree lists a .sig signature'
                    : 'cosign download signature returns one';
            v = {
                verdict: 'error',
                detail: `cosign verify said "${claim}", but ${seen} — the registry answered the calls differently (a failed ` +
                    'referrers call makes verify fall back to legacy signatures, and so does a bundle it cannot parse); not a verdict',
            };
        }
    }
    if (v.verdict === 'verified') {
        const imageSignature = v.types.some((t) => VERIFIED_SIGNATURE_TYPES.has(t));
        const accepted = v.types.length === 0
            ? 'a signature'
            : imageSignature
                ? 'an image signature'
                : `a signed attestation (${v.types.join(', ')}), not a \`cosign sign\` signature — cosign verify accepts any Sigstore bundle over the digest from that signer`;
        return {
            run: run('ok', `signature verified for ${who} — cosign accepted ${accepted}`),
            findings: [],
            summary: {
                image,
                checked: pinned.checked,
                check: 'verify',
                signature: 'verified',
                verified_as: v.types,
                provenance: 'not_checked',
                note: note(`cosign verify accepted ${accepted}, by ${who}, checked against Sigstore's trust root. Provenance is not checked when a signer is given.`),
            },
            cancelled,
        };
    }
    if (v.verdict !== 'rejected') {
        return {
            run: run('failed', `cosign verify did not reach a verdict — ${v.detail}`),
            findings: [],
            summary: { image, checked: pinned.checked, check: 'verify', signature: 'unknown', provenance: 'not_checked', note: note(`Not verified: ${v.detail}.`) },
            cancelled,
        };
    }
    const title = v.reason === 'no_signature' ? `Image ${image} has no signature to verify` : `Image ${image} is not signed by the expected signer`;
    const finding = makeFinding({
        tool: COSIGN_VERIFY_TOOL_NAME,
        rule_id: 'image-signature-not-verified',
        severity: 'high',
        category: 'security',
        subcategory: 'supply-chain',
        title,
        message: `cosign verify rejected ${pinned.checked ?? image} for ${who}: ${v.detail}. Nothing shows this image was built ` +
            'and signed by the identity you expect — do not deploy it until it verifies (or correct signer_identity / ' +
            'signer_issuer if the image is legitimately signed by another workflow).',
        file_path: image,
        snippet: image,
        fix_available: false,
    });
    return {
        run: run('ok', `NOT verified for ${who} — ${v.detail}`),
        findings: [finding],
        summary: { image, checked: pinned.checked, check: 'verify', signature: 'rejected', provenance: 'not_checked', note: note(`Rejected: ${v.detail}.`) },
        cancelled,
    };
}
/** Whether `image` has a signature and signed SLSA provenance — existence only. */
export async function detectImageSupplyChain(image, ctx) {
    const pinned = await pin(image, 'cosign-tree', ctx, {});
    if (isCheck(pinned))
        return pinned;
    const sig = await signatureEvidence(pinned.ref, ctx);
    const tree = sig.tree;
    if (tree === null) {
        const why = sig.treeWhy ?? 'unknown';
        return {
            run: { name: 'cosign-tree', status: 'failed', reason: `image ${image} (${pinned.checked ?? 'tag not pinned'}): cosign tree did not complete — ${why}`, target: image },
            findings: [],
            summary: { image, checked: pinned.checked, check: 'detect', signature: 'unknown', provenance: 'unknown', note: `Not checked: cosign tree did not complete (${why}). ${pinned.scope}` },
            cancelled: sig.cancelled,
        };
    }
    let cancelled = sig.cancelled;
    let provenance = 'unknown';
    let provenanceWhy;
    if (provenanceFromTree(tree) === 'present') {
        provenance = 'present';
    }
    else if (!cancelled) {
        const answers = [];
        for (const type of PROVENANCE_PREDICATE_TYPES) {
            if (ctx.signal?.aborted === true) {
                cancelled = true;
                break;
            }
            const r = await cosign(['download', 'attestation', `--predicate-type=${type}`, pinned.ref], ctx);
            if (r.outcome === 'cancelled') {
                cancelled = true;
                break;
            }
            const answer = classifyAttestationDownload(r);
            answers.push(answer);
            if (answer === 'unknown')
                provenanceWhy = `cosign download attestation did not answer — ${firstError(r.stderr) ?? r.outcome}`;
            if (answer === 'present')
                break;
        }
        provenance = answers.includes('present')
            ? 'present'
            : answers.length === PROVENANCE_PREDICATE_TYPES.length && answers.every((a) => a === 'absent')
                ? 'absent'
                : 'unknown';
        // What the tree could not vouch for stays unknown whatever the download said.
        if (provenance === 'absent' && incomplete(tree)) {
            provenance = 'unknown';
            provenanceWhy = 'cosign tree could not list every referrer';
        }
        if (cancelled && provenance === 'unknown')
            provenanceWhy = 'cancelled';
    }
    const signature = sig.state;
    const findings = [];
    if (signature === 'absent') {
        const legacyProvenance = provenance === 'present'
            ? ' A signed SLSA provenance attestation IS attached as a legacy .att tag, which `cosign verify-attestation` checks — `cosign verify` does not accept it as the image\'s signature.'
            : ' Nothing ties it to who built it.';
        findings.push(makeFinding({
            tool: COSIGN_TREE_TOOL_NAME,
            rule_id: 'image-unsigned',
            severity: 'low',
            category: 'security',
            subcategory: 'supply-chain',
            title: `Image ${image} has no Sigstore signature`,
            message: `cosign found no signature for ${pinned.checked ?? image} — no .sig tag, no signing bundle and no signed ` +
                `attestation bundle attached as an OCI referrer, which is everything \`cosign verify\` accepts.${legacyProvenance} ` +
                'On a multi-arch index this is the index: a signature on the per-platform images only is not seen. Sign it ' +
                'in the pipeline that builds it (cosign sign, keyless), then verify it before deploying: scan_containers ' +
                'with signer_identity and signer_issuer.',
            file_path: image,
            snippet: image,
            fix_available: false,
        }));
    }
    if (provenance === 'absent') {
        findings.push(makeFinding({
            tool: COSIGN_TREE_TOOL_NAME,
            rule_id: 'image-no-provenance',
            severity: 'info',
            category: 'security',
            subcategory: 'supply-chain',
            title: `Image ${image} has no SLSA provenance attestation`,
            message: `No signed SLSA provenance attestation (https://slsa.dev/provenance/v0.2 or v1) was found for ${pinned.checked ?? image}, ` +
                'as a legacy .att tag or an OCI referrer, so there is no signed record of the source and build that ' +
                "produced it. BuildKit's unsigned provenance inside an image index is not counted. Generate one where the " +
                'image is built (actions/attest-build-provenance with push-to-registry, or cosign attest).',
            file_path: image,
            snippet: image,
            fix_available: false,
        }));
    }
    const complete = signature !== 'unknown' && provenance !== 'unknown';
    const sigWords = {
        present: 'signature present (signer NOT verified)',
        attestation_only: `no \`cosign sign\` signature, but a signed attestation (${sig.attestationTypes.join(', ')}) (signer NOT verified)`,
        absent: 'signature absent',
        unknown: `signature unknown (${sig.why ?? 'not answered'})`,
    };
    const provWords = {
        present: 'SLSA provenance present (signer NOT verified)',
        absent: 'SLSA provenance absent',
        unknown: `SLSA provenance unknown (${provenanceWhy ?? 'not answered'})`,
    };
    const notes = [];
    if (signature === 'present')
        notes.push(UNVERIFIED_NOTE);
    if (signature === 'attestation_only') {
        notes.push(`No \`cosign sign\` signature is attached, but a signed attestation is (${sig.attestationTypes.join(', ')}) — and ` +
            'cosign verify accepts a signed attestation over the digest as the image\'s signature, so a verification ' +
            'with its signer can pass. Its signer was NOT verified: pass signer_identity and signer_issuer.');
    }
    if (provenance === 'present' && signature !== 'attestation_only') {
        notes.push(signature === 'present' ? "The provenance attestation's signer was not verified either." : 'A SLSA provenance attestation exists, but its signer was NOT verified.');
    }
    if (!complete)
        notes.push('What is unknown could not be read from the registry — it was not found absent.');
    if (signature === 'absent' && provenance === 'absent')
        notes.push('Neither a signature nor SLSA provenance was found.');
    notes.push(pinned.scope);
    return {
        run: {
            name: 'cosign-tree',
            status: complete ? 'ok' : 'failed',
            reason: `image ${image} (${pinned.checked ?? 'tag not pinned'}): ${sigWords[signature]}; ${provWords[provenance]}`,
            target: image,
        },
        findings,
        summary: {
            image,
            checked: pinned.checked,
            check: 'detect',
            signature: signature === 'present' ? 'present_unverified' : signature === 'attestation_only' ? 'attestation_only_unverified' : signature,
            provenance: provenance === 'present' ? 'present_unverified' : provenance,
            note: notes.join(' '),
        },
        cancelled,
    };
}
function describePolicy(policy) {
    const identity = policy.identity !== undefined ? `identity ${policy.identity}` : `identity matching ${policy.identityRegexp ?? '?'}`;
    const issuer = policy.issuer !== undefined ? `issuer ${policy.issuer}` : `issuer matching ${policy.issuerRegexp ?? '?'}`;
    return `${identity}, ${issuer}`;
}
//# sourceMappingURL=cosignCheck.js.map