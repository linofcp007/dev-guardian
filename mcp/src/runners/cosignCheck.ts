/**
 * cosign checks of a container image's supply chain, for `scan_containers`.
 *
 * Two different questions, never confused with each other:
 *
 *   - **verify** (a signer identity AND an OIDC issuer were given): a real
 *     `cosign verify` — the signature is checked against Sigstore's trust
 *     root and the certificate's identity against the one named. A rejection
 *     is a high finding (`cosign-verify` / `image-signature-not-verified`).
 *     The run records the signer (`ToolRun.signer`) and the finding's
 *     identity holds it: a rejection for one signer is re-measured only by a
 *     verification for the same one, and a rejection for another signer is a
 *     new finding.
 *   - **detect** (no signer given): only whether a signature and a signed
 *     SLSA provenance attestation EXIST. Absence is a low (`image-unsigned`)
 *     or info (`image-no-provenance`) finding. A signature that exists is
 *     `present_unverified`: anyone can sign an image, so its existence says
 *     nothing about WHO signed it, and the answer says so.
 *
 * ---- The verdict: only a network or registry failure withholds it ----
 *
 * Anyone who can push to the image's repository can attach anything to it:
 * a `.sig` tag holding a junk signature, a "signing bundle" that does not
 * parse, an ordinary artifact typed `https://spdx.dev/Document`. None of
 * those is a signature, and none may turn a rejection into "no verdict" — so
 * `cosign verify` failing is a REJECTION (a high finding) unless the failure
 * is a network, registry or Sigstore-service failure: the question was not
 * answered. The test for that reads cosign's own error framing (`dial tcp`,
 * `GET https://…: TOOMANYREQUESTS`, `setting up clients and keys`, …) after
 * every value cosign echoes back — the expected identity (the user's text),
 * the certificate's subjects (the signer's) — has been removed, so an
 * identity such as `…/org/timeout-svc/…` cannot pass for a timeout. An
 * unparseable bundle, an invalid signature, a missing certificate or key:
 * rejected. A regexp cosign cannot compile, or a cosign that crashed without
 * its `Error:` framing, is an error — that is not a verdict on the image.
 *
 * ---- What cosign cannot be taken at its word on (measured, v3.1.3) ----
 *
 * cosign swallows some registry failures and prints what it prints for
 * "nothing there". Measured against the fake registry in
 * `test/helpers/fakeOciRegistry.ts`, with a failure injected:
 *
 *   - `cosign tree` ignores any error but 404 on the legacy `.sig` / `.att`
 *     tags (a `.sig` answering 500 prints "No Supply Chain Security Related
 *     Artifacts found", exit 0). Its referrers call fails loudly ("getting
 *     referrers", exit 1); a referrer it cannot fetch is a line on stderr.
 *   - `cosign download signature` / `download attestation` read only the
 *     referrers that parse as Sigstore bundles, skip the rest in silence
 *     (`GetBundles`: "there may be non-Sigstore referrers"), then read the
 *     legacy tag — which fails loudly ("remote image: GET …").
 *   - `cosign verify` falls back to legacy signatures when the referrers
 *     call fails, or when no bundle parses, and says "no signatures found"
 *     (exit 10) — also for an image signed with a v3 bundle.
 *   - `cosign verify`'s exit 12 joins ONE error per signature, a transient
 *     one included.
 *
 * So: detect's "absent" needs `tree` to list no `.sig` and `download
 * signature` to say "no signatures associated" — and a referrer counts as a
 * signature (or a signed attestation) only when `download signature` returns
 * it as a Sigstore bundle, never on `tree`'s listing. Provenance is present
 * only when `download attestation` returns it (a parsed bundle or a legacy
 * `.att`), absent only when both v1 and v0.2 say none. verify's exit 10 is
 * confirmed: `tree` (loud) must list nothing and the `.sig` tag hold none —
 * or, when something is attached, verify is run once more, and "no
 * signatures found" again while the registry answered is a rejection: what
 * is attached is no signature it can use. An exit 12 with a registry error
 * folded in is withheld.
 *
 * ---- A registry failure cosign cannot see ----
 *
 * go-containerregistry (remote/referrers.go, v0.21.7) reads a referrers
 * answer whose Content-Type is not exactly the OCI index type (`…; charset=
 * utf-8`), an HTML 200, or a 400 / 406 as "this registry has no referrers
 * API", falls back to the tag schema, finds nothing, and reports nothing —
 * no error anywhere. A registry answering that way makes a signed image read
 * unsigned: detect says absent, verify says "no signatures found" (a high
 * finding). Measured with the fake registry (`; charset=utf-8`: `tree` lists
 * nothing, exit 0). Neither cosign nor dev-guardian can tell that apart from
 * an unsigned image; SECURITY.md and the tool's description say so.
 *
 * ---- The image cosign checks ----
 *
 * `cosign triangulate --type digest` pins the tag to a digest first, and
 * every later call checks that digest; the response names it. Trivy
 * resolves the tag separately, and on a multi-arch index this is the index's
 * digest — a signature on the per-platform images only reads as absent;
 * both are said. `triangulate` goes in cosign 4: without it the checks run
 * on the tag, and the answer says so.
 *
 * cosign older than 3.0 is not used at all: its `tree` does not list OCI
 * referrers unless asked (`--experimental-oci11`) — measured: cosign 2.6.5
 * on a signed `ghcr.io/sigstore/cosign/cosign:v3.1.3` prints "No …
 * Artifacts found", exit 0.
 */

import { compareSemver } from '../platform/semverCompare.js';
import type { Finding, ToolRun } from '../types.js';
import { runProcess, type ProcessRunResult } from './processRunner.js';
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

/**
 * Characters no image reference, identity, issuer or regexp has a reason to
 * hold, and that reshape any reason, note or log line they reach: C0
 * controls (ESC included), DEL, C1 controls (U+0085 included), zero-width
 * characters (U+200B–U+200D, U+2060, U+FEFF), the Unicode line and paragraph
 * separators, and the bidi embedding / override / isolate controls. As a
 * character-class body, for `scanContainers.ts`'s patterns too.
 */
export const UNSAFE_CHAR_CLASS =
  '\\u0000-\\u001f\\u007f-\\u009f\\u200b-\\u200d\\u2028\\u2029\\u202a-\\u202e\\u2060\\u2066-\\u2069\\ufeff';
export const UNSAFE_CHARS = new RegExp(`[${UNSAFE_CHAR_CLASS}]`);

/** `text` with every {@link UNSAFE_CHARS} character written as `\uXXXX` — never echoed raw. */
export function escapeUnsafe(text: string): string {
  return text.replace(new RegExp(`[${UNSAFE_CHAR_CLASS}]`, 'g'), (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

/** The signer an image must be signed by: one identity form and one issuer form. */
export interface SignerPolicy {
  identity?: string;
  identityRegexp?: string;
  issuer?: string;
  issuerRegexp?: string;
}

// ---------------------------------------------------------------------------
// Readiness: `cosign version`
// ---------------------------------------------------------------------------

export type CosignReadiness = { ok: true; version: string } | { ok: false; status: 'skipped' | 'failed'; reason: string };

/** Whether this cosign can be used — see the module comment for why 2.x cannot. */
export function readinessFromProbe(r: ProcessRunResult): CosignReadiness {
  if (r.outcome !== 'completed') {
    return { ok: false, status: 'failed', reason: `\`cosign version\` did not complete: ${firstError(r.stderr) ?? r.outcome.replace(/_/g, ' ')}` };
  }
  const version = extractVersion(`${r.stdout}\n${r.stderr}`);
  if (version === null) return { ok: false, status: 'failed', reason: '`cosign version` printed no version this can read' };
  const cmp = compareSemver(version, COSIGN_MIN_VERSION);
  if (cmp === null || cmp < 0) {
    return {
      ok: false,
      status: 'skipped',
      reason:
        `outdated: cosign ${version} is older than ${COSIGN_MIN_VERSION} — its \`cosign tree\` does not list OCI ` +
        'referrers, where every cosign v3 signature and every GitHub provenance attestation lives, so it would ' +
        'report a signed image as unsigned. Install cosign 3 (install_toolchain { tools: ["cosign"] }).',
    };
  }
  return { ok: true, version };
}

// ---------------------------------------------------------------------------
// The digest: `cosign triangulate --type digest`
// ---------------------------------------------------------------------------

export type TriangulateCause = 'not_found' | 'denied' | 'rate_limited' | 'unreachable' | 'registry_error' | 'other';

export type Resolution =
  | { kind: 'digest'; ref: string; digest: string }
  | { kind: 'tag_only'; reason: string }
  | { kind: 'error'; detail: string; cause: TriangulateCause; why: string };

const DIGEST_REF = /^(\S+)@(sha256:[0-9a-f]{64})$/;

/** Why an image cosign cannot find is often not a typo. */
const REGISTRY_ONLY_NOTE =
  'cosign reads the image and its signatures from the registry, never from the local Docker daemon: an image ' +
  'built locally and never pushed cannot be checked (push it, or scan the pushed reference).';

export function classifyTriangulate(r: ProcessRunResult): Resolution {
  if (r.outcome === 'completed') {
    const m = DIGEST_REF.exec(r.stdout.trim());
    if (m?.[2] !== undefined) return { kind: 'digest', ref: m[0], digest: m[2] };
    const detail = 'cosign triangulate printed no digest reference';
    return { kind: 'error', detail, cause: 'other', why: `cosign could not resolve the image (${detail})` };
  }
  if (/unknown command "triangulate"/.test(r.stderr)) {
    return { kind: 'tag_only', reason: 'this cosign has no `triangulate` (removed in cosign 4), so each call resolved the tag itself' };
  }
  const detail = escapeUnsafe(firstError(r.stderr) ?? `cosign triangulate ${r.outcome.replace(/_/g, ' ')}`);
  const cause = triangulateCause(r);
  const why: Record<TriangulateCause, string> = {
    not_found: `the registry has no such image or tag (${detail}). ${REGISTRY_ONLY_NOTE}`,
    denied:
      `the registry refused access (${detail}) — cosign reads registry credentials from the Docker config (docker ` +
      'login), and a registry such as Docker Hub gives the same answer for a repository that does not exist, so an ' +
      `image never pushed looks like this too. ${REGISTRY_ONLY_NOTE}`,
    rate_limited: `the registry is rate-limiting requests (${detail}) — try again later, or log in (docker login) for a higher limit`,
    unreachable: `the registry could not be reached (${detail})`,
    registry_error: `the registry failed (${detail}) — try again later`,
    other: `cosign could not resolve the image (${detail})`,
  };
  return { kind: 'error', detail, cause, why: why[cause] };
}

function triangulateCause(r: ProcessRunResult): TriangulateCause {
  if (r.outcome !== 'failed') return 'other';
  const s = r.stderr;
  if (/TOOMANYREQUESTS|\b429\b|rate limit/i.test(s)) return 'rate_limited';
  if (/MANIFEST_UNKNOWN|NAME_UNKNOWN|NOT_FOUND|\b404\b/.test(s)) return 'not_found';
  if (/UNAUTHORIZED|DENIED|\b401\b|\b403\b/.test(s)) return 'denied';
  if (NETWORK.test(stripEchoes(s))) return 'unreachable';
  if (/: UNKNOWN\b|UNAVAILABLE|unexpected status code 5\d\d|\b50[0-9]\b/.test(s)) return 'registry_error';
  return 'other';
}

// ---------------------------------------------------------------------------
// `cosign tree`
// ---------------------------------------------------------------------------

export type Presence = 'present' | 'absent' | 'unknown';

/** What `cosign tree` listed. */
export interface CosignTreeListing {
  /** A legacy `.sig` tag. */
  signature: boolean;
  /** Legacy `.att` attestations exist; the listing does not say of which predicate type. */
  legacyAttestations: boolean;
  /**
   * The type cosign printed for each OCI referrer — a bundle's predicate
   * type when it carries one, any other artifact's own type otherwise: the
   * listing alone cannot tell a Sigstore bundle from anything else.
   */
  referrerTypes: string[];
  /** Referrers cosign reported it could not fetch: the listing is incomplete. */
  fetchErrors: string[];
}

/** The predicate type of a cosign v3 image signature. */
const SIGN_PREDICATE = 'https://sigstore.dev/cosign/sign/v1';
/** What `cosign verify` prints as `critical.type` for an image signature, legacy or v3. */
const VERIFIED_SIGNATURE_TYPES: ReadonlySet<string> = new Set(['cosign container image signature', SIGN_PREDICATE]);
const BUNDLE_MEDIA_TYPE = /^application\/vnd\.dev\.sigstore\.bundle/;
/** The predicate types `download attestation` is asked for, newest first. */
export const PROVENANCE_PREDICATE_TYPES = ['https://slsa.dev/provenance/v1', 'https://slsa.dev/provenance/v0.2'] as const;

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
export function parseCosignTree(stdout: string, stderr: string): CosignTreeListing | null {
  const lines = stdout.split(/\r?\n/);
  if (!lines.some((l) => TREE_HEADER.test(l))) return null;
  const listing: CosignTreeListing = {
    signature: false,
    legacyAttestations: false,
    referrerTypes: [],
    fetchErrors: stderr.split(/\r?\n/).filter((l) => TREE_FETCH_ERROR.test(l.trim())),
  };
  let recognised = false;
  for (const line of lines) {
    if (TREE_NONE.test(line) || TREE_SBOMS.test(line)) {
      recognised = true;
    } else if (TREE_SIGNATURES.test(line)) {
      recognised = true;
      listing.signature = true;
    } else if (TREE_ATTESTATIONS.test(line)) {
      recognised = true;
      listing.legacyAttestations = true;
    } else {
      const type = TREE_REFERRER.exec(line)?.[1];
      if (type === undefined) continue;
      recognised = true;
      listing.referrerTypes.push(type);
    }
  }
  return recognised ? listing : null;
}

/**
 * What the listing alone says about an image signature: `present` (a legacy
 * `.sig` tag); `unknown` (a referrer cosign could not fetch); or `confirm` —
 * `download signature` decides, because `tree` also prints "nothing" when
 * the `.sig` tag failed, and prints a referrer's type whether or not it is a
 * Sigstore bundle.
 */
export function signatureFromTree(tree: CosignTreeListing): 'present' | 'unknown' | 'confirm' {
  if (tree.signature) return 'present';
  if (tree.fetchErrors.length > 0) return 'unknown';
  return 'confirm';
}

/** Whether anything at all is attached: a `.sig` tag or any referrer. */
export function treeListsAnything(tree: CosignTreeListing): boolean {
  return tree.signature || tree.referrerTypes.length > 0;
}

// ---------------------------------------------------------------------------
// The loud calls: `download signature`, `download attestation`
// ---------------------------------------------------------------------------

export interface SignatureDownload {
  state: 'present' | 'attestation_only' | 'absent' | 'unknown';
  /** The predicate types of the signed attestation bundles returned (for `attestation_only`). */
  attestationTypes: string[];
}

/**
 * `cosign download signature`: one JSON line per legacy signature, or per
 * referrer cosign parsed as a Sigstore bundle — nothing else. A legacy
 * signature, a message-signature bundle or a DSSE bundle whose predicate is
 * `…/cosign/sign/v1` is an image signature; any other DSSE bundle is a
 * signed attestation. "no signatures associated" is none; anything else did
 * not answer.
 */
export function classifySignatureDownload(r: ProcessRunResult): SignatureDownload {
  const none: SignatureDownload = { state: 'unknown', attestationTypes: [] };
  if (r.outcome === 'failed') {
    return /no signatures associated/.test(r.stderr) ? { state: 'absent', attestationTypes: [] } : none;
  }
  if (r.outcome !== 'completed' && r.outcome !== 'output_too_large') return none;
  let signature = false;
  let recognised = false;
  const types: string[] = [];
  for (const line of r.stdout.split(/\r?\n/)) {
    if (line.trim() === '') continue;
    let item: unknown;
    try {
      item = JSON.parse(line);
    } catch {
      // A cut-off last line of an output past the cap; any other is not ours.
      if (r.outcome === 'output_too_large') continue;
      return none;
    }
    if (!isRecord(item)) return none;
    if (typeof item['Base64Signature'] === 'string') {
      signature = true;
      recognised = true;
      continue;
    }
    if (typeof item['mediaType'] !== 'string' || !BUNDLE_MEDIA_TYPE.test(item['mediaType'])) continue;
    recognised = true;
    if (item['messageSignature'] !== undefined) {
      signature = true;
      continue;
    }
    const type = dssePredicateType(item['dsseEnvelope']) ?? 'a Sigstore bundle of unknown predicate type';
    if (type === SIGN_PREDICATE) signature = true;
    else if (!types.includes(type)) types.push(type);
  }
  if (signature) return { state: 'present', attestationTypes: types };
  if (recognised && types.length > 0) return { state: 'attestation_only', attestationTypes: types };
  return none;
}

function dssePredicateType(envelope: unknown): string | null {
  if (!isRecord(envelope) || typeof envelope['payload'] !== 'string') return null;
  try {
    const statement: unknown = JSON.parse(Buffer.from(envelope['payload'], 'base64').toString('utf8'));
    return isRecord(statement) && typeof statement['predicateType'] === 'string' ? statement['predicateType'] : null;
  } catch {
    return null;
  }
}

/**
 * One `cosign download attestation --predicate-type=<type>`. cosign prints
 * only attestations of that type (parsed bundles, or the legacy `.att`), so
 * any output — even past the stdout cap — means one exists; its own "no
 * attestations with predicate type" error means none does. Anything else did
 * not answer.
 */
export function classifyAttestationDownload(r: ProcessRunResult): Presence {
  if (r.outcome === 'output_too_large') return 'present';
  if (r.outcome === 'completed') return r.stdout.trim().length > 0 ? 'present' : 'unknown';
  if (r.outcome === 'failed' && /no attestations with predicate type/.test(r.stderr)) return 'absent';
  return 'unknown';
}

// ---------------------------------------------------------------------------
// `cosign verify`
// ---------------------------------------------------------------------------

export type RejectionReason = 'no_signature' | 'no_matching_signature' | 'no_certificate' | 'invalid_signature';

export type VerifyVerdict =
  | { verdict: 'verified'; types: string[]; digest?: string }
  | { verdict: 'no_signature_claimed'; detail: string }
  | { verdict: 'rejected'; reason: RejectionReason; detail: string }
  | { verdict: 'error'; detail: string };

/** Another identity or issuer than the one asked for. */
const IDENTITY_MISMATCH = /none of the expected identities matched|no matching CertificateIdentity found|expected (?:SAN|issuer) value/;
const NO_KEY_MATERIAL = /no certificate found on signature|empty key/;
const BAD_REGEXP = /error parsing regexp/;

/** Go's network errors, as net/http and the dialer frame them. Case-sensitive on purpose. */
const NETWORK = new RegExp(
  [
    'dial tcp',
    ': no such host',
    'i/o timeout',
    'connection reset by peer',
    'connection refused',
    'TLS handshake timeout',
    'tls: ',
    'context deadline exceeded',
    'Client\\.Timeout exceeded',
    'unexpected EOF',
    ': EOF\\b',
    'server misbehaving',
    'network is unreachable',
    'proxyconnect',
    'giving up after \\d+ attempt',
    'server gave HTTP response to HTTPS client',
    // Go's url.Error: `Post "<url>": <cause>` (the URL is an echo, removed first).
    '\\b(?:Get|Post|Head|Put|Patch|Delete) "…": ',
  ].join('|'),
);
/** A registry answering with an error, as go-containerregistry and cosign frame it. */
const REGISTRY = /\b(?:GET|HEAD|POST|PUT|PATCH|DELETE) https?:\/\/\S+: (?:[A-Z][A-Z_]+\b|unexpected status code)|unexpected status code \d{3}|remote image: |image tag not found|getting referrers|Error fetching /;
/** Sigstore's services (TUF, Rekor) not answering. */
const SIGSTORE_SERVICE =
  /setting up clients and keys|getting rekor public keys|getting ctlog public keys|updating local metadata and targets|error updating to TUF remote mirror|tuf refresh failed|failed to download [\w.]*root\.json|searching log query|getting trusted root|fetching trusted root|Could not fetch trusted_root/;

/**
 * cosign's stderr with every value it echoes removed: double- and
 * backtick-quoted strings (the expected identity or regexp, the certificate's
 * SAN and issuer, URLs) and the legacy subject list — from `got subjects [`
 * to the end of its line, since a branch name may itself hold a `]`.
 */
function stripEchoes(stderr: string): string {
  return stderr
    .replace(/got subjects \[[^\n]*/g, 'got subjects […]')
    .replace(/"(?:[^"\\\n]|\\.)*"/g, '"…"')
    .replace(/`[^`\n]*`/g, '`…`');
}

/** A network, registry or Sigstore-service failure in cosign's own framing — the question was not answered. */
function withheld(stderr: string): boolean {
  const own = stripEchoes(stderr);
  return NETWORK.test(own) || REGISTRY.test(own) || SIGSTORE_SERVICE.test(own);
}

/** How a `cosign verify` ended — see the module comment for the rule. */
export function classifyVerify(r: ProcessRunResult): VerifyVerdict {
  if (r.outcome === 'completed') return { verdict: 'verified', ...verifiedPayloads(r.stdout) };
  if (r.outcome !== 'failed') return { verdict: 'error', detail: `cosign verify ${r.outcome.replace(/_/g, ' ')}` };
  const framed = r.stderr.split(/\r?\n/).some((l) => l.startsWith('Error: '));
  const detail = escapeUnsafe(firstError(r.stderr) ?? `cosign verify exited ${r.exitCode ?? '(no exit code)'}`);
  if (!framed) return { verdict: 'error', detail: `cosign verify ended without its error framing — ${detail}` };
  if (r.exitCode === 10) return { verdict: 'no_signature_claimed', detail };
  if (BAD_REGEXP.test(r.stderr)) return { verdict: 'error', detail: `a signer regexp cosign cannot compile — ${detail}` };
  if (r.exitCode === 11 || withheld(r.stderr)) return { verdict: 'error', detail };
  if (IDENTITY_MISMATCH.test(r.stderr)) {
    const line = r.stderr.split(/\r?\n/).find((l) => IDENTITY_MISMATCH.test(l)) ?? detail;
    return {
      verdict: 'rejected',
      reason: 'no_matching_signature',
      detail: escapeUnsafe(clip(line.replace(/^Error:\s*/, '').replace(/^no matching (?:signatures|attestations):\s*/, '').trim())),
    };
  }
  if (NO_KEY_MATERIAL.test(r.stderr)) return { verdict: 'rejected', reason: 'no_certificate', detail };
  return { verdict: 'rejected', reason: 'invalid_signature', detail };
}

/** What `cosign verify` accepted (`critical.type` of each payload) and over which digest. */
function verifiedPayloads(stdout: string): { types: string[]; digest?: string } {
  const types: string[] = [];
  let digest: string | undefined;
  let parsed: unknown;
  try {
    // One JSON array on one line; cosign may print a blank line first.
    parsed = JSON.parse(stdout.split(/\r?\n/).find((l) => l.trimStart().startsWith('[')) ?? '');
  } catch {
    return { types };
  }
  if (!Array.isArray(parsed)) return { types };
  for (const item of parsed as unknown[]) {
    const critical = isRecord(item) && isRecord(item['critical']) ? item['critical'] : null;
    if (critical === null) continue;
    const type = critical['type'];
    if (typeof type === 'string' && !types.includes(type)) types.push(type);
    const image = critical['image'];
    const d = isRecord(image) ? image['docker-manifest-digest'] : undefined;
    if (typeof d === 'string' && digest === undefined) digest = d;
  }
  return digest !== undefined ? { types, digest } : { types };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * `cosign verify`'s argv. Each value is passed inside its own flag
 * (`--certificate-identity=<value>`), so no value can be read as another
 * option whatever it starts with; the reference is last.
 */
export function verifyArgs(ref: string, policy: SignerPolicy): string[] {
  const args = ['verify'];
  if (policy.identity !== undefined) args.push(`--certificate-identity=${policy.identity}`);
  if (policy.identityRegexp !== undefined) args.push(`--certificate-identity-regexp=${policy.identityRegexp}`);
  if (policy.issuer !== undefined) args.push(`--certificate-oidc-issuer=${policy.issuer}`);
  if (policy.issuerRegexp !== undefined) args.push(`--certificate-oidc-issuer-regexp=${policy.issuerRegexp}`);
  args.push(ref);
  return args;
}

/**
 * The signer, one spelling per policy: JSON of the fields given, in a fixed
 * order. Recorded as `ToolRun.signer`, part of a verification's target and
 * of its finding's identity — JSON, not `key=value` joined by a separator, so
 * no value can forge the boundary between two fields.
 */
export function canonicalSignerPolicy(policy: SignerPolicy): string {
  const out: Record<string, string> = {};
  if (policy.identity !== undefined) out['identity'] = policy.identity;
  if (policy.identityRegexp !== undefined) out['identity_regexp'] = policy.identityRegexp;
  if (policy.issuer !== undefined) out['issuer'] = policy.issuer;
  if (policy.issuerRegexp !== undefined) out['issuer_regexp'] = policy.issuerRegexp;
  return JSON.stringify(out);
}

/**
 * A warning for each signer regexp not anchored at both ends. cosign matches
 * a regexp anywhere in the certificate's value (Go RE2 `MatchString`), so
 * `https://github.com/org/app/` also accepts
 * `https://github.com/attacker/x/.github/workflows/y.yml@refs/heads/https://github.com/org/app/`
 * — a branch name is the attacker's to choose.
 */
export function unanchoredSignerRegexps(policy: SignerPolicy): string[] {
  const anchored = (re: string): boolean => re.startsWith('^') && (/(?<!\\)\$$/.test(re) || re.endsWith('\\z'));
  const out: string[] = [];
  for (const [field, re] of [
    ['signer_identity_regexp', policy.identityRegexp],
    ['signer_issuer_regexp', policy.issuerRegexp],
  ] as const) {
    if (re === undefined || anchored(re)) continue;
    out.push(
      `${field} ${JSON.stringify(re)} is not anchored (^…$): cosign accepts any certificate whose value merely ` +
        'CONTAINS a match — a workflow in another repository, on a branch named to include it, passes. Anchor it ' +
        'at both ends.',
    );
  }
  return out;
}

/** The first `Error: …` line cosign printed, without the prefix, bounded. */
function firstError(stderr: string): string | null {
  for (const raw of stderr.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith('Error: ')) return clip(line.slice('Error: '.length));
  }
  const first = stderr
    .split(/\r?\n/)
    .map((l) => l.trim())
    .find((l) => l.length > 0 && !l.startsWith('Command "triangulate" is deprecated'));
  return first === undefined ? null : clip(first);
}

function clip(text: string): string {
  return text.length > 400 ? `${text.slice(0, 399)}…` : text;
}

// ---------------------------------------------------------------------------
// Running it
// ---------------------------------------------------------------------------

/** What the response says about the image, fresh or from the cache. */
export interface ImageSignatureSummary {
  image: string;
  /** The `repo@sha256:…` every cosign call checked, or null when the tag was not pinned. */
  checked: string | null;
  /** `verify`: a signer was named; `detect`: existence only; `skipped`: cosign did not run. */
  check: 'verify' | 'detect' | 'skipped';
  signature: 'verified' | 'rejected' | 'present_unverified' | 'attestation_only_unverified' | 'absent' | 'unknown';
  /** verify: what cosign accepted — `critical.type` of each payload it verified. */
  verified_as?: string[];
  provenance: 'present_unverified' | 'absent' | 'unknown' | 'not_checked';
  note: string;
}

export interface CosignImageCheck {
  /** The one `tools_run` entry: `cosign-verify` or `cosign-tree`, with the image as its target. */
  run: ToolRun;
  findings: Finding[];
  summary: ImageSignatureSummary;
  /** True when a cosign call was cancelled — the scan's own outcome then says so. */
  cancelled: boolean;
}

export interface CosignRunContext {
  cwd: string;
  env: NodeJS.ProcessEnv;
  signal?: AbortSignal;
  onLog?: (line: string) => void;
}

/** What to do about an unverified signature — the same words everywhere. */
export const UNVERIFIED_NOTE =
  'A signature exists, but its signer was NOT verified: anyone can sign an image. Pass signer_identity ' +
  '(or signer_identity_regexp) and signer_issuer (or signer_issuer_regexp) to verify who signed it.';

/** The response's summary when cosign did not run at all. */
export function skippedSummary(image: string, reason: string): ImageSignatureSummary {
  return { image, checked: null, check: 'skipped', signature: 'unknown', provenance: 'unknown', note: `Not checked: ${reason}.` };
}

async function cosign(args: string[], ctx: CosignRunContext): Promise<ProcessRunResult> {
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
export async function cosignReadiness(ctx: CosignRunContext): Promise<CosignReadiness> {
  return readinessFromProbe(await cosign(['version'], ctx));
}

/** The reference every later call checks, and what to say about it. */
interface Pinned {
  ref: string;
  checked: string | null;
  scope: string;
}

/**
 * Pins `image` to a digest (`triangulate`), or explains why it could not:
 * the tag-only fallback, or — when the registry did not answer — the failed
 * check, returned as such, worded by its cause.
 */
async function pin(image: string, pass: 'cosign-verify' | 'cosign-tree', ctx: CosignRunContext, extra: Partial<ToolRun>): Promise<Pinned | CosignImageCheck> {
  const r = await cosign(['triangulate', '--type', 'digest', image], ctx);
  const res = classifyTriangulate(r);
  if (res.kind === 'digest') {
    return {
      ref: res.ref,
      checked: res.ref,
      scope:
        `cosign checked ${res.ref}, the digest the tag named when this scan pinned it; Trivy resolved the tag on ` +
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
  const why = res.why;
  // Each name spelled out: history/runNames.test.ts reads bookkeeping names from the source.
  return {
    run:
      pass === 'cosign-verify'
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

function isCheck(p: Pinned | CosignImageCheck): p is CosignImageCheck {
  return 'run' in p;
}

/** Whether the call was cancelled — asked afresh before each cosign, never started after one. */
function aborted(ctx: CosignRunContext): boolean {
  return ctx.signal?.aborted === true;
}

interface TreeRead {
  tree: CosignTreeListing | null;
  /** Why there is no listing, when there is none. */
  why?: string;
  cancelled: boolean;
}

async function readTree(ref: string, ctx: CosignRunContext): Promise<TreeRead> {
  const r = await cosign(['tree', ref], ctx);
  const tree = r.outcome === 'completed' ? parseCosignTree(r.stdout, r.stderr) : null;
  if (tree !== null) return { tree, cancelled: false };
  const why =
    r.outcome === 'completed'
      ? 'its output was not a listing this version of dev-guardian can read'
      : escapeUnsafe(firstError(r.stderr) ?? `cosign tree ${r.outcome.replace(/_/g, ' ')}`);
  return { tree: null, why, cancelled: r.outcome === 'cancelled' };
}

/** What `tree` listed, in words, for a rejection's detail. */
function describeListed(tree: CosignTreeListing): string {
  const parts: string[] = [];
  if (tree.signature) parts.push('a .sig tag');
  if (tree.referrerTypes.length > 0) parts.push(`OCI referrers typed ${[...new Set(tree.referrerTypes)].join(', ')}`);
  return parts.length > 0 ? parts.join(' and ') : 'nothing';
}

/**
 * verify's "no signatures found" (exit 10), settled: a rejection only when
 * the loud calls say nothing usable is there — see the module comment.
 */
async function settleNoSignature(ref: string, policy: SignerPolicy, claim: string, ctx: CosignRunContext): Promise<{ v: VerifyVerdict; cancelled: boolean }> {
  if (aborted(ctx)) return { v: { verdict: 'error', detail: 'cancelled' }, cancelled: true };
  const read = await readTree(ref, ctx);
  if (read.tree === null) {
    return {
      v: { verdict: 'error', detail: `cosign verify said "${claim}", and cosign tree — which fails loudly when the registry does — did not complete: ${read.why ?? 'unknown'}` },
      cancelled: read.cancelled,
    };
  }
  const tree = read.tree;
  if (tree.fetchErrors.length > 0) {
    return { v: { verdict: 'error', detail: `cosign verify said "${claim}", and cosign tree could not fetch ${tree.fetchErrors.length} referrer(s)` }, cancelled: false };
  }
  if (!treeListsAnything(tree)) {
    if (aborted(ctx)) return { v: { verdict: 'error', detail: 'cancelled' }, cancelled: true };
    const dl = await cosign(['download', 'signature', ref], ctx);
    const answer = classifySignatureDownload(dl);
    if (answer.state === 'absent') {
      return {
        v: { verdict: 'rejected', reason: 'no_signature', detail: `${claim} — nothing is attached to this digest (cosign tree lists nothing, and the .sig tag holds none)` },
        cancelled: false,
      };
    }
    if (answer.state === 'unknown') {
      return {
        v: { verdict: 'error', detail: `cosign verify said "${claim}", which could not be confirmed: cosign download signature did not answer — ${escapeUnsafe(firstError(dl.stderr) ?? dl.outcome)}` },
        cancelled: dl.outcome === 'cancelled',
      };
    }
    // A signature appeared between the calls: ask verify again, below.
  }
  if (aborted(ctx)) return { v: { verdict: 'error', detail: 'cancelled' }, cancelled: true };
  const again = await cosign(verifyArgs(ref, policy), ctx);
  const v = classifyVerify(again);
  if (v.verdict !== 'no_signature_claimed') return { v, cancelled: again.outcome === 'cancelled' };
  return {
    v: {
      verdict: 'rejected',
      reason: 'no_signature',
      detail:
        `cosign tree lists ${describeListed(tree)} for this digest, but cosign verify found no signature it can ` +
        'use — twice, while the registry answered. An artifact cosign cannot parse as a Sigstore signature, or ' +
        'that is not one, is no signature: anyone who can push to the repository can attach one',
    },
    cancelled: false,
  };
}

/** `cosign verify` of `image` against `policy`. */
export async function verifyImage(image: string, policy: SignerPolicy, ctx: CosignRunContext): Promise<CosignImageCheck> {
  const signer = canonicalSignerPolicy(policy);
  const pinned = await pin(image, 'cosign-verify', ctx, { signer });
  if (isCheck(pinned)) return pinned;
  const warnings = unanchoredSignerRegexps(policy);
  const first = await cosign(verifyArgs(pinned.ref, policy), ctx);
  let v = classifyVerify(first);
  let cancelled = first.outcome === 'cancelled';
  if (v.verdict === 'no_signature_claimed') {
    const settled = await settleNoSignature(pinned.ref, policy, v.detail, ctx);
    v = settled.v;
    cancelled = cancelled || settled.cancelled;
  }
  const who = describePolicy(policy);
  const run = (outcome: 'ok' | 'failed', reason: string): ToolRun => ({
    name: 'cosign-verify',
    status: outcome,
    reason: `image ${image} (${pinned.checked ?? 'tag not pinned'}): ${reason}`,
    target: image,
    signer,
  });
  const note = (text: string): string => [text, pinned.scope, ...warnings].join(' ');

  if (v.verdict === 'verified') {
    const imageSignature = v.types.some((t) => VERIFIED_SIGNATURE_TYPES.has(t));
    const accepted =
      v.types.length === 0
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
  const titles: Record<RejectionReason, string> = {
    no_signature: `Image ${image} has no signature cosign can verify`,
    no_matching_signature: `Image ${image} is not signed by the expected signer`,
    no_certificate: `Image ${image}'s signature has no certificate to verify`,
    invalid_signature: `Image ${image}'s signature does not verify`,
  };
  const finding = makeFinding({
    tool: COSIGN_VERIFY_TOOL_NAME,
    rule_id: 'image-signature-not-verified',
    severity: 'high',
    category: 'security',
    subcategory: 'supply-chain',
    title: titles[v.reason],
    message:
      `cosign verify rejected ${pinned.checked ?? image} for ${who}: ${v.detail}. Nothing shows this image was built ` +
      'and signed by the identity you expect — do not deploy it until it verifies (or correct signer_identity / ' +
      'signer_issuer if the image is legitimately signed by another workflow).',
    file_path: image,
    // The signer is part of what this finding says: a rejection for another
    // signer is another finding, never this one unchanged.
    snippet: `${image} signer=${signer}`,
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
export async function detectImageSupplyChain(image: string, ctx: CosignRunContext): Promise<CosignImageCheck> {
  const pinned = await pin(image, 'cosign-tree', ctx, {});
  if (isCheck(pinned)) return pinned;
  const read = await readTree(pinned.ref, ctx);
  const tree = read.tree;
  if (tree === null) {
    const why = read.why ?? 'unknown';
    return {
      run: { name: 'cosign-tree', status: 'failed', reason: `image ${image} (${pinned.checked ?? 'tag not pinned'}): cosign tree did not complete — ${why}`, target: image },
      findings: [],
      summary: { image, checked: pinned.checked, check: 'detect', signature: 'unknown', provenance: 'unknown', note: `Not checked: cosign tree did not complete (${why}). ${pinned.scope}` },
      cancelled: read.cancelled,
    };
  }

  let cancelled = false;
  // The signature: a listed .sig tag, or what `download signature` returns.
  let signature: SignatureDownload['state'];
  let attestationTypes: string[] = [];
  let signatureWhy: string | undefined;
  const fromTree = signatureFromTree(tree);
  if (fromTree === 'present') {
    signature = 'present';
  } else if (fromTree === 'unknown') {
    signature = 'unknown';
    signatureWhy = `cosign tree could not fetch ${tree.fetchErrors.length} referrer(s)`;
  } else if (aborted(ctx)) {
    signature = 'unknown';
    signatureWhy = 'cancelled';
    cancelled = true;
  } else {
    const dl = await cosign(['download', 'signature', pinned.ref], ctx);
    const answer = classifySignatureDownload(dl);
    signature = answer.state;
    attestationTypes = answer.attestationTypes;
    if (dl.outcome === 'cancelled') cancelled = true;
    if (answer.state === 'unknown') signatureWhy = `cosign download signature did not answer — ${escapeUnsafe(firstError(dl.stderr) ?? dl.outcome)}`;
  }

  // Provenance: only what `download attestation` returns (a parsed bundle or a legacy .att).
  let provenance: Presence = 'unknown';
  let provenanceWhy: string | undefined;
  if (!cancelled) {
    const answers: Presence[] = [];
    for (const type of PROVENANCE_PREDICATE_TYPES) {
      if (aborted(ctx)) {
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
      if (answer === 'unknown') provenanceWhy = `cosign download attestation did not answer — ${escapeUnsafe(firstError(r.stderr) ?? r.outcome)}`;
      if (answer === 'present') break;
    }
    provenance = answers.includes('present')
      ? 'present'
      : answers.length === PROVENANCE_PREDICATE_TYPES.length && answers.every((a) => a === 'absent')
        ? 'absent'
        : 'unknown';
    if (provenance === 'absent' && tree.fetchErrors.length > 0) {
      provenance = 'unknown';
      provenanceWhy = 'cosign tree could not list every referrer';
    }
  }
  if (cancelled && provenance === 'unknown') provenanceWhy = 'cancelled';

  const findings: Finding[] = [];
  if (signature === 'absent') {
    const listed =
      tree.referrerTypes.length > 0
        ? ` What is attached (OCI referrers typed ${[...new Set(tree.referrerTypes)].join(', ')}) is no Sigstore bundle cosign can parse — anyone who can push to the repository can attach such an artifact.`
        : '';
    const legacyProvenance =
      provenance === 'present'
        ? ' A signed SLSA provenance attestation IS attached as a legacy .att tag, which `cosign verify-attestation` checks — `cosign verify` does not accept it as the image\'s signature.'
        : ' Nothing ties it to who built it.';
    findings.push(
      makeFinding({
        tool: COSIGN_TREE_TOOL_NAME,
        rule_id: 'image-unsigned',
        severity: 'low',
        category: 'security',
        subcategory: 'supply-chain',
        title: `Image ${image} has no Sigstore signature`,
        message:
          `cosign found no signature for ${pinned.checked ?? image} — no .sig tag, and no signing or signed ` +
          `attestation bundle it can parse attached as an OCI referrer, which is everything \`cosign verify\` accepts.${listed}${legacyProvenance} ` +
          'On a multi-arch index this is the index: a signature on the per-platform images only is not seen. Sign it ' +
          'in the pipeline that builds it (cosign sign, keyless), then verify it before deploying: scan_containers ' +
          'with signer_identity and signer_issuer.',
        file_path: image,
        snippet: image,
        fix_available: false,
      }),
    );
  }
  if (provenance === 'absent') {
    findings.push(
      makeFinding({
        tool: COSIGN_TREE_TOOL_NAME,
        rule_id: 'image-no-provenance',
        severity: 'info',
        category: 'security',
        subcategory: 'supply-chain',
        title: `Image ${image} has no SLSA provenance attestation`,
        message:
          `No signed SLSA provenance attestation (https://slsa.dev/provenance/v0.2 or v1) was found for ${pinned.checked ?? image}, ` +
          'as a legacy .att tag or a Sigstore bundle attached as an OCI referrer, so there is no signed record of the ' +
          "source and build that produced it. BuildKit's unsigned provenance inside an image index is not counted. " +
          'Generate one where the image is built (actions/attest-build-provenance with push-to-registry, or cosign attest).',
        file_path: image,
        snippet: image,
        fix_available: false,
      }),
    );
  }

  const complete = signature !== 'unknown' && provenance !== 'unknown';
  const sigWords: Record<SignatureDownload['state'], string> = {
    present: 'signature present (signer NOT verified)',
    attestation_only: `no \`cosign sign\` signature, but a signed attestation (${attestationTypes.join(', ')}) (signer NOT verified)`,
    absent: 'signature absent',
    unknown: `signature unknown (${signatureWhy ?? 'not answered'})`,
  };
  const provWords: Record<Presence, string> = {
    present: 'SLSA provenance present (signer NOT verified)',
    absent: 'SLSA provenance absent',
    unknown: `SLSA provenance unknown (${provenanceWhy ?? 'not answered'})`,
  };
  const notes: string[] = [];
  if (signature === 'present') notes.push(UNVERIFIED_NOTE);
  if (signature === 'attestation_only') {
    notes.push(
      `No \`cosign sign\` signature is attached, but a signed attestation is (${attestationTypes.join(', ')}) — and ` +
        'cosign verify accepts a signed attestation over the digest as the image\'s signature, so a verification ' +
        'with its signer can pass. Its signer was NOT verified: pass signer_identity and signer_issuer.',
    );
  }
  if (provenance === 'present' && signature !== 'attestation_only') {
    notes.push(signature === 'present' ? "The provenance attestation's signer was not verified either." : 'A SLSA provenance attestation exists, but its signer was NOT verified.');
  }
  if (!complete) notes.push('What is unknown could not be read from the registry — it was not found absent.');
  if (signature === 'absent' && provenance === 'absent') notes.push('Neither a signature nor SLSA provenance was found.');
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
      signature:
        signature === 'present' ? 'present_unverified' : signature === 'attestation_only' ? 'attestation_only_unverified' : signature,
      provenance: provenance === 'present' ? 'present_unverified' : provenance,
      note: notes.join(' '),
    },
    cancelled,
  };
}

function describePolicy(policy: SignerPolicy): string {
  const identity =
    policy.identity !== undefined ? `identity ${policy.identity}` : `identity matching ${policy.identityRegexp ?? '?'}`;
  const issuer =
    policy.issuer !== undefined ? `issuer ${policy.issuer}` : `issuer matching ${policy.issuerRegexp ?? '?'}`;
  return `${identity}, ${issuer}`;
}
