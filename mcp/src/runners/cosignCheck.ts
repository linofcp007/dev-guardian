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
 * parse, an ordinary artifact typed `https://spdx.dev/Document`, an OCI index.
 * None of those is a signature, and none may turn a rejection into "no
 * verdict" — so `cosign verify` failing is a REJECTION (a high finding)
 * unless the failure is a network, registry or Sigstore-service failure: the
 * question was not answered. The test for that reads cosign's own error
 * framing (`dial tcp`, `GET https://…: TOOMANYREQUESTS`, `setting up clients
 * and keys`, …) after every value cosign echoes back — the expected identity
 * (the user's text), the certificate's subjects (the signer's) — has been
 * removed: every identity-mismatch line from its framing to its end
 * (sigstore-go prints the values unescaped, so quotes cannot be paired), then
 * quoted strings. An identity such as `…/org/timeout-svc/…` or a ref
 * `a"proxyconnect"b` cannot pass for a network failure. Rekor is a verdict
 * too: cosign frames EVERY Rekor error `searching log query:`, and Rekor
 * answers 400 for a signature that does not verify — only a 5xx, a 429 or a
 * network failure there withholds. An unparseable bundle, an invalid
 * signature, a missing certificate or key: rejected. A regexp cosign cannot
 * compile, or a cosign that crashed without its `Error:` framing, is an error
 * — that is not a verdict on the image.
 *
 * ---- What cosign cannot be taken at its word on (measured, v3.1.3) ----
 *
 * cosign swallows some registry failures and prints what it prints for
 * "nothing there". Measured against the fake registry in
 * `test/helpers/fakeOciRegistry.ts`, with a failure injected:
 *
 *   - `cosign download signature` / `download attestation` read the
 *     referrers index, fetch every referrer's manifest and each bundle's
 *     blob, return only what parses as a Sigstore bundle and skip the rest in
 *     silence (`GetBundles`: "there may be non-Sigstore referrers") — a
 *     manifest or blob the registry failed to serve included — then read the
 *     legacy tag, which fails loudly ("remote image: GET …").
 *   - `cosign verify` falls back to legacy signatures when the referrers
 *     call fails, or when no bundle parses, and says "no signatures found"
 *     (exit 10) — also for an image signed with a v3 bundle.
 *   - `cosign verify`'s exit 12 joins ONE error per signature, a transient
 *     one included.
 *   - `cosign tree` is not used at all. It prints a referrer's predicate-type
 *     annotation — the pusher's text — as it finds it, so an annotation
 *     holding a line break forges listing lines (round 4, I4), and it cannot
 *     fetch an OCI index attached as a referrer (I5).
 *
 * ---- The registry's own answers: cosign's `-d` trace ----
 *
 * So every download that decides an absence runs with `-d`, and what the
 * registry answered is read from cosign's request log (go-containerregistry's
 * transport logger, {@link parseRegistryTrace}):
 *
 *   - WHAT is attached is the referrers index the registry generated — its
 *     JSON is dumped in the log (or, where the registry has no referrers API,
 *     the `sha256-<hex>` fallback tag's index): digests, artifact types and
 *     annotations. Nothing cosign prints about them is read.
 *   - WHETHER each was served is the registry's status for its manifest, and
 *     for every bundle blob cosign fetched ({@link referrerFaults}): a 5xx, a
 *     429, a refusal, a transport error, a body that could not be read, or a
 *     referrer never fetched makes the answer unknown — never "absent", never
 *     a rejection. A 404, or a manifest served and judged no bundle (its blob
 *     never asked for), is the registry answering.
 *   - The fallback tag is not the registry's: whoever can push writes it,
 *     and cosign 3.1.3 is silent about any tag it cannot use (measured,
 *     round 5). Served and holding no index cosign reads, it is nothing
 *     attached; an entry of it cosign never fetched is not attached. It is
 *     read as go-containerregistry reads it (Go's encoding/json: field names
 *     case-insensitive, the last key wins), so what cosign did fetch from it
 *     is judged like any referrer. Only the registry failing to serve the tag
 *     withholds. "Never fetched" stays a fault for the index the registry's
 *     referrers API generates.
 *   - A log cut at its size cap is "could not be probed".
 *
 * One fault the log cannot show: a blob answered 200 whose body broke
 * mid-transfer (go-containerregistry logs the status, and redacts blob
 * bodies) reads exactly like a bundle that does not parse (round 4, I6). So
 * when the registry served more Sigstore bundles whole (manifest and blob
 * 2xx) than cosign returned, detect downloads once more and, still short,
 * answers unknown; verify, after its own re-run, rejects — and says both
 * causes. A bundle the registry answered 404 for is no such doubt.
 *
 * The log is read only for records that START with the logger's timestamp:
 * a line inside a dumped manifest body cannot, as long as the registry holds
 * JSON manifests. A registry that serves non-JSON manifests could forge one —
 * and could as easily fail the blob for real.
 *
 * ---- One registry fault no request reveals ----
 *
 * go-containerregistry (remote/referrers.go, v0.21.7) reads a referrers
 * answer that is no OCI index at all — an HTML 200, a 400, a 406 — as "this
 * registry has no referrers API", falls back to the tag schema, finds
 * nothing, and reports nothing. A registry that holds referrers and answers
 * that way makes a signed image read unsigned; neither cosign nor this can
 * tell. (A 200 index with a Content-Type other than exactly the OCI index
 * type, which go-containerregistry ignores the same way, IS seen: the index
 * is in the log, and a referrer cosign then never fetched cannot be probed.)
 * SECURITY.md and the tool's description say so.
 *
 * ---- Time ----
 *
 * Every cosign call for one image shares ONE deadline — the tool's timeout,
 * `GUARDIAN_SCAN_TIMEOUT_MS` (10 min by default) — and gets the time left,
 * at most {@link COSIGN_TIMEOUT_MS}. When it runs out, what was not settled
 * is no verdict, and says so.
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
 * cosign older than 3.0 is not used at all: it does not read OCI referrers
 * unless asked (`--experimental-oci11`) — measured: cosign 2.6.5's `tree` on
 * a signed `ghcr.io/sigstore/cosign/cosign:v3.1.3` prints "No … Artifacts
 * found", exit 0.
 */

import { compareSemver } from '../platform/semverCompare.js';
import type { Finding, ToolRun } from '../types.js';
import { runProcess, type ProcessRunResult } from './processRunner.js';
import { makeFinding } from './scannerParsers/index.js';
import { extractVersion } from './toolProbe.js';

/**
 * The weaknesses of the three findings, as annotations — the OWASP 2025
 * category follows from OWASP's own CWE lists (`frameworks/taxonomy.ts`):
 *
 *   - `image-signature-not-verified`: CWE-347, Improper Verification of
 *     Cryptographic Signature — there is a signature, and it does not verify
 *     for the expected signer. OWASP 2025: A04.
 *   - `image-unsigned`, `image-no-provenance`: CWE-345, Insufficient
 *     Verification of Data Authenticity — nothing signed ties the image to
 *     whoever built it, so whoever deploys it cannot verify where it came
 *     from. OWASP 2025: A08 (Software or Data Integrity Failures). Not
 *     CWE-1357 (Reliance on Insufficiently Trustworthy Component, A03): that
 *     is a judgement of the image itself, and an absent signature shows only
 *     that its authenticity cannot be checked, not that it is untrustworthy.
 */
const SIGNATURE_NOT_VERIFIED_CWE = 'CWE-347';
const AUTHENTICITY_NOT_VERIFIABLE_CWE = 'CWE-345';

/** Findings of a real `cosign verify`. */
export const COSIGN_VERIFY_TOOL_NAME = 'cosign-verify';
/** Findings of the existence check: what is attached as OCI referrers (and the legacy tags). */
export const COSIGN_REFERRERS_TOOL_NAME = 'cosign-referrers';

/** Each cosign call's own ceiling; cosign's own default `--timeout` is 3 min too. */
export const COSIGN_TIMEOUT_MS = 180_000;
/** One image's budget when `GUARDIAN_SCAN_TIMEOUT_MS` sets none — `runProcess`'s own default. */
const DEFAULT_IMAGE_BUDGET_MS = 10 * 60 * 1000;
/** The oldest cosign that reads OCI referrers by default. */
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

/**
 * `text` with every URL's query string removed. A registry hands a blob to a
 * CDN through a signed URL whose credentials are its query (ghcr.io does,
 * measured), and cosign's errors and request log print such a URL whole.
 */
export function stripQueries(text: string): string {
  // The query ends at whitespace, a quote, a fragment — or at the `: ` go-containerregistry puts after a URL.
  return text.replace(/(\b[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s?#"'`<>]*)\?[^\s#"'`<>]*?(?=:\s|:$|[\s#"'`<>]|$)/g, '$1');
}

/** Text cosign or a registry printed, fit for a reason, a note, a finding or a log line. */
function say(text: string): string {
  return escapeUnsafe(stripQueries(text));
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
  const detail = firstError(r.stderr) ?? `cosign triangulate ${r.outcome.replace(/_/g, ' ')}`;
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
// The registry's own answers: cosign's `-d` trace (round 3 I3, round 4 I4–I6)
// ---------------------------------------------------------------------------

export type Presence = 'present' | 'absent' | 'unknown';
export type FetchOutcome = 'served' | 'missing' | 'failed';

/** The predicate type of a cosign v3 image signature. */
const SIGN_PREDICATE = 'https://sigstore.dev/cosign/sign/v1';
/** What `cosign verify` prints as `critical.type` for an image signature, legacy or v3. */
const VERIFIED_SIGNATURE_TYPES: ReadonlySet<string> = new Set(['cosign container image signature', SIGN_PREDICATE]);
const BUNDLE_MEDIA_TYPE = /^application\/vnd\.dev\.sigstore\.bundle/;
/** The annotation cosign and GitHub put on a bundle referrer: its DSSE predicate type. */
const PREDICATE_ANNOTATION = 'dev.sigstore.bundle.predicateType';
/** The predicate types `download attestation` is asked for, newest first. */
export const PROVENANCE_PREDICATE_TYPES = ['https://slsa.dev/provenance/v1', 'https://slsa.dev/provenance/v0.2'] as const;

/** The registry's final answer to one request (a 3xx followed). */
export interface TraceAnswer {
  outcome: FetchOutcome;
  status: number | null;
  /** `200 https://…/manifests/sha256:…`, or a transport error — no query string, escaped. */
  detail: string;
  /** The body the log dumped for a 2xx (manifests and indexes; blob bodies are redacted), dechunked. */
  body: string | null;
}

/** One referrer as the registry's referrers index lists it — the registry's JSON, not cosign's words. */
export interface IndexedReferrer {
  digest: string;
  artifactType: string;
  /** The `dev.sigstore.bundle.predicateType` annotation, when the index carries one. */
  predicateType: string | null;
  /** Its artifactType is a Sigstore bundle's media type. */
  sigstore: boolean;
  /**
   * Read from the `sha256-<hex>` fallback tag, which whoever can push writes
   * — not from the index the registry's referrers API generates.
   */
  fromTag: boolean;
}

export type ReferrerIndex =
  | {
      state: 'listed';
      referrers: IndexedReferrer[];
      /** The fallback tag was served but held nothing cosign reads as an index (round 5, ruling 1). */
      tagHeldNoIndex?: boolean;
    }
  | { state: 'failed' | 'unprobed'; detail: string };

/** What one traced cosign call shows the registry answered. */
export interface RegistryTrace {
  /** By reference as requested (a digest, or a tag). */
  manifests: Map<string, TraceAnswer>;
  /** By digest. */
  blobs: Map<string, TraceAnswer>;
  /** The referrers of the subject(s) cosign looked up. */
  index: ReferrerIndex;
}

/** go-containerregistry's logger: every record starts a line with this timestamp. */
const TRACE_RECORD = /^\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2} /gm;
const TRACE_REQUEST = /^\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2} --> /m;
const TRACE_STATUS = /^<-- (\d{3}) (\S+)/;
const TRACE_TRANSPORT_ERROR = /^<-- (.+?) (?:GET|HEAD|POST|PUT|PATCH|DELETE) (\S+) \(/;
const TRACE_DUMP_FAILED = /^Failed to dump response (?:GET|HEAD|POST|PUT|PATCH|DELETE) (\S+): (.*)/;
const REGISTRY_PATH = /\/v2\/.+\/(manifests|blobs|referrers)\/([^/\s]+)$/;
/** The tag schema's referrers index: `sha256-<hex>`, nothing after it (`.sig`, `.att` are legacy tags). */
const FALLBACK_TAG = /^([a-z0-9]+)-([0-9a-f]{32,})$/;
/** Answers after which go-containerregistry reads the tag schema instead of the referrers API. */
const FALLS_BACK: ReadonlySet<number | null> = new Set([404, 400, 406]);
/** `runProcess`'s marker for a stderr cut at its cap. */
const TRUNCATED = '…(truncated)\n';

/**
 * What a `cosign … -d` trace shows the registry answered: every manifest and
 * blob request's final status (a 3xx followed — registries hand blobs to a
 * CDN, ghcr.io does, measured; the last answer wins, go-containerregistry
 * retries), and the referrers index the registry itself generated, read from
 * the dumped body. A trace that is missing, or cut at the stderr cap, holds
 * no index: "could not be probed", never "nothing attached".
 */
export function parseRegistryTrace(stderr: string): RegistryTrace {
  const none = (detail: string): RegistryTrace => ({ manifests: new Map(), blobs: new Map(), index: { state: 'unprobed', detail } });
  if (!TRACE_REQUEST.test(stderr)) return none('cosign printed no request log');
  if (stderr.includes(TRUNCATED)) return none("cosign's request log was cut at its size cap, so what the registry answered could not be read");

  interface Raw {
    url: string;
    status: number | null;
    detail: string;
    body: string | null;
  }
  const answers: Raw[] = [];
  // The dump of an answer is the record right after it (cosign 3.1.3 fetches in sequence, measured).
  let dumpFor: Raw | null = null;
  const starts = [...stderr.matchAll(TRACE_RECORD)];
  for (let i = 0; i < starts.length; i++) {
    const m = starts[i];
    if (m === undefined) continue;
    const next = starts[i + 1];
    const record = stderr.slice(m.index + m[0].length, next === undefined ? stderr.length : next.index);
    const line = record.split(/\r?\n/, 1)[0] ?? '';
    const owner = dumpFor;
    dumpFor = null;
    const status = TRACE_STATUS.exec(line);
    if (status?.[1] !== undefined && status[2] !== undefined) {
      const answer: Raw = { url: status[2], status: Number(status[1]), detail: `${status[1]} ${status[2]}`, body: null };
      answers.push(answer);
      dumpFor = answer;
      continue;
    }
    const err = TRACE_TRANSPORT_ERROR.exec(line);
    if (err?.[1] !== undefined && err[2] !== undefined) {
      answers.push({ url: err[2], status: null, detail: `${err[1]} (${err[2]})`, body: null });
      continue;
    }
    const dumpFailed = TRACE_DUMP_FAILED.exec(line);
    if (dumpFailed?.[1] !== undefined) {
      answers.push({ url: dumpFailed[1], status: null, detail: `the body could not be read: ${dumpFailed[2] ?? ''} (${dumpFailed[1]})`, body: null });
      continue;
    }
    if (owner !== null && line.startsWith('HTTP/')) owner.body = dumpedBody(record);
  }

  const manifests = new Map<string, TraceAnswer>();
  const blobs = new Map<string, TraceAnswer>();
  const apis = new Map<string, TraceAnswer>();
  const tags = new Map<string, TraceAnswer>();
  for (let i = 0; i < answers.length; i++) {
    const first = answers[i];
    if (first === undefined) continue;
    const place = REGISTRY_PATH.exec(first.url.replace(/[?#].*$/, ''));
    // A CDN hop, the /v2/ ping, a token exchange: not keyed on their own.
    if (place?.[1] === undefined || place[2] === undefined) continue;
    let final = first;
    for (let j = i; final.status !== null && final.status >= 300 && final.status < 400; ) {
      j += 1;
      const hop = answers[j];
      if (hop === undefined) break;
      final = hop;
    }
    const answer: TraceAnswer = { outcome: outcomeOf(final.status), status: final.status, detail: clip(say(final.detail)), body: final.body };
    const ref = place[2];
    if (place[1] === 'blobs') blobs.set(ref, answer);
    else if (place[1] === 'referrers') apis.set(ref, answer);
    else {
      const tag = FALLBACK_TAG.exec(ref);
      if (tag?.[1] !== undefined && tag[2] !== undefined) tags.set(`${tag[1]}:${tag[2]}`, answer);
      else manifests.set(ref, answer);
    }
  }
  return { manifests, blobs, index: referrerIndex(apis, tags) };
}

function outcomeOf(status: number | null): FetchOutcome {
  if (status !== null && status >= 200 && status < 300) return 'served';
  return status === 404 ? 'missing' : 'failed';
}

/**
 * The referrers the registry listed, per subject looked up: its referrers
 * API's index when that answered with one; otherwise — 404, 400, 406, or a
 * 2xx holding no index, go-containerregistry's fallback cases — the tag
 * schema's index, 404 there meaning none. The fallback tag is whatever a
 * pusher wrote: served, and no index cosign reads, it is nothing attached
 * (cosign 3.1.3 is silent about it, measured) — round 5, ruling 1. Only the
 * registry's own failure withholds: a 5xx, a 429, a refusal, a transport
 * error, a body that could not be read. A fallback never read is a lookup
 * never finished.
 */
function referrerIndex(apis: Map<string, TraceAnswer>, tags: Map<string, TraceAnswer>): ReferrerIndex {
  const subjects = new Set([...apis.keys(), ...tags.keys()]);
  if (subjects.size === 0) return { state: 'unprobed', detail: "cosign's request log shows no referrers lookup" };
  const referrers: IndexedReferrer[] = [];
  let tagHeldNoIndex = false;
  for (const subject of subjects) {
    const api = apis.get(subject);
    const fromApi = api?.outcome === 'served' ? readIndex(api.body, false) : null;
    if (fromApi !== null) {
      referrers.push(...fromApi);
      continue;
    }
    if (api !== undefined && api.outcome !== 'served' && !FALLS_BACK.has(api.status)) {
      return { state: 'failed', detail: `the registry's referrers API answered ${api.detail}` };
    }
    const tag = tags.get(subject);
    if (tag === undefined) {
      return { state: 'unprobed', detail: "the registry's referrers index was never read (cosign's request log shows no answer for the fallback tag)" };
    }
    if (tag.outcome === 'missing') continue;
    if (tag.outcome === 'failed') return { state: 'failed', detail: `the referrers fallback tag answered ${tag.detail}` };
    const fromTag = readIndex(tag.body, true);
    if (fromTag === null) tagHeldNoIndex = true;
    else referrers.push(...fromTag);
  }
  const seen = new Set<string>();
  const unique = referrers.filter((r) => {
    if (seen.has(r.digest)) return false;
    seen.add(r.digest);
    return true;
  });
  return tagHeldNoIndex ? { state: 'listed', referrers: unique, tagHeldNoIndex } : { state: 'listed', referrers: unique };
}

/**
 * An OCI index's `manifests`, or null when `body` holds no index — its
 * fields found as go-containerregistry finds them ({@link goField}), so that
 * what cosign fetched from a pusher's fallback tag is what this reads. Loose
 * otherwise: an entry this lists and cosign never fetched is harmless from
 * the fallback tag (it is not attached), and the registry's own index is
 * well formed.
 */
function readIndex(body: string | null, fromTag: boolean): IndexedReferrer[] | null {
  const index = body === null ? undefined : firstJsonObject(body);
  const manifests = isRecord(index) ? goField(index, 'manifests') : undefined;
  if (!Array.isArray(manifests)) return null;
  const out: IndexedReferrer[] = [];
  for (const entry of manifests as unknown[]) {
    if (!isRecord(entry)) continue;
    const digest = goField(entry, 'digest');
    if (typeof digest !== 'string') continue;
    const type = goField(entry, 'artifacttype');
    const artifactType = typeof type === 'string' ? type : '';
    const annotations = goField(entry, 'annotations');
    const predicate = isRecord(annotations) ? annotations[PREDICATE_ANNOTATION] : undefined;
    out.push({
      digest,
      artifactType,
      predicateType: typeof predicate === 'string' ? predicate : null,
      sigstore: BUNDLE_MEDIA_TYPE.test(artifactType),
      fromTag,
    });
  }
  return out;
}

/**
 * A JSON object's field as Go's encoding/json fills a struct field from it
 * (go-containerregistry parses an index that way): the key matches the
 * field's name case-insensitively — Unicode simple folding, so `ſ` is `s`
 * and the Kelvin sign is `k` — and the last matching key wins (measured by
 * the round-5 review: `{"manifests":[…],"Manifests":[]}` is an empty index
 * to cosign). `name` is lower case.
 */
function goField(obj: Record<string, unknown>, name: string): unknown {
  let value: unknown;
  for (const key of Object.keys(obj)) if (goFold(key) === name) value = obj[key];
  return value;
}

const LONG_S = String.fromCharCode(0x17f);
const KELVIN = String.fromCharCode(0x212a);
function goFold(key: string): string {
  return key.split(LONG_S).join('s').split(KELVIN).join('k').toLowerCase();
}

/** A manifest's layer digests, from its dumped body. */
function layersOf(body: string | null): string[] {
  const manifest = body === null ? undefined : firstJsonObject(body);
  if (!isRecord(manifest) || !Array.isArray(manifest['layers'])) return [];
  return (manifest['layers'] as unknown[]).flatMap((l) => (isRecord(l) && typeof l['digest'] === 'string' ? [l['digest']] : []));
}

/** The body of an `HTTP/1.1 …` dump record: after the headers, dechunked when it was sent chunked. */
function dumpedBody(record: string): string | null {
  const gap = /\r?\n\r?\n/.exec(record);
  if (gap === null) return null;
  const head = record.slice(0, gap.index);
  const rest = record.slice(gap.index + gap[0].length);
  return /^transfer-encoding:[ \t]*chunked[ \t]*\r?$/im.test(head) ? (dechunk(rest) ?? rest) : rest;
}

/** HTTP/1.1 chunked framing removed — sizes count bytes — or null when it is not well formed. */
function dechunk(text: string): string | null {
  const raw = Buffer.from(text, 'utf8');
  const parts: Buffer[] = [];
  let pos = 0;
  for (;;) {
    const eol = raw.indexOf(0x0a, pos);
    if (eol < 0) return null;
    const size = (raw.subarray(pos, eol).toString('latin1').split(';')[0] ?? '').trim();
    if (!/^[0-9a-fA-F]+$/.test(size)) return null;
    const n = parseInt(size, 16);
    if (n === 0) return Buffer.concat(parts).toString('utf8');
    const start = eol + 1;
    if (start + n > raw.length) return null;
    parts.push(raw.subarray(start, start + n));
    pos = start + n;
    if (raw[pos] === 0x0d) pos += 1;
    if (raw[pos] !== 0x0a) return null;
    pos += 1;
  }
}

/** The first complete JSON object in `text` (whatever follows it ignored), or undefined. */
function firstJsonObject(text: string): unknown {
  const start = text.indexOf('{');
  if (start < 0) return undefined;
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') inString = true;
    else if (c === '{' || c === '[') depth += 1;
    else if (c === '}' || c === ']') {
      depth -= 1;
      if (depth === 0) {
        try {
          return JSON.parse(text.slice(start, i + 1)) as unknown;
        } catch {
          return undefined;
        }
      }
    }
  }
  return undefined;
}

/**
 * Why what the registry's referrers index lists may hold a signature cosign
 * could not read — the index itself not read, a manifest or bundle blob the
 * registry failed to serve (5xx, 429, any refusal but 404, a transport error,
 * a body that could not be read), or a referrer of the registry's own index
 * never fetched — or null when the registry answered for every one (served,
 * or 404). cosign's `GetBundles` skips a referrer it cannot fetch in silence,
 * so without this a registry failure reads as "no signature" (round 3, I3).
 * An entry of the FALLBACK TAG cosign never fetched is no fault: a pusher
 * wrote it, cosign did not read it, and it is not attached (round 5, I7).
 */
export function referrerFaults(trace: RegistryTrace): string | null {
  if (trace.index.state !== 'listed') return trace.index.detail;
  const failed: string[] = [];
  let unprobed = 0;
  for (const ref of trace.index.referrers) {
    const name = `${describeReferrer(ref)} referrer ${say(ref.digest)}`;
    const manifest = trace.manifests.get(ref.digest);
    if (manifest === undefined) {
      if (!ref.fromTag) unprobed += 1;
      continue;
    }
    if (manifest.outcome === 'failed') {
      failed.push(`${name}: the registry answered ${manifest.detail}`);
      continue;
    }
    if (manifest.outcome !== 'served') continue;
    // A layer never asked for is one cosign judged no bundle: an answer, not a fault.
    for (const layer of layersOf(manifest.body)) {
      const blob = trace.blobs.get(layer);
      if (blob?.outcome === 'failed') failed.push(`${name}: its bundle ${say(layer)} — the registry answered ${blob.detail}`);
    }
  }
  if (failed.length > 0) return clip(`the registry failed to serve what its referrers index lists — ${failed.join('; ')}`, 800);
  if (unprobed > 0) return `${unprobed} referrer(s) the registry's referrers index lists could not be probed (never fetched in cosign's request log)`;
  return null;
}

/**
 * What counts as attached: every referrer of the registry's own index; of the
 * fallback tag's — which whoever can push writes — only what cosign fetched.
 */
function attachedReferrers(trace: RegistryTrace): IndexedReferrer[] {
  if (trace.index.state !== 'listed') return [];
  return trace.index.referrers.filter((r) => !r.fromTag || trace.manifests.has(r.digest));
}

/** What the fallback tag held that is nothing attached, in words — or '' when it held nothing of the kind. */
function fallbackNote(trace: RegistryTrace): string {
  if (trace.index.state !== 'listed') return '';
  const unread = trace.index.referrers.filter((r) => r.fromTag && !trace.manifests.has(r.digest)).length;
  const held: string[] = [];
  if (trace.index.tagHeldNoIndex === true) held.push('holds no OCI index cosign reads');
  if (unread > 0) held.push(`lists ${unread} ${unread === 1 ? 'entry' : 'entries'} cosign never read`);
  return held.length === 0 ? '' : `the referrers fallback tag, which anyone who can push writes, ${held.join(' and ')}: nothing attached`;
}

/** A referrer in words: a bundle by the predicate type its annotation names, anything else by its artifactType. */
function describeReferrer(ref: IndexedReferrer): string {
  if (ref.sigstore) return `Sigstore bundle (${ref.predicateType === null ? 'no predicate type named' : say(ref.predicateType)})`;
  return ref.artifactType === '' ? 'untyped' : say(ref.artifactType);
}

/** What the index lists, in words, for a rejection's or a finding's detail. */
function describeListed(referrers: IndexedReferrer[]): string {
  const types = [...new Set(referrers.map(describeReferrer))];
  return `${referrers.length} OCI referrer(s) — ${clip(types.join(', '), 400)}`;
}

// ---------------------------------------------------------------------------
// The downloads: `download signature`, `download attestation`
// ---------------------------------------------------------------------------

export interface SignatureDownload {
  state: 'present' | 'attestation_only' | 'absent' | 'unknown';
  /** The predicate types of the signed attestation bundles returned (for `attestation_only`), escaped. */
  attestationTypes: string[];
  /** How many Sigstore bundles cosign returned (legacy signatures not counted). */
  bundles: number;
  /** What each returned bundle is: its DSSE predicate type, or `message signature` — raw, never printed. */
  bundleTypes: string[];
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
  const none: SignatureDownload = { state: 'unknown', attestationTypes: [], bundles: 0, bundleTypes: [] };
  if (r.outcome === 'failed') {
    return /^Error: .*no signatures associated/m.test(r.stderr) ? { state: 'absent', attestationTypes: [], bundles: 0, bundleTypes: [] } : none;
  }
  if (r.outcome !== 'completed' && r.outcome !== 'output_too_large') return none;
  let signature = false;
  let bundles = 0;
  const types: string[] = [];
  const bundleTypes: string[] = [];
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
      continue;
    }
    if (typeof item['mediaType'] !== 'string' || !BUNDLE_MEDIA_TYPE.test(item['mediaType'])) continue;
    bundles += 1;
    if (item['messageSignature'] !== undefined) {
      signature = true;
      bundleTypes.push('message signature');
      continue;
    }
    const type = dssePredicateType(item['dsseEnvelope']) ?? 'a Sigstore bundle of unknown predicate type';
    bundleTypes.push(type);
    if (type === SIGN_PREDICATE) signature = true;
    else if (!types.includes(say(type))) types.push(say(type));
  }
  if (signature) return { state: 'present', attestationTypes: types, bundles, bundleTypes };
  // Past the cap, what was cut off may have been the signature.
  if (r.outcome === 'output_too_large') return none;
  if (types.length > 0) return { state: 'attestation_only', attestationTypes: types, bundles, bundleTypes };
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
  if (r.outcome === 'failed' && /^Error: .*no attestations with predicate type/m.test(r.stderr)) return 'absent';
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
    // go-retryablehttp giving up — it retries only a 5xx, a 429 or a network failure.
    'giving up after \\d+ attempt',
    'server gave HTTP response to HTTPS client',
    // A body that stopped arriving (round 3, M1): HTTP/2 stream resets and
    // GOAWAY, a connection closed mid-read (Windows: wsarecv / wsasend).
    'stream error',
    'INTERNAL_ERROR',
    'http2: ',
    'GOAWAY',
    'wsarecv',
    'wsasend',
    'forcibly closed',
    'broken pipe',
    'connection aborted',
    // Go's url.Error: `Post "<url>": <cause>` (the URL is an echo, removed first).
    '\\b(?:Get|Post|Head|Put|Patch|Delete) "…": ',
  ].join('|'),
);
/** A registry answering with an error, as go-containerregistry and cosign frame it. */
const REGISTRY = /\b(?:GET|HEAD|POST|PUT|PATCH|DELETE) https?:\/\/\S+: (?:[A-Z][A-Z_]+\b|unexpected status code)|unexpected status code \d{3}|remote image: |image tag not found|getting referrers|Error fetching /;
/**
 * Sigstore's services (TUF) not answering. NOT Rekor's `searching log
 * query:` — cosign frames EVERY Rekor client error that way, a 400 included,
 * and Rekor answers 400 when a signature does not verify against its key
 * (round 3, I1): a Rekor answer withholds the verdict only as a 5xx or a 429
 * ({@link SERVICE_STATUS}) or a network failure ({@link NETWORK}).
 */
const SIGSTORE_SERVICE =
  /setting up clients and keys|getting rekor public keys|getting ctlog public keys|updating local metadata and targets|error updating to TUF remote mirror|tuf refresh failed|failed to download [\w.]*root\.json|getting trusted root|fetching trusted root|Could not fetch trusted_root/;
/** A service answering 5xx or 429: go-swagger's `[POST /path][503]`, go-retryablehttp's `status 503:`. */
const SERVICE_STATUS = /\]\[(?:5\d\d|429)\]|\bstatus (?:5\d\d|429):/;

/**
 * cosign's stderr with every value it echoes removed, so nothing a user or a
 * signer chose can look like a network failure:
 *
 *   - every identity-mismatch framing, from its start to the END OF ITS LINE
 *     — sigstore-go prints `expected %s value "%s", got "%s"` unescaped, so
 *     a quote in a git ref (`refs/heads/a"proxyconnect"b`) or a workflow
 *     file name breaks any quote pairing (round 3, I2); an identity mismatch
 *     is itself a rejection cause, so nothing on that line can withhold one;
 *   - the legacy subject list, from `got subjects [` to the end of its line;
 *   - then double- and backtick-quoted strings (URLs, bodies, regexps).
 */
function stripEchoes(stderr: string): string {
  return stderr
    .replace(/(?:none of the expected identities matched|no matching CertificateIdentity found|failed to verify certificate identity)[^\n]*/g, '<identity mismatch>')
    .replace(/\bexpected [^\n]*?\bvalue\b[^\n]*/g, '<expected value>')
    .replace(/\bgot "[^\n]*/g, '<got value>')
    .replace(/got subjects \[[^\n]*/g, 'got subjects […]')
    .replace(/"[^"\n]*"/g, '"…"')
    .replace(/`[^`\n]*`/g, '`…`');
}

/** A network, registry or Sigstore-service failure in cosign's own framing — the question was not answered. */
function withheld(stderr: string): boolean {
  const own = stripEchoes(stderr);
  return NETWORK.test(own) || REGISTRY.test(own) || SIGSTORE_SERVICE.test(own) || SERVICE_STATUS.test(own);
}

/**
 * Every error cosign folded into its `Error:` block — one per signature or
 * bundle for exit 12 — joined and bounded, for a finding's detail.
 */
function errorBlock(stderr: string): string | null {
  const lines = stderr.split(/\r?\n/);
  const start = lines.findIndex((l) => l.startsWith('Error: '));
  if (start < 0) return null;
  const parts: string[] = [];
  for (let i = start; i < lines.length; i++) {
    const line = lines[i] ?? '';
    if (i > start && (line.startsWith('error during command execution:') || line.startsWith('Error: '))) break;
    const text = (i === start ? line.slice('Error: '.length) : line).trim();
    if (text.length > 0) parts.push(text);
  }
  return clip(say(parts.join(' | ')), 800);
}

/** Words a network failure is described with — for the re-run advice on a rejection, never to decide one. */
const NETWORKISH = /timeout|timed out|connection|network|dial|\bEOF\b|reset|refused|unavailable|temporar|stream error|GOAWAY|TLS|rate limit/i;

/** How a `cosign verify` ended — see the module comment for the rule. */
export function classifyVerify(r: ProcessRunResult): VerifyVerdict {
  if (r.outcome === 'completed') return { verdict: 'verified', ...verifiedPayloads(r.stdout) };
  if (r.outcome !== 'failed') return { verdict: 'error', detail: firstError(r.stderr) ?? `cosign verify ${r.outcome.replace(/_/g, ' ')}` };
  const framed = r.stderr.split(/\r?\n/).some((l) => l.startsWith('Error: '));
  const detail = firstError(r.stderr) ?? `cosign verify exited ${r.exitCode ?? '(no exit code)'}`;
  if (!framed) return { verdict: 'error', detail: `cosign verify ended without its error framing — ${detail}` };
  if (r.exitCode === 10) return { verdict: 'no_signature_claimed', detail };
  if (BAD_REGEXP.test(r.stderr)) return { verdict: 'error', detail: `a signer regexp cosign cannot compile — ${detail}` };
  if (r.exitCode === 11 || withheld(r.stderr)) return { verdict: 'error', detail };
  // A rejection names every error cosign folded in (one per signature), bounded.
  const all = errorBlock(r.stderr) ?? detail;
  if (IDENTITY_MISMATCH.test(r.stderr)) return { verdict: 'rejected', reason: 'no_matching_signature', detail: all };
  if (NO_KEY_MATERIAL.test(r.stderr)) return { verdict: 'rejected', reason: 'no_certificate', detail: all };
  return { verdict: 'rejected', reason: 'invalid_signature', detail: all };
}

/** What `cosign verify` accepted (`critical.type` of each payload, escaped) and over which digest. */
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
    if (typeof type === 'string' && !types.includes(say(type))) types.push(say(type));
    const image = critical['image'];
    const d = isRecord(image) ? image['docker-manifest-digest'] : undefined;
    if (typeof d === 'string' && digest === undefined) digest = say(d);
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

/** The first `Error: …` line cosign printed, without the prefix — bounded, no query string, escaped. */
function firstError(stderr: string): string | null {
  for (const raw of stderr.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith('Error: ')) return clip(say(line.slice('Error: '.length)));
  }
  // A `-d` trace is not an error message, and holds headers and bodies: never quote a line of it.
  if (TRACE_REQUEST.test(stderr)) return null;
  const first = stderr
    .split(/\r?\n/)
    .map((l) => l.trim())
    .find((l) => l.length > 0 && !l.startsWith('Command "triangulate" is deprecated'));
  return first === undefined ? null : clip(say(first));
}

function clip(text: string, max = 400): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
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
  /** The one `tools_run` entry: `cosign-verify` or `cosign-referrers`, with the image as its target. */
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

/** One image's cosign calls: their shared deadline, and whether one was cancelled or cut by it. */
interface ImageRun {
  ctx: CosignRunContext;
  budgetMs: number;
  deadline: number;
  exhausted: boolean;
  cancelled: boolean;
}

/**
 * The image's budget: the tool's timeout, read as `runProcess` reads it
 * (unset or 0: 10 min; negative: none), shared by every call.
 */
function imageRun(ctx: CosignRunContext): ImageRun {
  const configured = Number(process.env['GUARDIAN_SCAN_TIMEOUT_MS']) || DEFAULT_IMAGE_BUDGET_MS;
  const budgetMs = Number.isFinite(configured) && configured > 0 ? configured : Number.POSITIVE_INFINITY;
  return { ctx, budgetMs, deadline: Date.now() + budgetMs, exhausted: false, cancelled: false };
}

function budgetWords(run: ImageRun): string {
  return (
    `this image's time budget ran out — ${Math.round(run.budgetMs / 1000)} s (GUARDIAN_SCAN_TIMEOUT_MS), shared by ` +
    'all its cosign calls; nothing was concluded from the calls it cut short'
  );
}

/** stdout cap for a traced call: runProcess caps stderr at a tenth of it — 3.2 MB of trace. */
const TRACED_CAP_BYTES = 32 * 1024 * 1024;

/**
 * One cosign call, within the image's deadline. `traced`: with `-d`
 * (go-containerregistry's request log on stderr, read by
 * {@link parseRegistryTrace}) — its stderr is never forwarded as progress (it
 * holds headers and manifest bodies; credentials are `<redacted>` by
 * go-containerregistry, but nothing of it belongs in a notification), and it
 * gets a larger cap. No call starts once one was cancelled, or once the
 * deadline passed; a call the deadline cut says so in an `Error:` line.
 */
async function cosign(args: string[], run: ImageRun, traced = false): Promise<ProcessRunResult> {
  const idle = (outcome: 'cancelled' | 'timed_out', stderr: string): ProcessRunResult => ({ outcome, exitCode: null, stdout: '', stderr, truncated: false });
  if (run.cancelled || aborted(run.ctx)) {
    run.cancelled = true;
    return idle('cancelled', '');
  }
  const remaining = run.deadline - Date.now();
  if (remaining <= 0) {
    run.exhausted = true;
    return idle('timed_out', `Error: ${budgetWords(run)}\n`);
  }
  const [sub, ...rest] = args;
  const withTrace = traced && sub !== undefined ? [sub, ...(sub === 'download' && rest[0] !== undefined ? [rest[0], '-d', ...rest.slice(1)] : ['-d', ...rest])] : args;
  const onLog = run.ctx.onLog;
  const r = await runProcess({
    command: 'cosign',
    args: withTrace,
    cwd: run.ctx.cwd,
    env: run.ctx.env,
    timeoutMs: Math.min(COSIGN_TIMEOUT_MS, remaining),
    ...(traced ? { stdoutCapBytes: TRACED_CAP_BYTES } : {}),
    ...(run.ctx.signal !== undefined ? { signal: run.ctx.signal } : {}),
    ...(onLog !== undefined && !traced ? { onLog: (line: string) => onLog(say(line)) } : {}),
  });
  if (r.outcome === 'cancelled') run.cancelled = true;
  if (r.outcome === 'timed_out' && remaining < COSIGN_TIMEOUT_MS) {
    run.exhausted = true;
    return { ...r, stderr: `${r.stderr}\nError: ${budgetWords(run)}\n` };
  }
  return r;
}

/** What a call that did not answer said, or how it ended. */
function callWhy(r: ProcessRunResult): string {
  return firstError(r.stderr) ?? r.outcome.replace(/_/g, ' ');
}

/** Whether this cosign can be used (`cosign version`) — see {@link readinessFromProbe}. */
export async function cosignReadiness(ctx: CosignRunContext): Promise<CosignReadiness> {
  return readinessFromProbe(await cosign(['version'], imageRun(ctx)));
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
async function pin(image: string, pass: 'cosign-verify' | 'cosign-referrers', run: ImageRun, extra: Partial<ToolRun>): Promise<Pinned | CosignImageCheck> {
  const r = await cosign(['triangulate', '--type', 'digest', image], run);
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
        : { name: 'cosign-referrers', status: 'failed', reason: `image ${image}: ${why}`, target: image, ...extra },
    findings: [],
    summary: {
      image,
      checked: null,
      check: pass === 'cosign-verify' ? 'verify' : 'detect',
      signature: 'unknown',
      provenance: pass === 'cosign-verify' ? 'not_checked' : 'unknown',
      note: `Not checked: ${why}`,
    },
    cancelled: run.cancelled || aborted(run.ctx),
  };
}

function isCheck(p: Pinned | CosignImageCheck): p is CosignImageCheck {
  return 'run' in p;
}

/** Whether the scan was cancelled — asked before each cosign, and once more at the end. */
function aborted(ctx: CosignRunContext): boolean {
  return ctx.signal?.aborted === true;
}

/**
 * The Sigstore-typed referrers the registry served whole — manifest and every
 * bundle blob answered 2xx: what cosign should have returned. A 404, or a
 * blob cosign never asked for (it judged the manifest no bundle), is an
 * answer; only a 2xx can hide a body that broke mid-transfer (round 4, I6).
 */
function servedBundles(trace: RegistryTrace): IndexedReferrer[] {
  if (trace.index.state !== 'listed') return [];
  return trace.index.referrers.filter((r) => {
    if (!r.sigstore) return false;
    const manifest = trace.manifests.get(r.digest);
    if (manifest?.outcome !== 'served') return false;
    const layers = layersOf(manifest.body);
    return layers.length > 0 && layers.every((l) => trace.blobs.get(l)?.outcome === 'served');
  });
}

/** How many bundles the registry served whole beyond the `returned` cosign printed, or 0. */
function sigstoreShortfall(trace: RegistryTrace, returned: number): number {
  return Math.max(0, servedBundles(trace).length - returned);
}

/** Why a bundle listed and served but not returned is not "absent" — the two causes the log cannot tell apart. */
const UNREADABLE_BUNDLE =
  'listed and served, but cosign could not use it — not a bundle it can parse, or the transfer failed mid-body; ' +
  're-run if the registry was unstable';

/**
 * verify's "no signatures found" (exit 10), settled: a rejection only when
 * the registry answered for everything attached — see the module comment.
 * Never a rejection from a call that did not answer (cancelled, cut by the
 * deadline, failed).
 */
async function settleNoSignature(ref: string, policy: SignerPolicy, claim: string, run: ImageRun): Promise<VerifyVerdict> {
  const unconfirmed = (why: string): VerifyVerdict => ({ verdict: 'error', detail: `cosign verify said "${claim}", which could not be confirmed: ${why}` });
  const nothing = (trace: RegistryTrace): VerifyVerdict => {
    const note = fallbackNote(trace);
    return {
      verdict: 'rejected',
      reason: 'no_signature',
      detail:
        `${claim} — nothing is attached to this digest (the registry's referrers index lists nothing` +
        `${note === '' ? '' : `; ${note}`}, and the .sig tag holds none)`,
    };
  };

  const probe = await cosign(['download', 'signature', ref], run, true);
  const first = classifySignatureDownload(probe);
  if (first.state === 'unknown') return unconfirmed(`cosign download signature did not answer — ${callWhy(probe)}`);
  if (first.state === 'absent') {
    const trace = parseRegistryTrace(probe.stderr);
    if (trace.index.state !== 'listed') return unconfirmed(trace.index.detail);
    if (attachedReferrers(trace).length === 0) return nothing(trace);
  }

  // Something is attached: verify once more — a referrers call that failed
  // the first time reads the same as one that found nothing usable.
  const again = await cosign(verifyArgs(ref, policy), run);
  const v = classifyVerify(again);
  if (v.verdict !== 'no_signature_claimed') return v;

  // "No signatures found" twice, with something attached. cosign skips in
  // silence a referrer it cannot fetch, so before calling that a rejection,
  // ask the registry — through cosign's own trace of the same fetches —
  // whether it served everything its index lists (round 3, I3; round 4, I4–I6).
  const probe2 = await cosign(['download', 'signature', ref], run, true);
  const second = classifySignatureDownload(probe2);
  if (second.state === 'present' || second.state === 'attestation_only') {
    return {
      verdict: 'error',
      detail: `cosign verify found no signature twice, but cosign download signature now returns ${second.state === 'present' ? 'one' : 'a signed attestation'} — the registry answered differently; not a verdict`,
    };
  }
  if (second.state === 'unknown') return unconfirmed(`cosign download signature did not answer — ${callWhy(probe2)}`);
  const trace = parseRegistryTrace(probe2.stderr);
  const fault = referrerFaults(trace);
  if (fault !== null) return { verdict: 'error', detail: `cosign verify said "${claim}", but ${fault} — not a verdict` };
  const listed = attachedReferrers(trace);
  if (listed.length === 0) return nothing(trace);
  const served = servedBundles(trace).length > 0;
  return {
    verdict: 'rejected',
    reason: 'no_signature',
    detail: served
      ? `the registry's referrers index lists ${describeListed(listed)} for this digest: ${UNREADABLE_BUNDLE}. cosign ` +
        'verify found no signature it can use, twice — and anyone who can push to the repository can attach a bundle ' +
        'that does not parse'
      : `the registry's referrers index lists ${describeListed(listed)} for this digest, and the registry answered for ` +
        'each (served, or 404) — none is a Sigstore bundle cosign can read: cosign verify found no signature, twice. An ' +
        'artifact that is not a Sigstore signature is no signature — anyone who can push to the repository can attach one',
  };
}

/** `cosign verify` of `image` against `policy`. */
export async function verifyImage(image: string, policy: SignerPolicy, ctx: CosignRunContext): Promise<CosignImageCheck> {
  const run = imageRun(ctx);
  const signer = canonicalSignerPolicy(policy);
  const pinned = await pin(image, 'cosign-verify', run, { signer });
  if (isCheck(pinned)) return pinned;
  const warnings = unanchoredSignerRegexps(policy);
  const first = await cosign(verifyArgs(pinned.ref, policy), run);
  let v = classifyVerify(first);
  if (v.verdict === 'no_signature_claimed') v = await settleNoSignature(pinned.ref, policy, v.detail, run);
  // Cancelled at any point: the scan says so (round 4, M6).
  const cancelled = run.cancelled || aborted(ctx);
  const who = describePolicy(policy);
  const result = (outcome: 'ok' | 'failed', reason: string): ToolRun => ({
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
      run: result('ok', `signature verified for ${who} — cosign accepted ${accepted}`),
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
      run: result('failed', `cosign verify did not reach a verdict — ${v.detail}`),
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
      'signer_issuer if the image is legitimately signed by another workflow).' +
      (NETWORKISH.test(v.detail)
        ? ' The detail above names what reads like a network or service error, which cosign did not frame as one: ' +
          're-run the scan before acting on this finding.'
        : ''),
    file_path: image,
    // The signer is part of what this finding says: a rejection for another
    // signer is another finding, never this one unchanged.
    snippet: `${image} signer=${signer}`,
    fix_available: false,
    // CWE-347, Improper Verification of Cryptographic Signature: the image's
    // signature does not verify for the signer the project expects. OWASP
    // 2025 files 347 under A04. An annotation: fingerprint and identity are
    // unchanged.
    taxonomy: { cwe: [SIGNATURE_NOT_VERIFIED_CWE] },
  });
  return {
    run: result('ok', `NOT verified for ${who} — ${v.detail}`),
    findings: [finding],
    summary: { image, checked: pinned.checked, check: 'verify', signature: 'rejected', provenance: 'not_checked', note: note(`Rejected: ${v.detail}.`) },
    cancelled,
  };
}

interface SignatureRead {
  state: SignatureDownload['state'];
  attestationTypes: string[];
  /** Why it is unknown, when it is. */
  why?: string;
  /** What is attached (for an absence's wording). */
  listed: IndexedReferrer[];
  /** What the fallback tag held that is nothing attached, in words, or ''. */
  note: string;
  /** What each bundle the last download returned is — a signature is never a doubt about provenance (round 5, M7). */
  bundleTypes: string[];
}

/**
 * detect's signature: what `download signature` returns, the registry's
 * answers checked in its trace — and, when the index lists more Sigstore
 * bundles than cosign returned, one more download (round 4, I6): still
 * short is unknown, never "absent".
 */
async function readSignature(ref: string, run: ImageRun): Promise<SignatureRead> {
  const unknown = (why: string, bundleTypes: string[]): SignatureRead => ({ state: 'unknown', attestationTypes: [], why, listed: [], note: '', bundleTypes });
  for (let attempt = 1; ; attempt++) {
    const dl = await cosign(['download', 'signature', ref], run, true);
    const answer = classifySignatureDownload(dl);
    if (answer.state === 'present') return { state: 'present', attestationTypes: answer.attestationTypes, listed: [], note: '', bundleTypes: answer.bundleTypes };
    if (answer.state === 'unknown') return unknown(`cosign download signature did not answer — ${callWhy(dl)}`, []);
    const trace = parseRegistryTrace(dl.stderr);
    const fault = referrerFaults(trace);
    if (fault !== null) return unknown(fault, answer.bundleTypes);
    const short = sigstoreShortfall(trace, answer.bundles);
    if (short === 0) {
      return { state: answer.state, attestationTypes: answer.attestationTypes, listed: attachedReferrers(trace), note: fallbackNote(trace), bundleTypes: answer.bundleTypes };
    }
    if (attempt >= 2) {
      return unknown(
        `the registry served ${short} Sigstore bundle(s) its referrers index lists that cosign did not return, twice — ` +
          `${UNREADABLE_BUNDLE}; the one it did not return may be the signature`,
        answer.bundleTypes,
      );
    }
  }
}

/**
 * detect's provenance of one predicate type, by the same rules as
 * {@link readSignature}. A bundle served whole and not returned may hold
 * this provenance when its annotation names this type — or names none, unless
 * `download signature` returned it as something else (`returnedTypes`: what
 * each bundle it returned is). A signature is never a doubt about
 * provenance (round 5, M7).
 */
async function readAttestation(ref: string, type: string, run: ImageRun, returnedTypes: readonly string[]): Promise<{ state: Presence; why?: string }> {
  for (let attempt = 1; ; attempt++) {
    const r = await cosign(['download', 'attestation', `--predicate-type=${type}`, ref], run, true);
    const answer = classifyAttestationDownload(r);
    if (answer === 'present') return { state: 'present' };
    if (answer === 'unknown') return { state: 'unknown', why: `cosign download attestation did not answer — ${callWhy(r)}` };
    // The same silence as for signatures: a provenance bundle the registry
    // failed to serve, or one that broke mid-body, is not "no provenance".
    const trace = parseRegistryTrace(r.stderr);
    const fault = referrerFaults(trace);
    if (fault !== null) return { state: 'unknown', why: fault };
    const served = servedBundles(trace);
    const named = served.filter((x) => x.predicateType === type).length;
    const unannotated = served.filter((x) => x.predicateType === null).length;
    const namedElse = served.length - named - unannotated;
    // What `download signature` returned as something else accounts first
    // for the bundles annotated as something else, then for the unannotated.
    const returnedElse = returnedTypes.filter((t) => t !== type).length;
    const short = named + unannotated - Math.min(unannotated, Math.max(0, returnedElse - namedElse));
    if (short === 0) return { state: 'absent' };
    if (attempt >= 2) {
      return {
        state: 'unknown',
        why: `the registry served ${short} Sigstore bundle(s) that may hold ${type} provenance, and cosign returned none, twice — ${UNREADABLE_BUNDLE}`,
      };
    }
  }
}

/** Whether `image` has a signature and signed SLSA provenance — existence only. */
export async function detectImageSupplyChain(image: string, ctx: CosignRunContext): Promise<CosignImageCheck> {
  const run = imageRun(ctx);
  const pinned = await pin(image, 'cosign-referrers', run, {});
  if (isCheck(pinned)) return pinned;

  const sig = await readSignature(pinned.ref, run);
  const signature = sig.state;
  const attestationTypes = sig.attestationTypes;

  // Provenance: only what `download attestation` returns (a parsed bundle or a legacy .att).
  let provenance: Presence = 'unknown';
  let provenanceWhy: string | undefined;
  const answers: Presence[] = [];
  for (const type of PROVENANCE_PREDICATE_TYPES) {
    if (run.cancelled) break;
    const one = await readAttestation(pinned.ref, type, run, sig.bundleTypes);
    if (one.state === 'unknown') provenanceWhy = one.why;
    answers.push(one.state);
    if (one.state === 'present') break;
  }
  provenance = answers.includes('present')
    ? 'present'
    : answers.length === PROVENANCE_PREDICATE_TYPES.length && answers.every((a) => a === 'absent')
      ? 'absent'
      : 'unknown';
  const cancelled = run.cancelled || aborted(ctx);
  if (provenance === 'unknown' && provenanceWhy === undefined && cancelled) provenanceWhy = 'cancelled';

  const findings: Finding[] = [];
  if (signature === 'absent') {
    const listed =
      (sig.listed.length > 0
        ? ` What is attached (${describeListed(sig.listed)}) is no Sigstore bundle — anyone who can push to the repository can attach such an artifact.`
        : '') + (sig.note === '' ? '' : ` Note: ${sig.note}.`);
    const legacyProvenance =
      provenance === 'present'
        ? ' A signed SLSA provenance attestation IS attached as a legacy .att tag, which `cosign verify-attestation` checks — `cosign verify` does not accept it as the image\'s signature.'
        : ' Nothing ties it to who built it.';
    findings.push(
      makeFinding({
        tool: COSIGN_REFERRERS_TOOL_NAME,
        rule_id: 'image-unsigned',
        severity: 'low',
        category: 'security',
        subcategory: 'supply-chain',
        title: `Image ${image} has no Sigstore signature`,
        message:
          `cosign found no signature for ${pinned.checked ?? image} — no .sig tag, and no signing or signed ` +
          `attestation bundle attached as an OCI referrer, which is everything \`cosign verify\` accepts.${listed}${legacyProvenance} ` +
          'On a multi-arch index this is the index: a signature on the per-platform images only is not seen. Sign it ' +
          'in the pipeline that builds it (cosign sign, keyless), then verify it before deploying: scan_containers ' +
          'with signer_identity and signer_issuer.',
        file_path: image,
        snippet: image,
        fix_available: false,
        taxonomy: { cwe: [AUTHENTICITY_NOT_VERIFIABLE_CWE] },
      }),
    );
  }
  if (provenance === 'absent') {
    findings.push(
      makeFinding({
        tool: COSIGN_REFERRERS_TOOL_NAME,
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
        taxonomy: { cwe: [AUTHENTICITY_NOT_VERIFIABLE_CWE] },
      }),
    );
  }

  const complete = signature !== 'unknown' && provenance !== 'unknown';
  const sigWords: Record<SignatureDownload['state'], string> = {
    present: 'signature present (signer NOT verified)',
    attestation_only: `no \`cosign sign\` signature, but a signed attestation (${attestationTypes.join(', ')}) (signer NOT verified)`,
    absent: 'signature absent',
    unknown: `signature unknown (${sig.why ?? 'not answered'})`,
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
      name: 'cosign-referrers',
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
