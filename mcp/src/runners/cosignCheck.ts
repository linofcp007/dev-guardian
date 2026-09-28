/**
 * cosign checks of a container image's supply chain, for `scan_containers`.
 *
 * Two different questions, never confused with each other:
 *
 *   - **verify** (a signer identity AND an OIDC issuer were given): a real
 *     `cosign verify` — the signature is checked against Sigstore's trust
 *     root and the certificate's identity against the one named. A rejection
 *     is a high finding (`cosign-verify` / `image-signature-not-verified`).
 *   - **detect** (no signer given): only whether a signature and a signed
 *     SLSA provenance attestation EXIST — `cosign tree`, then, for legacy
 *     `.att` tags whose predicate types the listing does not show,
 *     `cosign download attestation --predicate-type=…`. Absence is a low
 *     (`image-unsigned`) or info (`image-no-provenance`) finding. A
 *     signature that exists is reported `present_unverified`: anyone can
 *     sign an image, so its existence says nothing about WHO signed it, and
 *     the answer says so.
 *
 * The product's rule holds throughout: an output this module cannot read is
 * `unknown` and the check `failed` — never "absent", never "verified". That
 * matters most for `cosign tree`, which prints a human listing (emoji and
 * all) rather than JSON: a listing it does not recognise is not read as an
 * empty one, and a referrer cosign reported it could not fetch makes an
 * absence unknown.
 *
 * Everything below was measured against cosign v3.1.3 on 2026-09-28 (the
 * outputs are in `test/unit/runners/cosignCheck.test.ts`): v3 signs with a
 * Sigstore bundle attached as an OCI referrer (`https://sigstore.dev/cosign/
 * sign/v1`), older signatures are `.sig` tags, and GitHub's build-provenance
 * attestations appear as `https://slsa.dev/provenance/v1` referrers. `tree`
 * lists both kinds (its OCI 1.1 mode is on by default in v3). `verify`
 * exits 10 (no signature), 12 (no matching signature) or 13 (no
 * certificate) for a legacy signature, but 1 for a v3 bundle whose identity
 * does not match — with the same "no matching attestations" prefix that a
 * regexp it cannot compile gets, so the stderr decides.
 */

import type { Finding, ToolRun } from '../types.js';
import { runProcess, type ProcessRunResult } from './processRunner.js';
import { makeFinding } from './scannerParsers/index.js';

/** Findings of a real `cosign verify`. */
export const COSIGN_VERIFY_TOOL_NAME = 'cosign-verify';
/** Findings of the existence check (`cosign tree` + `download attestation`). */
export const COSIGN_TREE_TOOL_NAME = 'cosign-tree';

/** Each cosign call's own budget; cosign's own default `--timeout` is 3 min too. */
export const COSIGN_TIMEOUT_MS = 180_000;

/** The signer an image must be signed by: one identity form and one issuer form. */
export interface SignerPolicy {
  identity?: string;
  identityRegexp?: string;
  issuer?: string;
  issuerRegexp?: string;
}

export type Presence = 'present' | 'absent' | 'unknown';

/** What `cosign tree` listed. */
export interface CosignTreeListing {
  /** A cosign signature: a legacy `.sig` tag, or a signing bundle attached as an OCI referrer. */
  signature: boolean;
  /** Legacy `.att` attestations exist; the listing does not say of which predicate type. */
  legacyAttestations: boolean;
  /** The type cosign printed for each OCI referrer (a bundle's predicate type when it has one). */
  referrerTypes: string[];
  /** A Sigstore bundle cosign could not name a predicate type for: it could be a signature or provenance. */
  ambiguousBundles: boolean;
  /** Referrers cosign reported it could not fetch: the listing is incomplete. */
  fetchErrors: string[];
}

/** Signing bundles and cosign's own OCI 1.1 signature artifacts. */
const SIGNATURE_TYPES: ReadonlySet<string> = new Set([
  'https://sigstore.dev/cosign/sign/v1',
  'application/vnd.dev.cosign.artifact.sig.v1+json',
]);
/** SLSA provenance, any version (`https://slsa.dev/provenance/v0.2`, `…/v1`). */
const PROVENANCE_TYPE = /^https:\/\/slsa\.dev\/provenance\//;
const BUNDLE_TYPE = /^application\/vnd\.dev\.sigstore\.bundle/;
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
    ambiguousBundles: false,
    fetchErrors: stderr.split(/\r?\n/).filter((l) => TREE_FETCH_ERROR.test(l.trim())),
  };
  let recognised = false;
  for (const line of lines) {
    if (TREE_NONE.test(line)) {
      recognised = true;
    } else if (TREE_SIGNATURES.test(line)) {
      recognised = true;
      listing.signature = true;
    } else if (TREE_ATTESTATIONS.test(line)) {
      recognised = true;
      listing.legacyAttestations = true;
    } else if (TREE_SBOMS.test(line)) {
      recognised = true;
    } else {
      const type = TREE_REFERRER.exec(line)?.[1];
      if (type === undefined) continue;
      recognised = true;
      listing.referrerTypes.push(type);
      if (SIGNATURE_TYPES.has(type)) listing.signature = true;
      else if (BUNDLE_TYPE.test(type)) listing.ambiguousBundles = true;
    }
  }
  return recognised ? listing : null;
}

/** Whether the listing shows a signature; an absence it cannot vouch for is unknown. */
export function signatureFromTree(tree: CosignTreeListing): Presence {
  if (tree.signature) return 'present';
  return tree.fetchErrors.length > 0 || tree.ambiguousBundles ? 'unknown' : 'absent';
}

/**
 * Whether the listing shows SLSA provenance — or `download` when only a
 * legacy `.att` tag could hold it and its attestations must be read.
 */
export function provenanceFromTree(tree: CosignTreeListing): Presence | 'download' {
  if (tree.referrerTypes.some((t) => PROVENANCE_TYPE.test(t))) return 'present';
  if (tree.legacyAttestations) return 'download';
  return tree.fetchErrors.length > 0 || tree.ambiguousBundles ? 'unknown' : 'absent';
}

/**
 * One `cosign download attestation --predicate-type=<type>`. cosign prints
 * only attestations of that type, so any output — even past the stdout cap —
 * means one exists; its own "no attestations with predicate type" error means
 * none does. Anything else did not answer.
 */
export function classifyAttestationDownload(r: ProcessRunResult): Presence {
  if (r.outcome === 'output_too_large') return 'present';
  if (r.outcome === 'completed') return r.stdout.trim().length > 0 ? 'present' : 'unknown';
  if (r.outcome === 'failed' && /no attestations with predicate type/.test(r.stderr)) return 'absent';
  return 'unknown';
}

export type VerifyVerdict =
  | { verdict: 'verified' }
  | { verdict: 'rejected'; reason: 'no_signature' | 'no_matching_signature' | 'no_certificate'; detail: string }
  | { verdict: 'error'; detail: string };

/** A v3 bundle whose certificate names someone else (exit 1, see the module comment). */
const IDENTITY_MISMATCH = /no matching CertificateIdentity found|none of the expected identities matched/;
const BAD_REGEXP = /error parsing regexp/;

/** How a `cosign verify` ended — see the module comment for the exit codes. */
export function classifyVerify(r: ProcessRunResult): VerifyVerdict {
  if (r.outcome === 'completed') return { verdict: 'verified' };
  if (r.outcome !== 'failed') return { verdict: 'error', detail: `cosign verify ${r.outcome.replace(/_/g, ' ')}` };
  const detail = firstError(r.stderr) ?? `cosign verify exited ${r.exitCode ?? '(no exit code)'}`;
  switch (r.exitCode) {
    case 10:
      return { verdict: 'rejected', reason: 'no_signature', detail };
    case 12:
      return { verdict: 'rejected', reason: 'no_matching_signature', detail };
    case 13:
      return { verdict: 'rejected', reason: 'no_certificate', detail };
    case 1:
      if (IDENTITY_MISMATCH.test(r.stderr) && !BAD_REGEXP.test(r.stderr)) {
        return { verdict: 'rejected', reason: 'no_matching_signature', detail: firstMismatch(r.stderr) ?? detail };
      }
      return { verdict: 'error', detail };
    default:
      return { verdict: 'error', detail };
  }
}

/**
 * `cosign verify`'s argv. Each value is passed inside its own flag
 * (`--certificate-identity=<value>`), so no value can be read as another
 * option whatever it starts with; the image — already refused when it
 * starts with `-` — is last.
 */
export function verifyArgs(image: string, policy: SignerPolicy): string[] {
  const args = ['verify'];
  if (policy.identity !== undefined) args.push(`--certificate-identity=${policy.identity}`);
  if (policy.identityRegexp !== undefined) args.push(`--certificate-identity-regexp=${policy.identityRegexp}`);
  if (policy.issuer !== undefined) args.push(`--certificate-oidc-issuer=${policy.issuer}`);
  if (policy.issuerRegexp !== undefined) args.push(`--certificate-oidc-issuer-regexp=${policy.issuerRegexp}`);
  args.push(image);
  return args;
}

/** The first `Error: …` line cosign printed, without the prefix, bounded. */
function firstError(stderr: string): string | null {
  for (const raw of stderr.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith('Error: ')) return clip(line.slice('Error: '.length));
  }
  const first = stderr.split(/\r?\n/).find((l) => l.trim().length > 0);
  return first === undefined ? null : clip(first.trim());
}

/** For a v3 bundle mismatch, the line naming what the certificate held. */
function firstMismatch(stderr: string): string | null {
  const line = stderr.split(/\r?\n/).find((l) => IDENTITY_MISMATCH.test(l));
  return line === undefined ? null : clip(line.trim());
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
  /** `verify`: a signer was named; `detect`: existence only; `skipped`: cosign did not run. */
  check: 'verify' | 'detect' | 'skipped';
  signature: 'verified' | 'rejected' | 'present_unverified' | 'absent' | 'unknown';
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
  return { image, check: 'skipped', signature: 'unknown', provenance: 'unknown', note: `Not checked: ${reason}.` };
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

/** `cosign verify` of `image` against `policy`. */
export async function verifyImage(image: string, policy: SignerPolicy, ctx: CosignRunContext): Promise<CosignImageCheck> {
  const r = await cosign(verifyArgs(image, policy), ctx);
  const v = classifyVerify(r);
  const signer = describePolicy(policy);
  const cancelled = r.outcome === 'cancelled';
  if (v.verdict === 'verified') {
    return {
      run: { name: 'cosign-verify', status: 'ok', reason: `image ${image}: signature verified (${signer})`, target: image },
      findings: [],
      summary: {
        image,
        check: 'verify',
        signature: 'verified',
        provenance: 'not_checked',
        note: `Signed by ${signer}, verified against Sigstore's trust root. Provenance is not checked when a signer is given.`,
      },
      cancelled,
    };
  }
  if (v.verdict === 'error') {
    return {
      run: { name: 'cosign-verify', status: 'failed', reason: `image ${image}: cosign verify did not complete — ${v.detail}`, target: image },
      findings: [],
      summary: { image, check: 'verify', signature: 'unknown', provenance: 'not_checked', note: `Not verified: cosign did not complete (${v.detail}).` },
      cancelled,
    };
  }
  const title =
    v.reason === 'no_signature'
      ? `Image ${image} has no signature to verify`
      : `Image ${image} is not signed by the expected signer`;
  const finding = makeFinding({
    tool: COSIGN_VERIFY_TOOL_NAME,
    rule_id: 'image-signature-not-verified',
    severity: 'high',
    category: 'security',
    subcategory: 'supply-chain',
    title,
    message:
      `cosign verify rejected ${image} for ${signer}: ${v.detail}. Nothing shows this image was built and signed ` +
      'by the identity you expect — do not deploy it until it verifies (or correct signer_identity / signer_issuer ' +
      'if the image is legitimately signed by another workflow).',
    file_path: image,
    snippet: image,
    fix_available: false,
  });
  return {
    run: { name: 'cosign-verify', status: 'ok', reason: `image ${image}: signature NOT verified (${signer}) — ${v.detail}`, target: image },
    findings: [finding],
    summary: { image, check: 'verify', signature: 'rejected', provenance: 'not_checked', note: `Rejected: ${v.detail}.` },
    cancelled,
  };
}

/** Whether `image` has a signature and signed SLSA provenance — existence only. */
export async function detectImageSupplyChain(image: string, ctx: CosignRunContext): Promise<CosignImageCheck> {
  const treeRun = await cosign(['tree', image], ctx);
  const tree = treeRun.outcome === 'completed' ? parseCosignTree(treeRun.stdout, treeRun.stderr) : null;
  if (tree === null) {
    const why =
      treeRun.outcome === 'completed'
        ? 'its output was not a listing this version of dev-guardian can read'
        : (firstError(treeRun.stderr) ?? `cosign tree ${treeRun.outcome.replace(/_/g, ' ')}`);
    return {
      run: { name: 'cosign-tree', status: 'failed', reason: `image ${image}: cosign tree did not complete — ${why}`, target: image },
      findings: [],
      summary: { image, check: 'detect', signature: 'unknown', provenance: 'unknown', note: `Not checked: cosign tree did not complete (${why}).` },
      cancelled: treeRun.outcome === 'cancelled',
    };
  }

  const signature = signatureFromTree(tree);
  let provenance: Presence;
  let cancelled = false;
  const fromTree = provenanceFromTree(tree);
  if (fromTree !== 'download') {
    provenance = fromTree;
  } else {
    const answers: Presence[] = [];
    for (const type of PROVENANCE_PREDICATE_TYPES) {
      const r = await cosign(['download', 'attestation', `--predicate-type=${type}`, image], ctx);
      if (r.outcome === 'cancelled') cancelled = true;
      const answer = classifyAttestationDownload(r);
      answers.push(answer);
      if (answer === 'present') break;
    }
    provenance = answers.includes('present') ? 'present' : answers.every((a) => a === 'absent') ? 'absent' : 'unknown';
    // What the tree could not vouch for stays unknown whatever the download said.
    if (provenance === 'absent' && (tree.fetchErrors.length > 0 || tree.ambiguousBundles)) provenance = 'unknown';
  }

  const findings: Finding[] = [];
  if (signature === 'absent') {
    findings.push(
      makeFinding({
        tool: COSIGN_TREE_TOOL_NAME,
        rule_id: 'image-unsigned',
        severity: 'low',
        category: 'security',
        subcategory: 'supply-chain',
        title: `Image ${image} has no Sigstore signature`,
        message:
          `cosign found no signature for ${image} — neither a .sig tag nor a signing bundle attached as an OCI ` +
          'referrer — so nothing ties it to who built it. Sign it in the pipeline that builds it (cosign sign, ' +
          'keyless), then verify it before deploying: scan_containers with signer_identity and signer_issuer.',
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
          `No signed SLSA provenance attestation (https://slsa.dev/provenance/v0.2 or v1) was found for ${image}, ` +
          'as a legacy .att tag or an OCI referrer, so there is no signed record of the source and build that ' +
          "produced it. BuildKit's unsigned provenance inside an image index is not counted. Generate one where the " +
          'image is built (actions/attest-build-provenance with push-to-registry, or cosign attest).',
        file_path: image,
        snippet: image,
        fix_available: false,
      }),
    );
  }

  const complete = signature !== 'unknown' && provenance !== 'unknown';
  const parts = [
    `signature ${signature === 'present' ? 'present (signer NOT verified)' : signature}`,
    `SLSA provenance ${provenance === 'present' ? 'present (signer NOT verified)' : provenance}`,
  ];
  if (tree.fetchErrors.length > 0) parts.push(`cosign could not fetch ${tree.fetchErrors.length} referrer(s)`);
  const notes: string[] = [];
  if (signature === 'present') notes.push(UNVERIFIED_NOTE);
  if (provenance === 'present') {
    notes.push(
      signature === 'present'
        ? "The provenance attestation's signer was not verified either."
        : "A SLSA provenance attestation exists, but its signer was NOT verified.",
    );
  }
  if (!complete) notes.push('What is unknown could not be read from the registry — it was not found absent.');
  return {
    run: {
      name: 'cosign-tree',
      status: complete ? 'ok' : 'failed',
      reason: `image ${image}: ${parts.join('; ')}`,
      target: image,
    },
    findings,
    summary: {
      image,
      check: 'detect',
      signature: signature === 'present' ? 'present_unverified' : signature,
      provenance: provenance === 'present' ? 'present_unverified' : provenance,
      note: notes.length > 0 ? notes.join(' ') : 'Neither a signature nor SLSA provenance was found.',
    },
    cancelled: cancelled || treeRun.outcome === 'cancelled',
  };
}

function describePolicy(policy: SignerPolicy): string {
  const identity =
    policy.identity !== undefined ? `identity ${policy.identity}` : `identity matching ${policy.identityRegexp ?? '?'}`;
  const issuer =
    policy.issuer !== undefined ? `issuer ${policy.issuer}` : `issuer matching ${policy.issuerRegexp ?? '?'}`;
  return `${identity}, ${issuer}`;
}
