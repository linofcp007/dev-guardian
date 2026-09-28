/**
 * The pure half of scan_containers' cosign check (`runners/cosignCheck.ts`):
 * reading `cosign version`, `triangulate`, `tree`, `download signature`,
 * `download attestation` and `verify`.
 *
 * Every output below is real, captured from cosign v3.1.3 (and v2.6.5 where
 * named) on 2026-09-28 — against public images, or against the fake registry
 * of `test/helpers/fakeOciRegistry.ts` with a failure injected. The rule they
 * all serve: an output this module cannot read, or one cosign may have
 * produced by swallowing a registry error, is `unknown` — never "absent" and
 * never "rejected".
 */
import { describe, expect, it } from 'vitest';
import {
  canonicalSignerPolicy,
  classifyAttestationDownload,
  classifySignatureDownload,
  classifyTriangulate,
  classifyVerify,
  parseCosignTree,
  readinessFromProbe,
  signatureFromTree,
  treeListsAnything,
  unanchoredSignerRegexps,
  verifyArgs,
} from '../../../src/runners/cosignCheck.js';
import type { ProcessRunResult } from '../../../src/runners/processRunner.js';

/** cgr.dev/chainguard/static:latest — a legacy `.sig` tag and a legacy `.att` tag. */
const TREE_LEGACY = [
  '📦 Supply Chain Security Related artifacts for an image: cgr.dev/chainguard/static:latest',
  '└── 💾 Attestations for an image tag: cgr.dev/chainguard/static:sha256-41e17ed83c594a64a9396b6ab96dd26d5ddc290dacf4c177464712ff21ad534f.att',
  '   ├── 🍒 sha256:e2ee0775e2825b7c937fcb9b31f0101870a86e57d664becd1c79f4b51c2b96c2',
  '   ├── 🍒 sha256:fd172894f873c64c4dbc9d9444ca8cdb03cf64aba077b7837c94c52b8b2c3650',
  '   └── 🍒 sha256:f6cb0fae4e61872c9486c7f0201bf5e82c4a2850ce616146350bceed72e96252',
  '└── 🔐 Signatures for an image tag: cgr.dev/chainguard/static:sha256-41e17ed83c594a64a9396b6ab96dd26d5ddc290dacf4c177464712ff21ad534f.sig',
  '   └── 🍒 sha256:064523df0fd3979ec03a0737e967c53fe291926030dd2f5eba56ec1344cb73ca',
  '',
].join('\n');

/** alpine:3.20 — nothing listed. No trailing newline, as cosign prints it. */
const TREE_NONE =
  '📦 Supply Chain Security Related artifacts for an image: alpine:3.20\n' +
  'No Supply Chain Security Related Artifacts found for image alpine:3.20,\n' +
  ' start creating one with simply running$ cosign sign <img>';

/** ghcr.io/sigstore/cosign/cosign:v3.1.3 — cosign v3's signing bundles, attached as OCI referrers. */
const TREE_REFERRER_SIGNATURE = [
  '📦 Supply Chain Security Related artifacts for an image: ghcr.io/sigstore/cosign/cosign:v3.1.3',
  '└── 🔗 https://sigstore.dev/cosign/sign/v1 artifacts via OCI referrer: ghcr.io/sigstore/cosign/cosign@sha256:7d0f35c4822c49b5dd8e8fc6810e6edaa602febe7ac7469b2306b30dfed0c19d',
  '   └── 🍒 sha256:2c7c785bf5657d810a98b5a27d3f2ae49069fb0adc732b836d1f0b1b7e87c9ad',
  '└── 🔗 https://sigstore.dev/cosign/sign/v1 artifacts via OCI referrer: ghcr.io/sigstore/cosign/cosign@sha256:677339a642f43620d88287e5920eb1ff7526e1e960eb885b93a2d2606b8a0838',
  '   └── 🍒 sha256:d63f04f03cce4544cef933c273813d22ac416a6e35e60e7549bdb77f934c1ae8',
  '',
].join('\n');

/** ghcr.io/actions/actions-runner:latest — GitHub's build-provenance attestation as a referrer, no `cosign sign`. */
const TREE_REFERRER_PROVENANCE = [
  '📦 Supply Chain Security Related artifacts for an image: ghcr.io/actions/actions-runner:latest',
  '└── 🔗 https://slsa.dev/provenance/v1 artifacts via OCI referrer: ghcr.io/actions/actions-runner@sha256:ffce13d652bbe7eab8ab4733a45b30290441eb488bf28a274d74720ff5ee831e',
  '   └── 🍒 sha256:a12d4c69500caf250c79e1e56ccc984f4972d42be5b611551eef7ac172748702',
  '',
].join('\n');

function result(partial: Partial<ProcessRunResult>): ProcessRunResult {
  return { outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false, ...partial };
}
const failed = (exitCode: number, stderr: string): ProcessRunResult => result({ outcome: 'failed', exitCode, stderr });

const COSIGN_VERSION_OUT = (v: string): string =>
  ['cosign: A tool for Container Signing, Verification and Storage in an OCI registry', '', `GitVersion:    v${v}`, 'GoVersion:     go1.26.4'].join('\n');

describe('readinessFromProbe (`cosign version`) — cosign 2.x cannot see OCI referrers', () => {
  it('3.x is ready', () => {
    expect(readinessFromProbe(result({ stdout: COSIGN_VERSION_OUT('3.1.3') }))).toEqual({ ok: true, version: '3.1.3' });
  });

  it('2.x is skipped as outdated, and the reason says why an existence check would lie', () => {
    const r = readinessFromProbe(result({ stdout: COSIGN_VERSION_OUT('2.6.5') }));
    expect(r).toMatchObject({ ok: false, status: 'skipped' });
    expect(r.ok ? '' : r.reason).toMatch(/^outdated: cosign 2\.6\.5 .*3\.0\.0/);
    expect(r.ok ? '' : r.reason).toMatch(/OCI referrers/);
  });

  it.each([
    ['a version it cannot read', result({ stdout: 'cosign: something else entirely' })],
    ['a version command that fails', failed(1, 'boom')],
    ['a version command that hangs', result({ outcome: 'timed_out', exitCode: null })],
  ])('%s is a failed cosign, not a ready one', (_name, r) => {
    expect(readinessFromProbe(r)).toMatchObject({ ok: false, status: 'failed' });
  });
});

describe('classifyTriangulate — which digest every later call checks', () => {
  it('reads `<repo>@sha256:<hex>`', () => {
    const r = result({
      stdout: 'cgr.dev/chainguard/static@sha256:41e17ed83c594a64a9396b6ab96dd26d5ddc290dacf4c177464712ff21ad534f\n',
      stderr: 'Command "triangulate" is deprecated, triangulate will be removed in v4.0.0\n',
    });
    expect(classifyTriangulate(r)).toEqual({
      kind: 'digest',
      ref: 'cgr.dev/chainguard/static@sha256:41e17ed83c594a64a9396b6ab96dd26d5ddc290dacf4c177464712ff21ad534f',
      digest: 'sha256:41e17ed83c594a64a9396b6ab96dd26d5ddc290dacf4c177464712ff21ad534f',
    });
  });

  it('a cosign without `triangulate` (removed in v4) checks the tag, and says so — once', () => {
    const r = failed(1, 'Error: unknown command "triangulate" for "cosign"\n');
    const c = classifyTriangulate(r);
    expect(c).toMatchObject({ kind: 'tag_only' });
    expect(c.kind === 'tag_only' ? c.reason : '').not.toMatch(/not pinned/);
  });

  // Review round 2: every failure used to be worded "never pushed", a 429 included.
  it.each([
    ['a tag the registry does not have (404)', 'Error: GET http://localhost:5000/v2/app/manifests/2: MANIFEST_UNKNOWN: manifest unknown\n', 'not_found', /never pushed/],
    ['Docker Hub refusing an unknown repository (401 — the same answer as missing credentials)', 'Error: GET https://index.docker.io/v2/library/myapp-never-pushed/manifests/dev: UNAUTHORIZED: authentication required\n', 'denied', /credentials.*never pushed|never pushed.*credentials/],
    ['rate limiting (429)', 'Error: GET https://index.docker.io/v2/library/alpine/manifests/3.20: TOOMANYREQUESTS: You have reached your pull rate limit\n', 'rate_limited', /rate-limit/],
    ['an unreachable registry', 'Error: Get "https://no-such-registry.invalid/v2/": dial tcp: lookup no-such-registry.invalid: no such host\n', 'unreachable', /could not be reached/],
    ['a registry failing (5xx)', 'Error: GET http://localhost:5000/v2/app/manifests/1: UNKNOWN: injected manifest failure\n', 'registry_error', /registry failed/],
  ])('%s: an error worded by its cause', (_name, stderr, cause, wording) => {
    const c = classifyTriangulate(failed(1, stderr));
    expect(c).toMatchObject({ kind: 'error', cause });
    expect(c.kind === 'error' ? c.why : '').toMatch(wording);
    if (cause === 'rate_limited' || cause === 'unreachable' || cause === 'registry_error') {
      expect(c.kind === 'error' ? c.why : '').not.toMatch(/never pushed/);
    }
  });
});

describe('parseCosignTree', () => {
  it('reads a legacy .sig tag and a legacy .att tag (whose predicate types the listing does not give)', () => {
    const tree = parseCosignTree(TREE_LEGACY, '');
    expect(tree).toMatchObject({ signature: true, legacyAttestations: true, referrerTypes: [], fetchErrors: [] });
    expect(tree === null ? null : signatureFromTree(tree)).toBe('present');
    expect(tree === null ? null : treeListsAnything(tree)).toBe(true);
  });

  it('"nothing found" is NOT absence yet: cosign tree swallows a failing .sig / .att — a loud call decides', () => {
    const tree = parseCosignTree(TREE_NONE, '');
    expect(tree).not.toBeNull();
    expect(tree === null ? null : signatureFromTree(tree)).toBe('confirm');
    expect(tree === null ? null : treeListsAnything(tree)).toBe(false);
  });

  it('a referrer is NOT a signature on the listing alone — anyone who can push can attach one; the bundle has to parse', () => {
    for (const listing of [TREE_REFERRER_SIGNATURE, TREE_REFERRER_PROVENANCE]) {
      const tree = parseCosignTree(listing, '');
      expect(tree === null ? null : signatureFromTree(tree)).toBe('confirm');
      expect(tree === null ? null : treeListsAnything(tree)).toBe(true);
    }
    expect(parseCosignTree(TREE_REFERRER_SIGNATURE, '')?.referrerTypes).toEqual([
      'https://sigstore.dev/cosign/sign/v1',
      'https://sigstore.dev/cosign/sign/v1',
    ]);
  });

  it('a referrer cosign could not fetch makes an absence unknown (measured: exit 0, "No … found", error on stderr)', () => {
    const stderr =
      'Error fetching artifact localhost:51571/app@sha256:7762f2536179d5c9d909d39289a760f47d909f7b47647642c72f71067ff9026a: GET http://localhost:51571/v2/app/manifests/sha256:7762f2536179d5c9d909d39289a760f47d909f7b47647642c72f71067ff9026a: UNKNOWN: injected referrer-manifest failure\n';
    const tree = parseCosignTree(TREE_NONE, stderr);
    expect(tree?.fetchErrors).toHaveLength(1);
    expect(tree === null ? null : signatureFromTree(tree)).toBe('unknown');
  });

  it.each([
    ['empty output', ''],
    ['the header alone (cosign stopped after it)', '📦 Supply Chain Security Related artifacts for an image: alpine:3.20\n'],
    ['a format this module does not know', 'Supply chain artifacts for alpine:3.20:\n  signatures: 0\n'],
  ])('%s is not read at all (null) — an unreadable listing is never "unsigned"', (_name, stdout) => {
    expect(parseCosignTree(stdout, '')).toBeNull();
  });
});

/** One `download signature` line for a v3 bundle (the shape measured on ghcr.io, 2026-09-28). */
function bundleLine(predicateType: string): string {
  const statement = JSON.stringify({ _type: 'https://in-toto.io/Statement/v1', subject: [], predicateType, predicate: {} });
  return JSON.stringify({
    mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
    verificationMaterial: { certificate: { rawBytes: 'TUlJ' } },
    dsseEnvelope: { payload: Buffer.from(statement).toString('base64'), payloadType: 'application/vnd.in-toto+json', signatures: [{ sig: 'TUVZ' }] },
  });
}
const LEGACY_LINE = '{"Base64Signature":"MEUCIBaf","Payload":"eyJjcml0aWNhbCI6e319","Cert":{"Raw":"MIIH"},"Chain":null,"Bundle":null,"RFC3161Timestamp":null}';

describe('classifySignatureDownload — the loud half of "no signature", and what each signature IS', () => {
  it('a legacy signature: present', () => {
    expect(classifySignatureDownload(result({ stdout: `${LEGACY_LINE}\n` }))).toEqual({ state: 'present', attestationTypes: [] });
  });

  it('a v3 signing bundle (DSSE, predicate type https://sigstore.dev/cosign/sign/v1): present', () => {
    expect(classifySignatureDownload(result({ stdout: `${bundleLine('https://sigstore.dev/cosign/sign/v1')}\n` })).state).toBe('present');
  });

  it('a message-signature bundle: present', () => {
    const line = JSON.stringify({ mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json', verificationMaterial: {}, messageSignature: { signature: 'TUVZ' } });
    expect(classifySignatureDownload(result({ stdout: `${line}\n` })).state).toBe('present');
  });

  it('only signed attestation bundles (a Sigstore bundle media type, parsed by cosign): attestation only, with their types', () => {
    expect(classifySignatureDownload(result({ stdout: `${bundleLine('https://slsa.dev/provenance/v1')}\n` }))).toEqual({
      state: 'attestation_only',
      attestationTypes: ['https://slsa.dev/provenance/v1'],
    });
  });

  it('"no signatures associated": absent — whatever tree listed was no bundle cosign could parse', () => {
    expect(classifySignatureDownload(failed(1, 'Error: localhost:54697/app:1: no signatures associated\n')).state).toBe('absent');
  });

  it.each([
    ['a .sig tag the registry fails on (silent in tree, loud here)', failed(1, 'Error: localhost:54713/app:1: remote image: GET http://localhost:54713/v2/app/manifests/sha256-793a.sig: UNKNOWN: injected sig failure\n')],
    ['a timeout', result({ outcome: 'timed_out', exitCode: null })],
    ['output that is not JSON lines', result({ stdout: 'something else\n' })],
    ['exit 0 with nothing', result({ stdout: '' })],
  ])('%s: unknown', (_name, r) => {
    expect(classifySignatureDownload(r).state).toBe('unknown');
  });
});

describe('classifyAttestationDownload', () => {
  it('a match prints the attestation: present', () => {
    expect(classifyAttestationDownload(result({ stdout: '{"payloadType":"application/vnd.in-toto+json"}\n' }))).toBe('present');
  });

  it("cosign's own \"no attestations with predicate type\" (exit 1): absent", () => {
    const stderr = "Error: no attestations with predicate type 'https://slsa.dev/provenance/v0.2' found\n";
    expect(classifyAttestationDownload(failed(1, stderr))).toBe('absent');
  });

  it('a failing .att tag — silent in tree, loud here — a timeout, or exit 0 with nothing: unknown', () => {
    const stderr =
      'Error: remote image: GET http://localhost:57901/v2/app/manifests/sha256-793a57cec5ee88d1c38575cefc16cc65ae89457c508bc2359621099b2caf5021.att: UNKNOWN: injected att failure\n';
    expect(classifyAttestationDownload(failed(1, stderr))).toBe('unknown');
    expect(classifyAttestationDownload(result({ outcome: 'timed_out', exitCode: null }))).toBe('unknown');
    expect(classifyAttestationDownload(result({ stdout: '' }))).toBe('unknown');
  });
});

describe('classifyVerify — only a network or registry failure withholds the verdict (review round 2, N1)', () => {
  it('exit 0: verified, with what cosign accepted and over which digest', () => {
    const stdout =
      '\n[{"critical":{"identity":{"docker-reference":"ghcr.io/actions/actions-runner:latest"},"image":{"docker-manifest-digest":"sha256:e5496277be5d09bc968b3d64911b74e219ac4a3f2edce956a3ecf9271bea1ef4"},"type":"https://slsa.dev/provenance/v1"},"optional":{}}]\n';
    expect(classifyVerify(result({ stdout }))).toEqual({
      verdict: 'verified',
      types: ['https://slsa.dev/provenance/v1'],
      digest: 'sha256:e5496277be5d09bc968b3d64911b74e219ac4a3f2edce956a3ecf9271bea1ef4',
    });
  });

  it('exit 10 ("no signatures found") is only a CLAIM — cosign also says it when the referrers call failed', () => {
    expect(classifyVerify(failed(10, 'Error: no signatures found\nerror during command execution: no signatures found\n'))).toEqual({
      verdict: 'no_signature_claimed',
      detail: 'no signatures found',
    });
  });

  it('exit 12 naming another signer: rejected, naming who did sign', () => {
    const stderr =
      'Error: no matching signatures: none of the expected identities matched what was in the certificate, got subjects ' +
      '[https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main] with issuer https://token.actions.githubusercontent.com\n' +
      'error during command execution: no matching signatures: none of the expected identities matched …\n';
    const r = classifyVerify(failed(12, stderr));
    expect(r).toMatchObject({ verdict: 'rejected', reason: 'no_matching_signature' });
    expect(r.verdict === 'rejected' ? r.detail : '').toContain('got subjects [https://github.com/chainguard-images/');
  });

  it.each([
    ['a junk signature with no certificate or key (measured: "empty key")', 12, 'Error: no matching signatures: empty key\n', 'no_certificate'],
    ['a key-signed signature (no certificate)', 12, 'Error: no matching signatures: no certificate found on signature\n', 'no_certificate'],
    ['exit 13', 13, 'Error: no certificate found on signature\n', 'no_certificate'],
    ['an invalid signature', 12, 'Error: no matching signatures: invalid signature when validating ASN.1 encoded signature\n', 'invalid_signature'],
    ['a certificate Fulcio never issued', 12, 'Error: no matching signatures: x509: certificate signed by unknown authority\n', 'invalid_signature'],
    ["a bundle that does not verify (the v3 path's exit 1)", 1, 'Error: no matching attestations: failed to verify log inclusion: transparency log certificate does not match\n', 'invalid_signature'],
  ])('%s: REJECTED — only a network or registry failure withholds a verdict', (_name, exitCode, stderr, reason) => {
    expect(classifyVerify(failed(exitCode, stderr))).toMatchObject({ verdict: 'rejected', reason });
  });

  // The expected identity and the certificate's are echoed back — the user's
  // and the attacker's text. Neither may decide whether a failure was transient.
  it.each([
    ['org/app', 'https://github.com/org/app/.github/workflows/release.yml@refs/heads/main'],
    ['org/timeout-svc', 'https://github.com/org/timeout-svc/.github/workflows/release.yml@refs/heads/main'],
    ['org/eof-parser', 'https://github.com/org/eof-parser/.github/workflows/release.yml@refs/heads/main'],
    ['a value with "dial tcp" and "i/o timeout" in it', 'https://github.com/org/x/.github/workflows/y.yml@refs/heads/dial tcp i/o timeout'],
  ])('a v3 bundle mismatch for %s is rejected whatever the echoed identity says', (_name, identity) => {
    const stderr =
      'Error: no matching attestations: failed to verify certificate identity: no matching CertificateIdentity found, last error: ' +
      `expected SAN value "${identity}", got "keyless@projectsigstore.iam.gserviceaccount.com"\n` +
      'error during command execution: …\n';
    expect(classifyVerify(failed(1, stderr))).toMatchObject({ verdict: 'rejected', reason: 'no_matching_signature' });
  });

  it('a regexp holding "fetching " in the echo is still a rejection', () => {
    const stderr =
      'Error: no matching attestations: failed to verify certificate identity: no matching CertificateIdentity found, last error: ' +
      'expected SAN value to match regex "^https://github.com/org/fetching x/", got "keyless@projectsigstore.iam.gserviceaccount.com"\n';
    expect(classifyVerify(failed(1, stderr))).toMatchObject({ verdict: 'rejected' });
  });

  it("a legacy subject list with a ']' inside a branch name is stripped whole", () => {
    const stderr =
      'Error: no matching signatures: none of the expected identities matched what was in the certificate, got subjects ' +
      '[https://github.com/evil/x/.github/workflows/y.yml@refs/heads/a]b dial tcp i/o timeout] with issuer https://token.actions.githubusercontent.com\n';
    expect(classifyVerify(failed(12, stderr))).toMatchObject({ verdict: 'rejected', reason: 'no_matching_signature' });
  });

  it.each([
    ['a rate-limited registry, folded beside a mismatch', 12, 'Error: no matching signatures: none of the expected identities matched what was in the certificate, got subjects [https://github.com/other/x/.github/workflows/y.yml@refs/heads/main] with issuer https://token.actions.githubusercontent.com\n fetching payload: GET https://ghcr.io/v2/org/app/blobs/sha256:abcd: TOOMANYREQUESTS: rate limit exceeded\n'],
    ['an online Rekor lookup that failed (measured)', 12, 'Error: no matching signatures: searching log query: Post "https://rekor.sigstore.dev/api/v1/log/entries/retrieve": giving up after 4 attempt(s): Post "https://rekor.sigstore.dev/api/v1/log/entries/retrieve": http: server gave HTTP response to HTTPS client\n'],
    ['an unreachable registry', 1, 'Error: Get "https://no-such-registry.invalid/v2/": dial tcp: lookup no-such-registry.invalid: no such host\n'],
    ['a .sig tag the registry fails on', 1, 'Error: GET http://localhost:54713/v2/app/manifests/sha256-793a.sig: UNKNOWN: injected sig failure\n'],
    ['no network to Sigstore (TUF)', 1, 'Error: setting up clients and keys: getting rekor public keys: updating local metadata and targets\n'],
    ['a connection reset', 12, 'Error: no matching signatures: fetching bundle: read tcp 10.0.0.2:50000->140.82.1.1:443: read: connection reset by peer\n'],
    ['a tag that does not exist (exit 11)', 11, 'Error: image tag not found: GET https://index.docker.io/v2/library/alpine/manifests/x: MANIFEST_UNKNOWN\n'],
    ['a regexp cosign cannot compile (a configuration error, not a verdict on the image)', 1, 'Error: no matching attestations: error parsing regexp: missing closing ): `(`\n'],
    ['no cosign error framing at all (a crash)', 2, 'panic: runtime error: invalid memory address or nil pointer dereference\n'],
  ])('%s: withheld (error)', (_name, exitCode, stderr) => {
    expect(classifyVerify(failed(exitCode, stderr)).verdict).toBe('error');
  });

  it('a timeout or a cancellation is an error', () => {
    expect(classifyVerify(result({ outcome: 'timed_out', exitCode: null })).verdict).toBe('error');
    expect(classifyVerify(result({ outcome: 'cancelled', exitCode: null })).verdict).toBe('error');
  });
});

describe('verifyArgs', () => {
  it('passes each value inside its flag (`--flag=value`), so none can be read as an option; the reference is last', () => {
    expect(verifyArgs('ghcr.io/org/app@sha256:ab', { identity: 'a@b.example', issuer: 'https://accounts.google.com' })).toEqual([
      'verify',
      '--certificate-identity=a@b.example',
      '--certificate-oidc-issuer=https://accounts.google.com',
      'ghcr.io/org/app@sha256:ab',
    ]);
    expect(verifyArgs('ghcr.io/org/app:1', { identityRegexp: '^https://github.com/org/', issuerRegexp: '-looks-like-a-flag' })).toEqual([
      'verify',
      '--certificate-identity-regexp=^https://github.com/org/',
      '--certificate-oidc-issuer-regexp=-looks-like-a-flag',
      'ghcr.io/org/app:1',
    ]);
  });
});

describe('the signer, canonically — part of a verification pass target (review I1)', () => {
  it('one spelling per policy, and two policies never share one (no separator a value could forge)', () => {
    expect(canonicalSignerPolicy({ issuer: 'https://x', identity: 'a@b' })).toBe('{"identity":"a@b","issuer":"https://x"}');
    const a = canonicalSignerPolicy({ identityRegexp: 'a issuer=b', issuer: 'c' });
    const b = canonicalSignerPolicy({ identityRegexp: 'a', issuer: 'b issuer=c' });
    expect(a).not.toBe(b);
  });
});

describe('unanchoredSignerRegexps (review M3)', () => {
  it('warns for a regexp not anchored at both ends — it matches any identity that merely CONTAINS it', () => {
    const w = unanchoredSignerRegexps({ identityRegexp: 'https://github.com/org/app/', issuer: 'https://token.actions.githubusercontent.com' });
    expect(w).toHaveLength(1);
    expect(w[0]).toMatch(/signer_identity_regexp/);
    expect(w[0]).toMatch(/\^…\$/);
    expect(unanchoredSignerRegexps({ identityRegexp: '^https://github.com/org/app/', issuerRegexp: 'token' })).toHaveLength(2);
  });

  it('nothing for anchored regexps or exact values', () => {
    expect(
      unanchoredSignerRegexps({ identityRegexp: '^https://github\\.com/org/app/\\.github/workflows/release\\.yml@refs/heads/main$', issuerRegexp: '^https://token\\.actions\\.githubusercontent\\.com\\z' }),
    ).toEqual([]);
    expect(unanchoredSignerRegexps({ identity: 'a@b', issuer: 'https://x' })).toEqual([]);
  });
});
