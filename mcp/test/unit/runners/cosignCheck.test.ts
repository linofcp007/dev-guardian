/**
 * The pure half of scan_containers' cosign check (`runners/cosignCheck.ts`):
 * reading `cosign version`, `triangulate`, `download signature`, `download
 * attestation`, `verify`, and the `-d` request log of the downloads.
 *
 * Every output below is real, captured from cosign v3.1.3 (and v2.6.5 where
 * named) on 2026-09-28 — against public images, or against the fake registry
 * of `test/helpers/fakeOciRegistry.ts` with a failure injected; the request
 * logs are built by `traceOf` in the exact shape measured. The rule they all
 * serve: an output this module cannot read, or one cosign may have produced
 * by swallowing a registry error, is `unknown` — never "absent" and never
 * "rejected".
 */
import { describe, expect, it } from 'vitest';
import {
  canonicalSignerPolicy,
  classifyAttestationDownload,
  classifySignatureDownload,
  classifyTriangulate,
  classifyVerify,
  escapeUnsafe,
  parseRegistryTrace,
  referrerFaults,
  readinessFromProbe,
  stripQueries,
  unanchoredSignerRegexps,
  verifyArgs,
} from '../../../src/runners/cosignCheck.js';
import type { ProcessRunResult } from '../../../src/runners/processRunner.js';

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
  it('a legacy signature: present (no bundle counted)', () => {
    expect(classifySignatureDownload(result({ stdout: `${LEGACY_LINE}\n` }))).toEqual({ state: 'present', attestationTypes: [], bundles: 0 });
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
      bundles: 1,
    });
  });

  it('round 4, I6: counts every bundle cosign returned — what the index lists beyond it was not returned', () => {
    const stdout = [bundleLine('https://slsa.dev/provenance/v1'), bundleLine('https://spdx.dev/Document'), LEGACY_LINE, ''].join('\n');
    expect(classifySignatureDownload(result({ stdout }))).toMatchObject({ state: 'present', bundles: 2 });
  });

  it('round 4, M4: a predicate type holding a bidi override or ESC is escaped, never carried raw', () => {
    const evil = `https://evil.example/${String.fromCharCode(0x202e)}${String.fromCharCode(0x1b)}[31mtype`;
    const types = classifySignatureDownload(result({ stdout: `${bundleLine(evil)}\n` })).attestationTypes;
    expect(types).toEqual([escapeUnsafe(evil)]);
    expect(types[0]).toContain('\\u202e');
    expect(types[0]).not.toContain(String.fromCharCode(0x202e));
  });

  it('past the stdout cap with no signature seen: unknown — what was cut off may have been the signature', () => {
    const stdout = `${bundleLine('https://slsa.dev/provenance/v1')}\n{"mediaType":"application/vnd.dev.sig`;
    expect(classifySignatureDownload(result({ outcome: 'output_too_large', stdout })).state).toBe('unknown');
  });

  it('"no signatures associated": absent — the trace then says whether anything the registry lists went unreturned', () => {
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

// ---------------------------------------------------------------------------
// Review round 3
// ---------------------------------------------------------------------------

const failedWith = (exitCode: number, stderr: string): ProcessRunResult => ({
  outcome: 'failed',
  exitCode,
  stdout: '',
  stderr,
  truncated: false,
});

describe('classifyVerify — a Rekor answer is a verdict unless it is a 5xx, a 429 or a network failure (round 3, I1)', () => {
  it.each([
    [
      'Rekor 400 (it rejects a signature that does not verify against its key) — measured with cosign 3.1.3 + a fake Rekor',
      'Error: no matching signatures: searching log query: [POST /api/v1/log/entries/retrieve][400] searchLogQueryBadRequest {"code":400,"message":"verifying signature: invalid signature when validating ASN.1 encoded signature"}\n',
    ],
    ['Rekor 200 [] — measured', 'Error: no matching signatures: signature not found in transparency log\n'],
    ['any other Rekor 4xx', 'Error: no matching signatures: searching log query: [POST /api/v1/log/entries/retrieve][422] searchLogQueryUnprocessableEntity {"code":422,"message":"x"}\n'],
  ])('%s: REJECTED', (_name, stderr) => {
    expect(classifyVerify(failedWith(12, stderr))).toMatchObject({ verdict: 'rejected', reason: 'invalid_signature' });
  });

  it.each([
    ['Rekor 503 through its retries — measured', 'Error: no matching signatures: searching log query: Post "http://localhost:56362/api/v1/log/entries/retrieve": giving up after 4 attempt(s): status 503: {"code":503,"message":"unavailable"}\n'],
    ['Rekor 429 through its retries — measured', 'Error: no matching signatures: searching log query: Post "http://localhost:56371/api/v1/log/entries/retrieve": giving up after 4 attempt(s): status 429: {"code":429,"message":"slow down"}\n'],
    ['Rekor 500 without retries', 'Error: no matching signatures: searching log query: [POST /api/v1/log/entries/retrieve][500] searchLogQueryDefault {"code":500,"message":"x"}\n'],
    ['Rekor unreachable', 'Error: no matching signatures: searching log query: Post "https://rekor.sigstore.dev/api/v1/log/entries/retrieve": dial tcp: lookup rekor.sigstore.dev: no such host\n'],
  ])('%s: withheld', (_name, stderr) => {
    expect(classifyVerify(failedWith(12, stderr)).verdict).toBe('error');
  });
});

describe('classifyVerify — an echoed identity cannot smuggle a network failure past the strip (round 3, I2)', () => {
  // sigstore-go prints `expected %s value "%s", got "%s"` UNESCAPED: a quote
  // in a git ref or a workflow file name breaks any quote pairing.
  it.each([
    ['a git ref holding quotes', 'https://github.com/evil/x/.github/workflows/r.yml@refs/heads/a"proxyconnect"b'],
    ['a workflow file named with quotes', 'https://github.com/evil/x/.github/workflows/a" dial tcp ".yml@refs/heads/main'],
    ['an i/o timeout between quotes', 'https://github.com/evil/x/.github/workflows/r.yml@refs/heads/"i/o timeout"'],
  ])('%s in a v3 bundle SAN: rejected', (_name, san) => {
    const stderr =
      'Error: no matching attestations: failed to verify certificate identity: no matching CertificateIdentity found, last error: ' +
      `expected SAN value "https://github.com/org/app/.github/workflows/release.yml@refs/heads/main", got "${san}"\n`;
    expect(classifyVerify(failedWith(1, stderr))).toMatchObject({ verdict: 'rejected', reason: 'no_matching_signature' });
  });

  it('the same in a legacy subject list: rejected', () => {
    const stderr =
      'Error: no matching signatures: none of the expected identities matched what was in the certificate, got subjects ' +
      '[https://github.com/evil/x/.github/workflows/r.yml@refs/heads/a"proxyconnect"b] with issuer https://token.actions.githubusercontent.com\n';
    expect(classifyVerify(failedWith(12, stderr))).toMatchObject({ verdict: 'rejected', reason: 'no_matching_signature' });
  });

  it('an EXPECTED identity (the user\'s own text) with quotes cannot either', () => {
    const stderr =
      'Error: no matching attestations: failed to verify certificate identity: no matching CertificateIdentity found, last error: ' +
      'expected SAN value to match regex "^https://github.com/org/"dial tcp"/", got "keyless@projectsigstore.iam.gserviceaccount.com"\n';
    expect(classifyVerify(failedWith(1, stderr)).verdict).toBe('rejected');
  });
});

describe('classifyVerify — body-read failures and the full error list (round 3, M1)', () => {
  it.each([
    ['an HTTP/2 stream error', 'Error: no matching signatures: fetching bundle: stream error: stream ID 5; INTERNAL_ERROR; received from peer\n'],
    ['an HTTP/2 GOAWAY', 'Error: no matching signatures: fetching bundle: http2: server sent GOAWAY and closed the connection; LastStreamID=7, ErrCode=NO_ERROR\n'],
    ['a connection closed mid-body (Windows)', 'Error: no matching signatures: fetching payload: read tcp 10.0.0.2:50000->140.82.1.1:443: wsarecv: An existing connection was forcibly closed by the remote host.\n'],
    ['a broken pipe', 'Error: no matching signatures: write tcp 10.0.0.2:50000->140.82.1.1:443: write: broken pipe\n'],
  ])('%s: withheld', (_name, stderr) => {
    expect(classifyVerify(failedWith(12, stderr)).verdict).toBe('error');
  });

  it('exit 12 names every signature error it folded, not only the first line (bounded)', () => {
    const stderr =
      'Error: no matching signatures: none of the expected identities matched what was in the certificate, got subjects [https://github.com/a/b/.github/workflows/c.yml@refs/heads/main] with issuer https://token.actions.githubusercontent.com\n' +
      ' empty key\n' +
      'error during command execution: …\n';
    const r = classifyVerify(failedWith(12, stderr));
    expect(r.verdict).toBe('rejected');
    const detail = r.verdict === 'rejected' ? r.detail : '';
    expect(detail).toContain('got subjects');
    expect(detail).toContain('empty key');
    expect(detail.length).toBeLessThanOrEqual(900);
  });
});

// ---------------------------------------------------------------------------
// The `-d` request log — rounds 3 and 4
// ---------------------------------------------------------------------------

/**
 * A `cosign … -d` request log as cosign 3.1.3 prints it (go-containerregistry's
 * transport logger, measured 2026-09-28 against the fake registry): each
 * request, its dump, the answer line, then — for an answer with a status — the
 * response dump: `HTTP/1.1 …`, CRLF headers, a blank line, the body (chunked
 * when the registry sent it chunked; `[body redacted]` for a blob). A string
 * answer is a transport error. `eol: '\n'` drops the CRs.
 */
interface Step {
  url: string;
  answer: number | string;
  body?: string;
  chunks?: number;
}
const T = '2026/09/28 23:48:25';
function traceOf(steps: Step[], eol = '\r\n'): string {
  const out: string[] = [];
  for (const s of steps) {
    const path = s.url.replace(/^\w+:\/\/[^/]+/, '');
    out.push(`${T} --> GET ${s.url}`, `${T} GET ${path} HTTP/1.1${eol}Host: h${eol}User-Agent: cosign/v3.1.3${eol}${eol}`);
    if (typeof s.answer === 'string') {
      out.push(`${T} <-- ${s.answer} GET ${s.url} (2ms)`);
      continue;
    }
    out.push(`${T} <-- ${s.answer} ${s.url} (1ms)`);
    const body = s.body ?? '';
    if (s.chunks === undefined) {
      out.push(`${T} HTTP/1.1 ${s.answer} X${eol}Content-Length: ${Buffer.byteLength(body)}${eol}Content-Type: application/json${eol}${eol}${body}`);
      continue;
    }
    const size = Math.ceil(body.length / s.chunks);
    const parts: string[] = [];
    for (let i = 0; i < body.length; i += size) {
      const part = body.slice(i, i + size);
      parts.push(`${Buffer.byteLength(part).toString(16)}${eol}${part}${eol}`);
    }
    out.push(`${T} HTTP/1.1 ${s.answer} X${eol}Transfer-Encoding: chunked${eol}Content-Type: application/vnd.oci.image.index.v1+json${eol}${eol}${parts.join('')}0${eol}${eol}`);
  }
  return `${out.join('\n')}\n`;
}

const H = 'http://localhost:53669/v2/app';
const IMG = 'sha256:793a57cec5ee88d1c38575cefc16cc65ae89457c508bc2359621099b2caf5021';
const IMG_HEX = IMG.slice('sha256:'.length);
const ART = 'sha256:4894c92a3136586fe332ca198e4abf12498875c546273821726b624107e1311f';
const LAYER = 'sha256:fe36ea8e8f1231cc1967b305b49ed981156f7dfa3648f836ae1950debfb8655e';
const BUNDLE_TYPE = 'application/vnd.dev.sigstore.bundle.v0.3+json';
const SIGN = 'https://sigstore.dev/cosign/sign/v1';

/** The registry's referrers index — its own JSON, as the fake registry (and a real one) generates it. */
const indexBody = (entries: Array<Record<string, unknown>>): string =>
  JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.index.v1+json', manifests: entries });
const bundleEntry = (digest = ART, predicateType: string | null = SIGN): Record<string, unknown> => ({
  mediaType: 'application/vnd.oci.image.manifest.v1+json',
  digest,
  size: 757,
  artifactType: BUNDLE_TYPE,
  ...(predicateType === null ? {} : { annotations: { 'dev.sigstore.bundle.content': 'dsse-envelope', 'dev.sigstore.bundle.predicateType': predicateType } }),
});
const bundleManifest = (layer = LAYER): string =>
  JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json', artifactType: BUNDLE_TYPE, layers: [{ mediaType: BUNDLE_TYPE, digest: layer, size: 3000 }] });

/** `download signature -d` on an image with one signing bundle: the whole exchange, as measured. */
const fullExchange = (blob: number | string = 200, eol = '\r\n', chunks = 1): string =>
  traceOf(
    [
      { url: `${H}/manifests/1`, answer: 200, body: '{"schemaVersion":2,"layers":[]}' },
      { url: `${H}/referrers/${IMG}`, answer: 200, body: indexBody([bundleEntry()]), chunks },
      { url: `${H}/manifests/${ART}`, answer: 200, body: bundleManifest() },
      { url: `${H}/blobs/${LAYER}`, answer: blob, body: '[body redacted: omitting binary blobs from logs]' },
      { url: `${H}/manifests/1`, answer: 200, body: '{"schemaVersion":2,"layers":[]}' },
      { url: `${H}/manifests/sha256-${IMG_HEX}.sig`, answer: 404, body: '{"errors":[{"code":"MANIFEST_UNKNOWN"}]}' },
    ],
    eol,
  );

describe('parseRegistryTrace — the referrer set is the registry\'s own index (round 4, I4/I5)', () => {
  it('reads the index the registry generated, from the chunked body the log dumped — digests, artifact types, annotations', () => {
    const t = parseRegistryTrace(fullExchange());
    expect(t.index).toEqual({ state: 'listed', referrers: [{ digest: ART, artifactType: BUNDLE_TYPE, predicateType: SIGN, sigstore: true }] });
    expect(t.manifests.get(ART)?.outcome).toBe('served');
    expect(t.blobs.get(LAYER)?.outcome).toBe('served');
    expect(t.manifests.get(`sha256-${IMG_HEX}.sig`)?.outcome).toBe('missing');
  });

  it('an index sent in several chunks, and a log with LF-only line ends, read the same', () => {
    const want = parseRegistryTrace(fullExchange()).index;
    expect(parseRegistryTrace(fullExchange(200, '\r\n', 5)).index).toEqual(want);
    expect(parseRegistryTrace(fullExchange(200, '\n', 3)).index).toEqual(want);
  });

  it('no referrers API (404): the fallback tag\'s index — the ghcr.io shape; a 404 there is "nothing attached"', () => {
    const viaTag = traceOf([
      { url: `${H}/referrers/${IMG}`, answer: 404, body: '{"errors":[{"code":"MANIFEST_UNKNOWN"}]}' },
      { url: `${H}/manifests/sha256-${IMG_HEX}`, answer: 200, body: indexBody([bundleEntry()]) },
    ]);
    expect(parseRegistryTrace(viaTag).index).toMatchObject({ state: 'listed', referrers: [{ digest: ART, sigstore: true }] });
    const none = traceOf([
      { url: `${H}/referrers/${IMG}`, answer: 404 },
      { url: `${H}/manifests/sha256-${IMG_HEX}`, answer: 404 },
    ]);
    expect(parseRegistryTrace(none).index).toEqual({ state: 'listed', referrers: [] });
  });

  it('a referrers API answering an index is the index, even when cosign then fell back (a Content-Type with "; charset=utf-8", measured) — and what cosign never fetched cannot be probed', () => {
    const charset = traceOf([
      { url: `${H}/referrers/${IMG}`, answer: 200, body: indexBody([bundleEntry()]), chunks: 1 },
      { url: `${H}/manifests/sha256-${IMG_HEX}`, answer: 404 },
      { url: `${H}/manifests/sha256-${IMG_HEX}.sig`, answer: 404 },
    ]);
    const t = parseRegistryTrace(charset);
    expect(t.index).toMatchObject({ state: 'listed', referrers: [{ digest: ART }] });
    expect(referrerFaults(t)).toMatch(/could not be probed/);
  });

  it.each([
    ['a 500', 500, /answered 500/],
    ['a 429', 429, /answered 429/],
    ['a 401', 401, /answered 401/],
    ['a transport error', 'read tcp 10.0.0.2:5->1.2.3.4:443: read: connection reset by peer', /connection reset/],
  ])('a referrers API answering %s: the index failed, named', (_name, answer, why) => {
    const t = parseRegistryTrace(traceOf([{ url: `${H}/referrers/${IMG}`, answer }]));
    expect(t.index.state).toBe('failed');
    expect(referrerFaults(t)).toMatch(why);
  });

  it.each([
    ['a 400', 400, undefined],
    ['a 406', 406, undefined],
    ['an HTML 200', 200, '<html><body>registry</body></html>'],
  ])('a referrers API answering %s is go-containerregistry\'s "no referrers API" — the fallback decides (the blind spot SECURITY.md names)', (_name, answer, body) => {
    const t = parseRegistryTrace(
      traceOf([
        { url: `${H}/referrers/${IMG}`, answer, ...(body === undefined ? {} : { body }) },
        { url: `${H}/manifests/sha256-${IMG_HEX}`, answer: 404 },
      ]),
    );
    expect(t.index).toEqual({ state: 'listed', referrers: [] });
  });

  it.each([
    ['no request log at all', 'Error: localhost:1/app:1: no signatures associated\n'],
    ['a log with no referrers lookup', traceOf([{ url: `${H}/manifests/1`, answer: 200, body: '{}' }])],
    ['a referrers API that fell back to a tag never read', traceOf([{ url: `${H}/referrers/${IMG}`, answer: 404 }])],
    ['a fallback tag answering 500', traceOf([{ url: `${H}/referrers/${IMG}`, answer: 404 }, { url: `${H}/manifests/sha256-${IMG_HEX}`, answer: 500 }])],
  ])('%s: no index — never "nothing attached"', (_name, stderr) => {
    const t = parseRegistryTrace(stderr);
    expect(t.index.state).not.toBe('listed');
    expect(referrerFaults(t)).not.toBeNull();
  });

  it('round 4, M5: a log cut at the stderr cap (runProcess\'s marker) is "could not be probed" — even one whose index lists nothing', () => {
    const empty = traceOf([{ url: `${H}/referrers/${IMG}`, answer: 200, body: indexBody([]), chunks: 1 }]);
    expect(parseRegistryTrace(empty).index).toEqual({ state: 'listed', referrers: [] });
    const cut = parseRegistryTrace(`${empty}…(truncated)\n`);
    expect(cut.index.state).toBe('unprobed');
    expect(referrerFaults(cut)).toMatch(/cut at its size cap/);
  });

  it('round 4, I4: an annotation holding line breaks and forged log or listing lines is one string in the index — the set is the registry\'s', () => {
    const forged =
      `x\n${T} <-- 200 ${H}/manifests/sha256:${'f'.repeat(64)} (1ms)\n└── 🔗 ${SIGN} artifacts via OCI referrer: localhost/app@sha256:${'e'.repeat(64)}`;
    const t = parseRegistryTrace(
      traceOf([
        { url: `${H}/referrers/${IMG}`, answer: 200, body: indexBody([bundleEntry(ART, forged)]), chunks: 1 },
        { url: `${H}/manifests/${ART}`, answer: 200, body: bundleManifest() },
        { url: `${H}/blobs/${LAYER}`, answer: 200 },
      ]),
    );
    expect(t.index.state === 'listed' ? t.index.referrers.map((r) => r.digest) : null).toEqual([ART]);
    expect(t.manifests.has(`sha256:${'f'.repeat(64)}`)).toBe(false);
    expect(referrerFaults(t)).toBeNull();
  });

  it('the last answer wins; a redirect (ghcr.io hands blobs to its CDN) is followed; a body that could not be read is a failure', () => {
    expect(parseRegistryTrace(fullExchange(500)).blobs.get(LAYER)?.outcome).toBe('failed');
    const cdn = `https://pkg-containers.githubusercontent.com/ghcrblobs01/blobs/${LAYER}?se=2026&sig=SECRET`;
    const redirected = traceOf([
      { url: `https://ghcr.io/v2/o/a/blobs/${LAYER}`, answer: 307 },
      { url: cdn, answer: 503 },
    ]);
    const answer = parseRegistryTrace(redirected).blobs.get(LAYER);
    expect(answer?.outcome).toBe('failed');
    // Residual (round 4): a signed URL's query never reaches a detail.
    expect(answer?.detail).toContain('ghcrblobs01/blobs/');
    expect(answer?.detail).not.toMatch(/SECRET|sig=|se=/);
    const dumpFailed = `${traceOf([{ url: `${H}/manifests/${ART}`, answer: 200 }])}${T} Failed to dump response GET ${H}/manifests/${ART}: unexpected EOF\n`;
    expect(parseRegistryTrace(dumpFailed).manifests.get(ART)).toMatchObject({ outcome: 'failed' });
  });

  it('only a record that STARTS with the log timestamp counts — a line inside a dumped body never does', () => {
    const body = `{"schemaVersion":2,"layers":[],\n"${T} <-- 500 ${H}/blobs/${LAYER} (1ms)":1}`;
    const t = parseRegistryTrace(traceOf([{ url: `${H}/manifests/${ART}`, answer: 200, body }, { url: `${H}/blobs/${LAYER}`, answer: 200 }]));
    expect(t.blobs.get(LAYER)?.outcome).toBe('served');
  });
});

describe('referrerFaults — what the index lists and cosign did not return is never "absent" on its own (rounds 3–4)', () => {
  const listed = (answers: Step[]): string =>
    traceOf([{ url: `${H}/referrers/${IMG}`, answer: 200, body: indexBody([bundleEntry()]), chunks: 1 }, ...answers]);

  it.each([
    ['its bundle blob answered 500', listed([{ url: `${H}/manifests/${ART}`, answer: 200, body: bundleManifest() }, { url: `${H}/blobs/${LAYER}`, answer: 500 }]), /500/],
    ['its manifest answered 503', listed([{ url: `${H}/manifests/${ART}`, answer: 503 }]), /503/],
    ['its blob\'s connection dropped', listed([{ url: `${H}/manifests/${ART}`, answer: 200, body: bundleManifest() }, { url: `${H}/blobs/${LAYER}`, answer: 'read tcp 1.2.3.4:5->6.7.8.9:443: read: connection reset by peer' }]), /connection reset/],
    ['it was never fetched', listed([]), /could not be probed/],
  ])('%s: a fault, named', (_name, stderr, why) => {
    expect(referrerFaults(parseRegistryTrace(stderr)) ?? '').toMatch(why);
  });

  it.each([
    ['served, blob served (cosign returned it, or it did not parse)', listed([{ url: `${H}/manifests/${ART}`, answer: 200, body: bundleManifest() }, { url: `${H}/blobs/${LAYER}`, answer: 200 }])],
    ['its blob answered 404', listed([{ url: `${H}/manifests/${ART}`, answer: 200, body: bundleManifest() }, { url: `${H}/blobs/${LAYER}`, answer: 404 }])],
    ['its manifest answered 404', listed([{ url: `${H}/manifests/${ART}`, answer: 404 }])],
    ['its manifest served and its layer never fetched (cosign judged it no bundle — measured: https://spdx.dev/Document)', listed([{ url: `${H}/manifests/${ART}`, answer: 200, body: bundleManifest() }])],
  ])('%s: no fault — the registry answered', (_name, stderr) => {
    expect(referrerFaults(parseRegistryTrace(stderr))).toBeNull();
  });

  it('round 4, I5: an OCI index attached as a referrer, served — the registry answered (cosign tree could not fetch it; the downloads do)', () => {
    const idx = 'sha256:6934ed41aadbd2340a2f760e73b4e8e9d56d1a3c2034cc2c46470231a0a42540';
    const t = parseRegistryTrace(
      traceOf([
        { url: `${H}/referrers/${IMG}`, answer: 200, body: indexBody([{ mediaType: 'application/vnd.oci.image.index.v1+json', digest: idx, size: 298, artifactType: 'application/vnd.example.index' }]), chunks: 1 },
        { url: `${H}/manifests/${idx}`, answer: 200, body: '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}' },
      ]),
    );
    expect(t.index).toMatchObject({ state: 'listed', referrers: [{ digest: idx, sigstore: false }] });
    expect(referrerFaults(t)).toBeNull();
  });

  it('round 4, M4: an artifact type holding a bidi override or ESC is escaped in the fault it names', () => {
    const evil = `application/x${String.fromCharCode(0x202e)}${String.fromCharCode(0x1b)}[31mevil`;
    const t = parseRegistryTrace(
      traceOf([
        { url: `${H}/referrers/${IMG}`, answer: 200, body: indexBody([{ mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: ART, size: 1, artifactType: evil }]), chunks: 1 },
        { url: `${H}/manifests/${ART}`, answer: 500 },
      ]),
    );
    const fault = referrerFaults(t) ?? '';
    expect(fault).toContain('\\u202e');
    expect(fault).toContain('\\u001b');
    expect(fault).not.toContain(String.fromCharCode(0x202e));
    expect(fault).not.toContain(String.fromCharCode(0x1b));
  });
});

describe('query strings never reach a reason (round 4, residual)', () => {
  const SIGNED = 'https://pkg-containers.githubusercontent.com/ghcrblobs/blobs/sha256:ab?se=2026-09-29&sig=SECRETSIG&sp=r';

  it('stripQueries drops every query, quoted or not, and keeps the rest', () => {
    expect(stripQueries(`GET ${SIGNED}: UNKNOWN`)).toBe('GET https://pkg-containers.githubusercontent.com/ghcrblobs/blobs/sha256:ab: UNKNOWN');
    expect(stripQueries(`Get "${SIGNED}": dial tcp`)).toBe('Get "https://pkg-containers.githubusercontent.com/ghcrblobs/blobs/sha256:ab": dial tcp');
  });

  it('in a triangulate failure, a verify rejection and a withheld verify', () => {
    const tri = classifyTriangulate(failed(1, `Error: GET ${SIGNED}: UNAUTHORIZED: denied\n`));
    expect(tri.kind === 'error' ? tri.why : '').not.toMatch(/SECRETSIG|sig=/);
    const rejected = classifyVerify(failed(12, `Error: no matching signatures: invalid signature when validating ASN.1 encoded signature\n fetched from ${SIGNED}\n`));
    expect(rejected.verdict).toBe('rejected');
    expect(rejected.verdict === 'rejected' ? rejected.detail : '').not.toMatch(/SECRETSIG|sig=/);
    const withheld = classifyVerify(failed(12, `Error: no matching signatures: fetching bundle: Get "${SIGNED}": dial tcp: i/o timeout\n`));
    expect(withheld.verdict).toBe('error');
    expect(withheld.verdict === 'error' ? withheld.detail : '').not.toMatch(/SECRETSIG|sig=/);
  });
});

describe('what cosign verify accepted is escaped (round 4, M4)', () => {
  it('a critical.type holding a bidi override or ESC', () => {
    const evil = `https://evil.example/${String.fromCharCode(0x202e)}${String.fromCharCode(0x1b)}[0m`;
    const stdout = `${JSON.stringify([{ critical: { type: evil, image: { 'docker-manifest-digest': IMG } } }])}\n`;
    const v = classifyVerify(result({ stdout }));
    expect(v).toMatchObject({ verdict: 'verified', types: [escapeUnsafe(evil)] });
  });
});


describe('the absence messages count only in cosign\'s own Error: framing (round 3)', () => {
  it('a registry body echoing "no signatures associated" in a trace is not an absence', () => {
    const stderr = `${T} <-- 500 http://h/v2/app/blobs/${LAYER} (1ms)\n{"errors":[{"message":"no signatures associated"}]}\nError: remote image: GET http://h/v2/app/blobs/${LAYER}: UNKNOWN\n`;
    expect(classifySignatureDownload(failedWith(1, stderr)).state).toBe('unknown');
    const att = `{"message":"no attestations with predicate type 'x' found"}\nError: remote image: GET http://h/x: UNKNOWN\n`;
    expect(classifyAttestationDownload(failedWith(1, att))).toBe('unknown');
  });
});
