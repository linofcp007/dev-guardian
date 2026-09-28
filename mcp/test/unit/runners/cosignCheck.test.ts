/**
 * The pure half of scan_containers' cosign check (`runners/cosignCheck.ts`):
 * reading `cosign tree`, `cosign download attestation` and `cosign verify`.
 *
 * Every output below is real, captured from cosign v3.1.3 on 2026-09-28
 * against public images (only the digests' middles are as printed — nothing
 * is abbreviated). What each one proves is named in its test; the rule they
 * all serve: an output this module cannot read is `unknown`, never "absent"
 * and never "verified".
 */
import { describe, expect, it } from 'vitest';
import {
  classifyAttestationDownload,
  classifyVerify,
  parseCosignTree,
  provenanceFromTree,
  signatureFromTree,
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

/** alpine:3.20 — nothing at all. Note: no trailing newline, as cosign prints it. */
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

/** ghcr.io/actions/actions-runner:latest — a GitHub build-provenance attestation as a referrer, no signature. */
const TREE_REFERRER_PROVENANCE = [
  '📦 Supply Chain Security Related artifacts for an image: ghcr.io/actions/actions-runner:latest',
  '└── 🔗 https://slsa.dev/provenance/v1 artifacts via OCI referrer: ghcr.io/actions/actions-runner@sha256:ffce13d652bbe7eab8ab4733a45b30290441eb488bf28a274d74720ff5ee831e',
  '   └── 🍒 sha256:a12d4c69500caf250c79e1e56ccc984f4972d42be5b611551eef7ac172748702',
  '',
].join('\n');

function result(partial: Partial<ProcessRunResult>): ProcessRunResult {
  return { outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false, ...partial };
}

describe('parseCosignTree', () => {
  it('reads a legacy .sig tag and a legacy .att tag (whose predicate types the listing does not give)', () => {
    const tree = parseCosignTree(TREE_LEGACY, '');
    expect(tree).toEqual({
      signature: true,
      legacyAttestations: true,
      referrerTypes: [],
      ambiguousBundles: false,
      fetchErrors: [],
    });
    expect(tree === null ? null : signatureFromTree(tree)).toBe('present');
    // The .att tag may or may not hold provenance: it has to be downloaded.
    expect(tree === null ? null : provenanceFromTree(tree)).toBe('download');
  });

  it('reads "nothing found" as absent — signature and provenance both', () => {
    const tree = parseCosignTree(TREE_NONE, '');
    expect(tree).not.toBeNull();
    expect(tree === null ? null : signatureFromTree(tree)).toBe('absent');
    expect(tree === null ? null : provenanceFromTree(tree)).toBe('absent');
  });

  it("counts cosign v3's signing bundle attached as an OCI referrer as a signature", () => {
    const tree = parseCosignTree(TREE_REFERRER_SIGNATURE, '');
    expect(tree?.referrerTypes).toEqual(['https://sigstore.dev/cosign/sign/v1', 'https://sigstore.dev/cosign/sign/v1']);
    expect(tree === null ? null : signatureFromTree(tree)).toBe('present');
    expect(tree === null ? null : provenanceFromTree(tree)).toBe('absent');
  });

  it('counts a SLSA provenance referrer as provenance — and a provenance attestation is not an image signature', () => {
    const tree = parseCosignTree(TREE_REFERRER_PROVENANCE, '');
    expect(tree === null ? null : provenanceFromTree(tree)).toBe('present');
    expect(tree === null ? null : signatureFromTree(tree)).toBe('absent');
  });

  it('a referrer cosign could not fetch makes an absence unknown, never "absent"', () => {
    const stderr =
      'Error fetching artifact registry.example/app@sha256:aaaa: GET https://registry.example/v2/app/manifests/sha256:aaaa: TOOMANYREQUESTS\n';
    const tree = parseCosignTree(TREE_REFERRER_PROVENANCE, stderr);
    expect(tree?.fetchErrors).toHaveLength(1);
    expect(tree === null ? null : signatureFromTree(tree)).toBe('unknown');
    // What WAS listed still counts.
    expect(tree === null ? null : provenanceFromTree(tree)).toBe('present');
  });

  it('a sigstore bundle whose predicate type cosign did not name could be either: unknown, not absent', () => {
    const stdout =
      '📦 Supply Chain Security Related artifacts for an image: registry.example/app:1\n' +
      '└── 🔗 application/vnd.dev.sigstore.bundle.v0.3+json artifacts via OCI referrer: registry.example/app@sha256:bbbb\n' +
      '   └── 🍒 sha256:cccc\n';
    const tree = parseCosignTree(stdout, '');
    expect(tree?.ambiguousBundles).toBe(true);
    expect(tree === null ? null : signatureFromTree(tree)).toBe('unknown');
    expect(tree === null ? null : provenanceFromTree(tree)).toBe('unknown');
  });

  it('an SBOM referrer is neither a signature nor provenance', () => {
    const stdout =
      '📦 Supply Chain Security Related artifacts for an image: registry.example/app:1\n' +
      '└── 🔗 https://spdx.dev/Document artifacts via OCI referrer: registry.example/app@sha256:bbbb\n' +
      '   └── 🍒 sha256:cccc\n';
    const tree = parseCosignTree(stdout, '');
    expect(tree === null ? null : signatureFromTree(tree)).toBe('absent');
    expect(tree === null ? null : provenanceFromTree(tree)).toBe('absent');
  });

  it.each([
    ['empty output', ''],
    ['the header alone (cosign stopped after it)', '📦 Supply Chain Security Related artifacts for an image: alpine:3.20\n'],
    ['a format this module does not know', 'Supply chain artifacts for alpine:3.20:\n  signatures: 0\n'],
  ])('%s is not read at all (null) — an unreadable listing is never "unsigned"', (_name, stdout) => {
    expect(parseCosignTree(stdout, '')).toBeNull();
  });
});

describe('classifyAttestationDownload', () => {
  it('a match prints the attestation: present', () => {
    expect(classifyAttestationDownload(result({ stdout: '{"payloadType":"application/vnd.in-toto+json"}\n' }))).toBe('present');
  });

  it("cosign's own \"no attestations with predicate type\" (exit 1): absent", () => {
    const stderr =
      "Error: no attestations with predicate type 'https://slsa.dev/provenance/v0.2' found\n" +
      "error during command execution: no attestations with predicate type 'https://slsa.dev/provenance/v0.2' found\n";
    expect(classifyAttestationDownload(result({ outcome: 'failed', exitCode: 1, stderr }))).toBe('absent');
  });

  it('anything else — a registry error, a timeout, exit 0 with nothing printed — is unknown', () => {
    const stderr = 'Error: Get "https://no-such-registry.invalid/v2/": dial tcp: lookup no-such-registry.invalid: no such host\n';
    expect(classifyAttestationDownload(result({ outcome: 'failed', exitCode: 1, stderr }))).toBe('unknown');
    expect(classifyAttestationDownload(result({ outcome: 'timed_out', exitCode: null }))).toBe('unknown');
    expect(classifyAttestationDownload(result({ stdout: '' }))).toBe('unknown');
  });

  it('output past the cap is still output, and cosign prints only matching attestations: present', () => {
    expect(classifyAttestationDownload(result({ outcome: 'output_too_large', exitCode: null, truncated: true }))).toBe('present');
  });
});

describe('classifyVerify', () => {
  it('exit 0: verified', () => {
    expect(classifyVerify(result({ stdout: '[{"critical":{}}]' }))).toEqual({ verdict: 'verified' });
  });

  it('exit 10 (no signature at all): rejected', () => {
    const r = classifyVerify(result({ outcome: 'failed', exitCode: 10, stderr: 'Error: no signatures found\nerror during command execution: no signatures found\n' }));
    expect(r).toMatchObject({ verdict: 'rejected', reason: 'no_signature', detail: 'no signatures found' });
  });

  it('exit 12 (a legacy signature by someone else): rejected, naming who did sign', () => {
    const stderr =
      'Error: no matching signatures: none of the expected identities matched what was in the certificate, got subjects ' +
      '[https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main] with issuer https://token.actions.githubusercontent.com\n' +
      'error during command execution: no matching signatures: …\n';
    const r = classifyVerify(result({ outcome: 'failed', exitCode: 12, stderr }));
    expect(r).toMatchObject({ verdict: 'rejected', reason: 'no_matching_signature' });
    expect(r.verdict === 'rejected' ? r.detail : '').toContain('got subjects [https://github.com/chainguard-images/');
  });

  it('exit 13 (signed with a key, no certificate to hold an identity): rejected', () => {
    const r = classifyVerify(result({ outcome: 'failed', exitCode: 13, stderr: 'Error: no certificate found on signature\n' }));
    expect(r).toMatchObject({ verdict: 'rejected', reason: 'no_certificate' });
  });

  it("exit 1 with a v3 bundle's identity mismatch is a rejection too — cosign does not use 12 there", () => {
    const stderr =
      'Error: no matching attestations: failed to verify log inclusion: transparency log certificate does not match\n' +
      'failed to verify certificate identity: no matching CertificateIdentity found, last error: expected issuer value ' +
      '"https://token.actions.githubusercontent.com", got "https://accounts.google.com"\n';
    expect(classifyVerify(result({ outcome: 'failed', exitCode: 1, stderr }))).toMatchObject({
      verdict: 'rejected',
      reason: 'no_matching_signature',
    });
  });

  it.each([
    [
      'a regexp cosign cannot compile (also prefixed "no matching attestations")',
      1,
      'Error: no matching attestations: error parsing regexp: missing closing ): `(`\nerror parsing regexp: missing closing ): `(`\n',
    ],
    ['an unreachable registry', 1, 'Error: Get "https://no-such-registry.invalid/v2/": dial tcp: lookup no-such-registry.invalid: no such host\n'],
    ['a tag that does not exist (exit 11)', 11, 'Error: image tag not found: GET https://index.docker.io/v2/library/alpine/manifests/x: MANIFEST_UNKNOWN\n'],
  ])('%s is an error — the check did not complete — never a rejection', (_name, exitCode, stderr) => {
    const r = classifyVerify(result({ outcome: 'failed', exitCode, stderr }));
    expect(r.verdict).toBe('error');
  });

  it('a timeout or a cancellation is an error', () => {
    expect(classifyVerify(result({ outcome: 'timed_out', exitCode: null })).verdict).toBe('error');
    expect(classifyVerify(result({ outcome: 'cancelled', exitCode: null })).verdict).toBe('error');
  });
});

describe('verifyArgs', () => {
  it('passes each value inside its flag (`--flag=value`), so none can be read as an option; the image is last', () => {
    expect(verifyArgs('ghcr.io/org/app:1', { identity: 'a@b.example', issuer: 'https://accounts.google.com' })).toEqual([
      'verify',
      '--certificate-identity=a@b.example',
      '--certificate-oidc-issuer=https://accounts.google.com',
      'ghcr.io/org/app:1',
    ]);
    expect(
      verifyArgs('ghcr.io/org/app:1', { identityRegexp: '^https://github.com/org/', issuerRegexp: '-looks-like-a-flag' }),
    ).toEqual([
      'verify',
      '--certificate-identity-regexp=^https://github.com/org/',
      '--certificate-oidc-issuer-regexp=-looks-like-a-flag',
      'ghcr.io/org/app:1',
    ]);
  });
});
