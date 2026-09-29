/**
 * A fake OCI registry on 127.0.0.1 (plain HTTP — go-containerregistry, and
 * so cosign, talks HTTP to a `localhost:<port>` registry without any flag),
 * holding ONE image and whatever supply-chain artifacts a test attaches to
 * it, with a failure injectable per artifact kind.
 *
 * It exists because cosign itself swallows some registry failures (Part E
 * review, I2), and only a registry that fails on purpose shows which:
 *
 *   - `cosign tree` ignores any error but 404 on the legacy `.sig` / `.att`
 *     tags and prints "No Supply Chain Security Related Artifacts found",
 *     exit 0;
 *   - `cosign verify` falls back to legacy signatures when the referrers
 *     call fails, and says "no signatures found" (exit 10) for an image
 *     signed with a v3 bundle;
 *   - `cosign download signature` / `download attestation` try the bundles
 *     first and ignore a failure there too — but their legacy half fails
 *     loudly;
 *   - `cosign tree`'s referrers call fails loudly ("getting referrers").
 *
 * (The check no longer runs `cosign tree` — round 4 — but the e2e tests
 * still pin what it prints: the reasons it is not used.)
 *
 * Nothing here is signed for real: a bundle's layer is not a verifiable
 * Sigstore bundle, and a legacy signature's base64 is not a signature. What
 * the fixture serves is enough for cosign to LIST and DOWNLOAD artifacts,
 * which is what the existence check reads — and for `verify` to find
 * nothing, or fall back.
 */

import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

/**
 * A self-signed certificate Fulcio never issued (SAN: the org/app release
 * workflow), for a legacy signature whose certificate cannot chain to
 * Sigstore — an invalid signature. Public certificate only: its key was
 * discarded when it was made (openssl, 2026-09-28).
 */
export const UNTRUSTED_CERT_PEM = [
  '-----BEGIN CERTIFICATE-----',
  'MIICMTCCAdigAwIBAgIUT/vx17UnInX+tufPJKKR/+eRqw4wCgYIKoZIzj0EAwIw',
  'QzEiMCAGA1UECgwZZGV2LWd1YXJkaWFuIHRlc3QgZml4dHVyZTEdMBsGA1UEAwwU',
  'bm90IGlzc3VlZCBieSBGdWxjaW8wHhcNMjYwOTI4MjA1NTQyWhcNMzYwOTI1MjA1',
  'NTQyWjBDMSIwIAYDVQQKDBlkZXYtZ3VhcmRpYW4gdGVzdCBmaXh0dXJlMR0wGwYD',
  'VQQDDBRub3QgaXNzdWVkIGJ5IEZ1bGNpbzBZMBMGByqGSM49AgEGCCqGSM49AwEH',
  'A0IABAk2V3o26nYFVnWu5ZlZv3RBenmweP+iun/kUjTPg/AcYy46MrTjkidgcF4V',
  'eiDTT7GJyWmgcYK1gQTyCWgZ4iGjgakwgaYwHQYDVR0OBBYEFH434d8msLLp42DK',
  'SHDFDqPs72pvMB8GA1UdIwQYMBaAFH434d8msLLp42DKSHDFDqPs72pvMA8GA1Ud',
  'EwEB/wQFMAMBAf8wUwYDVR0RBEwwSoZIaHR0cHM6Ly9naXRodWIuY29tL29yZy9h',
  'cHAvLmdpdGh1Yi93b3JrZmxvd3MvcmVsZWFzZS55bWxAcmVmcy9oZWFkcy9tYWlu',
  'MAoGCCqGSM49BAMCA0cAMEQCIAsLdSJSLsSlvt5MPQ2qXdAQoCe8cspZshbsLUn1',
  'ArD/AiB1KtYUuPXgIEGNdhoYjzoiCq5awj6RNVXI/uMQkIm6bQ==',
  '-----END CERTIFICATE-----',
  '',
].join('\n');

/** The artifact kinds a failure can be injected into. */
export type FaultTarget = 'manifest' | 'sig' | 'att' | 'sbom' | 'referrers' | 'referrer-manifest' | 'referrer-blob';

export interface FakeImageOptions {
  /**
   * A legacy `sha256-<hex>.sig` tag with one simple-signing layer whose
   * signature is junk. `true`: no certificate (cosign: "empty key"); a PEM
   * string: that certificate attached (a certificate Fulcio never issued).
   */
  legacySignature?: boolean | string;
  /**
   * Referrers that are NOT Sigstore bundles: the `artifactType` of each —
   * `https://spdx.dev/Document` looks like a predicate type in `cosign
   * tree`, which prints a bundle's predicate type and any other artifact's
   * type the same way.
   */
  otherReferrers?: readonly string[];
  /**
   * The Content-Type the referrers API answers with (default: exactly the
   * OCI index type). go-containerregistry treats anything else as "no
   * referrers API" and falls back to the tag schema, so cosign sees nothing —
   * the index is still in its `-d` request log.
   */
  referrersContentType?: string;
  /** Predicate types of the DSSE attestations in a legacy `.att` tag. */
  legacyAttestations?: readonly string[];
  /**
   * Sigstore bundles attached as OCI referrers: the predicate type each
   * bundle's annotation names (`https://sigstore.dev/cosign/sign/v1` for a
   * cosign v3 signature, `https://slsa.dev/provenance/v1` for provenance).
   */
  referrerBundles?: readonly string[];
  /**
   * REAL Sigstore bundles (their JSON, as `cosign download signature` prints
   * one) attached as OCI referrers — they parse, so cosign returns them; they
   * were signed for another image, so `verify` rejects them. The annotation
   * names the DSSE payload's predicate type, as cosign's own push does.
   */
  realBundles?: readonly string[];
  /**
   * OCI image INDEXES attached as referrers (a subject and an artifactType —
   * OCI 1.1 allows it): the `artifactType` of each. `cosign tree` cannot
   * fetch one as an image and prints an error line for it.
   */
  indexReferrers?: readonly string[];
  /**
   * No referrers API: `/referrers/…` answers 404, and the referrers live in
   * the tag-schema fallback index `sha256-<hex>` — the ghcr.io shape
   * (measured) and the one a client pushes itself.
   */
  noReferrersApi?: boolean;
  /**
   * The `sha256-<hex>` fallback tag's raw body, built from the referrers'
   * descriptors — whatever a pusher wrote there, valid index or not (round
   * 5). Implies `noReferrersApi`. `mediaType`: its Content-Type (default: the
   * OCI index type).
   */
  fallbackTag?: { body: (referrers: ReadonlyArray<Record<string, unknown>>) => string; mediaType?: string };
  /** Bundle referrers without the `dev.sigstore.*` annotations — a tool that omits them (round 5, M7). */
  omitBundleAnnotations?: boolean;
  /**
   * HTTP status to answer instead, per artifact kind (500, 429, …).
   * `referrer-blob`: the layer of every bundle referrer — what `tree` never
   * fetches and cosign's `GetBundles` skips in silence when it fails.
   */
  faults?: Partial<Record<FaultTarget, number>>;
  /**
   * Reset the connection mid-body on this many bundle-blob requests (then
   * serve them): a 200 status line, headers, a few bytes, then the socket
   * is destroyed — go-containerregistry logs the 200 and nothing else.
   * `Infinity`: every time.
   */
  resetBundleBlobs?: number;
}

export interface FakeRegistry {
  /** `localhost:<port>` — the name, not the address, is what makes cosign speak plain HTTP to it. */
  host: string;
  /** The image by tag: `localhost:<port>/app:1`. */
  image: string;
  /** Its manifest digest, `sha256:<hex>`. */
  digest: string;
  /** Every request served, as `METHOD path?query -> status`. */
  requests: string[];
  close(): Promise<void>;
}

const OCI_MANIFEST = 'application/vnd.oci.image.manifest.v1+json';
const OCI_INDEX = 'application/vnd.oci.image.index.v1+json';
const OCI_CONFIG = 'application/vnd.oci.image.config.v1+json';
const OCI_EMPTY = 'application/vnd.oci.empty.v1+json';
const BUNDLE = 'application/vnd.dev.sigstore.bundle.v0.3+json';
const SIMPLE_SIGNING = 'application/vnd.dev.cosign.simplesigning.v1+json';
const DSSE = 'application/vnd.dsse.envelope.v1+json';

interface Stored {
  mediaType: string;
  body: Buffer;
  digest: string;
}

function sha256(body: Buffer): string {
  return `sha256:${createHash('sha256').update(body).digest('hex')}`;
}

function json(value: unknown): Buffer {
  return Buffer.from(JSON.stringify(value));
}

function descriptor(mediaType: string, body: Buffer, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { mediaType, digest: sha256(body), size: body.length, ...extra };
}

const ERROR_CODE: Record<number, string> = { 404: 'MANIFEST_UNKNOWN', 429: 'TOOMANYREQUESTS', 500: 'UNKNOWN', 503: 'UNAVAILABLE' };

export async function startFakeRegistry(opts: FakeImageOptions = {}): Promise<FakeRegistry> {
  const repo = 'app';
  const blobs = new Map<string, Buffer>();
  const manifests = new Map<string, Stored>();
  const kindOf = new Map<string, FaultTarget>();
  const referrers: Array<Record<string, unknown>> = [];

  const blob = (body: Buffer): string => {
    const d = sha256(body);
    blobs.set(d, body);
    return d;
  };
  const putManifest = (value: Record<string, unknown>, tags: string[], kind: FaultTarget): Stored => {
    const body = json(value);
    const stored: Stored = { mediaType: String(value['mediaType']), body, digest: sha256(body) };
    for (const key of [stored.digest, ...tags]) {
      manifests.set(key, stored);
      kindOf.set(key, kind);
    }
    return stored;
  };

  // The image: an empty config, no layers.
  const config = json({ architecture: 'amd64', os: 'linux', rootfs: { type: 'layers', diff_ids: [] }, config: {} });
  blob(config);
  const image = putManifest(
    { schemaVersion: 2, mediaType: OCI_MANIFEST, config: descriptor(OCI_CONFIG, config), layers: [] },
    ['1'],
    'manifest',
  );
  const hex = image.digest.slice('sha256:'.length);
  const emptyConfig = Buffer.from('{}');
  blob(emptyConfig);

  if (opts.legacySignature !== undefined && opts.legacySignature !== false) {
    const payload = json({
      critical: { identity: { 'docker-reference': `${repo}` }, image: { 'docker-manifest-digest': image.digest }, type: 'cosign container image signature' },
      optional: null,
    });
    blob(payload);
    const annotations: Record<string, string> = { 'dev.cosignproject.cosign/signature': 'bm90LWEtc2lnbmF0dXJl' };
    if (typeof opts.legacySignature === 'string') annotations['dev.sigstore.cosign/certificate'] = opts.legacySignature;
    putManifest(
      {
        schemaVersion: 2,
        mediaType: OCI_MANIFEST,
        config: descriptor(OCI_CONFIG, emptyConfig),
        layers: [descriptor(SIMPLE_SIGNING, payload, { annotations })],
      },
      [`sha256-${hex}.sig`],
      'sig',
    );
  }

  for (const artifactType of opts.otherReferrers ?? []) {
    const layer = json({ note: `an ordinary artifact of type ${artifactType}` });
    blob(layer);
    const stored = putManifest(
      {
        schemaVersion: 2,
        mediaType: OCI_MANIFEST,
        artifactType,
        config: descriptor(OCI_EMPTY, emptyConfig),
        layers: [descriptor('application/json', layer)],
        subject: { mediaType: OCI_MANIFEST, digest: image.digest, size: image.body.length },
      },
      [],
      'referrer-manifest',
    );
    referrers.push({ mediaType: OCI_MANIFEST, digest: stored.digest, size: stored.body.length, artifactType });
  }

  if (opts.legacyAttestations !== undefined && opts.legacyAttestations.length > 0) {
    const layers = opts.legacyAttestations.map((predicateType) => {
      const statement = json({ _type: 'https://in-toto.io/Statement/v0.1', subject: [{ name: repo, digest: { sha256: hex } }], predicateType, predicate: {} });
      const envelope = json({ payloadType: 'application/vnd.in-toto+json', payload: statement.toString('base64'), signatures: [{ keyid: '', sig: 'bm90LWEtc2lnbmF0dXJl' }] });
      blob(envelope);
      return descriptor(DSSE, envelope, { annotations: { 'dev.cosignproject.cosign/signature': '', predicateType } });
    });
    putManifest({ schemaVersion: 2, mediaType: OCI_MANIFEST, config: descriptor(OCI_CONFIG, emptyConfig), layers }, [`sha256-${hex}.att`], 'att');
  }

  const bundleBlobs = new Set<string>();
  const bundles: Array<{ layer: Buffer; predicateType: string }> = [
    ...(opts.referrerBundles ?? []).map((predicateType) => ({
      layer: json({ mediaType: BUNDLE, note: `not a real bundle (${predicateType})` }),
      predicateType,
    })),
    ...(opts.realBundles ?? []).map((text) => {
      const parsed = JSON.parse(text) as { dsseEnvelope?: { payload?: string } };
      const statement = JSON.parse(Buffer.from(parsed.dsseEnvelope?.payload ?? '', 'base64').toString('utf8')) as { predicateType?: string };
      return { layer: Buffer.from(text.trim()), predicateType: statement.predicateType ?? 'unknown' };
    }),
  ];
  for (const { layer, predicateType } of bundles) {
    bundleBlobs.add(blob(layer));
    const annotations = opts.omitBundleAnnotations === true ? undefined : { 'dev.sigstore.bundle.content': 'dsse-envelope', 'dev.sigstore.bundle.predicateType': predicateType };
    const stored = putManifest(
      {
        schemaVersion: 2,
        mediaType: OCI_MANIFEST,
        artifactType: BUNDLE,
        config: descriptor(OCI_EMPTY, emptyConfig),
        layers: [descriptor(BUNDLE, layer)],
        subject: { mediaType: OCI_MANIFEST, digest: image.digest, size: image.body.length },
        ...(annotations === undefined ? {} : { annotations }),
      },
      [],
      'referrer-manifest',
    );
    referrers.push({ mediaType: OCI_MANIFEST, digest: stored.digest, size: stored.body.length, artifactType: BUNDLE, ...(annotations === undefined ? {} : { annotations }) });
  }

  for (const artifactType of opts.indexReferrers ?? []) {
    const stored = putManifest(
      { schemaVersion: 2, mediaType: OCI_INDEX, artifactType, manifests: [], subject: { mediaType: OCI_MANIFEST, digest: image.digest, size: image.body.length } },
      [],
      'referrer-manifest',
    );
    referrers.push({ mediaType: OCI_INDEX, digest: stored.digest, size: stored.body.length, artifactType });
  }

  // The tag-schema fallback: the referrers index stored as a manifest — or,
  // with `fallbackTag`, whatever bytes a pusher put there.
  const noReferrersApi = opts.noReferrersApi === true || opts.fallbackTag !== undefined;
  if (opts.fallbackTag !== undefined) {
    const body = Buffer.from(opts.fallbackTag.body(referrers));
    manifests.set(`sha256-${hex}`, { mediaType: opts.fallbackTag.mediaType ?? OCI_INDEX, body, digest: sha256(body) });
    kindOf.set(`sha256-${hex}`, 'referrers');
  } else if (noReferrersApi) {
    putManifest({ schemaVersion: 2, mediaType: OCI_INDEX, manifests: referrers }, [`sha256-${hex}`], 'referrers');
  }

  const requests: string[] = [];
  const faults = opts.faults ?? {};
  let resetsLeft = opts.resetBundleBlobs ?? 0;

  const fail = (res: ServerResponse, status: number, message: string): void => {
    const code = ERROR_CODE[status] ?? 'UNKNOWN';
    res.writeHead(status, { 'Content-Type': 'application/json', 'Docker-Distribution-API-Version': 'registry/2.0' });
    res.end(JSON.stringify({ errors: [{ code, message }] }));
  };

  const handle = (req: IncomingMessage, res: ServerResponse): number => {
    const url = new URL(req.url ?? '/', 'http://fake');
    const path = url.pathname;
    const head = req.method === 'HEAD';
    if (path === '/v2/' || path === '/v2') {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Docker-Distribution-API-Version': 'registry/2.0' });
      res.end('{}');
      return 200;
    }
    const m = new RegExp(`^/v2/${repo}/(manifests|blobs|referrers)/(.+)$`).exec(path);
    if (m === null) {
      fail(res, 404, 'no such route');
      return 404;
    }
    const [, what, ref] = m;
    if (what === 'referrers') {
      if (noReferrersApi) {
        fail(res, 404, 'referrers API not supported');
        return 404;
      }
      if (faults.referrers !== undefined) {
        fail(res, faults.referrers, 'injected referrers failure');
        return faults.referrers;
      }
      const wanted = url.searchParams.get('artifactType');
      const list = ref === image.digest ? referrers.filter((r) => wanted === null || r['artifactType'] === wanted) : [];
      const headers: Record<string, string> = { 'Content-Type': opts.referrersContentType ?? OCI_INDEX };
      if (wanted !== null) headers['OCI-Filters-Applied'] = 'artifactType';
      res.writeHead(200, headers);
      res.end(head ? undefined : JSON.stringify({ schemaVersion: 2, mediaType: OCI_INDEX, manifests: list }));
      return 200;
    }
    if (what === 'blobs') {
      if (faults['referrer-blob'] !== undefined && bundleBlobs.has(ref ?? '')) {
        fail(res, faults['referrer-blob'], 'injected referrer-blob failure');
        return faults['referrer-blob'];
      }
      const body = blobs.get(ref ?? '');
      if (body === undefined) {
        fail(res, 404, 'blob unknown');
        return 404;
      }
      if (!head && resetsLeft > 0 && bundleBlobs.has(ref ?? '')) {
        // A 200, a few bytes, then the connection dies mid-body.
        resetsLeft -= 1;
        res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': String(body.length), 'Docker-Content-Digest': ref ?? '' });
        res.write(body.subarray(0, Math.min(16, body.length)), () => res.socket?.destroy());
        return 200;
      }
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': String(body.length), 'Docker-Content-Digest': ref ?? '' });
      res.end(head ? undefined : body);
      return 200;
    }
    // manifests: a fault answers for the kind the name belongs to — also
    // for a name that holds nothing (an injected 500 on `.sig` is a 500
    // whether or not a signature exists).
    const key = ref ?? '';
    const kind: FaultTarget | undefined =
      kindOf.get(key) ?? (key.endsWith('.sig') ? 'sig' : key.endsWith('.att') ? 'att' : key.endsWith('.sbom') ? 'sbom' : undefined);
    const injected = kind === undefined ? undefined : faults[kind];
    if (injected !== undefined) {
      fail(res, injected, `injected ${kind} failure`);
      return injected;
    }
    const stored = manifests.get(key);
    if (stored === undefined) {
      fail(res, 404, 'manifest unknown');
      return 404;
    }
    res.writeHead(200, {
      'Content-Type': stored.mediaType,
      'Content-Length': String(stored.body.length),
      'Docker-Content-Digest': stored.digest,
    });
    res.end(head ? undefined : stored.body);
    return 200;
  };

  const server = createServer((req, res) => {
    let status = 500;
    try {
      status = handle(req, res);
    } catch (e) {
      fail(res, 500, e instanceof Error ? e.message : String(e));
    }
    requests.push(`${req.method ?? '?'} ${req.url ?? ''} -> ${status}`);
  });
  await new Promise<void>((resolveListen) => server.listen(0, '127.0.0.1', resolveListen));
  const port = (server.address() as AddressInfo).port;
  const host = `localhost:${port}`;
  return {
    host,
    image: `${host}/${repo}:1`,
    digest: image.digest,
    requests,
    close: () =>
      new Promise<void>((resolveClose) => {
        server.closeAllConnections();
        server.close(() => resolveClose());
      }),
  };
}
