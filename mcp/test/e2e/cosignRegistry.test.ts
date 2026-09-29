/**
 * The REAL cosign against a registry that fails on purpose
 * (`test/helpers/fakeOciRegistry.ts`) — Part E review, I2.
 *
 * cosign swallows some registry failures and prints what it prints for
 * "nothing there"; the unit tests hold the reading of each output, this file
 * holds the claim that matters: with a failure injected, the check says
 * `unknown` and `failed`, never "unsigned", "no provenance" or "rejected".
 * Each case also pins the raw cosign behaviour it defends against, so a
 * cosign that stops swallowing (or starts swallowing something new) shows up
 * here first.
 *
 * Needs cosign ≥ 3.0 on PATH: without it every test is a visible skip, and
 * `GUARDIAN_REQUIRE_COSIGN=1` turns that skip into a failure. The `verify`
 * cases also need Sigstore's TUF trust root (network, once: `cosign
 * initialize` into a temporary TUF_ROOT) — without it they skip, saying so.
 * The existence cases need nothing but the fake registry on 127.0.0.1.
 */

import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import {
  detectImageSupplyChain,
  readinessFromProbe,
  verifyImage,
  type CosignRunContext,
} from '../../src/runners/cosignCheck.js';
import { runProcess } from '../../src/runners/processRunner.js';
import { startFakeRegistry, UNTRUSTED_CERT_PEM, type FakeImageOptions } from '../helpers/fakeOciRegistry.js';
import { startFakeRekor } from '../helpers/fakeRekor.js';
import { isInstalled } from '../helpers/toolchain.js';

const scratch = mkdtempSync(join(tmpdir(), 'guardian-cosign-e2e-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

/** cosign's own state kept out of the user's home: its TUF cache, and no registry credentials. */
const ENV: NodeJS.ProcessEnv = {
  ...process.env,
  TUF_ROOT: join(scratch, 'tuf'),
  DOCKER_CONFIG: join(scratch, 'docker'),
  NO_PROXY: 'localhost,127.0.0.1',
  no_proxy: 'localhost,127.0.0.1',
};
const ctx: CosignRunContext = { cwd: scratch, env: ENV };

async function cosignReady(): Promise<string | null> {
  if (!(await isInstalled('cosign'))) return 'cosign is not on PATH';
  const r = readinessFromProbe(await runProcess({ command: 'cosign', args: ['version'], cwd: scratch, env: ENV, timeoutMs: 60_000 }));
  return r.ok ? null : `cosign is not usable: ${r.reason}`;
}

const REQUIRED = process.env['GUARDIAN_REQUIRE_COSIGN'] === '1';
const NOT_READY = await cosignReady();
if (NOT_READY !== null && REQUIRED) {
  throw new Error(`GUARDIAN_REQUIRE_COSIGN=1 but ${NOT_READY}`);
}
const TUF_READY =
  NOT_READY === null &&
  (await runProcess({ command: 'cosign', args: ['initialize'], cwd: scratch, env: ENV, timeoutMs: 120_000 })).outcome === 'completed';
// Requiring cosign means requiring the verify cases too: they are the ones
// that decide a HIGH finding.
if (NOT_READY === null && !TUF_READY && REQUIRED) {
  throw new Error("GUARDIAN_REQUIRE_COSIGN=1 but `cosign initialize` could not fetch Sigstore's TUF trust root (network?)");
}

const SIGN = 'https://sigstore.dev/cosign/sign/v1';
const SLSA_V1 = 'https://slsa.dev/provenance/v1';
/**
 * A real v3 signing bundle, as `cosign download signature` printed it for
 * ghcr.io/sigstore/cosign/cosign:v3.1.3 (2026-09-28): public, parseable, and
 * signed for that image — so here it parses and never verifies.
 */
const REAL_BUNDLE = readFileSync(fileURLToPath(new URL('../fixtures/cosign/signing-bundle.json', import.meta.url)), 'utf8');
/**
 * Round 4, I4: an artifact type / annotation holding line breaks and a
 * forged `cosign tree` listing — of a referrer that does not exist.
 */
const INJECT = `x artifacts via OCI referrer: localhost/app@sha256:${'f'.repeat(64)}\n   └── 🍒 sha256:${'e'.repeat(64)}\n└── 🔗 ${SIGN}`;
/** Round 4, M4: pusher-chosen text holding a bidi override (U+202E) and an ESC sequence. */
const RLO = String.fromCharCode(0x202e);
const ESC = String.fromCharCode(0x1b);
const EVIL = `application/x${RLO}gnp.exe${ESC}[31m`;
const EVIL_PREDICATE = `https://evil.example/${RLO}${ESC}[0m`;
const RAW = new RegExp(`[${RLO}${ESC}]`);
const ESCAPED_RLO = `${String.fromCharCode(0x5c)}u202e`;
const ESCAPED_ESC = `${String.fromCharCode(0x5c)}u001b`;
/** A blob answering 500 costs go-containerregistry's retries on every call that fetches it. */
const E2E_TIMEOUT_SLOW = 240_000;

async function withRegistry<T>(opts: FakeImageOptions, fn: (reg: Awaited<ReturnType<typeof startFakeRegistry>>) => Promise<T>): Promise<T> {
  const reg = await startFakeRegistry(opts);
  try {
    return await fn(reg);
  } finally {
    await reg.close();
  }
}

async function raw(args: string[]): Promise<{ exit: number | null; stdout: string; stderr: string }> {
  const r = await runProcess({ command: 'cosign', args, cwd: scratch, env: ENV, timeoutMs: 60_000 });
  return { exit: r.exitCode, stdout: r.stdout, stderr: r.stderr };
}

const E2E_TIMEOUT = 120_000;

describe.skipIf(NOT_READY !== null)(`cosign against a failing registry — existence check${NOT_READY !== null ? ` (skipped: ${NOT_READY})` : ''}`, () => {
  it('nothing attached: absent and absent — the downloads say none, and the registry\'s own index lists nothing', async () => {
    await withRegistry({}, async (reg) => {
      const c = await detectImageSupplyChain(reg.image, ctx);
      expect(c.run).toMatchObject({ name: 'cosign-referrers', status: 'ok', target: reg.image });
      expect(c.findings.map((f) => f.rule_id).sort()).toEqual(['image-no-provenance', 'image-unsigned']);
      expect(c.summary).toMatchObject({ signature: 'absent', provenance: 'absent', checked: `${reg.host}/app@${reg.digest}` });
    });
  }, E2E_TIMEOUT);

  it('.sig answers 500: cosign tree still says "nothing found", exit 0 (one reason it is not used) — the check says unknown, never unsigned', async () => {
    await withRegistry({ faults: { sig: 500 } }, async (reg) => {
      const tree = await raw(['tree', reg.image]);
      expect(tree.exit).toBe(0);
      expect(tree.stdout).toMatch(/No Supply Chain Security Related Artifacts found/);

      const c = await detectImageSupplyChain(reg.image, ctx);
      expect(c.run.status).toBe('failed');
      expect(c.summary.signature).toBe('unknown');
      expect(c.findings.map((f) => f.rule_id)).toEqual(['image-no-provenance']);
    });
  }, E2E_TIMEOUT);

  it('.att answers 500: provenance unknown, never "no provenance"', async () => {
    await withRegistry({ faults: { att: 500 } }, async (reg) => {
      const c = await detectImageSupplyChain(reg.image, ctx);
      expect(c.run.status).toBe('failed');
      expect(c.summary.provenance).toBe('unknown');
      expect(c.findings.map((f) => f.rule_id)).toEqual(['image-unsigned']);
    });
  }, E2E_TIMEOUT);

  it('.sig answers 429: unknown too', async () => {
    await withRegistry({ faults: { sig: 429 } }, async (reg) => {
      const c = await detectImageSupplyChain(reg.image, ctx);
      expect(c.summary.signature).toBe('unknown');
      expect(c.findings.some((f) => f.rule_id === 'image-unsigned')).toBe(false);
    });
  }, E2E_TIMEOUT);

  it('the referrers API answers 500: failed, no finding at all', async () => {
    await withRegistry({ referrerBundles: [SIGN], faults: { referrers: 500 } }, async (reg) => {
      const c = await detectImageSupplyChain(reg.image, ctx);
      expect(c.run.status).toBe('failed');
      expect(c.run.reason).toMatch(/referrers/);
      expect(c.findings).toEqual([]);
    });
  }, E2E_TIMEOUT);

  it('a referrer whose manifest answers 500: unknown', async () => {
    await withRegistry({ referrerBundles: [SIGN], faults: { 'referrer-manifest': 500 } }, async (reg) => {
      const c = await detectImageSupplyChain(reg.image, ctx);
      expect(c.run.status).toBe('failed');
      expect(c.summary.signature).toBe('unknown');
      expect(c.findings.some((f) => f.rule_id === 'image-unsigned')).toBe(false);
    });
  }, E2E_TIMEOUT);

  it('a legacy .sig and a legacy .att holding SLSA v1: present and present', async () => {
    await withRegistry({ legacySignature: true, legacyAttestations: [SLSA_V1] }, async (reg) => {
      const c = await detectImageSupplyChain(reg.image, ctx);
      expect(c.run.status).toBe('ok');
      expect(c.findings).toEqual([]);
      expect(c.summary).toMatchObject({ signature: 'present_unverified', provenance: 'present_unverified' });
    });
  }, E2E_TIMEOUT);

  // Review round 2, N1: an artifact typed like a predicate is not a bundle at
  // all — anyone who can push can attach one: no signature.
  it('N1: an ordinary artifact typed https://spdx.dev/Document is no signature — unsigned, and no provenance', async () => {
    await withRegistry({ otherReferrers: ['https://spdx.dev/Document'] }, async (reg) => {
      const c = await detectImageSupplyChain(reg.image, ctx);
      expect(c.run.status).toBe('ok');
      expect(c.summary).toMatchObject({ signature: 'absent', provenance: 'absent' });
      expect(c.findings.map((f) => f.rule_id).sort()).toEqual(['image-no-provenance', 'image-unsigned']);
    });
  }, E2E_TIMEOUT);

  // Round 4, I6: a bundle the registry served (200) that cosign did not
  // return is junk OR a body that broke mid-transfer — the log cannot tell
  // which, so the existence check asks twice and then says unknown. The
  // fixture's junk bundles do not parse (nothing here is signed for real).
  it.each([
    ['a "signing bundle" cosign cannot parse', { referrerBundles: [SIGN] }],
    ['a "provenance bundle" cosign cannot parse', { referrerBundles: [SLSA_V1] }],
  ] as const)('N1 + I6: %s — unknown, both causes named; never "unsigned"', async (_name, opts) => {
    await withRegistry(opts, async (reg) => {
      const c = await detectImageSupplyChain(reg.image, ctx);
      expect(c.run.status).toBe('failed');
      expect(c.summary.signature).toBe('unknown');
      expect(c.run.reason).toMatch(/not a bundle it can parse, or the transfer failed mid-body; re-run if the registry was unstable/);
      expect(c.findings.some((f) => f.rule_id === 'image-unsigned')).toBe(false);
    });
  }, E2E_TIMEOUT);

  it('I6: a real signing bundle whose first transfer breaks mid-body (200, then the connection dies) — asked again: present', async () => {
    await withRegistry({ realBundles: [REAL_BUNDLE], resetBundleBlobs: 1 }, async (reg) => {
      const c = await detectImageSupplyChain(reg.image, ctx);
      expect(c.summary.signature).toBe('present_unverified');
      expect(c.findings.some((f) => f.rule_id === 'image-unsigned')).toBe(false);
    });
  }, E2E_TIMEOUT);

  it('I6: every transfer of it breaks mid-body — cosign says "no signatures associated", the log shows a 200: unknown, never "unsigned"', async () => {
    await withRegistry({ realBundles: [REAL_BUNDLE], resetBundleBlobs: Number.POSITIVE_INFINITY }, async (reg) => {
      const dl = await raw(['download', 'signature', reg.image]);
      expect(dl.stderr).toMatch(/no signatures associated/);

      const c = await detectImageSupplyChain(reg.image, ctx);
      expect(c.summary.signature).toBe('unknown');
      expect(c.run.reason).toMatch(/the transfer failed mid-body/);
      expect(c.findings.some((f) => f.rule_id === 'image-unsigned')).toBe(false);
    });
  }, E2E_TIMEOUT);

  // Round 4, I4: `cosign tree` prints a referrer's type as it finds it — a
  // line break in it forges listing lines. The check reads the registry's
  // own index instead.
  it('I4: an artifact type holding forged listing lines — tree prints them; the check reads the registry\'s index: unsigned, as it is', async () => {
    await withRegistry({ otherReferrers: [INJECT] }, async (reg) => {
      const tree = await raw(['tree', reg.image]);
      expect(tree.stdout).toContain(`sha256:${'f'.repeat(64)}`);

      const c = await detectImageSupplyChain(reg.image, ctx);
      expect(c.run.status).toBe('ok');
      expect(c.summary).toMatchObject({ signature: 'absent', provenance: 'absent' });
    });
  }, E2E_TIMEOUT);

  // Round 4, I5: OCI 1.1 lets an index be a referrer; cosign tree cannot
  // fetch one as an image and prints an error. The downloads read it.
  it('I5: an OCI index attached as a referrer — tree errors on it; the registry served it: unsigned, as it is', async () => {
    await withRegistry({ indexReferrers: ['application/vnd.example.index'] }, async (reg) => {
      const c = await detectImageSupplyChain(reg.image, ctx);
      expect(c.run.status).toBe('ok');
      expect(c.summary).toMatchObject({ signature: 'absent', provenance: 'absent' });
      expect(c.findings.map((f) => f.rule_id).sort()).toEqual(['image-no-provenance', 'image-unsigned']);
    });
  }, E2E_TIMEOUT);

  it('M4: a pusher-chosen artifact type with a bidi override and ESC reaches the finding escaped, never raw', async () => {
    await withRegistry({ otherReferrers: [EVIL] }, async (reg) => {
      const c = await detectImageSupplyChain(reg.image, ctx);
      const unsigned = c.findings.find((f) => f.rule_id === 'image-unsigned');
      expect(unsigned?.message).toContain(ESCAPED_RLO);
      expect(unsigned?.message).toContain(ESCAPED_ESC);
      expect(unsigned?.message).not.toMatch(RAW);
    });
  }, E2E_TIMEOUT);

  // Round 3, I3: a REAL signing bundle, its blob served, failing, or gone.
  it('I3: a real signing bundle served: present', async () => {
    await withRegistry({ realBundles: [REAL_BUNDLE] }, async (reg) => {
      const c = await detectImageSupplyChain(reg.image, ctx);
      expect(c.summary.signature).toBe('present_unverified');
      expect(c.findings.some((f) => f.rule_id === 'image-unsigned')).toBe(false);
    });
  }, E2E_TIMEOUT);

  it('I3: its blob answers 500 — cosign returns nothing and says nothing; the trace shows the 500: unknown, never "unsigned"', async () => {
    await withRegistry({ realBundles: [REAL_BUNDLE], faults: { 'referrer-blob': 500 } }, async (reg) => {
      const dl = await raw(['download', 'signature', reg.image]);
      expect(dl.stderr).toMatch(/no signatures associated/);

      const c = await detectImageSupplyChain(reg.image, ctx);
      expect(c.run.status).toBe('failed');
      expect(c.summary.signature).toBe('unknown');
      expect(c.summary.provenance).toBe('unknown');
      expect(c.run.reason).toMatch(/500/);
      expect(c.findings).toEqual([]);
    });
  }, E2E_TIMEOUT_SLOW);

  it('I3: its blob answers 404 — the registry answered: no signature, "unsigned"', async () => {
    await withRegistry({ realBundles: [REAL_BUNDLE], faults: { 'referrer-blob': 404 } }, async (reg) => {
      const c = await detectImageSupplyChain(reg.image, ctx);
      expect(c.run.status).toBe('ok');
      expect(c.summary.signature).toBe('absent');
      expect(c.findings.some((f) => f.rule_id === 'image-unsigned')).toBe(true);
    });
  }, E2E_TIMEOUT);

  // Round 4: a referrers answer whose Content-Type is not exactly the OCI
  // index type is read by go-containerregistry as "no referrers API" — cosign
  // then sees nothing and says nothing. The index is in the log all the same,
  // and what it lists cosign never fetched: unknown, no longer a false "absent".
  it('a referrers API answering `…; charset=utf-8` — cosign sees nothing (raw); the check reads the index from the log: unknown, never unsigned', async () => {
    await withRegistry({ realBundles: [REAL_BUNDLE], referrersContentType: 'application/vnd.oci.image.index.v1+json; charset=utf-8' }, async (reg) => {
      const tree = await raw(['tree', reg.image]);
      expect(tree.exit).toBe(0);
      expect(tree.stdout).toMatch(/No Supply Chain Security Related Artifacts found/);
      const dl = await raw(['download', 'signature', reg.image]);
      expect(dl.stderr).toMatch(/no signatures associated/);

      const c = await detectImageSupplyChain(reg.image, ctx);
      expect(c.summary.signature).toBe('unknown');
      expect(c.run.reason).toMatch(/could not be probed/);
      expect(c.findings.some((f) => f.rule_id === 'image-unsigned')).toBe(false);
    });
  }, E2E_TIMEOUT);

  // The KNOWN blind spot that remains, pinned so a cosign /
  // go-containerregistry that changes it shows up here: a referrers API
  // answering with no index at all (a 400, a 406, an HTML 200) reads as "no
  // referrers API"; the tag fallback finds nothing, and nothing anywhere says
  // otherwise. A signed image then reads unsigned — SECURITY.md says so.
  it('KNOWN BLIND SPOT: a referrers API answering 406 hides every referrer — the check\'s "absent" is the false one it cannot avoid', async () => {
    await withRegistry({ realBundles: [REAL_BUNDLE], faults: { referrers: 406 } }, async (reg) => {
      const dl = await raw(['download', 'signature', reg.image]);
      expect(dl.stderr).toMatch(/no signatures associated/);
      const c = await detectImageSupplyChain(reg.image, ctx);
      expect(c.summary.signature).toBe('absent');
    });
  }, E2E_TIMEOUT);

  it('an image the registry does not have: failed, and the reason says cosign reads the registry only', async () => {
    await withRegistry({}, async (reg) => {
      const c = await detectImageSupplyChain(`${reg.host}/app:never-pushed`, ctx);
      expect(c.run.status).toBe('failed');
      expect(c.run.reason).toMatch(/never pushed/);
      expect(c.findings).toEqual([]);
    });
  }, E2E_TIMEOUT);
});

describe.skipIf(NOT_READY !== null || !TUF_READY)(
  `cosign against a failing registry — verify${NOT_READY !== null ? ` (skipped: ${NOT_READY})` : !TUF_READY ? ' (skipped: `cosign initialize` could not fetch Sigstore\'s TUF trust root — no network?)' : ''}`,
  () => {
    const policy = { identity: 'https://github.com/org/app/.github/workflows/release.yml@refs/heads/main', issuer: 'https://token.actions.githubusercontent.com' };

    it('nothing attached: "no signatures found", confirmed by the download and the registry\'s index — the high finding', async () => {
      await withRegistry({}, async (reg) => {
        const c = await verifyImage(reg.image, policy, ctx);
        expect(c.run).toMatchObject({ name: 'cosign-verify', status: 'ok' });
        expect(c.findings.map((f) => [f.rule_id, f.severity])).toEqual([['image-signature-not-verified', 'high']]);
        expect(c.summary.signature).toBe('rejected');
      });
    }, E2E_TIMEOUT);

    it('a signed image whose referrers call fails: verify says "no signatures found" (exit 10) — failed, NOT rejected', async () => {
      await withRegistry({ referrerBundles: [SIGN], faults: { referrers: 500 } }, async (reg) => {
        const v = await raw(['verify', `--certificate-identity=${policy.identity}`, `--certificate-oidc-issuer=${policy.issuer}`, reg.image]);
        expect(v.exit).toBe(10);
        expect(v.stderr).toMatch(/no signatures found/);

        const c = await verifyImage(reg.image, policy, ctx);
        expect(c.run.status).toBe('failed');
        expect(c.run.reason).toMatch(/could not be confirmed/);
        expect(c.findings).toEqual([]);
        expect(c.summary.signature).toBe('unknown');
      });
    }, E2E_TIMEOUT);

    // Review round 2, N1: what anyone who can push can attach never turns a
    // rejection into "no verdict".
    it.each([
      ['a "signing bundle" verify cannot parse (round 4, I6: both causes named)', { referrerBundles: [SIGN] }, /Sigstore bundle \(https:\/\/sigstore\.dev\/cosign\/sign\/v1\).*listed and served, but cosign could not use it — not a bundle it can parse, or the transfer failed mid-body; re-run if the registry was unstable/],
      ['round 4, I4: a bundle whose annotation forges listing lines', { referrerBundles: [INJECT] }, /listed and served, but cosign could not use it/],
      ['round 4, I5: an OCI index attached as a referrer', { indexReferrers: ['application/vnd.example.index'] }, /application\/vnd\.example\.index.*none is a Sigstore bundle cosign can read/],
      ['an ordinary artifact typed https://spdx.dev/Document', { otherReferrers: ['https://spdx.dev/Document'] }, /https:\/\/spdx\.dev\/Document/],
      ['a legacy .sig holding a junk signature and no certificate (exit 12 "empty key")', { legacySignature: true }, /empty key/],
    ] as const)('N1: %s — REJECTED, the high finding', async (_name, opts, detail) => {
      await withRegistry(opts, async (reg) => {
        const c = await verifyImage(reg.image, policy, ctx);
        expect(c.run).toMatchObject({ name: 'cosign-verify', status: 'ok' });
        expect(c.findings.map((f) => [f.rule_id, f.severity])).toEqual([['image-signature-not-verified', 'high']]);
        expect(c.findings[0]?.message).toMatch(detail);
        expect(c.summary.signature).toBe('rejected');
      });
    }, E2E_TIMEOUT);

    // Round 3, I1 — deterministic: a legacy signature with a parseable
    // certificate sends cosign to Rekor's search, here a fake Rekor
    // (COSIGN_REKOR_URL; the argv dev-guardian builds is unchanged). cosign
    // frames every Rekor error `searching log query:`, a 400 included — and
    // Rekor answers 400 when the signature does not verify.
    it.each([
      ['400 (Rekor rejects the signature)', { status: 400, body: { code: 400, message: 'verifying signature: invalid signature when validating ASN.1 encoded signature' } }, 'rejected'],
      ['200 [] (not in the transparency log)', { status: 200, body: [] }, 'rejected'],
      ['422 (any other 4xx)', { status: 422, body: { code: 422, message: 'unprocessable' } }, 'rejected'],
      ['503 (the service is down)', { status: 503, body: { code: 503, message: 'unavailable' } }, 'unknown'],
      ['429 (rate limited)', { status: 429, body: { code: 429, message: 'slow down' } }, 'unknown'],
    ] as const)('I1: Rekor answering %s → %s', async (_name, answer, expected) => {
      const rekor = await startFakeRekor(answer);
      try {
        await withRegistry({ legacySignature: UNTRUSTED_CERT_PEM }, async (reg) => {
          const c = await verifyImage(reg.image, policy, { ...ctx, env: { ...ENV, COSIGN_REKOR_URL: rekor.url } });
          expect(rekor.requests.length, 'cosign searched the fake Rekor').toBeGreaterThan(0);
          expect(c.summary.signature).toBe(expected);
          if (expected === 'rejected') expect(c.findings.map((f) => f.severity)).toEqual(['high']);
          else expect(c.findings).toEqual([]);
        });
      } finally {
        await rekor.close();
      }
    }, E2E_TIMEOUT);

    // Round 3, I3: a REAL (parseable) signing bundle — signed for another
    // image — attached as a referrer, its blob served or not.
    it('I3: the bundle served — cosign verify reads it and rejects it (it signs another digest): REJECTED', async () => {
      await withRegistry({ realBundles: [REAL_BUNDLE] }, async (reg) => {
        const c = await verifyImage(reg.image, policy, ctx);
        expect(c.summary.signature).toBe('rejected');
        expect(c.findings.map((f) => f.severity)).toEqual(['high']);
      });
    }, E2E_TIMEOUT);

    it('I3: its blob answers 500 — verify says "no signatures found" twice, the trace shows the 500: NO verdict', async () => {
      await withRegistry({ realBundles: [REAL_BUNDLE], faults: { 'referrer-blob': 500 } }, async (reg) => {
        const c = await verifyImage(reg.image, policy, ctx);
        expect(c.run.status).toBe('failed');
        expect(c.run.reason).toMatch(/the registry failed to serve what its referrers index lists/);
        expect(c.run.reason).toMatch(/500/);
        expect(c.findings).toEqual([]);
      });
    }, E2E_TIMEOUT_SLOW);

    it('I3: its blob answers 404 — the registry answered: REJECTED', async () => {
      await withRegistry({ realBundles: [REAL_BUNDLE], faults: { 'referrer-blob': 404 } }, async (reg) => {
        const c = await verifyImage(reg.image, policy, ctx);
        expect(c.summary.signature).toBe('rejected');
        expect(c.findings[0]?.message).toMatch(/answered for each \(served, or 404\)/);
      });
    }, E2E_TIMEOUT);

    it('I6: every transfer of the bundle breaks mid-body — after the re-run, REJECTED with both causes named', async () => {
      await withRegistry({ realBundles: [REAL_BUNDLE], resetBundleBlobs: Number.POSITIVE_INFINITY }, async (reg) => {
        const c = await verifyImage(reg.image, policy, ctx);
        expect(c.summary.signature).toBe('rejected');
        expect(c.findings[0]?.message).toMatch(/not a bundle it can parse, or the transfer failed mid-body; re-run if the registry was unstable/);
      });
    }, E2E_TIMEOUT);

    it('M4: a pusher-chosen artifact type and predicate type reach the finding and the reason escaped, never raw', async () => {
      await withRegistry({ otherReferrers: [EVIL], referrerBundles: [EVIL_PREDICATE] }, async (reg) => {
        const c = await verifyImage(reg.image, policy, ctx);
        expect(c.summary.signature).toBe('rejected');
        const message = c.findings[0]?.message ?? '';
        expect(message).toContain(ESCAPED_RLO);
        expect(message).toContain(ESCAPED_ESC);
        for (const text of [message, c.run.reason ?? '', c.summary.note]) expect(text).not.toMatch(RAW);
      });
    }, E2E_TIMEOUT);

    it('.sig answers 500: failed, no finding', async () => {
      await withRegistry({ faults: { sig: 500 } }, async (reg) => {
        const c = await verifyImage(reg.image, policy, ctx);
        expect(c.run.status).toBe('failed');
        expect(c.findings).toEqual([]);
      });
    }, E2E_TIMEOUT);
  },
);
