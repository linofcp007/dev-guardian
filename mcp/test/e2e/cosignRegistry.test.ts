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
  it('nothing attached: absent and absent — every absence confirmed by a call that fails loudly', async () => {
    await withRegistry({}, async (reg) => {
      const c = await detectImageSupplyChain(reg.image, ctx);
      expect(c.run).toMatchObject({ name: 'cosign-tree', status: 'ok', target: reg.image });
      expect(c.findings.map((f) => f.rule_id).sort()).toEqual(['image-no-provenance', 'image-unsigned']);
      expect(c.summary).toMatchObject({ signature: 'absent', provenance: 'absent', checked: `${reg.host}/app@${reg.digest}` });
    });
  }, E2E_TIMEOUT);

  it('.sig answers 500: cosign tree still says "nothing found", exit 0 — the check says unknown, never unsigned', async () => {
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

  it('the referrers API answers 500: cosign tree fails loudly — failed, no finding at all', async () => {
    await withRegistry({ referrerBundles: [SIGN], faults: { referrers: 500 } }, async (reg) => {
      const c = await detectImageSupplyChain(reg.image, ctx);
      expect(c.run.status).toBe('failed');
      expect(c.run.reason).toMatch(/getting referrers/);
      expect(c.findings).toEqual([]);
    });
  }, E2E_TIMEOUT);

  it('a referrer cosign cannot fetch: tree says "nothing found" with an error on stderr — unknown', async () => {
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

  // Review round 2, N1: the fixture's bundles do not parse as Sigstore
  // bundles (nothing here is signed for real), and an artifact typed like a
  // predicate is not a bundle at all. Anyone who can push can attach either:
  // neither is a signature, whatever `tree` lists.
  it.each([
    ['an ordinary artifact typed https://spdx.dev/Document', { otherReferrers: ['https://spdx.dev/Document'] }],
    ['a "signing bundle" cosign cannot parse', { referrerBundles: [SIGN] }],
    ['a "provenance bundle" cosign cannot parse', { referrerBundles: [SLSA_V1] }],
  ] as const)('N1: %s is no signature — unsigned, and no provenance', async (_name, opts) => {
    await withRegistry(opts, async (reg) => {
      const tree = await raw(['tree', reg.image]);
      expect(tree.stdout).toMatch(/artifacts via OCI referrer/);

      const c = await detectImageSupplyChain(reg.image, ctx);
      expect(c.run.status).toBe('ok');
      expect(c.summary).toMatchObject({ signature: 'absent', provenance: 'absent' });
      expect(c.findings.map((f) => f.rule_id).sort()).toEqual(['image-no-provenance', 'image-unsigned']);
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

  it('I3: its blob answers 404 — listed but unreadable is no signature: "unsigned"', async () => {
    await withRegistry({ realBundles: [REAL_BUNDLE], faults: { 'referrer-blob': 404 } }, async (reg) => {
      const c = await detectImageSupplyChain(reg.image, ctx);
      expect(c.run.status).toBe('ok');
      expect(c.summary.signature).toBe('absent');
      expect(c.findings.some((f) => f.rule_id === 'image-unsigned')).toBe(true);
    });
  }, E2E_TIMEOUT);

  // A KNOWN blind spot, pinned so a cosign / go-containerregistry that fixes
  // it shows up here: a referrers answer whose Content-Type is not exactly
  // the OCI index type is read as "no referrers API", the tag fallback finds
  // nothing, and nothing is reported — no error anywhere. A signed image then
  // reads unsigned; SECURITY.md says so. Asserted on cosign's raw output only:
  // the check's own answer here is the false "absent" it cannot avoid.
  it('KNOWN BLIND SPOT: a referrers API answering `…; charset=utf-8` hides every referrer — cosign tree lists nothing, exit 0', async () => {
    await withRegistry(
      { referrerBundles: [SIGN], referrersContentType: 'application/vnd.oci.image.index.v1+json; charset=utf-8' },
      async (reg) => {
        const tree = await raw(['tree', reg.image]);
        expect(tree.exit).toBe(0);
        expect(tree.stdout).toMatch(/No Supply Chain Security Related Artifacts found/);
        expect(tree.stderr).not.toMatch(/Error/);
      },
    );
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

    it('nothing attached: "no signatures found", confirmed by tree and download — the high finding', async () => {
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
        expect(c.run.reason).toMatch(/cosign tree — which fails loudly when the registry does — did not complete: getting referrers/);
        expect(c.findings).toEqual([]);
        expect(c.summary.signature).toBe('unknown');
      });
    }, E2E_TIMEOUT);

    // Review round 2, N1: what anyone who can push can attach never turns a
    // rejection into "no verdict".
    it.each([
      ['a "signing bundle" verify cannot parse', { referrerBundles: [SIGN] }, /cosign tree lists OCI referrers typed https:\/\/sigstore\.dev\/cosign\/sign\/v1/],
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
        expect(c.run.reason).toMatch(/the registry failed to serve what cosign tree lists/);
        expect(c.run.reason).toMatch(/500/);
        expect(c.findings).toEqual([]);
      });
    }, E2E_TIMEOUT_SLOW);

    it('I3: its blob answers 404 — listed but could not be read: REJECTED', async () => {
      await withRegistry({ realBundles: [REAL_BUNDLE], faults: { 'referrer-blob': 404 } }, async (reg) => {
        const c = await verifyImage(reg.image, policy, ctx);
        expect(c.summary.signature).toBe('rejected');
        expect(c.findings[0]?.message).toMatch(/could not be read or parsed/);
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
