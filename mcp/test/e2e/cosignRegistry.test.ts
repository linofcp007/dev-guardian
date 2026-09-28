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

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  detectImageSupplyChain,
  readinessFromProbe,
  verifyImage,
  type CosignRunContext,
} from '../../src/runners/cosignCheck.js';
import { runProcess } from '../../src/runners/processRunner.js';
import { startFakeRegistry, type FakeImageOptions } from '../helpers/fakeOciRegistry.js';
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

const NOT_READY = await cosignReady();
if (NOT_READY !== null && process.env['GUARDIAN_REQUIRE_COSIGN'] === '1') {
  throw new Error(`GUARDIAN_REQUIRE_COSIGN=1 but ${NOT_READY}`);
}
const TUF_READY =
  NOT_READY === null &&
  (await runProcess({ command: 'cosign', args: ['initialize'], cwd: scratch, env: ENV, timeoutMs: 120_000 })).outcome === 'completed';

const SIGN = 'https://sigstore.dev/cosign/sign/v1';
const SLSA_V1 = 'https://slsa.dev/provenance/v1';

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

  it('a signing bundle as an OCI referrer: present', async () => {
    await withRegistry({ referrerBundles: [SIGN] }, async (reg) => {
      const c = await detectImageSupplyChain(reg.image, ctx);
      expect(c.summary.signature).toBe('present_unverified');
      expect(c.findings.map((f) => f.rule_id)).toEqual(['image-no-provenance']);
    });
  }, E2E_TIMEOUT);

  it('only a signed provenance bundle (review M2): "attestation only", no "unsigned" finding', async () => {
    await withRegistry({ referrerBundles: [SLSA_V1] }, async (reg) => {
      const c = await detectImageSupplyChain(reg.image, ctx);
      expect(c.findings).toEqual([]);
      expect(c.summary).toMatchObject({ signature: 'attestation_only_unverified', provenance: 'present_unverified' });
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
        expect(c.run.reason).toMatch(/could not be confirmed/);
        expect(c.findings).toEqual([]);
        expect(c.summary.signature).toBe('unknown');
      });
    }, E2E_TIMEOUT);

    it('a signing bundle verify cannot parse: "no signatures found" while tree lists it — failed, NOT rejected', async () => {
      await withRegistry({ referrerBundles: [SIGN] }, async (reg) => {
        const c = await verifyImage(reg.image, policy, ctx);
        expect(c.run.status).toBe('failed');
        expect(c.run.reason).toMatch(/cosign tree lists https:\/\/sigstore\.dev\/cosign\/sign\/v1/);
        expect(c.findings).toEqual([]);
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
