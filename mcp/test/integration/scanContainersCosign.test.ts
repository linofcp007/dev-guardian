/**
 * scan_containers' image signature and provenance check (cosign).
 *
 * For the image it scans, when cosign ≥ 3.0 is installed and the network is
 * not disabled:
 *   - the tag is pinned to a digest first (`cosign triangulate`), and every
 *     later call checks that digest — the response names it;
 *   - with a signer identity AND an issuer: a real `cosign verify` — a
 *     rejection is a high finding, but only a CONFIRMED one: cosign says
 *     "no signatures found" also when its referrers call failed, and folds
 *     transient errors into "no matching signatures";
 *   - without them: only whether a signature and a SLSA provenance
 *     attestation exist — and "absent" only when a call that fails loudly
 *     agrees (`cosign tree` swallows a failing `.sig` / `.att`);
 *   - cosign missing, older than 3.0, or GUARDIAN_OFFLINE=1: skipped, in
 *     missing_tools.
 *
 * cosign itself is faked here (`runProcess` is mocked) with the outputs
 * `test/unit/runners/cosignCheck.test.ts` documents; the real binary against
 * a failing registry is `test/e2e/cosignRegistry.test.ts`.
 */
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));
vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual = await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>(
    '../../src/tools/scanHelpers.js',
  );
  return { ...actual, scannerAvailable: vi.fn() };
});

import { runProcess, type ProcessRunOptions, type ProcessRunResult } from '../../src/runners/processRunner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import type { PluginContext } from '../../src/context.js';
import { TOOLS } from '../../src/tools/index.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/scanContainers.js');
  await import('../../src/tools/diffScans.js');
});

function tool(name = 'scan_containers') {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`${name} not registered`);
  return t;
}

function plugin(projectPath: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' },
    scriptsDir: projectPath,
    progressNotifier: { send: () => {} },
  };
}

const IMAGE = 'ghcr.io/org/app:1.2.3';
const DIGEST = 'sha256:41e17ed83c594a64a9396b6ab96dd26d5ddc290dacf4c177464712ff21ad534f';
const PINNED = `ghcr.io/org/app@${DIGEST}`;
const ok: ProcessRunResult = { outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false };
const exit = (exitCode: number, stderr: string): ProcessRunResult => ({ ...ok, outcome: 'failed', exitCode, stderr });
const out = (stdout: string): ProcessRunResult => ({ ...ok, stdout });

const VERSION = (v: string): ProcessRunResult => out(`cosign: A tool for Container Signing\n\nGitVersion:    v${v}\nGoVersion:     go1.26.4\n`);
const TRIANGULATED = out(`${PINNED}\n`);
const TREE_NONE =
  `📦 Supply Chain Security Related artifacts for an image: ${PINNED}\n` +
  `No Supply Chain Security Related Artifacts found for image ${PINNED},\n` +
  ' start creating one with simply running$ cosign sign <img>';
const TREE_LEGACY = [
  `📦 Supply Chain Security Related artifacts for an image: ${PINNED}`,
  '└── 💾 Attestations for an image tag: ghcr.io/org/app:sha256-41e17ed83c594a64a9396b6ab96dd26d5ddc290dacf4c177464712ff21ad534f.att',
  '   └── 🍒 sha256:e2ee0775e2825b7c937fcb9b31f0101870a86e57d664becd1c79f4b51c2b96c2',
  '└── 🔐 Signatures for an image tag: ghcr.io/org/app:sha256-41e17ed83c594a64a9396b6ab96dd26d5ddc290dacf4c177464712ff21ad534f.sig',
  '   └── 🍒 sha256:064523df0fd3979ec03a0737e967c53fe291926030dd2f5eba56ec1344cb73ca',
  '',
].join('\n');
const TREE_SIGN_BUNDLE = [
  `📦 Supply Chain Security Related artifacts for an image: ${PINNED}`,
  '└── 🔗 https://sigstore.dev/cosign/sign/v1 artifacts via OCI referrer: ghcr.io/org/app@sha256:7d0f35c4822c49b5dd8e8fc6810e6edaa602febe7ac7469b2306b30dfed0c19d',
  '   └── 🍒 sha256:2c7c785bf5657d810a98b5a27d3f2ae49069fb0adc732b836d1f0b1b7e87c9ad',
  '',
].join('\n');
const TREE_PROVENANCE_ONLY = [
  `📦 Supply Chain Security Related artifacts for an image: ${PINNED}`,
  '└── 🔗 https://slsa.dev/provenance/v1 artifacts via OCI referrer: ghcr.io/org/app@sha256:ffce13d652bbe7eab8ab4733a45b30290441eb488bf28a274d74720ff5ee831e',
  '   └── 🍒 sha256:a12d4c69500caf250c79e1e56ccc984f4972d42be5b611551eef7ac172748702',
  '',
].join('\n');
/** One `download signature` line for a v3 bundle (the shape measured on ghcr.io, 2026-09-28). */
function bundleLine(predicateType: string): string {
  const statement = JSON.stringify({ _type: 'https://in-toto.io/Statement/v1', subject: [], predicateType, predicate: {} });
  return JSON.stringify({
    mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
    verificationMaterial: {},
    dsseEnvelope: { payload: Buffer.from(statement).toString('base64'), payloadType: 'application/vnd.in-toto+json', signatures: [] },
  });
}
const NO_SIGNATURES = exit(1, `Error: ${PINNED}: no signatures associated\n`);
const SIG_500 = exit(1, `Error: ${PINNED}: remote image: GET https://ghcr.io/v2/org/app/manifests/sha256-41e1.sig: UNKNOWN: injected\n`);
const NO_V1 = exit(1, "Error: no attestations with predicate type 'https://slsa.dev/provenance/v1' found\n");
const NO_V02 = exit(1, "Error: no attestations with predicate type 'https://slsa.dev/provenance/v0.2' found\n");
const ATT_500 = exit(1, 'Error: remote image: GET https://ghcr.io/v2/org/app/manifests/sha256-41e1.att: UNKNOWN: injected\n');
const VERIFIED_SIGNATURE = out(
  `[{"critical":{"identity":{"docker-reference":"ghcr.io/org/app"},"image":{"docker-manifest-digest":"${DIGEST}"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]\n`,
);
const VERIFIED_PROVENANCE = out(
  `[{"critical":{"identity":{"docker-reference":"ghcr.io/org/app"},"image":{"docker-manifest-digest":"${DIGEST}"},"type":"https://slsa.dev/provenance/v1"},"optional":{}}]\n`,
);
const MISMATCH_12 = exit(
  12,
  'Error: no matching signatures: none of the expected identities matched what was in the certificate, got subjects [https://github.com/evil/fork/.github/workflows/x.yml@refs/heads/main] with issuer https://token.actions.githubusercontent.com\n',
);

interface Answers {
  version?: ProcessRunResult;
  triangulate?: ProcessRunResult;
  tree?: ProcessRunResult;
  signature?: ProcessRunResult;
  v1?: ProcessRunResult;
  v02?: ProcessRunResult;
  /** One answer, or one per call in order (the last repeats) — verify may be re-run once. */
  verify?: ProcessRunResult | ProcessRunResult[];
}

/** Fake cosign: answers by subcommand; Trivy and everything else succeed with no output. */
function fakeCosign(answers: Answers): void {
  let verifies = 0;
  vi.mocked(runProcess).mockImplementation(async (opts: ProcessRunOptions) => {
    if (opts.command !== 'cosign') return ok;
    const args = opts.args ?? [];
    if (args[0] === 'verify' && Array.isArray(answers.verify)) {
      const answer = answers.verify[Math.min(verifies, answers.verify.length - 1)];
      verifies += 1;
      return answer ?? VERIFIED_SIGNATURE;
    }
    if (args[0] === 'version') return answers.version ?? VERSION('3.1.3');
    if (args[0] === 'triangulate') return answers.triangulate ?? TRIANGULATED;
    if (args[0] === 'tree') return answers.tree ?? out(TREE_NONE);
    if (args[0] === 'verify') return (Array.isArray(answers.verify) ? undefined : answers.verify) ?? VERIFIED_SIGNATURE;
    if (args[0] === 'download' && args[1] === 'signature') return answers.signature ?? NO_SIGNATURES;
    if (args[0] === 'download' && args.includes('--predicate-type=https://slsa.dev/provenance/v1')) return answers.v1 ?? NO_V1;
    if (args[0] === 'download') return answers.v02 ?? NO_V02;
    throw new Error(`unexpected cosign call: ${args.join(' ')}`);
  });
}

function cosignCalls(): string[][] {
  return vi.mocked(runProcess).mock.calls.filter((c) => c[0].command === 'cosign').map((c) => c[0].args ?? []);
}

interface Run {
  name: string;
  status: string;
  reason?: string;
  target?: string;
  signer?: string;
}
interface Summary {
  image: string;
  checked: string | null;
  check: string;
  signature: string;
  verified_as?: string[];
  provenance: string;
  note: string;
}
interface Scan {
  ok: true;
  scan_id: string;
  coverage: string;
  tools_run: Run[];
  missing_tools: string[];
  warnings: string[];
  top_findings: { tool: string; rule_id?: string; severity: string; title: string; message?: string; file_path?: string }[];
  image_signature?: Summary;
}
type Refused = { ok: false; error: { code: string; message: string } };

async function scan(input: Record<string, unknown>, ctx?: PluginContext, project?: string): Promise<Scan> {
  const dir = project ?? makeTempDir('containers-cosign-');
  const r = (await tool().handler({ project_path: dir, image: IMAGE, ...input }, ctx ?? plugin(dir))) as Scan | Refused;
  if (!r.ok) throw new Error(`scan refused: ${r.error.message}`);
  return r;
}

const cosignFindings = (r: Scan) => r.top_findings.filter((f) => f.tool.startsWith('cosign'));

beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(scannerAvailable).mockImplementation(async (name) => `/fake/bin/${name}`);
  vi.stubEnv('GUARDIAN_OFFLINE', '0');
});
afterEach(() => {
  vi.unstubAllEnvs();
});

describe('scan_containers + cosign: when the check cannot run', () => {
  it('cosign not installed: skipped, in missing_tools, coverage partial — never a clean image', async () => {
    vi.mocked(scannerAvailable).mockImplementation(async (name) => (name === 'cosign' ? null : `/fake/bin/${name}`));
    fakeCosign({});
    const r = await scan({});
    expect(r.tools_run.find((t) => t.name === 'cosign')).toMatchObject({ status: 'skipped', reason: 'not_installed' });
    expect(r.missing_tools).toContain('cosign');
    expect(r.coverage).toBe('partial');
    expect(cosignCalls()).toEqual([]);
    expect(r.image_signature).toMatchObject({ image: IMAGE, check: 'skipped', signature: 'unknown', provenance: 'unknown' });
  });

  it('cosign 2.x (review I3): skipped as outdated, in missing_tools — its tree cannot see OCI referrers', async () => {
    fakeCosign({ version: VERSION('2.6.5') });
    const r = await scan({});
    const run = r.tools_run.find((t) => t.name === 'cosign');
    expect(run?.status).toBe('skipped');
    expect(run?.reason).toMatch(/^outdated: cosign 2\.6\.5/);
    expect(r.missing_tools).toContain('cosign');
    expect(cosignCalls()).toEqual([['version']]);
    expect(cosignFindings(r)).toEqual([]);
  });

  it('GUARDIAN_OFFLINE=1: skipped with that reason, in missing_tools, and cosign is never started', async () => {
    vi.stubEnv('GUARDIAN_OFFLINE', '1');
    fakeCosign({});
    const r = await scan({});
    const run = r.tools_run.find((t) => t.name === 'cosign');
    expect(run?.status).toBe('skipped');
    expect(run?.reason).toMatch(/GUARDIAN_OFFLINE=1/);
    expect(r.missing_tools).toContain('cosign');
    expect(cosignCalls()).toEqual([]);
  });

  it('no image: nothing to check — no cosign entry, no gap, even with cosign absent', async () => {
    vi.mocked(scannerAvailable).mockImplementation(async (name) => (name === 'cosign' ? null : `/fake/bin/${name}`));
    fakeCosign({});
    const project = makeTempDir('containers-cosign-');
    writeFileSync(join(project, 'Dockerfile'), 'FROM alpine:3.20\n', 'utf8');
    const r = (await tool().handler({ project_path: project }, plugin(project))) as Scan | Refused;
    if (!r.ok) throw new Error(r.error.message);
    expect(r.tools_run.some((t) => t.name.startsWith('cosign'))).toBe(false);
    expect(r.missing_tools).not.toContain('cosign');
    expect(cosignCalls()).toEqual([]);
    expect(r.image_signature).toBeUndefined();
  });

  it('an image its registry does not have (e.g. built locally, never pushed): failed, and the reason says so', async () => {
    fakeCosign({ triangulate: exit(1, 'Error: GET https://index.docker.io/v2/library/myapp/manifests/dev: UNAUTHORIZED: authentication required\n') });
    const r = await scan({ image: 'myapp:dev' });
    const run = r.tools_run.find((t) => t.name === 'cosign-tree');
    expect(run?.status).toBe('failed');
    expect(run?.reason).toMatch(/UNAUTHORIZED/);
    expect(run?.reason).toMatch(/never pushed/);
    expect(run?.reason).toMatch(/local Docker/);
    expect(cosignCalls().map((c) => c[0])).toEqual(['version', 'triangulate']);
    expect(cosignFindings(r)).toEqual([]);
  });

  it('review round 2: a rate-limited registry is worded as rate limiting, never "never pushed"', async () => {
    fakeCosign({ triangulate: exit(1, 'Error: GET https://index.docker.io/v2/library/alpine/manifests/3.20: TOOMANYREQUESTS: pull rate limit\n') });
    const r = await scan({ image: 'alpine:3.20' });
    const run = r.tools_run.find((t) => t.name === 'cosign-tree');
    expect(run?.status).toBe('failed');
    expect(run?.reason).toMatch(/rate-limit/);
    expect(run?.reason).not.toMatch(/never pushed/);
  });
});

describe('scan_containers + cosign: the digest cosign checked (review M1)', () => {
  it('pins the tag once and checks that digest in every later call; the response and the reason name it', async () => {
    fakeCosign({});
    const r = await scan({});
    const calls = cosignCalls();
    expect(calls.slice(0, 2)).toEqual([['version'], ['triangulate', '--type', 'digest', IMAGE]]);
    for (const c of calls.slice(2)) expect(c.at(-1)).toBe(PINNED);
    expect(r.image_signature?.checked).toBe(PINNED);
    expect(r.image_signature?.note).toMatch(/Trivy resolved the tag on its own/);
    expect(r.image_signature?.note).toMatch(/multi-arch index/);
    expect(r.tools_run.find((t) => t.name === 'cosign-tree')?.reason).toContain(PINNED);
  });

  it('a cosign without `triangulate` (v4) checks the tag and says the digest was not pinned', async () => {
    fakeCosign({ triangulate: exit(1, 'Error: unknown command "triangulate" for "cosign"\n') });
    const r = await scan({});
    expect(r.image_signature?.checked).toBeNull();
    expect(r.image_signature?.note).toMatch(/not pinned/);
    expect(r.image_signature?.note.match(/not pinned/g)).toHaveLength(1);
    expect(cosignCalls().slice(2).every((c) => c.at(-1) === IMAGE)).toBe(true);
  });
});

describe('scan_containers + cosign: without a signer (existence only)', () => {
  it('nothing attached — confirmed by the loud calls: a low "unsigned" and an info "no provenance"', async () => {
    fakeCosign({});
    const r = await scan({});
    expect(r.tools_run.find((t) => t.name === 'cosign-tree')).toMatchObject({ status: 'ok', target: IMAGE });
    expect(cosignFindings(r).map((f) => [f.tool, f.rule_id, f.severity]).sort()).toEqual([
      ['cosign-tree', 'image-no-provenance', 'info'],
      ['cosign-tree', 'image-unsigned', 'low'],
    ]);
    expect(cosignFindings(r).every((f) => f.file_path === IMAGE)).toBe(true);
    expect(r.image_signature).toMatchObject({ check: 'detect', signature: 'absent', provenance: 'absent' });
    expect(cosignCalls().map((c) => c.slice(0, 2).join(' '))).toEqual([
      'version',
      'triangulate --type',
      `tree ${PINNED}`,
      'download signature',
      'download attestation',
      'download attestation',
    ]);
    expect(r.coverage).toBe('full');
  });

  it('review I2: tree says "nothing" but the .sig tag fails loudly — signature unknown, no "unsigned" finding, failed', async () => {
    fakeCosign({ signature: SIG_500 });
    const r = await scan({});
    const run = r.tools_run.find((t) => t.name === 'cosign-tree');
    expect(run?.status).toBe('failed');
    expect(run?.reason).toMatch(/UNKNOWN/);
    expect(cosignFindings(r).map((f) => f.rule_id)).toEqual(['image-no-provenance']);
    expect(r.image_signature).toMatchObject({ signature: 'unknown', provenance: 'absent' });
    expect(r.coverage).toBe('partial');
  });

  it('review I2: the .att tag fails loudly — provenance unknown, no "no provenance" finding, failed', async () => {
    fakeCosign({ v1: ATT_500 });
    const r = await scan({});
    expect(r.tools_run.find((t) => t.name === 'cosign-tree')?.status).toBe('failed');
    expect(cosignFindings(r).map((f) => f.rule_id)).toEqual(['image-unsigned']);
    expect(r.image_signature).toMatchObject({ signature: 'absent', provenance: 'unknown' });
  });

  it('a signature and a provenance attestation: no finding — and the answer says the signer was NOT verified', async () => {
    fakeCosign({ tree: out(TREE_LEGACY), v1: out('{"payloadType":"application/vnd.in-toto+json"}\n') });
    const r = await scan({});
    expect(cosignFindings(r)).toEqual([]);
    expect(r.image_signature).toMatchObject({ signature: 'present_unverified', provenance: 'present_unverified' });
    expect(r.image_signature?.note).toMatch(/NOT verified/);
    expect(r.tools_run.find((t) => t.name === 'cosign-tree')?.reason).toMatch(/NOT verified/);
    // A listed signature needs no download; provenance in a legacy .att does.
    expect(cosignCalls().map((c) => c.slice(0, 2).join(' '))).toEqual(['version', 'triangulate --type', `tree ${PINNED}`, 'download attestation']);
  });

  it('review M2: signed provenance with no `cosign sign` — no "unsigned" finding; the answer says exactly what is there', async () => {
    const bundle = out(`${bundleLine('https://slsa.dev/provenance/v1')}\n`);
    fakeCosign({ tree: out(TREE_PROVENANCE_ONLY), signature: bundle, v1: bundle });
    const r = await scan({});
    expect(cosignFindings(r)).toEqual([]);
    expect(r.image_signature).toMatchObject({ signature: 'attestation_only_unverified', provenance: 'present_unverified' });
    expect(r.image_signature?.note).toMatch(/no `cosign sign` signature/i);
    expect(r.image_signature?.note).toMatch(/cosign verify accepts/);
    expect(r.image_signature?.note).toContain('https://slsa.dev/provenance/v1');
  });

  // Review round 2, N1: anyone who can push can attach a referrer. A listing
  // is not a signature: it counts only when cosign parses it as a Sigstore bundle.
  it.each([
    ['a non-Sigstore artifact typed like a predicate (https://spdx.dev/Document)', 'https://spdx.dev/Document'],
    ['a "signing bundle" cosign cannot parse', 'https://sigstore.dev/cosign/sign/v1'],
    ['a "provenance bundle" cosign cannot parse', 'https://slsa.dev/provenance/v1'],
  ])('N1: %s is no signature — "unsigned" (and no provenance) stands', async (_name, type) => {
    const listing = [
      `📦 Supply Chain Security Related artifacts for an image: ${PINNED}`,
      `└── 🔗 ${type} artifacts via OCI referrer: ghcr.io/org/app@sha256:bc9e5912af702e3d84909a74d1a659ca6000000000000000000000000000000`,
      '   └── 🍒 sha256:cccc',
      '',
    ].join('\n');
    fakeCosign({ tree: out(listing) });
    const r = await scan({});
    expect(r.image_signature).toMatchObject({ signature: 'absent', provenance: 'absent' });
    expect(cosignFindings(r).map((f) => f.rule_id).sort()).toEqual(['image-no-provenance', 'image-unsigned']);
  });

  it('`cosign tree` failing is a failed check with no finding — absence was never established', async () => {
    fakeCosign({ tree: exit(1, 'Error: getting referrers: GET https://ghcr.io/v2/org/app/referrers/sha256:41e1: UNKNOWN\n') });
    const r = await scan({});
    const run = r.tools_run.find((t) => t.name === 'cosign-tree');
    expect(run?.status).toBe('failed');
    expect(run?.reason).toMatch(/getting referrers/);
    expect(cosignFindings(r)).toEqual([]);
    expect(r.image_signature).toMatchObject({ signature: 'unknown', provenance: 'unknown' });
  });

  it('review M8: a cancelled download starts no further cosign — and the scan says it was cancelled', async () => {
    fakeCosign({ v1: { ...ok, outcome: 'cancelled', exitCode: null } });
    const project = makeTempDir('containers-cosign-');
    const r = (await tool().handler({ project_path: project, image: IMAGE }, plugin(project))) as Scan | Refused;
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.message).toMatch(/cancelled/);
    const calls = cosignCalls();
    expect(calls.at(-1)).toContain('--predicate-type=https://slsa.dev/provenance/v1');
    expect(calls.filter((c) => c.includes('--predicate-type=https://slsa.dev/provenance/v0.2'))).toEqual([]);
  });
});

describe('scan_containers + cosign: with a signer (real verification)', () => {
  const signer = {
    signer_identity: 'https://github.com/org/app/.github/workflows/release.yml@refs/heads/main',
    signer_issuer: 'https://token.actions.githubusercontent.com',
  };

  it('verified: cosign-verify ok, no finding; the run records the signer; the answer says what was accepted', async () => {
    fakeCosign({ verify: VERIFIED_SIGNATURE });
    const r = await scan(signer);
    expect(cosignCalls().at(-1)).toEqual([
      'verify',
      `--certificate-identity=${signer.signer_identity}`,
      `--certificate-oidc-issuer=${signer.signer_issuer}`,
      PINNED,
    ]);
    const run = r.tools_run.find((t) => t.name === 'cosign-verify');
    expect(run).toMatchObject({ status: 'ok', target: IMAGE });
    expect(run?.signer).toBe(JSON.stringify({ identity: signer.signer_identity, issuer: signer.signer_issuer }));
    expect(cosignFindings(r)).toEqual([]);
    expect(r.image_signature).toMatchObject({ check: 'verify', signature: 'verified', verified_as: ['https://sigstore.dev/cosign/sign/v1'] });
  });

  it('review M2: verified through a signed provenance attestation — the answer says it was not an image signature', async () => {
    fakeCosign({ verify: VERIFIED_PROVENANCE });
    const r = await scan(signer);
    expect(r.image_signature).toMatchObject({ signature: 'verified', verified_as: ['https://slsa.dev/provenance/v1'] });
    expect(r.image_signature?.note).toMatch(/signed attestation/);
    expect(r.image_signature?.note).toMatch(/not a `cosign sign` signature/);
  });

  it('signed by someone else: a high finding naming who did sign', async () => {
    fakeCosign({ verify: MISMATCH_12 });
    const r = await scan(signer);
    const f = cosignFindings(r);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ tool: 'cosign-verify', rule_id: 'image-signature-not-verified', severity: 'high', file_path: IMAGE });
    expect(f[0]?.message).toContain('evil/fork');
    expect(r.image_signature?.signature).toBe('rejected');
  });

  it('review I2: exit 12 with a transient error folded in is no rejection — failed, no finding', async () => {
    fakeCosign({
      verify: exit(12, 'Error: no matching signatures: fetching payload: GET https://ghcr.io/v2/org/app/blobs/sha256:ab: TOOMANYREQUESTS\n'),
    });
    const r = await scan(signer);
    expect(r.tools_run.find((t) => t.name === 'cosign-verify')?.status).toBe('failed');
    expect(cosignFindings(r)).toEqual([]);
  });

  it('N1: "no signatures found" twice while tree lists a signing bundle (the referrers call worked) — REJECTED: an unusable bundle is no signature', async () => {
    fakeCosign({ verify: exit(10, 'Error: no signatures found\n'), tree: out(TREE_SIGN_BUNDLE) });
    const r = await scan(signer);
    expect(cosignCalls().filter((c) => c[0] === 'verify')).toHaveLength(2);
    expect(cosignFindings(r).map((f) => [f.rule_id, f.severity])).toEqual([['image-signature-not-verified', 'high']]);
    expect(cosignFindings(r)[0]?.message).toContain('https://sigstore.dev/cosign/sign/v1');
    expect(r.image_signature?.signature).toBe('rejected');
  });

  it('a re-run that verifies (the first answer came from a failed referrers call) is a verification', async () => {
    fakeCosign({ verify: [exit(10, 'Error: no signatures found\n'), VERIFIED_SIGNATURE], tree: out(TREE_SIGN_BUNDLE) });
    const r = await scan(signer);
    expect(r.image_signature?.signature).toBe('verified');
    expect(cosignFindings(r)).toEqual([]);
  });

  it.each([
    ['a junk signature with no certificate or key ("empty key", measured)', 'Error: no matching signatures: empty key\n'],
    ['a certificate Fulcio never issued', 'Error: no matching signatures: x509: certificate signed by unknown authority\n'],
    [
      'an identity containing "timeout" in the echo',
      'Error: no matching signatures: none of the expected identities matched what was in the certificate, got subjects [https://github.com/org/timeout-svc/.github/workflows/r.yml@refs/heads/main] with issuer https://token.actions.githubusercontent.com\n',
    ],
  ])('N1: %s is REJECTED — a HIGH finding, not "no verdict"', async (_name, stderr) => {
    fakeCosign({ verify: exit(12, stderr) });
    const r = await scan(signer);
    expect(r.tools_run.find((t) => t.name === 'cosign-verify')?.status).toBe('ok');
    expect(cosignFindings(r).map((f) => [f.rule_id, f.severity])).toEqual([['image-signature-not-verified', 'high']]);
  });

  it('review round 2: a rejection for another signer is a NEW finding, not the old one unchanged (the identity holds the signer)', async () => {
    const project = makeTempDir('containers-cosign-identity-');
    const ctx = plugin(project);
    fakeCosign({ verify: MISMATCH_12 });
    const a = await scan(
      { signer_identity: 'https://github.com/org/app/.github/workflows/A.yml@refs/heads/main', signer_issuer: signer.signer_issuer },
      ctx,
      project,
    );
    vi.mocked(runProcess).mockReset();
    fakeCosign({ verify: MISMATCH_12 });
    const b = await scan(
      { signer_identity: 'https://github.com/org/app/.github/workflows/B.yml@refs/heads/main', signer_issuer: signer.signer_issuer },
      ctx,
      project,
    );
    const d = (await tool('diff_scans').handler({ project_path: project, from_scan_id: a.scan_id, to_scan_id: b.scan_id }, ctx)) as {
      ok: boolean;
      summary: { new: number; resolved: number; not_remeasured: number };
    };
    expect(d.ok).toBe(true);
    expect(d.summary).toMatchObject({ new: 1, resolved: 0, not_remeasured: 1 });
  });

  it('review I2: "no signatures found" that the loud calls cannot confirm (tree fails / .sig fails) — failed', async () => {
    for (const answers of [
      { tree: exit(1, 'Error: getting referrers: GET https://ghcr.io/v2/org/app/referrers/sha256:41e1: UNKNOWN\n') },
      { signature: SIG_500 },
    ] satisfies Answers[]) {
      vi.mocked(runProcess).mockReset();
      fakeCosign({ verify: exit(10, 'Error: no signatures found\n'), ...answers });
      const r = await scan(signer);
      expect(r.tools_run.find((t) => t.name === 'cosign-verify')?.status).toBe('failed');
      expect(cosignFindings(r)).toEqual([]);
    }
  });

  it('"no signatures found", confirmed (tree lists nothing, the .sig tag answers "none"): the high finding', async () => {
    fakeCosign({ verify: exit(10, 'Error: no signatures found\n') });
    const r = await scan({ signer_identity_regexp: '^https://github.com/org/app/', signer_issuer: signer.signer_issuer });
    expect(cosignFindings(r).map((x) => [x.rule_id, x.severity])).toEqual([['image-signature-not-verified', 'high']]);
    expect(cosignCalls().map((c) => c.slice(0, 2).join(' '))).toEqual([
      'version',
      'triangulate --type',
      `verify --certificate-identity-regexp=^https://github.com/org/app/`,
      `tree ${PINNED}`,
      'download signature',
    ]);
  });

  it('cosign could not finish (network): failed, no finding, coverage partial', async () => {
    fakeCosign({ verify: exit(1, 'Error: Get "https://ghcr.io/v2/": dial tcp: lookup ghcr.io: no such host\n') });
    const r = await scan(signer);
    expect(r.tools_run.find((t) => t.name === 'cosign-verify')).toMatchObject({ status: 'failed' });
    expect(cosignFindings(r)).toEqual([]);
    expect(r.coverage).toBe('partial');
    expect(r.image_signature?.signature).toBe('unknown');
  });

  it("review I1 (the reviewer's repro): a pass for ANOTHER signer never resolves a rejection — diff_scans", async () => {
    const project = makeTempDir('containers-cosign-i1-');
    const ctx = plugin(project);
    fakeCosign({ verify: MISMATCH_12 });
    const a = await scan(
      { signer_identity: 'https://github.com/org/app/.github/workflows/EXPECTED.yml@refs/heads/main', signer_issuer: signer.signer_issuer },
      ctx,
      project,
    );
    expect(cosignFindings(a)).toHaveLength(1);
    vi.mocked(runProcess).mockReset();
    fakeCosign({ verify: VERIFIED_SIGNATURE });
    const b = await scan({ signer_identity_regexp: '^.*$', signer_issuer_regexp: '^.*$' }, ctx, project);
    expect(cosignFindings(b)).toEqual([]);
    const d = (await tool('diff_scans').handler({ project_path: project, from_scan_id: a.scan_id, to_scan_id: b.scan_id }, ctx)) as {
      ok: boolean;
      summary: { resolved: number; not_remeasured: number };
    };
    expect(d.ok).toBe(true);
    expect(d.summary).toMatchObject({ resolved: 0, not_remeasured: 1 });
  });

  it('review M3: an unanchored signer regexp is verified as asked, with a warning in the response', async () => {
    fakeCosign({ verify: VERIFIED_SIGNATURE });
    const r = await scan({ signer_identity_regexp: 'https://github.com/org/app/', signer_issuer: signer.signer_issuer });
    expect(r.warnings.join('\n')).toMatch(/signer_identity_regexp .*not anchored/);
    expect(r.image_signature?.note).toMatch(/not anchored/);
  });
});

describe('scan_containers + cosign: the signer arguments are checked before anything runs', () => {
  it.each([
    ['an identity without an issuer', { signer_identity: 'a@b.example' }, /signer_issuer/],
    ['an issuer without an identity', { signer_issuer: 'https://accounts.google.com' }, /signer_identity/],
    ['an identity and its regexp together', { signer_identity: 'a@b.example', signer_identity_regexp: '.*', signer_issuer: 'https://x' }, /signer_identity_regexp/],
    ['an issuer and its regexp together', { signer_identity: 'a@b.example', signer_issuer: 'https://x', signer_issuer_regexp: '.*' }, /signer_issuer_regexp/],
    ['a line break in a value', { signer_identity: 'a@b.example\n--insecure-ignore-tlog', signer_issuer: 'https://x' }, /control character/],
    ['U+2028 (a line separator) in a value (review M4)', { signer_identity: 'a@b.example\u2028x', signer_issuer: 'https://x' }, /control character/],
    ['U+0085 (next line) in a value (review M4)', { signer_identity: 'a@b.example', signer_issuer: 'https://x\u0085y' }, /control character/],
  ])('refuses %s', async (_name, extra, message) => {
    fakeCosign({});
    const project = makeTempDir('containers-cosign-');
    const c = plugin(project);
    const r = (await tool().handler({ project_path: project, image: IMAGE, ...extra }, c)) as Scan | Refused;
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe('unsupported_target');
      expect(r.error.message).toMatch(message);
    }
    expect(vi.mocked(runProcess)).not.toHaveBeenCalled();
    expect(c.storage.scans.listHistory(10)).toHaveLength(0);
  });

  it.each(['app:1\u001b[31m', 'app:1\u0085', 'app\u2028:1', 'app\u2029:1', 'app:1\u009b'])(
    'review M4: refuses image %j — it flows into reasons and notes',
    async (image) => {
      fakeCosign({});
      const project = makeTempDir('containers-cosign-');
      const r = (await tool().handler({ project_path: project, image }, plugin(project))) as Scan | Refused;
      expect(r.ok).toBe(false);
      expect(vi.mocked(runProcess)).not.toHaveBeenCalled();
    },
  );

  it.each(['app\u200b:1', 'app:1\u200d', 'app\u2060:1', 'app:1\ufeff'])(
    'review round 2: refuses image %j — a zero-width character hides in every reason and note',
    async (image) => {
      fakeCosign({});
      const project = makeTempDir('containers-cosign-');
      const r = (await tool().handler({ project_path: project, image }, plugin(project))) as Scan | Refused;
      expect(r.ok).toBe(false);
      expect(vi.mocked(runProcess)).not.toHaveBeenCalled();
    },
  );

  it('review round 2: refuses a zero-width character in a signer value', async () => {
    fakeCosign({});
    const project = makeTempDir('containers-cosign-');
    const r = (await tool().handler(
      { project_path: project, image: IMAGE, signer_identity: 'a@b\u200b.example', signer_issuer: 'https://x' },
      plugin(project),
    )) as Scan | Refused;
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.message).toMatch(/control character/);
  });

  it('review round 2: the refusal names the character as \\uXXXX — it never echoes a bidi override or a line separator raw', async () => {
    for (const bad of ['\u202e', '\u2028', '\u0085', '\u200b']) {
      const project = makeTempDir('containers-cosign-');
      const handler = tool().handler;
      const r = (await handler({ project_path: project, image: `app${bad}:1` }, plugin(project))) as Scan | Refused;
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.error.message).not.toContain(bad);
        expect(r.error.message).toContain(`\\u${bad.charCodeAt(0).toString(16).padStart(4, '0')}`);
      }
    }
  });

  it('refuses a signer without an image — there is nothing to verify', async () => {
    fakeCosign({});
    const project = makeTempDir('containers-cosign-');
    const c = plugin(project);
    const r = (await tool().handler(
      { project_path: project, signer_identity: 'a@b.example', signer_issuer: 'https://accounts.google.com' },
      c,
    )) as Scan | Refused;
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.message).toMatch(/image/);
    expect(vi.mocked(runProcess)).not.toHaveBeenCalled();
  });
});
