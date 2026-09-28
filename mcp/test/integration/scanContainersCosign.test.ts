/**
 * scan_containers' image signature and provenance check (cosign).
 *
 * For the image it scans, when cosign is installed and the network is not
 * disabled:
 *   - with a signer identity AND an issuer: a real `cosign verify` — a
 *     rejection is a high finding;
 *   - without them: only whether a signature and a SLSA provenance
 *     attestation exist (`cosign tree`, then `cosign download attestation`
 *     for legacy `.att` tags) — low / info findings when absent, and the
 *     answer says a signature that exists was NOT verified;
 *   - cosign missing or GUARDIAN_OFFLINE=1: skipped, in missing_tools.
 *
 * cosign itself is faked (`runProcess` is mocked); the outputs it answers
 * with are the real ones `test/unit/runners/cosignCheck.test.ts` documents.
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
});

function tool() {
  const t = TOOLS.find((x) => x.name === 'scan_containers');
  if (!t) throw new Error('scan_containers not registered');
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
const ok: ProcessRunResult = { outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false };
const exit = (exitCode: number, stderr: string): ProcessRunResult => ({ ...ok, outcome: 'failed', exitCode, stderr });

const TREE_NONE =
  `📦 Supply Chain Security Related artifacts for an image: ${IMAGE}\n` +
  `No Supply Chain Security Related Artifacts found for image ${IMAGE},\n` +
  ' start creating one with simply running$ cosign sign <img>';
const TREE_LEGACY = [
  `📦 Supply Chain Security Related artifacts for an image: ${IMAGE}`,
  '└── 💾 Attestations for an image tag: ghcr.io/org/app:sha256-41e17ed83c594a64a9396b6ab96dd26d5ddc290dacf4c177464712ff21ad534f.att',
  '   └── 🍒 sha256:e2ee0775e2825b7c937fcb9b31f0101870a86e57d664becd1c79f4b51c2b96c2',
  '└── 🔐 Signatures for an image tag: ghcr.io/org/app:sha256-41e17ed83c594a64a9396b6ab96dd26d5ddc290dacf4c177464712ff21ad534f.sig',
  '   └── 🍒 sha256:064523df0fd3979ec03a0737e967c53fe291926030dd2f5eba56ec1344cb73ca',
  '',
].join('\n');
const NO_V1 = exit(1, "Error: no attestations with predicate type 'https://slsa.dev/provenance/v1' found\n");
const NO_V02 = exit(1, "Error: no attestations with predicate type 'https://slsa.dev/provenance/v0.2' found\n");

/** Fake cosign: `answers` by subcommand; Trivy and everything else succeed with no output. */
function fakeCosign(answers: {
  tree?: ProcessRunResult;
  v1?: ProcessRunResult;
  v02?: ProcessRunResult;
  verify?: ProcessRunResult;
}): void {
  vi.mocked(runProcess).mockImplementation(async (opts: ProcessRunOptions) => {
    if (opts.command !== 'cosign') return ok;
    const args = opts.args ?? [];
    if (args[0] === 'tree') return answers.tree ?? ok;
    if (args[0] === 'verify') return answers.verify ?? ok;
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
}
interface Scan {
  ok: true;
  scan_id: string;
  coverage: string;
  tools_run: Run[];
  missing_tools: string[];
  top_findings: { tool: string; rule_id?: string; severity: string; title: string; message?: string; file_path?: string }[];
  image_signature?: { image: string; check: string; signature: string; provenance: string; note: string };
}
type Refused = { ok: false; error: { code: string; message: string } };

async function scan(input: Record<string, unknown>, ctx?: PluginContext): Promise<Scan> {
  const project = makeTempDir('containers-cosign-');
  const r = (await tool().handler({ project_path: project, image: IMAGE, ...input }, ctx ?? plugin(project))) as Scan | Refused;
  if (!r.ok) throw new Error(`scan refused: ${r.error.message}`);
  return r;
}

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

  it('GUARDIAN_OFFLINE=1: skipped with that reason, in missing_tools, and cosign is never started', async () => {
    vi.stubEnv('GUARDIAN_OFFLINE', '1');
    fakeCosign({ tree: { ...ok, stdout: TREE_NONE } });
    const r = await scan({});
    const run = r.tools_run.find((t) => t.name === 'cosign');
    expect(run?.status).toBe('skipped');
    expect(run?.reason).toMatch(/GUARDIAN_OFFLINE=1/);
    expect(r.missing_tools).toContain('cosign');
    expect(cosignCalls()).toEqual([]);
    expect(r.top_findings.filter((f) => f.tool.startsWith('cosign'))).toEqual([]);
  });

  it('no image: nothing to check — no cosign entry, no gap, even with cosign absent', async () => {
    vi.mocked(scannerAvailable).mockImplementation(async (name) => (name === 'cosign' ? null : `/fake/bin/${name}`));
    fakeCosign({});
    const project = makeTempDir('containers-cosign-');
    writeFileSync(join(project, 'Dockerfile'), 'FROM alpine:3.20\n', 'utf8');
    const r = (await tool().handler({ project_path: project }, plugin(project))) as Scan | Refused;
    if (!r.ok) throw new Error(r.error.message);
    expect(r.ok).toBe(true);
    expect(r.tools_run.some((t) => t.name.startsWith('cosign'))).toBe(false);
    expect(r.missing_tools).not.toContain('cosign');
    expect(cosignCalls()).toEqual([]);
    expect(r.image_signature).toBeUndefined();
  });
});

describe('scan_containers + cosign: without a signer (existence only)', () => {
  it('nothing attached: a low "unsigned" and an info "no provenance" finding on the image', async () => {
    fakeCosign({ tree: { ...ok, stdout: TREE_NONE } });
    const r = await scan({});
    expect(r.tools_run.find((t) => t.name === 'cosign-tree')).toMatchObject({ status: 'ok', target: IMAGE });
    const mine = r.top_findings.filter((f) => f.tool === 'cosign-tree');
    expect(mine.map((f) => [f.rule_id, f.severity]).sort()).toEqual([
      ['image-no-provenance', 'info'],
      ['image-unsigned', 'low'],
    ]);
    expect(mine.every((f) => f.file_path === IMAGE)).toBe(true);
    expect(r.image_signature).toMatchObject({ check: 'detect', signature: 'absent', provenance: 'absent' });
    // Nothing legacy to read: `download attestation` is never needed.
    expect(cosignCalls()).toEqual([['tree', IMAGE]]);
    expect(r.coverage).toBe('full');
  });

  it('a signature and a provenance attestation: no finding — and the answer says the signer was NOT verified', async () => {
    fakeCosign({ tree: { ...ok, stdout: TREE_LEGACY }, v1: { ...ok, stdout: '{"payloadType":"application/vnd.in-toto+json"}\n' } });
    const r = await scan({});
    expect(r.top_findings.filter((f) => f.tool.startsWith('cosign'))).toEqual([]);
    expect(r.image_signature).toMatchObject({ signature: 'present_unverified', provenance: 'present_unverified' });
    expect(r.image_signature?.note).toMatch(/NOT verified/);
    expect(r.image_signature?.note).toMatch(/signer_identity/);
    expect(r.tools_run.find((t) => t.name === 'cosign-tree')?.reason).toMatch(/NOT verified/);
    expect(cosignCalls()).toEqual([
      ['tree', IMAGE],
      ['download', 'attestation', '--predicate-type=https://slsa.dev/provenance/v1', IMAGE],
    ]);
  });

  it('legacy attestations that are not provenance (v1 and v0.2 both absent): an info "no provenance" finding', async () => {
    fakeCosign({ tree: { ...ok, stdout: TREE_LEGACY } });
    const r = await scan({});
    expect(r.top_findings.filter((f) => f.tool === 'cosign-tree').map((f) => f.rule_id)).toEqual(['image-no-provenance']);
    expect(r.image_signature?.provenance).toBe('absent');
    expect(cosignCalls()).toHaveLength(3);
  });

  it('`cosign tree` failing is a failed check with no finding — absence was never established', async () => {
    fakeCosign({ tree: exit(1, 'Error: Get "https://ghcr.io/v2/": dial tcp: i/o timeout\n') });
    const r = await scan({});
    const run = r.tools_run.find((t) => t.name === 'cosign-tree');
    expect(run?.status).toBe('failed');
    expect(run?.reason).toMatch(/i\/o timeout/);
    expect(r.top_findings.filter((f) => f.tool.startsWith('cosign'))).toEqual([]);
    expect(r.coverage).toBe('partial');
    expect(r.image_signature).toMatchObject({ signature: 'unknown', provenance: 'unknown' });
  });

  it('an unreadable provenance download leaves provenance unknown: failed, and still the signature verdict', async () => {
    const down = exit(1, 'Error: GET https://ghcr.io/v2/org/app/manifests/sha256-41e1.att: TOOMANYREQUESTS\n');
    fakeCosign({ tree: { ...ok, stdout: TREE_LEGACY }, v1: down, v02: down });
    const r = await scan({});
    expect(r.tools_run.find((t) => t.name === 'cosign-tree')?.status).toBe('failed');
    expect(r.top_findings.filter((f) => f.tool.startsWith('cosign'))).toEqual([]);
    expect(r.image_signature).toMatchObject({ signature: 'present_unverified', provenance: 'unknown' });
  });
});

describe('scan_containers + cosign: with a signer (real verification)', () => {
  const signer = { signer_identity: 'https://github.com/org/app/.github/workflows/release.yml@refs/heads/main', signer_issuer: 'https://token.actions.githubusercontent.com' };

  it('verified: cosign-verify ok, no finding, no existence probe', async () => {
    fakeCosign({ verify: { ...ok, stdout: '[{"critical":{}}]' } });
    const r = await scan(signer);
    expect(cosignCalls()).toEqual([
      [
        'verify',
        `--certificate-identity=${signer.signer_identity}`,
        `--certificate-oidc-issuer=${signer.signer_issuer}`,
        IMAGE,
      ],
    ]);
    expect(r.tools_run.find((t) => t.name === 'cosign-verify')).toMatchObject({ status: 'ok', target: IMAGE });
    expect(r.top_findings.filter((f) => f.tool.startsWith('cosign'))).toEqual([]);
    expect(r.image_signature).toMatchObject({ check: 'verify', signature: 'verified', provenance: 'not_checked' });
  });

  it('signed by someone else: a high finding naming who did sign', async () => {
    fakeCosign({
      verify: exit(
        12,
        'Error: no matching signatures: none of the expected identities matched what was in the certificate, got subjects [https://github.com/evil/fork/.github/workflows/x.yml@refs/heads/main] with issuer https://token.actions.githubusercontent.com\n',
      ),
    });
    const r = await scan(signer);
    const f = r.top_findings.filter((x) => x.tool === 'cosign-verify');
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ rule_id: 'image-signature-not-verified', severity: 'high', file_path: IMAGE });
    expect(f[0]?.message).toContain('evil/fork');
    expect(r.tools_run.find((t) => t.name === 'cosign-verify')?.status).toBe('ok');
    expect(r.image_signature?.signature).toBe('rejected');
  });

  it('no signature at all: the same high finding', async () => {
    fakeCosign({ verify: exit(10, 'Error: no signatures found\n') });
    const r = await scan({ signer_identity_regexp: '^https://github.com/org/', signer_issuer: signer.signer_issuer });
    expect(cosignCalls()[0]).toContain('--certificate-identity-regexp=^https://github.com/org/');
    expect(r.top_findings.filter((x) => x.tool === 'cosign-verify').map((x) => x.severity)).toEqual(['high']);
  });

  it('cosign could not finish (network): failed, no finding, coverage partial', async () => {
    fakeCosign({ verify: exit(1, 'Error: Get "https://ghcr.io/v2/": dial tcp: lookup ghcr.io: no such host\n') });
    const r = await scan(signer);
    expect(r.tools_run.find((t) => t.name === 'cosign-verify')).toMatchObject({ status: 'failed' });
    expect(r.top_findings.filter((x) => x.tool.startsWith('cosign'))).toEqual([]);
    expect(r.coverage).toBe('partial');
    expect(r.image_signature?.signature).toBe('unknown');
  });
});

describe('scan_containers + cosign: the signer arguments are checked before anything runs', () => {
  it.each([
    ['an identity without an issuer', { signer_identity: 'a@b.example' }, /signer_issuer/],
    ['an issuer without an identity', { signer_issuer: 'https://accounts.google.com' }, /signer_identity/],
    ['an identity and its regexp together', { signer_identity: 'a@b.example', signer_identity_regexp: '.*', signer_issuer: 'https://x' }, /signer_identity_regexp/],
    ['an issuer and its regexp together', { signer_identity: 'a@b.example', signer_issuer: 'https://x', signer_issuer_regexp: '.*' }, /signer_issuer_regexp/],
    ['a line break in a value', { signer_identity: 'a@b.example\n--insecure-ignore-tlog', signer_issuer: 'https://x' }, /control character/],
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
