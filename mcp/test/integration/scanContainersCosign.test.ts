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
 *     attestation exist — and "absent" only when the downloads say so AND
 *     their `-d` request log shows the registry answered for everything its
 *     own referrers index lists;
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
import { detectImageSupplyChain, verifyImage } from '../../src/runners/cosignCheck.js';
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
const LEGACY_LINE = '{"Base64Signature":"MEUCIBaf","Payload":"eyJjcml0aWNhbCI6e319","Cert":{"Raw":"MIIH"},"Chain":null,"Bundle":null,"RFC3161Timestamp":null}';
const BUNDLE_TYPE = 'application/vnd.dev.sigstore.bundle.v0.3+json';
const SIGN = 'https://sigstore.dev/cosign/sign/v1';
const PROVENANCE = 'https://slsa.dev/provenance/v1';
/** A referrer the registry's index lists: its manifest digest, artifactType, annotation, and the bundle blob. */
interface Referrer {
  digest: string;
  artifactType: string;
  predicateType?: string;
  layer?: string;
}
const SIGN_BUNDLE: Referrer = {
  digest: 'sha256:7d0f35c4822c49b5dd8e8fc6810e6edaa602febe7ac7469b2306b30dfed0c19d',
  artifactType: BUNDLE_TYPE,
  predicateType: SIGN,
  layer: 'sha256:2c7c785bf5657d810a98b5a27d3f2ae49069fb0adc732b836d1f0b1b7e87c9ad',
};
const PROVENANCE_BUNDLE: Referrer = {
  digest: 'sha256:ffce13d652bbe7eab8ab4733a45b30290441eb488bf28a274d74720ff5ee831e',
  artifactType: BUNDLE_TYPE,
  predicateType: PROVENANCE,
  layer: 'sha256:a12d4c69500caf250c79e1e56ccc984f4972d42be5b611551eef7ac172748702',
};
const SPDX: Referrer = {
  digest: 'sha256:bc9e5912af702e3d84909a74d1a659ca68c25cd67a042d26988f2a0258d87693',
  artifactType: 'https://spdx.dev/Document',
  layer: 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
};
/** One `download signature` line for a v3 bundle (the shape measured on ghcr.io, 2026-09-28). */
function bundleLine(predicateType: string): string {
  const statement = JSON.stringify({ _type: 'https://in-toto.io/Statement/v1', subject: [], predicateType, predicate: {} });
  return JSON.stringify({
    mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
    verificationMaterial: {},
    dsseEnvelope: { payload: Buffer.from(statement).toString('base64'), payloadType: 'application/vnd.in-toto+json', signatures: [] },
  });
}
/**
 * A `cosign … -d` request log in the shape cosign 3.1.3 prints (see the unit
 * test's `traceOf`): the referrers lookup with the registry's own index as its
 * dumped, chunked body; then each referrer's manifest (its body dumped) and
 * its bundle blob, answered as `answers` says (`m:` for a manifest; `never
 * fetched` leaves it out of the log) — by default, every one served.
 * `lookup`: the referrers API's own answer. `fallback`: the referrers API
 * answers 404 and the `sha256-<hex>` fallback tag serves this body instead;
 * `referrers` are then only what cosign fetched.
 */
function traceOf(referrers: Referrer[], answers: Array<[string, number | string]> = [], lookup: number | string = 200, fallback?: string): string {
  const T = '2026/09/28 23:03:02';
  const H = 'https://ghcr.io/v2/org/app';
  const lines: string[] = [];
  const exchange = (url: string, answer: number | string, body?: string): void => {
    lines.push(`${T} --> GET ${url}`, `${T} GET ${url.slice('https://ghcr.io'.length)} HTTP/1.1\r\nHost: ghcr.io\r\n\r\n`);
    if (typeof answer === 'string') {
      lines.push(`${T} <-- ${answer} GET ${url} (2ms)`);
      return;
    }
    lines.push(`${T} <-- ${answer} ${url} (1ms)`);
    const b = body ?? '';
    lines.push(`${T} HTTP/1.1 ${answer} X\r\nTransfer-Encoding: chunked\r\n\r\n${Buffer.byteLength(b).toString(16)}\r\n${b}\r\n0\r\n\r\n`);
  };
  const answerFor = (digest: string, fallback: number | string): number | string => {
    const found = answers.filter(([d]) => d === digest).at(-1);
    return found === undefined ? fallback : found[1];
  };
  const index = {
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.index.v1+json',
    manifests: referrers.map((r) => ({
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      digest: r.digest,
      size: 700,
      artifactType: r.artifactType,
      ...(r.predicateType === undefined ? {} : { annotations: { 'dev.sigstore.bundle.predicateType': r.predicateType } }),
    })),
  };
  if (fallback !== undefined) {
    // No referrers API: go-containerregistry reads the fallback tag, which whoever can push writes.
    exchange(`${H}/referrers/${DIGEST}`, 404, '{"errors":[{"code":"NOT_FOUND"}]}');
    exchange(`${H}/manifests/sha256-${DIGEST.slice('sha256:'.length)}`, 200, fallback);
  } else {
    exchange(`${H}/referrers/${DIGEST}`, lookup, JSON.stringify(index));
    if (lookup !== 200) return `${lines.join('\n')}\n`;
  }
  for (const r of referrers) {
    const manifest = answerFor(`m:${r.digest}`, 200);
    if (manifest === 'never fetched') continue;
    const layers = r.layer === undefined ? [] : [{ mediaType: r.artifactType, digest: r.layer, size: 3000 }];
    exchange(`${H}/manifests/${r.digest}`, manifest, JSON.stringify({ schemaVersion: 2, artifactType: r.artifactType, layers }));
    // cosign fetches the blob of a served bundle manifest only (measured).
    if (manifest === 200 && r.layer !== undefined && r.artifactType === BUNDLE_TYPE) exchange(`${H}/blobs/${r.layer}`, answerFor(r.layer, 200), '[body redacted]');
  }
  return `${lines.join('\n')}\n`;
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

/** One answer, or one per call in order (the last repeats). */
type Seq = ProcessRunResult | ProcessRunResult[];

interface Answers {
  version?: ProcessRunResult;
  triangulate?: ProcessRunResult;
  signature?: Seq;
  v1?: Seq;
  v02?: Seq;
  verify?: Seq;
  /** What the registry's referrers index lists — the `-d` log of every traced download (default: nothing). */
  referrers?: Referrer[];
  /** Per digest (`m:` for a manifest): how the registry answered. Default: served. */
  answers?: Array<[string, number | string]>;
  /** The referrers API's own answer (default 200, with the index). */
  lookup?: number | string;
  /** The fallback tag's body (the referrers API answering 404) — `referrers` are then what cosign fetched. */
  fallback?: string;
  /** A whole request log instead of the one built from the above. */
  trace?: string;
  /** Called before each cosign call answers — to abort the scan, or move the clock. */
  onCall?: (args: string[], opts: ProcessRunOptions) => ProcessRunResult | undefined;
}

/** Fake cosign: answers by subcommand; Trivy and everything else succeed with no output. */
function fakeCosign(answers: Answers): void {
  const counts = new Map<string, number>();
  const next = (key: string, seq: Seq | undefined, fallback: ProcessRunResult): ProcessRunResult => {
    const n = counts.get(key) ?? 0;
    counts.set(key, n + 1);
    if (seq === undefined) return fallback;
    if (!Array.isArray(seq)) return seq;
    return seq[Math.min(n, seq.length - 1)] ?? fallback;
  };
  vi.mocked(runProcess).mockImplementation(async (opts: ProcessRunOptions) => {
    if (opts.command !== 'cosign') return ok;
    const args = opts.args ?? [];
    const override = answers.onCall?.(args, opts);
    if (override !== undefined) return override;
    if (args[0] === 'version') return answers.version ?? VERSION('3.1.3');
    if (args[0] === 'triangulate') return answers.triangulate ?? TRIANGULATED;
    if (args[0] === 'verify') return next('verify', answers.verify, VERIFIED_SIGNATURE);
    if (args[0] === 'download') {
      const base =
        args[1] === 'signature'
          ? next('signature', answers.signature, NO_SIGNATURES)
          : args.includes(`--predicate-type=${PROVENANCE}`)
            ? next('v1', answers.v1, NO_V1)
            : next('v02', answers.v02, NO_V02);
      if (!args.includes('-d')) return base;
      const trace = answers.trace ?? traceOf(answers.referrers ?? [], answers.answers, answers.lookup, answers.fallback);
      return { ...base, stderr: `${trace}${base.stderr}` };
    }
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
  top_findings: { tool: string; rule_id?: string; severity: string; title: string; message?: string; file_path?: string; cwe?: string[]; owasp?: string[] }[];
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
    const run = r.tools_run.find((t) => t.name === 'cosign-referrers');
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
    const run = r.tools_run.find((t) => t.name === 'cosign-referrers');
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
    expect(r.tools_run.find((t) => t.name === 'cosign-referrers')?.reason).toContain(PINNED);
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

/** A pusher-chosen string holding a bidi override and an ESC sequence (round 4, M4). */
const EVIL = `application/x${String.fromCharCode(0x202e)}gnp.exe${String.fromCharCode(0x1b)}[31m`;
const RAW = new RegExp(`[${String.fromCharCode(0x202e)}${String.fromCharCode(0x1b)}]`);

describe('scan_containers + cosign: without a signer (existence only)', () => {
  it('nothing attached — the downloads say none and the registry\'s index lists nothing: a low "unsigned" and an info "no provenance"', async () => {
    fakeCosign({});
    const r = await scan({});
    expect(r.tools_run.find((t) => t.name === 'cosign-referrers')).toMatchObject({ status: 'ok', target: IMAGE });
    expect(cosignFindings(r).map((f) => [f.tool, f.rule_id, f.severity]).sort()).toEqual([
      ['cosign-referrers', 'image-no-provenance', 'info'],
      ['cosign-referrers', 'image-unsigned', 'low'],
    ]);
    expect(cosignFindings(r).every((f) => f.file_path === IMAGE)).toBe(true);
    // Unreleased (review of 3.0.0, S11): CWE-345, which OWASP 2025 files under A08.
    expect(cosignFindings(r).map((f) => [f.rule_id, f.cwe, f.owasp]).sort()).toEqual([
      ['image-no-provenance', ['CWE-345'], ['A08:2025']],
      ['image-unsigned', ['CWE-345'], ['A08:2025']],
    ]);
    expect(r.image_signature).toMatchObject({ check: 'detect', signature: 'absent', provenance: 'absent' });
    // Round 4, I4: `cosign tree` is never run — every download that decides an absence runs with -d.
    expect(cosignCalls().map((c) => c.slice(0, 3).join(' '))).toEqual([
      'version',
      'triangulate --type digest',
      'download signature -d',
      'download attestation -d',
      'download attestation -d',
    ]);
    expect(r.coverage).toBe('full');
  });

  it('review I2: the .sig tag fails loudly — signature unknown, no "unsigned" finding, failed', async () => {
    fakeCosign({ signature: SIG_500 });
    const r = await scan({});
    const run = r.tools_run.find((t) => t.name === 'cosign-referrers');
    expect(run?.status).toBe('failed');
    expect(run?.reason).toMatch(/UNKNOWN/);
    expect(cosignFindings(r).map((f) => f.rule_id)).toEqual(['image-no-provenance']);
    expect(r.image_signature).toMatchObject({ signature: 'unknown', provenance: 'absent' });
    expect(r.coverage).toBe('partial');
  });

  it('review I2: the .att tag fails loudly — provenance unknown, no "no provenance" finding, failed', async () => {
    fakeCosign({ v1: ATT_500 });
    const r = await scan({});
    expect(r.tools_run.find((t) => t.name === 'cosign-referrers')?.status).toBe('failed');
    expect(cosignFindings(r).map((f) => f.rule_id)).toEqual(['image-unsigned']);
    expect(r.image_signature).toMatchObject({ signature: 'absent', provenance: 'unknown' });
  });

  it('a signature and a provenance attestation: no finding — and the answer says the signer was NOT verified', async () => {
    fakeCosign({ signature: out(`${LEGACY_LINE}\n`), v1: out('{"payloadType":"application/vnd.in-toto+json"}\n') });
    const r = await scan({});
    expect(cosignFindings(r)).toEqual([]);
    expect(r.image_signature).toMatchObject({ signature: 'present_unverified', provenance: 'present_unverified' });
    expect(r.image_signature?.note).toMatch(/NOT verified/);
    expect(r.tools_run.find((t) => t.name === 'cosign-referrers')?.reason).toMatch(/NOT verified/);
    expect(cosignCalls().map((c) => c.slice(0, 2).join(' '))).toEqual(['version', 'triangulate --type', 'download signature', 'download attestation']);
  });

  it('review M2: signed provenance with no `cosign sign` — no "unsigned" finding; the answer says exactly what is there', async () => {
    const bundle = out(`${bundleLine(PROVENANCE)}\n`);
    fakeCosign({ referrers: [PROVENANCE_BUNDLE], signature: bundle, v1: bundle });
    const r = await scan({});
    expect(cosignFindings(r)).toEqual([]);
    expect(r.image_signature).toMatchObject({ signature: 'attestation_only_unverified', provenance: 'present_unverified' });
    expect(r.image_signature?.note).toMatch(/no `cosign sign` signature/i);
    expect(r.image_signature?.note).toMatch(/cosign verify accepts/);
    expect(r.image_signature?.note).toContain(PROVENANCE);
  });

  // Round 3, I3: cosign skips in silence a referrer it cannot fetch — a
  // listed bundle the registry failed to serve is never "absent".
  it('I3: a listed signing bundle whose blob answered 500 — signature unknown (named), no "unsigned" finding', async () => {
    fakeCosign({ referrers: [SIGN_BUNDLE], answers: [[SIGN_BUNDLE.layer ?? '', 500]] });
    const r = await scan({});
    const run = r.tools_run.find((t) => t.name === 'cosign-referrers');
    expect(run?.status).toBe('failed');
    expect(run?.reason).toMatch(/signature unknown \(the registry failed to serve/);
    expect(run?.reason).toMatch(/500/);
    expect(r.image_signature).toMatchObject({ signature: 'unknown', provenance: 'unknown' });
    expect(cosignFindings(r)).toEqual([]);
  });

  it('I3: the same bundle answered 404 — the registry answered: "unsigned" stands, with no second download', async () => {
    fakeCosign({ referrers: [SIGN_BUNDLE], answers: [[SIGN_BUNDLE.layer ?? '', 404]] });
    const r = await scan({});
    expect(r.image_signature).toMatchObject({ signature: 'absent', provenance: 'absent' });
    expect(cosignFindings(r).map((f) => f.rule_id).sort()).toEqual(['image-no-provenance', 'image-unsigned']);
    expect(cosignCalls().filter((c) => c[1] === 'signature')).toHaveLength(1);
  });

  it('N1: a non-Sigstore artifact typed like a predicate (https://spdx.dev/Document) is no signature — "unsigned" stands, naming what is attached', async () => {
    fakeCosign({ referrers: [SPDX] });
    const r = await scan({});
    expect(r.image_signature).toMatchObject({ signature: 'absent', provenance: 'absent' });
    const unsigned = cosignFindings(r).find((f) => f.rule_id === 'image-unsigned');
    expect(unsigned?.message).toContain('https://spdx.dev/Document');
    expect(unsigned?.message).toMatch(/is no Sigstore bundle/);
  });

  // Round 4, I6: a bundle the registry served (200) that cosign did not
  // return is either junk or a body that broke mid-transfer — the log cannot
  // tell which. One more download; still none is unknown, never "absent".
  it.each([
    ['a signing bundle', SIGN_BUNDLE],
    ['a provenance bundle', PROVENANCE_BUNDLE],
  ])('I6: %s served but not returned, twice — signature unknown (both causes named), no "unsigned" finding', async (_name, bundle) => {
    fakeCosign({ referrers: [bundle] });
    const r = await scan({});
    expect(r.image_signature?.signature).toBe('unknown');
    expect(cosignFindings(r).map((f) => f.rule_id)).not.toContain('image-unsigned');
    expect(r.tools_run.find((t) => t.name === 'cosign-referrers')?.reason).toMatch(/not a bundle it can parse, or the transfer failed mid-body; re-run if the registry was unstable/);
    expect(cosignCalls().filter((c) => c[1] === 'signature')).toHaveLength(2);
  });

  it('I6: the second download returns the bundle (the first transfer broke mid-body) — present', async () => {
    fakeCosign({ referrers: [SIGN_BUNDLE], signature: [NO_SIGNATURES, out(`${bundleLine(SIGN)}\n`)] });
    const r = await scan({});
    expect(r.image_signature?.signature).toBe('present_unverified');
    expect(cosignFindings(r).map((f) => f.rule_id)).not.toContain('image-unsigned');
  });

  it('I6: a provenance bundle served but not returned by download attestation, twice — provenance unknown, no "no provenance" finding', async () => {
    fakeCosign({ referrers: [PROVENANCE_BUNDLE], signature: out(`${bundleLine(PROVENANCE)}\n`) });
    const r = await scan({});
    expect(r.image_signature).toMatchObject({ signature: 'attestation_only_unverified', provenance: 'unknown' });
    expect(cosignFindings(r)).toEqual([]);
    expect(cosignCalls().filter((c) => c.includes(`--predicate-type=${PROVENANCE}`))).toHaveLength(2);
  });

  it('I6: a signing bundle the attestation downloads skip is no doubt about provenance — its annotation names another predicate', async () => {
    fakeCosign({ referrers: [SIGN_BUNDLE], signature: out(`${bundleLine(SIGN)}\n`) });
    const r = await scan({});
    expect(r.image_signature).toMatchObject({ signature: 'present_unverified', provenance: 'absent' });
    expect(cosignCalls().filter((c) => c[1] === 'attestation')).toHaveLength(2);
  });

  it('I5: an OCI index attached as a referrer (served) is no signature — "unsigned" stands (cosign tree could not fetch it)', async () => {
    const index: Referrer = { digest: 'sha256:6934ed41aadbd2340a2f760e73b4e8e9d56d1a3c2034cc2c46470231a0a42540', artifactType: 'application/vnd.example.index' };
    fakeCosign({ referrers: [index] });
    const r = await scan({});
    expect(r.image_signature).toMatchObject({ signature: 'absent', provenance: 'absent' });
    expect(cosignFindings(r).map((f) => f.rule_id).sort()).toEqual(['image-no-provenance', 'image-unsigned']);
  });

  it('I4: an artifact type holding forged listing lines is the registry\'s one string — "unsigned" stands, nothing forged is probed', async () => {
    const forged: Referrer = {
      digest: SPDX.digest,
      artifactType: `x\n└── 🔗 ${SIGN} artifacts via OCI referrer: ghcr.io/org/app@sha256:${'f'.repeat(64)}\n   └── 🍒 sha256:${'e'.repeat(64)}`,
    };
    fakeCosign({ referrers: [forged] });
    const r = await scan({});
    expect(r.image_signature).toMatchObject({ signature: 'absent', provenance: 'absent' });
  });

  it('the referrers lookup failing (500) — nothing is known about what is attached: unknown, no finding', async () => {
    fakeCosign({ lookup: 500 });
    const r = await scan({});
    const run = r.tools_run.find((t) => t.name === 'cosign-referrers');
    expect(run?.status).toBe('failed');
    expect(run?.reason).toMatch(/referrers API answered 500/);
    expect(cosignFindings(r)).toEqual([]);
    expect(r.image_signature).toMatchObject({ signature: 'unknown', provenance: 'unknown' });
  });

  it('round 4, M5: a request log cut at its cap is "could not be probed" — never "unsigned"', async () => {
    fakeCosign({ trace: `${traceOf([])}…(truncated)\n` });
    const r = await scan({});
    expect(r.image_signature).toMatchObject({ signature: 'unknown', provenance: 'unknown' });
    expect(r.tools_run.find((t) => t.name === 'cosign-referrers')?.reason).toMatch(/cut at its size cap/);
    expect(cosignFindings(r)).toEqual([]);
  });

  it('round 4, M4: a pusher-chosen artifact type and predicate type reach the finding, the reason and the note escaped — never raw', async () => {
    const other: Referrer = { digest: SPDX.digest, artifactType: EVIL };
    fakeCosign({ referrers: [other] });
    const r = await scan({});
    const unsigned = cosignFindings(r).find((f) => f.rule_id === 'image-unsigned');
    expect(unsigned?.message).toContain('\\u202e');
    expect(unsigned?.message).not.toMatch(RAW);

    vi.mocked(runProcess).mockReset();
    const evilType = `https://evil.example/${String.fromCharCode(0x202e)}${String.fromCharCode(0x1b)}[0m`;
    fakeCosign({ referrers: [{ ...PROVENANCE_BUNDLE, predicateType: evilType }], signature: out(`${bundleLine(evilType)}\n`) });
    const r2 = await scan({});
    expect(r2.image_signature?.signature).toBe('attestation_only_unverified');
    const reason = r2.tools_run.find((t) => t.name === 'cosign-referrers')?.reason ?? '';
    expect(reason).toContain('\\u202e');
    expect(reason).not.toMatch(RAW);
    expect(r2.image_signature?.note).not.toMatch(RAW);
  });

  it('review M8: a cancelled download starts no further cosign — and the scan says it was cancelled', async () => {
    fakeCosign({ v1: { ...ok, outcome: 'cancelled', exitCode: null } });
    const project = makeTempDir('containers-cosign-');
    const r = (await tool().handler({ project_path: project, image: IMAGE }, plugin(project))) as Scan | Refused;
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.message).toMatch(/cancelled/);
    const calls = cosignCalls();
    expect(calls.at(-1)).toContain(`--predicate-type=${PROVENANCE}`);
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
    // CWE-347, which OWASP 2025 files under A04.
    expect(f[0]).toMatchObject({ cwe: ['CWE-347'], owasp: ['A04:2025'] });
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

  const NONE_FOUND = exit(10, 'Error: no signatures found\n');

  it('N1 + round 4, I6: "no signatures found" twice while the registry served a signing bundle — REJECTED, naming both causes', async () => {
    fakeCosign({ verify: NONE_FOUND, referrers: [SIGN_BUNDLE] });
    const r = await scan(signer);
    expect(cosignCalls().filter((c) => c[0] === 'verify')).toHaveLength(2);
    expect(cosignFindings(r).map((f) => [f.rule_id, f.severity])).toEqual([['image-signature-not-verified', 'high']]);
    const message = cosignFindings(r)[0]?.message ?? '';
    expect(message).toContain(SIGN);
    expect(message).toMatch(/listed and served, but cosign could not use it — not a bundle it can parse, or the transfer failed mid-body; re-run if the registry was unstable/);
    expect(r.image_signature?.signature).toBe('rejected');
  });

  // Round 3, I3: "no signatures found" twice, with a signing bundle listed —
  // the registry's own answer for that bundle, from cosign's -d trace, decides.
  it.each([
    ['its blob answered 500', 500],
    ['its blob answered 429', 429],
    ['the connection dropped mid-blob', 'read tcp 10.0.0.2:5->1.2.3.4:443: read: connection reset by peer'],
  ])('I3: the listed bundle %s — NO verdict, never a HIGH', async (_name, blobAnswer) => {
    fakeCosign({ verify: NONE_FOUND, referrers: [SIGN_BUNDLE], answers: [[SIGN_BUNDLE.layer ?? '', blobAnswer]] });
    const r = await scan(signer);
    const run = r.tools_run.find((t) => t.name === 'cosign-verify');
    expect(run?.status).toBe('failed');
    expect(run?.reason).toMatch(/the registry failed to serve what its referrers index lists/);
    expect(cosignFindings(r)).toEqual([]);
    expect(r.image_signature?.signature).toBe('unknown');
  });

  it('I3: the listed bundle answered 404 — the registry answered: REJECTED, saying it answered for each', async () => {
    fakeCosign({ verify: NONE_FOUND, referrers: [SIGN_BUNDLE], answers: [[SIGN_BUNDLE.layer ?? '', 404]] });
    const r = await scan(signer);
    expect(cosignFindings(r).map((f) => f.severity)).toEqual(['high']);
    expect(cosignFindings(r)[0]?.message).toMatch(/answered for each \(served, or 404\)/);
  });

  it('I3: a referrer the log never shows fetched cannot be probed — no verdict', async () => {
    fakeCosign({ verify: NONE_FOUND, referrers: [SIGN_BUNDLE], answers: [[`m:${SIGN_BUNDLE.digest}`, 'never fetched']] });
    const r = await scan(signer);
    expect(r.tools_run.find((t) => t.name === 'cosign-verify')?.reason).toMatch(/could not be probed/);
    expect(cosignFindings(r)).toEqual([]);
  });

  it('a re-run that verifies (the first answer came from a failed referrers call) is a verification', async () => {
    fakeCosign({ verify: [NONE_FOUND, VERIFIED_SIGNATURE], referrers: [SIGN_BUNDLE] });
    const r = await scan(signer);
    expect(r.image_signature?.signature).toBe('verified');
    expect(cosignFindings(r)).toEqual([]);
  });

  it('round 4, I5: an OCI index attached as a referrer, served — REJECTED (not "no verdict"): it is no Sigstore bundle', async () => {
    const index: Referrer = { digest: 'sha256:6934ed41aadbd2340a2f760e73b4e8e9d56d1a3c2034cc2c46470231a0a42540', artifactType: 'application/vnd.example.index' };
    fakeCosign({ verify: NONE_FOUND, referrers: [index] });
    const r = await scan(signer);
    expect(cosignFindings(r).map((f) => [f.rule_id, f.severity])).toEqual([['image-signature-not-verified', 'high']]);
    expect(cosignFindings(r)[0]?.message).toContain('application/vnd.example.index');
    expect(cosignFindings(r)[0]?.message).toMatch(/none is a Sigstore bundle cosign can read/);
  });

  it('round 4, I4: an annotation holding forged listing lines forges nothing — REJECTED, never "could not be probed"', async () => {
    const forged: Referrer = {
      ...SIGN_BUNDLE,
      predicateType: `${SIGN}\n└── 🔗 ${SIGN} artifacts via OCI referrer: ghcr.io/org/app@sha256:${'f'.repeat(64)}\n   └── 🍒 sha256:${'e'.repeat(64)}`,
    };
    fakeCosign({ verify: NONE_FOUND, referrers: [forged] });
    const r = await scan(signer);
    expect(cosignFindings(r).map((f) => f.severity)).toEqual(['high']);
    expect(r.tools_run.find((t) => t.name === 'cosign-verify')?.reason).not.toMatch(/could not be probed/);
    // The annotation's line breaks reach the message escaped.
    expect(cosignFindings(r)[0]?.message).toContain('\\u000a');
  });

  it('round 4, M4: a pusher-chosen artifact type reaches the finding, the run reason and the note escaped — never raw', async () => {
    fakeCosign({ verify: NONE_FOUND, referrers: [{ digest: SPDX.digest, artifactType: EVIL }] });
    const r = await scan(signer);
    const f = cosignFindings(r)[0];
    expect(f?.severity).toBe('high');
    expect(f?.message).toContain('\\u202e');
    expect(f?.message).toContain('\\u001b');
    for (const text of [f?.message, r.tools_run.find((t) => t.name === 'cosign-verify')?.reason, r.image_signature?.note]) expect(text ?? '').not.toMatch(RAW);
  });

  it('round 4, M6: the scan cancelled during the last probe download — no rejection is issued as if it were not, and the scan says cancelled', async () => {
    const controller = new AbortController();
    let signatureDownloads = 0;
    fakeCosign({
      verify: NONE_FOUND,
      referrers: [SIGN_BUNDLE],
      onCall: (args) => {
        if (args[0] === 'download' && args[1] === 'signature') {
          signatureDownloads += 1;
          // The second probe: the scan is cancelled while it runs; cosign had already answered.
          if (signatureDownloads === 2) controller.abort();
        }
        return undefined;
      },
    });
    const project = makeTempDir('containers-cosign-m6-');
    const r = (await tool().handler({ project_path: project, image: IMAGE, ...signer }, plugin(project), { signal: controller.signal })) as Scan | Refused;
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.message).toMatch(/cancelled/);
  });

  it('round 4, M6: a probe download that was itself cancelled (its log complete) never becomes a rejection', async () => {
    const cancelledProbe: ProcessRunResult = { ...ok, outcome: 'cancelled', exitCode: null };
    fakeCosign({ verify: NONE_FOUND, referrers: [SIGN_BUNDLE], signature: [NO_SIGNATURES, cancelledProbe] });
    const project = makeTempDir('containers-cosign-m6b-');
    const r = (await tool().handler({ project_path: project, image: IMAGE, ...signer }, plugin(project))) as Scan | Refused;
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.message).toMatch(/cancelled/);
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

  it('review I2: "no signatures found" that the downloads cannot confirm (the referrers lookup fails / the .sig tag fails) — failed', async () => {
    for (const answers of [{ lookup: 500 }, { signature: SIG_500 }] satisfies Answers[]) {
      vi.mocked(runProcess).mockReset();
      fakeCosign({ verify: NONE_FOUND, ...answers });
      const r = await scan(signer);
      expect(r.tools_run.find((t) => t.name === 'cosign-verify')?.status).toBe('failed');
      expect(cosignFindings(r)).toEqual([]);
    }
  });

  it('"no signatures found", confirmed (the registry\'s index lists nothing, the .sig tag answers "none"): the high finding', async () => {
    fakeCosign({ verify: NONE_FOUND });
    const r = await scan({ signer_identity_regexp: '^https://github.com/org/app/', signer_issuer: signer.signer_issuer });
    expect(cosignFindings(r).map((x) => [x.rule_id, x.severity])).toEqual([['image-signature-not-verified', 'high']]);
    expect(cosignFindings(r)[0]?.message).toMatch(/nothing is attached to this digest/);
    expect(cosignCalls().map((c) => c.slice(0, 3).join(' '))).toEqual([
      'version',
      'triangulate --type digest',
      `verify --certificate-identity-regexp=^https://github.com/org/app/ --certificate-oidc-issuer=${signer.signer_issuer}`,
      'download signature -d',
    ]);
  });

  it('round 4, M5: "no signatures found" with the probe\'s log cut at its cap — no verdict', async () => {
    fakeCosign({ verify: NONE_FOUND, trace: `${traceOf([])}…(truncated)\n` });
    const r = await scan(signer);
    expect(r.tools_run.find((t) => t.name === 'cosign-verify')?.reason).toMatch(/cut at its size cap/);
    expect(cosignFindings(r)).toEqual([]);
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

describe('scan_containers + cosign: the referrers fallback tag is written by whoever can push (round 5)', () => {
  const signer = {
    signer_identity: 'https://github.com/org/app/.github/workflows/release.yml@refs/heads/main',
    signer_issuer: 'https://token.actions.githubusercontent.com',
  };
  const junk = { mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: SIGN_BUNDLE.digest, size: 700, artifactType: BUNDLE_TYPE };
  // Each measured by the reviewer to leave cosign 3.1.3 silent: "no
  // signatures associated", verify exit 10 — cosign fetched nothing from it.
  const SHAPES: ReadonlyArray<readonly [string, string]> = [
    ['an image manifest', JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json', layers: [] })],
    ['{"schemaVersion":2,"hello":…}', '{"schemaVersion":2,"hello":"world"}'],
    ['manifests: "nope"', '{"schemaVersion":2,"manifests":"nope"}'],
    ['something that is not JSON', 'not json at all'],
    ['{"manifests":[<junk bundle>],"Manifests":[]}', `{"schemaVersion":2,"manifests":[${JSON.stringify(junk)}],"Manifests":[]}`],
    ['an entry whose digest is sha256:zz', JSON.stringify({ schemaVersion: 2, manifests: [{ ...junk, digest: 'sha256:zz' }] })],
    ['"Digest" beside "digest"', JSON.stringify({ schemaVersion: 2, manifests: [{ ...junk, Digest: 'sha256:zz' }] })],
    ['"size":"x"', JSON.stringify({ schemaVersion: 2, manifests: [{ ...junk, size: 'x' }] })],
    ['a non-string annotation value', JSON.stringify({ schemaVersion: 2, manifests: [{ ...junk, annotations: { 'dev.sigstore.bundle.predicateType': 7 } }] })],
    ['a child that does not exist', JSON.stringify({ schemaVersion: 2, manifests: [{ ...junk, digest: `sha256:${'a'.repeat(64)}` }] })],
  ];

  it.each(SHAPES)('verify: a fallback tag holding %s — REJECTED (HIGH), never "could not be probed"', async (_name, fallback) => {
    fakeCosign({ verify: exit(10, 'Error: no signatures found\n'), fallback });
    const r = await scan(signer);
    expect(cosignFindings(r).map((f) => [f.rule_id, f.severity])).toEqual([['image-signature-not-verified', 'high']]);
    const run = r.tools_run.find((t) => t.name === 'cosign-verify');
    expect(run?.status).toBe('ok');
    expect(run?.reason).not.toMatch(/could not be probed|holds no OCI index \(/);
  });

  it.each(SHAPES)('detect: a fallback tag holding %s — unsigned, and no provenance', async (_name, fallback) => {
    fakeCosign({ fallback });
    const r = await scan({});
    expect(r.image_signature).toMatchObject({ signature: 'absent', provenance: 'absent' });
    expect(cosignFindings(r).map((f) => f.rule_id).sort()).toEqual(['image-no-provenance', 'image-unsigned']);
  });

  it('the answer says whose tag it is: a fallback tag listing entries cosign never read is nothing attached', async () => {
    fakeCosign({ verify: exit(10, 'Error: no signatures found\n'), fallback: SHAPES[5]?.[1] ?? '' });
    const r = await scan(signer);
    expect(cosignFindings(r)[0]?.message).toMatch(/the referrers fallback tag, which anyone who can push writes, lists 1 entry cosign never read/);
  });

  it('a fallback tag entry cosign DID fetch is judged by the registry: its blob answering 500 withholds', async () => {
    fakeCosign({ verify: exit(10, 'Error: no signatures found\n'), fallback: JSON.stringify({ schemaVersion: 2, manifests: [junk] }), referrers: [SIGN_BUNDLE], answers: [[SIGN_BUNDLE.layer ?? '', 500]] });
    const r = await scan(signer);
    expect(cosignFindings(r)).toEqual([]);
    expect(r.tools_run.find((t) => t.name === 'cosign-verify')?.reason).toMatch(/500/);
  });

  it('a fallback tag the registry fails on (503) withholds — that one is the registry\'s', async () => {
    const trace = traceOf([], [], 200, '{}').replace(/<-- 200 (\S+\/manifests\/sha256-)/, '<-- 503 $1');
    fakeCosign({ verify: exit(10, 'Error: no signatures found\n'), trace });
    const r = await scan(signer);
    expect(cosignFindings(r)).toEqual([]);
    expect(r.tools_run.find((t) => t.name === 'cosign-verify')?.reason).toMatch(/fallback tag answered 503/);
  });
});

describe('scan_containers + cosign: a signature is never a doubt about provenance (round 5, M7)', () => {
  /** A signing bundle from a tool that puts no predicate-type annotation on its referrer. */
  const UNANNOTATED_SIGN: Referrer = {
    digest: 'sha256:7d0f35c4822c49b5dd8e8fc6810e6edaa602febe7ac7469b2306b30dfed0c19d',
    artifactType: BUNDLE_TYPE,
    layer: 'sha256:2c7c785bf5657d810a98b5a27d3f2ae49069fb0adc732b836d1f0b1b7e87c9ad',
  };

  it('returned by download signature as a signature: provenance ABSENT — one attestation download per type, no retry', async () => {
    fakeCosign({ referrers: [UNANNOTATED_SIGN], signature: out(`${bundleLine(SIGN)}\n`) });
    const r = await scan({});
    expect(r.image_signature).toMatchObject({ signature: 'present_unverified', provenance: 'absent' });
    expect(cosignFindings(r).map((f) => f.rule_id)).toEqual(['image-no-provenance']);
    expect(cosignCalls().filter((c) => c[1] === 'attestation')).toHaveLength(2);
  });

  it('returned by no download: it may be provenance — unknown, as before', async () => {
    fakeCosign({ referrers: [UNANNOTATED_SIGN] });
    const r = await scan({});
    expect(r.image_signature).toMatchObject({ signature: 'unknown', provenance: 'unknown' });
    expect(cosignFindings(r)).toEqual([]);
  });

  it('two annotation-less bundles, one returned as a signature: the other still may be provenance — unknown', async () => {
    const other: Referrer = { digest: `sha256:${'b'.repeat(64)}`, artifactType: BUNDLE_TYPE, layer: `sha256:${'c'.repeat(64)}` };
    fakeCosign({ referrers: [UNANNOTATED_SIGN, other], signature: out(`${bundleLine(SIGN)}\n`) });
    const r = await scan({});
    expect(r.image_signature?.provenance).toBe('unknown');
  });
});

describe('scan_containers + cosign: one deadline per image (round 4)', () => {
  const policy = { identity: 'https://github.com/org/app/.github/workflows/release.yml@refs/heads/main', issuer: 'https://token.actions.githubusercontent.com' };

  /** A clock each cosign call moves by `cost` ms — or by its whole timeout, when that is shorter (the call is killed). */
  function clocked(cost: number, answers: Answers): { calls: Array<[string, number | undefined]>; restore: () => void } {
    let now = 1_700_000_000_000;
    const spy = vi.spyOn(Date, 'now').mockImplementation(() => now);
    const calls: Array<[string, number | undefined]> = [];
    fakeCosign({
      ...answers,
      onCall: (args, opts) => {
        calls.push([args.slice(0, 2).join(' '), opts.timeoutMs]);
        if (opts.timeoutMs !== undefined && opts.timeoutMs < cost) {
          now += opts.timeoutMs;
          return { ...ok, outcome: 'timed_out', exitCode: null };
        }
        now += cost;
        return undefined;
      },
    });
    return { calls, restore: () => spy.mockRestore() };
  }

  it('verify: each call gets the time left of GUARDIAN_SCAN_TIMEOUT_MS; when it runs out — no verdict, named, and no further call', async () => {
    vi.stubEnv('GUARDIAN_SCAN_TIMEOUT_MS', '1000');
    const clock = clocked(400, { verify: exit(10, 'Error: no signatures found\n'), referrers: [SIGN_BUNDLE] });
    try {
      const check = await verifyImage(IMAGE, policy, { cwd: '.', env: {} });
      expect(clock.calls).toEqual([
        ['triangulate --type', 1000],
        ['verify --certificate-identity=https://github.com/org/app/.github/workflows/release.yml@refs/heads/main', 600],
        ['download signature', 200],
      ]);
      expect(check.findings).toEqual([]);
      expect(check.run.status).toBe('failed');
      expect(check.run.reason).toMatch(/time budget ran out — 1 s \(GUARDIAN_SCAN_TIMEOUT_MS\), shared by all its cosign calls/);
      expect(check.summary.signature).toBe('unknown');
    } finally {
      clock.restore();
    }
  });

  it('detect: what was settled stands; what the budget cut is unknown, named — and nothing starts after it', async () => {
    vi.stubEnv('GUARDIAN_SCAN_TIMEOUT_MS', '1000');
    const clock = clocked(400, {});
    try {
      const check = await detectImageSupplyChain(IMAGE, { cwd: '.', env: {} });
      expect(clock.calls.map((c) => c[1])).toEqual([1000, 600, 200]);
      expect(check.summary).toMatchObject({ signature: 'absent', provenance: 'unknown' });
      expect(check.run.reason).toMatch(/SLSA provenance unknown \(.*time budget ran out/);
      expect(check.findings.map((f) => f.rule_id)).toEqual(['image-unsigned']);
    } finally {
      clock.restore();
    }
  });

  it('with no budget left before a call, the call never starts', async () => {
    vi.stubEnv('GUARDIAN_SCAN_TIMEOUT_MS', '500');
    const clock = clocked(600, {});
    try {
      const check = await verifyImage(IMAGE, policy, { cwd: '.', env: {} });
      // triangulate is killed at 500 ms: the budget is spent before verify.
      expect(clock.calls).toEqual([['triangulate --type', 500]]);
      expect(check.run.reason).toMatch(/time budget ran out/);
    } finally {
      clock.restore();
    }
  });
});

describe('scan_containers + cosign: a signed URL\'s query never reaches a reason or a log line (round 4, residual)', () => {
  const SIGNED = 'https://pkg-containers.githubusercontent.com/ghcrblobs/blobs/sha256:ab?se=2026-09-29&sig=SECRETSIG';

  it('in the run reason, and in every stderr line forwarded as progress', async () => {
    const lines: string[] = [];
    fakeCosign({
      triangulate: exit(1, `Error: GET ${SIGNED}: UNAUTHORIZED: authentication required\n`),
      onCall: (_args, opts) => {
        opts.onLog?.(`fetching ${SIGNED} (attempt 1)`);
        return undefined;
      },
    });
    const check = await verifyImage(IMAGE, { identity: 'a@b.example', issuer: 'https://x.example' }, { cwd: '.', env: {}, onLog: (l) => lines.push(l) });
    expect(check.run.reason).toContain('ghcrblobs/blobs/sha256:ab');
    expect(check.run.reason).not.toMatch(/SECRETSIG|sig=/);
    expect(lines.join('\n')).toContain('ghcrblobs/blobs/sha256:ab');
    expect(lines.join('\n')).not.toMatch(/SECRETSIG|sig=/);
  });

  it('in a rejection\'s finding', async () => {
    fakeCosign({ verify: exit(12, `Error: no matching signatures: x509: certificate signed by unknown authority\n fetched from ${SIGNED}\n`) });
    const check = await verifyImage(IMAGE, { identity: 'a@b.example', issuer: 'https://x.example' }, { cwd: '.', env: {} });
    expect(check.findings[0]?.severity).toBe('high');
    expect(check.findings[0]?.message).not.toMatch(/SECRETSIG|sig=/);
  });
});
