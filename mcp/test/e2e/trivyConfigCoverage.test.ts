/**
 * Review I3, against the REAL Trivy on PATH: `trivy config` drops a file it
 * cannot parse with one ERROR line on stderr (which `--quiet` hides) and
 * exits 0. Reproduced on 0.69.3 before the fix:
 *   - a .tf with an open security group → 1 high; with an unclosed
 *     `resource {` appended → 0 findings, coverage full;
 *   - a Kubernetes Pod with `privileged: true` → findings; templated
 *     (`name: {{ name }}`) → 0, full, and Trivy logs `Detected config files
 *     num=0` with no error at all;
 *   - a Dockerfile with `HEALTHCHECK --interval=bogus` → `ERROR [dockerfile
 *     scanner] Failed to parse file`, and trivy-dockerfile ok.
 *
 * Gated on Trivy being on PATH; `GUARDIAN_REQUIRE_SEMGREP=1` turns a missing
 * Trivy into a failure, as elsewhere.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { resetScannerCache } from '../../src/tools/scanHelpers.js';
import type { ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

vi.setConfig({ testTimeout: 300_000 });

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/scanIac.js');
  await import('../../src/tools/scanContainers.js');
  resetScannerCache();
});

const TRIVY_INSTALLED = await isInstalled('trivy');
const REQUIRE_TOOLCHAIN = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

function project(files: Record<string, string>): string {
  const dir = resolveProjectPath(makeTempDir('trivy-config-e2e-')).path;
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), body);
  }
  return dir;
}

function plugin(dir: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
}

interface ScanOut {
  scan_id: string;
  coverage: string;
  tools_run: ToolRun[];
  missing_tools: string[];
}

async function run(name: string, dir: string, input: Record<string, unknown> = {}): Promise<{ out: ScanOut; findings: number }> {
  const tool = TOOLS.find((t) => t.name === name);
  if (!tool) throw new Error(`${name} not registered`);
  const p = plugin(dir);
  const r = await tool.handler({ project_path: dir, force: true, ...input }, p);
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  const out = r as unknown as ScanOut;
  return { out, findings: p.storage.findings.listByScan(out.scan_id).length };
}

const OPEN_SG = `resource "aws_security_group" "open" {
  name = "open"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`;
const POD = `apiVersion: v1
kind: Pod
metadata:
  name: priv
spec:
  containers:
    - name: c
      image: nginx
      securityContext:
        privileged: true
`;

describe('trivy config parse errors and unrecognised IaC (real Trivy)', () => {
  it.runIf(REQUIRE_TOOLCHAIN)('GUARDIAN_REQUIRE_SEMGREP=1 — Trivy must be on PATH', () => {
    expect(TRIVY_INSTALLED).toBe(true);
  });

  it.skipIf(!TRIVY_INSTALLED)('scan_iac: a .tf Trivy could not parse is partial, the file named', async () => {
    const clean = await run('scan_iac', project({ 'main.tf': OPEN_SG }));
    expect(clean.findings).toBeGreaterThan(0);
    expect(clean.out.coverage).toBe('full');

    const broken = await run('scan_iac', project({ 'main.tf': `${OPEN_SG}\nresource "aws_s3_bucket" "b" {\n` }));
    const trivy = broken.out.tools_run.find((t) => t.name === 'trivy-config');
    expect(trivy?.status).toBe('ok');
    expect(trivy?.reason).toMatch(/could not parse 1 file: main\.tf/);
    expect(broken.out.missing_tools).toContain('trivy-config');
    expect(broken.out.coverage).toBe('partial');
  });

  it.skipIf(!TRIVY_INSTALLED)('scan_iac: a templated manifest Trivy did not recognise is partial; plain YAML is not', async () => {
    const templated = await run('scan_iac', project({ 'k8s/pod.yaml': POD.replace('name: priv', 'name: {{ name }}') }));
    const trivy = templated.out.tools_run.find((t) => t.name === 'trivy-config');
    expect(trivy?.reason).toMatch(/no config file recognised.*k8s\/pod\.yaml/);
    expect(templated.out.coverage).toBe('partial');

    const plain = await run('scan_iac', project({ 'config.yaml': 'foo: bar\n' }));
    expect(plain.out.tools_run.find((t) => t.name === 'trivy-config')).toEqual({ name: 'trivy-config', status: 'ok' });
    expect(plain.out.coverage).toBe('full');
  });

  /**
   * Round 2, item 3: projects Trivy reads nothing from, legitimately, must
   * not be permanently partial. Measured on 0.69.3: a Kustomize base +
   * overlay is num=2 (the Deployment and the patch); a kustomization.yaml
   * alone (a remote base) is num=0 with no error — not a manifest to Trivy,
   * which needs apiVersion, kind AND metadata; a CRD and a custom resource
   * are num=1 each (Kubernetes detection is not limited to core kinds); a
   * skaffold.yaml is num=0.
   */
  it.skipIf(!TRIVY_INSTALLED)('Kustomize, CRDs and custom resources: complete, never permanently partial', async () => {
    const DEPLOY = POD.replace('kind: Pod', 'kind: Deployment').replace('apiVersion: v1', 'apiVersion: apps/v1');
    const kustomize = await run(
      'scan_iac',
      project({
        'base/kustomization.yaml': 'apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - deployment.yaml\n',
        'base/deployment.yaml': DEPLOY,
        'overlays/prod/kustomization.yaml':
          'apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - ../../base\npatches:\n  - path: replicas.yaml\n',
        'overlays/prod/replicas.yaml': 'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: priv\nspec:\n  replicas: 3\n',
      }),
    );
    expect(kustomize.out.coverage).toBe('full');

    const remoteBase = await run(
      'scan_iac',
      project({
        'kustomization.yaml':
          'apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - https://github.com/example/base?ref=v1\n',
        'skaffold.yaml': 'apiVersion: skaffold/v4beta6\nkind: Config\nbuild:\n  artifacts: []\n',
      }),
    );
    expect(remoteBase.out.tools_run.find((t) => t.name === 'trivy-config')).toEqual({ name: 'trivy-config', status: 'ok' });
    expect(remoteBase.out.coverage).toBe('full');

    const crd = await run(
      'scan_iac',
      project({
        'crd.yaml':
          'apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: widgets.example.com\nspec:\n  group: example.com\n  names:\n    kind: Widget\n    plural: widgets\n  scope: Namespaced\n  versions: []\n',
        'widget.yaml': 'apiVersion: example.com/v1\nkind: Widget\nmetadata:\n  name: my-widget\nspec:\n  size: 3\n',
      }),
    );
    expect(crd.out.coverage).toBe('full');
  });

  it.skipIf(!TRIVY_INSTALLED)('scan_containers: a Dockerfile Trivy could not parse is partial, named', async () => {
    const dir = project({ Dockerfile: 'FROM alpine:3.18\nHEALTHCHECK --interval=bogus CMD true\n' });
    const r = await run('scan_containers', dir);
    const trivy = r.out.tools_run.find((t) => t.name === 'trivy-dockerfile');
    expect(trivy?.status).toBe('ok');
    expect(trivy?.reason).toMatch(/could not parse 1 file: Dockerfile .*invalid duration/);
    expect(r.out.missing_tools).toContain('trivy-dockerfile');
    expect(r.out.coverage).not.toBe('full');
  });
});
