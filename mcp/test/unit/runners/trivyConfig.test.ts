/**
 * `trivy config` judged by what it logged, not by its exit code (review I3):
 * canned logs measured on Trivy 0.69.3, so the judgement is tested on a
 * machine without Trivy too. `test/e2e/trivyConfigCoverage.test.ts` runs the
 * same shapes through the real Trivy.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { iacLookingFiles, judgeTrivyConfig, parseTrivyConfigLog } from '../../../src/runners/trivyConfig.js';
import type { TrivyRunResult } from '../../../src/runners/trivyRun.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

// Verbatim from Trivy 0.69.3 (`trivy config --format json`, no --quiet).
const TF_BROKEN_LOG = [
  '2026-09-29T11:19:17+01:00\tINFO\tLoaded\tfile_path="C:\\\\tmp\\\\empty.yaml"',
  '2026-09-29T11:19:17+01:00\tINFO\t[misconfig] Misconfiguration scanning is enabled',
  '2026-09-29T11:19:19+01:00\tERROR\t[terraform parser] Error parsing file\tmodule="root" file_path="main.tf" cause="resource \\"aws_s3_bucket\\" \\"b\\" {" err="main.tf:11,30-31: Unclosed configuration block; There is no closing brace for this block before the end of the file. This may be caused by incorrect brace nesting elsewhere in this file."',
  '2026-09-29T11:19:19+01:00\tINFO\t[terraform scanner] Scanning root module\tfile_path="."',
  '2026-09-29T11:19:19+01:00\tERROR\t[terraform parser] Error parsing file\tmodule="root" file_path="main.tf" cause="resource \\"aws_s3_bucket\\" \\"b\\" {" err="main.tf:11,30-31: Unclosed configuration block; There is no closing brace for this block before the end of the file. This may be caused by incorrect brace nesting elsewhere in this file."',
  '2026-09-29T11:19:19+01:00\tINFO\t[terraform parser] No files found, nothing to do.\tmodule="root"',
  '2026-09-29T11:19:19+01:00\tINFO\tDetected config files\tnum=1',
].join('\n');
const DOCKERFILE_BROKEN_LOG = [
  '2026-09-29T11:19:28+01:00\tERROR\t[dockerfile scanner] Failed to parse file\tfile_path="Dockerfile" err="parse dockerfile instruction: parse instruction \\"healthcheck\\": time: invalid duration \\"bogus\\""',
  '2026-09-29T11:19:28+01:00\tINFO\tDetected config files\tnum=0',
].join('\n');
const NOTHING_DETECTED_LOG = '2026-09-29T11:19:25+01:00\tINFO\tDetected config files\tnum=0\n';
const TWO_DETECTED_LOG = '2026-09-29T11:19:16+01:00\tINFO\tDetected config files\tnum=2\n';

describe('parseTrivyConfigLog', () => {
  it('reads the parse errors, one per file, and the detected count', () => {
    expect(parseTrivyConfigLog(TF_BROKEN_LOG)).toEqual({
      detected: 1,
      parseErrors: [
        {
          file: 'main.tf',
          message: expect.stringMatching(/^Error parsing file: main\.tf:11,30-31: Unclosed configuration block/),
        },
      ],
    });
    expect(parseTrivyConfigLog(DOCKERFILE_BROKEN_LOG)).toEqual({
      detected: 0,
      parseErrors: [{ file: 'Dockerfile', message: expect.stringMatching(/invalid duration/) }],
    });
  });

  it('an ERROR line with no file is kept, unnamed', () => {
    const log = '2026-09-29T11:00:00+01:00\tERROR\t[misconfig] Something broke\terr="boom"\n';
    expect(parseTrivyConfigLog(log).parseErrors).toEqual([{ file: null, message: 'Something broke: boom' }]);
  });

  it('no count logged is unknown, never zero', () => {
    expect(parseTrivyConfigLog('').detected).toBeNull();
  });
});

function tree(files: Record<string, string>): string {
  const dir = makeTempDir('trivy-config-');
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), body, 'utf8');
  }
  return dir;
}

const POD = 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: {{ name }}\nspec:\n  containers: []\n';

describe('iacLookingFiles', () => {
  it('finds what Trivy detects: Terraform/OpenTofu, Dockerfiles by its names, Kubernetes manifests, CloudFormation', () => {
    const dir = tree({
      'infra/main.tf': 'resource "x" "y" {}\n',
      'infra/vars.tf.json': '{}',
      'infra/main.tofu': 'resource "x" "y" {}\n',
      'Dockerfile': 'FROM alpine\n',
      'Dockerfile.prod': 'FROM alpine\n',
      'svc/api.Dockerfile': 'FROM alpine\n',
      'svc/Containerfile': 'FROM alpine\n',
      'svc/app.Containerfile': 'FROM alpine\n',
      'k8s/pod.yaml': POD,
      'k8s/widget.yaml': 'apiVersion: example.com/v1\nkind: Widget\nmetadata:\n  name: {{ name }}\n',
      'k8s/deploy.json': '{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"x"}}',
      'cfn/stack.json': '{"AWSTemplateFormatVersion":"2010-09-09","Resources":{}}',
      'cfn/stack.yml': 'Resources:\n  B:\n    Type: AWS::S3::Bucket\n',
    });
    expect(iacLookingFiles(dir, null).files).toEqual([
      'Dockerfile',
      'Dockerfile.prod',
      'cfn/stack.json',
      'cfn/stack.yml',
      'infra/main.tf',
      'infra/main.tofu',
      'infra/vars.tf.json',
      'k8s/deploy.json',
      'k8s/pod.yaml',
      'k8s/widget.yaml',
      'svc/Containerfile',
      'svc/api.Dockerfile',
      'svc/app.Containerfile',
    ]);
  });

  /**
   * Round 2, item 3 — measured with Trivy 0.69.3 (`trivy config`): each of
   * these alone is `Detected config files num=0` with no error, legitimately:
   * Trivy's Kubernetes detection needs top-level apiVersion, kind AND
   * metadata, so a kustomization.yaml / Component, skaffold.yaml or a kind
   * cluster config is not a manifest to it; a Chart.yaml alone renders
   * nothing (a chart that fails to render is Trivy's own ERROR line); a
   * `.tfvars` alone and a lowercase `dockerfile` are not files it reads.
   * Counted as IaC-looking, every Kustomize-only or skaffold project read
   * partial on every scan, with nothing to fix.
   */
  // Round 4, item 7: the JSON rule matched the three keys ANYWHERE, so a JSON
  // Schema listing them as properties read partial. Top-level keys only.
  it('JSON: only top-level keys count, never a schema that lists them as properties', () => {
    const dir = tree({
      'schemas/pod.schema.json': JSON.stringify({
        $schema: 'http://json-schema.org/draft-07/schema#',
        type: 'object',
        properties: { apiVersion: { type: 'string' }, kind: { type: 'string' }, metadata: { type: 'object' } },
      }),
      'openapi.json': JSON.stringify({ components: { schemas: { Res: { properties: { Resources: {}, Type: 'AWS::X' } } } } }),
      'k8s/deploy.json': JSON.stringify({ apiVersion: 'apps/v1', kind: 'Deployment', metadata: { name: 'x' } }),
      'k8s/list.json': JSON.stringify([{ apiVersion: 'v1', kind: 'Pod', metadata: { name: 'x' } }]),
      'cfn/stack.json': JSON.stringify({ Resources: { B: { Type: 'AWS::S3::Bucket' } } }),
    });
    expect(iacLookingFiles(dir, null).files).toEqual(['cfn/stack.json', 'k8s/deploy.json']);
  });

  it('does not count what Trivy never detects: Kustomize, skaffold, kind configs, a bare Chart.yaml, .tfvars', () => {
    const dir = tree({
      'base/kustomization.yaml': 'apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - https://example.com/base\n',
      'components/x/kustomization.yaml': 'apiVersion: kustomize.config.k8s.io/v1alpha1\nkind: Component\npatches: []\n',
      'skaffold.yaml': 'apiVersion: skaffold/v4beta6\nkind: Config\nbuild:\n  artifacts: []\n',
      'kind.yaml': 'kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnodes: []\n',
      'chart/Chart.yaml': 'apiVersion: v2\nname: x\nversion: 0.1.0\n',
      'x.tfvars': 'a = 1\n',
      'lower/dockerfile': 'FROM alpine\n',
    });
    expect(iacLookingFiles(dir, null).files).toEqual([]);
  });

  /**
   * A chart's templates are Helm's to render, never files Trivy reads as they
   * are: a template disabled by `{{- if .Values.x.enabled }}` renders nothing
   * and is absent from the report legitimately (measured on 0.69.3: num=1,
   * only the enabled template listed). With the per-file comparison of round
   * 4, counting them would make every chart with an optional resource
   * partial. A chart that fails to render is Trivy's own ERROR line.
   */
  it("a Helm chart's templates are not counted, subcharts' neither; the chart's siblings still are", () => {
    const POD = 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: {{ .Values.name }}\n';
    const dir = tree({
      'chart/Chart.yaml': 'apiVersion: v2\nname: x\nversion: 0.1.0\n',
      'chart/templates/pod.yaml': POD,
      'chart/templates/ingress.yaml': '{{- if .Values.ingress.enabled }}\napiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: x\n{{- end }}\n',
      'chart/charts/sub/Chart.yaml': 'apiVersion: v2\nname: sub\nversion: 0.1.0\n',
      'chart/charts/sub/templates/pod.yaml': POD,
      'k8s/templates/pod.yaml': POD,
    });
    expect(iacLookingFiles(dir, null).files).toEqual(['k8s/templates/pod.yaml']);
  });

  it('plain YAML and JSON that are not IaC do not count', () => {
    const dir = tree({
      'config.yaml': 'foo: bar\nlist:\n  - 1\n',
      'docker-compose.yml': 'services:\n  web:\n    image: nginx\n',
      'openapi.yaml': 'openapi: 3.0.0\ninfo:\n  title: x\n',
      'package.json': '{"name":"x"}',
      'notes.md': 'kind: Pod\napiVersion: v1\n',
      // `kind:` indented under something else is not a top-level manifest key.
      'values.yaml': 'app:\n  apiVersion: v1\n  kind: Pod\n',
    });
    expect(iacLookingFiles(dir, null).files).toEqual([]);
  });

  it('skips dependency, build and hidden directories, and .guardianignore entries', () => {
    const dir = tree({
      'node_modules/x/main.tf': 'resource "a" "b" {}\n',
      'vendor/y/Dockerfile': 'FROM alpine\n',
      '.terraform/modules/m/main.tf': 'resource "a" "b" {}\n',
      'fixtures/Dockerfile': 'FROM alpine\n',
      'main.tf': 'resource "a" "b" {}\n',
    });
    const ignores = (rel: string): boolean => rel === 'fixtures' || rel.startsWith('fixtures/');
    expect(iacLookingFiles(dir, { ignores }).files).toEqual(['main.tf']);
  });
});

describe('judgeTrivyConfig', () => {
  const completed = (stderr: string): TrivyRunResult => ({
    outcome: 'completed',
    exitCode: 0,
    stdout: '',
    stderr,
    truncated: false,
    honoured: [],
  });

  it('a file Trivy could not parse makes the pass partial, named', () => {
    const j = judgeTrivyConfig({ name: 'trivy-config', run: completed(TF_BROKEN_LOG), raw: null, iacFiles: ['main.tf'] });
    expect(j.toolRun.status).toBe('ok');
    expect(j.toolRun.reason).toMatch(/could not parse 1 file: main\.tf \(.*Unclosed configuration block/);
    expect(j.missing).toEqual(['trivy-config']);
  });

  it('no config file recognised while IaC-looking files exist is partial, and names them', () => {
    const j = judgeTrivyConfig({ name: 'trivy-config', run: completed(NOTHING_DETECTED_LOG), raw: null, iacFiles: ['k8s/pod.yaml'] });
    expect(j.toolRun.status).toBe('ok');
    expect(j.toolRun.reason).toMatch(/no config file recognised.*k8s\/pod\.yaml/);
    expect(j.missing).toEqual(['trivy-config']);
  });

  it('nothing detected where nothing looks like IaC is complete', () => {
    const j = judgeTrivyConfig({ name: 'trivy-config', run: completed(NOTHING_DETECTED_LOG), raw: null, iacFiles: [] });
    expect(j.toolRun).toEqual({ name: 'trivy-config', status: 'ok' });
    expect(j.missing).toEqual([]);
  });

  it('detected files, each in the report, and no error is complete', () => {
    // Terraform is reported per module DIRECTORY ('.' at the root) — measured on 0.69.3.
    const raw = JSON.stringify({ Results: [{ Target: '.', Type: 'terraform' }] });
    const j = judgeTrivyConfig({ name: 'trivy-config', run: completed(TWO_DETECTED_LOG), raw, iacFiles: ['main.tf'] });
    expect(j.toolRun).toEqual({ name: 'trivy-config', status: 'ok' });
  });

  /**
   * Round 4, item 1: the check ran only when Trivy detected NOTHING, so a
   * templated pod.yaml beside one clean Dockerfile read full (num=1). Trivy
   * lists every file it read in Results — clean ones too, with their
   * `MisconfSummary` Successes (measured on 0.69.3) — so each IaC-looking
   * file is compared with the report, one by one.
   */
  it('an IaC-looking file absent from the report is named, whatever else Trivy read', () => {
    const raw = JSON.stringify({
      Results: [
        { Target: 'Dockerfile', Type: 'dockerfile', MisconfSummary: { Successes: 27, Failures: 0 } },
        { Target: 'infra', Type: 'terraform', MisconfSummary: { Successes: 51, Failures: 0 } },
        { Target: 'mod/main.tf', Type: 'terraform' },
        { Target: 'k8s/clean.yaml', Type: 'kubernetes' },
      ],
    });
    const j = judgeTrivyConfig({
      name: 'trivy-config',
      run: completed('2026-09-29T11:19:16+01:00\tINFO\tDetected config files\tnum=4\n'),
      raw,
      iacFiles: ['Dockerfile', 'infra/main.tf', 'infra/vars.tf', 'k8s/clean.yaml', 'k8s/pod.yaml', 'mod/main.tf', 'mod/vars.tf'],
    });
    expect(j.toolRun.reason).toMatch(/Trivy read nothing from 1 IaC-looking file: k8s\/pod\.yaml/);
    expect(j.missing).toEqual(['trivy-config']);
  });

  it('scan_containers: a Dockerfile given in a subdirectory is reported by its own name', () => {
    const raw = JSON.stringify({ Results: [{ Target: 'Dockerfile', Type: 'dockerfile' }] });
    const j = judgeTrivyConfig({ name: 'trivy-dockerfile', run: completed(''), raw, iacFiles: ['docker/Dockerfile'], singleFile: true });
    expect(j.missing).toEqual([]);
  });

  it('a count that was not logged falls back to the report: Results mean something was read', () => {
    const raw = JSON.stringify({ Results: [{ Target: 'Dockerfile', Type: 'dockerfile' }] });
    expect(judgeTrivyConfig({ name: 'trivy-dockerfile', run: completed(''), raw, iacFiles: ['Dockerfile'] }).missing).toEqual([]);
    expect(
      judgeTrivyConfig({ name: 'trivy-dockerfile', run: completed(''), raw: '{}', iacFiles: ['Dockerfile'] }).missing,
    ).toEqual(['trivy-dockerfile']);
  });

  it('a run that did not complete is failed', () => {
    const j = judgeTrivyConfig({
      name: 'trivy-config',
      run: { outcome: 'timed_out', exitCode: null, stdout: '', stderr: '', truncated: false, honoured: [] },
      raw: null,
      iacFiles: [],
    });
    expect(j.toolRun.status).toBe('failed');
    expect(j.missing).toEqual([]);
  });
});
