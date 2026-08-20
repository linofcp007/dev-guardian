/**
 * The four states drift detection has to keep apart, plus the two degenerate
 * ones.
 *
 * "Their hash moved" and "our hash moved" are different facts with different
 * consequences, and collapsing them into one "the file changed" warning is
 * what makes a drift notice useless: the common case (the user edited their
 * own config, exactly as intended) would drown the rare case (we shipped a
 * fix they never received). Each state is asserted independently here.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { detectConfigDrift } from '../../../src/configdrift/detect.js';
import { hashConfigText } from '../../../src/configdrift/hash.js';
import {
  MANIFEST_SCHEMA_VERSION,
  writeManifest,
  type ConfigManifestEntry,
} from '../../../src/configdrift/manifest.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const SHIPPED_V1 = 'rules:\n  - id: wp-unescaped-output\n    pattern: broken\n';
const SHIPPED_V2 = 'rules:\n  - id: wp-unescaped-output\n    pattern: fixed\n';

interface Harness {
  projectPath: string;
  configsDir: string;
}

function harness(): Harness {
  const projectPath = makeTempDir('drift-project-');
  const configsDir = makeTempDir('drift-configs-');
  mkdirSync(join(configsDir, 'semgrep'), { recursive: true });
  return { projectPath, configsDir };
}

function shipped(h: Harness, content: string): void {
  writeFileSync(join(h.configsDir, 'semgrep', 'base.yml'), content, 'utf8');
}

function userCopy(h: Harness, content: string): void {
  writeFileSync(join(h.projectPath, '.semgrep.yml'), content, 'utf8');
}

function record(h: Harness, entry: Partial<ConfigManifestEntry> = {}): void {
  const full: ConfigManifestEntry = {
    target: '.semgrep.yml',
    source: 'semgrep/base.yml',
    plugin_version: '1.7.0',
    source_sha256: hashConfigText(SHIPPED_V1),
    target_sha256: hashConfigText(SHIPPED_V1),
    recorded_at: '2026-01-01T00:00:00.000Z',
    provenance: 'copied',
    ...entry,
  };
  writeManifest(h.projectPath, { schema_version: MANIFEST_SCHEMA_VERSION, entries: [full] });
}

function detect(h: Harness) {
  return detectConfigDrift({
    projectPath: h.projectPath,
    configsDir: h.configsDir,
    currentVersion: '1.9.0',
  });
}

describe('detectConfigDrift', () => {
  it('reports no manifest, and no entries, for a project initialised before this existed', () => {
    const h = harness();
    shipped(h, SHIPPED_V2);
    userCopy(h, SHIPPED_V1);
    const report = detect(h);
    expect(report.manifest_present).toBe(false);
    expect(report.entries).toEqual([]);
  });

  it('does not throw on a corrupt manifest — it degrades to "no manifest"', () => {
    const h = harness();
    shipped(h, SHIPPED_V2);
    mkdirSync(join(h.projectPath, '.dev-guardian'), { recursive: true });
    writeFileSync(join(h.projectPath, '.dev-guardian', 'configs.json'), '{ not json', 'utf8');
    const report = detect(h);
    expect(report.manifest_present).toBe(false);
    expect(report.entries).toEqual([]);
  });

  it('reports in_sync when neither side moved', () => {
    const h = harness();
    shipped(h, SHIPPED_V1);
    userCopy(h, SHIPPED_V1);
    record(h);
    expect(detect(h).entries.map((e) => e.state)).toEqual(['in_sync']);
  });

  it('reports in_sync across a pure line-ending difference', () => {
    const h = harness();
    shipped(h, SHIPPED_V1);
    userCopy(h, SHIPPED_V1.replace(/\n/g, '\r\n'));
    record(h);
    expect(detect(h).entries.map((e) => e.state)).toEqual(['in_sync']);
  });

  it('reports local_edit when the user edited their copy and we shipped nothing new', () => {
    const h = harness();
    shipped(h, SHIPPED_V1);
    userCopy(h, `${SHIPPED_V1}  - id: my-own-rule\n`);
    record(h);
    expect(detect(h).entries.map((e) => e.state)).toEqual(['local_edit']);
  });

  it('reports upstream_update when we shipped a newer version and they did not touch theirs', () => {
    const h = harness();
    shipped(h, SHIPPED_V2);
    userCopy(h, SHIPPED_V1);
    record(h);
    const entry = detect(h).entries[0];
    if (entry === undefined) throw new Error('expected one drift entry');
    expect(entry.state).toBe('upstream_update');
    expect(entry.recorded_plugin_version).toBe('1.7.0');
    expect(entry.current_plugin_version).toBe('1.9.0');
  });

  it('reports diverged when both sides moved', () => {
    const h = harness();
    shipped(h, SHIPPED_V2);
    userCopy(h, `${SHIPPED_V1}  - id: my-own-rule\n`);
    record(h);
    expect(detect(h).entries.map((e) => e.state)).toEqual(['diverged']);
  });

  it('reports pending_merge while a delivered .new file is still on disk', () => {
    const h = harness();
    shipped(h, SHIPPED_V2);
    userCopy(h, SHIPPED_V1);
    writeFileSync(join(h.projectPath, '.semgrep.yml.new'), SHIPPED_V2, 'utf8');
    record(h, { delivered_as: '.semgrep.yml.new', delivered_at: '2026-02-01T00:00:00.000Z' });
    expect(detect(h).entries.map((e) => e.state)).toEqual(['pending_merge']);
  });

  it('reports target_missing when the user deleted their copy', () => {
    const h = harness();
    shipped(h, SHIPPED_V1);
    record(h);
    expect(detect(h).entries.map((e) => e.state)).toEqual(['target_missing']);
  });

  it('reports source_missing when the shipped baseline is unreachable', () => {
    const h = harness();
    userCopy(h, SHIPPED_V1);
    record(h);
    expect(detect(h).entries.map((e) => e.state)).toEqual(['source_missing']);
  });
});
