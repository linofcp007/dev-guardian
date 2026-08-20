/**
 * Finding the project's own Semgrep rules — and refusing to pass Semgrep one
 * that would take the whole scan down with it.
 *
 * ---- Why the loadability guard is the important half ------------------
 *
 * Measured against semgrep 1.164.0, `--config=auto --config <path>`:
 *
 *   - path does not exist        → `paths.scanned: []`, exit 7
 *   - malformed YAML             → `paths.scanned: []`, exit 7
 *   - valid YAML, no `rules` key → `paths.scanned: []`, exit 7
 *   - `rules: []`                → `paths.scanned: []`, exit 0
 *   - a rule with an uncompilable pattern → `paths.scanned` NON-empty, exit 2
 *
 * The first four scan nothing at all. Until now a broken `.semgrep.yml` in a
 * user's project was harmless, because nothing read it; the moment `scan_sast`
 * starts passing it to Semgrep, a single stray character in a file the user
 * owns silently turns every SAST scan into "0 findings" — the exact failure
 * shape this whole round is about. So the file is structurally checked here
 * before it is ever handed to Semgrep.
 *
 * The last case is deliberately NOT filtered: a rule that fails to compile is
 * a real scan that lost one rule, and `scan_sast` reports it rather than
 * dropping the config.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { hashConfigText } from '../../../src/configdrift/hash.js';
import {
  MANIFEST_SCHEMA_VERSION,
  writeManifest,
  type ConfigManifestEntry,
} from '../../../src/configdrift/manifest.js';
import {
  isLoadableSemgrepConfig,
  resolveProjectSemgrepConfigs,
} from '../../../src/platform/projectSemgrepConfig.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const GOOD = 'rules:\n  - id: x\n    pattern: foo(...)\n    message: m\n    languages: [python]\n    severity: WARNING\n';

function project(): string {
  return makeTempDir('project-semgrep-');
}

function entry(over: Partial<ConfigManifestEntry> = {}): ConfigManifestEntry {
  return {
    target: '.semgrep.yml',
    source: 'semgrep/base.yml',
    plugin_version: '1.8.0',
    source_sha256: hashConfigText(GOOD),
    target_sha256: hashConfigText(GOOD),
    recorded_at: '2026-01-01T00:00:00.000Z',
    provenance: 'copied',
    ...over,
  };
}

function withManifest(p: string, entries: ConfigManifestEntry[]): void {
  writeManifest(p, { schema_version: MANIFEST_SCHEMA_VERSION, entries });
}

describe('resolveProjectSemgrepConfigs', () => {
  it('finds the target the manifest recorded for a shipped semgrep config', () => {
    const p = project();
    writeFileSync(join(p, '.semgrep.yml'), GOOD, 'utf8');
    withManifest(p, [entry()]);
    const found = resolveProjectSemgrepConfigs(p);
    expect(found).toHaveLength(1);
    expect(found[0]?.target).toBe('.semgrep.yml');
    expect(found[0]?.via).toBe('manifest');
    expect(found[0]?.path).toBe(join(p, '.semgrep.yml'));
  });

  it('follows the manifest to a non-default filename', () => {
    // The manifest is the honest source precisely because the target is not
    // required to be `.semgrep.yml`.
    const p = project();
    mkdirSync(join(p, 'ci'), { recursive: true });
    writeFileSync(join(p, 'ci', 'rules.yml'), GOOD, 'utf8');
    withManifest(p, [entry({ target: 'ci/rules.yml' })]);
    expect(resolveProjectSemgrepConfigs(p).map((c) => c.target)).toEqual(['ci/rules.yml']);
  });

  it('ignores manifest entries that are not semgrep configs', () => {
    const p = project();
    writeFileSync(join(p, '.gitleaks.toml'), '# gl\n', 'utf8');
    withManifest(p, [entry({ target: '.gitleaks.toml', source: 'gitleaks/gitleaks.toml' })]);
    expect(resolveProjectSemgrepConfigs(p)).toEqual([]);
  });

  it('falls back to the conventional filenames when there is no manifest', () => {
    const p = project();
    writeFileSync(join(p, '.semgrep.yml'), GOOD, 'utf8');
    const found = resolveProjectSemgrepConfigs(p);
    expect(found.map((c) => c.target)).toEqual(['.semgrep.yml']);
    expect(found[0]?.via).toBe('convention');
  });

  it('recognises the .yaml spelling too', () => {
    const p = project();
    writeFileSync(join(p, '.semgrep.yaml'), GOOD, 'utf8');
    expect(resolveProjectSemgrepConfigs(p).map((c) => c.target)).toEqual(['.semgrep.yaml']);
  });

  it('does not list the same file twice when the manifest and the convention agree', () => {
    const p = project();
    writeFileSync(join(p, '.semgrep.yml'), GOOD, 'utf8');
    withManifest(p, [entry()]);
    expect(resolveProjectSemgrepConfigs(p)).toHaveLength(1);
  });

  it('returns nothing for a project that has no rules of its own', () => {
    expect(resolveProjectSemgrepConfigs(project())).toEqual([]);
  });

  it('drops a manifest target that is no longer on disk', () => {
    // Semgrep exits 7 and scans NOTHING when a --config path does not resolve.
    const p = project();
    withManifest(p, [entry()]);
    expect(resolveProjectSemgrepConfigs(p)).toEqual([]);
  });

  it('drops a config that would abort the scan, rather than passing it through', () => {
    const p = project();
    writeFileSync(join(p, '.semgrep.yml'), 'rules: [ this is : not: valid', 'utf8');
    expect(resolveProjectSemgrepConfigs(p)).toEqual([]);
  });
});

describe('isLoadableSemgrepConfig', () => {
  it('accepts a file with a non-empty rules array', () => {
    const p = project();
    const f = join(p, 'ok.yml');
    writeFileSync(f, GOOD, 'utf8');
    expect(isLoadableSemgrepConfig(f)).toBe(true);
  });

  it('rejects malformed YAML', () => {
    const p = project();
    const f = join(p, 'bad.yml');
    writeFileSync(f, 'rules: [ this is : not: valid', 'utf8');
    expect(isLoadableSemgrepConfig(f)).toBe(false);
  });

  it('rejects valid YAML with no rules key', () => {
    const p = project();
    const f = join(p, 'norules.yml');
    writeFileSync(f, 'hello: world\n', 'utf8');
    expect(isLoadableSemgrepConfig(f)).toBe(false);
  });

  it('rejects an empty rules array — Semgrep scans zero files with one', () => {
    const p = project();
    const f = join(p, 'empty.yml');
    writeFileSync(f, 'rules: []\n', 'utf8');
    expect(isLoadableSemgrepConfig(f)).toBe(false);
  });

  it('accepts a rule whose pattern cannot compile — that is a lost rule, not a lost scan', () => {
    // The wp-unescaped-output shape: `pattern: echo $_GET[$X]` is not valid
    // PHP. Semgrep still scans every file and reports the rule in `errors`.
    const p = project();
    const f = join(p, 'deadrule.yml');
    writeFileSync(
      f,
      'rules:\n  - id: dead\n    pattern: echo $_GET[$X]\n    message: m\n    languages: [php]\n    severity: ERROR\n',
      'utf8',
    );
    expect(isLoadableSemgrepConfig(f)).toBe(true);
  });

  it('returns false rather than throwing for a path that is not there', () => {
    expect(isLoadableSemgrepConfig(join(project(), 'nope.yml'))).toBe(false);
  });
});
