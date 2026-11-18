/**
 * The selftest's registry of controls, held to the rule packs and to the
 * shipped canaries (`src/selftest/controls.ts`, `configs/selftest/`).
 *
 * A pack added to `configs/semgrep/` without a canary would be a control the
 * selftest silently does not have: the suite names it instead. And the
 * selftest stays a leaf — nothing in the scan pipeline may come to depend on
 * what it saved.
 */

import { cpSync, existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { ruleIdsInFile } from '../../../src/runners/semgrepRuleIds.js';
import { CANARY_MARKER, CANARY_SUFFIX } from '../../../src/selftest/canaries.js';
import { CORE_CONTROLS, controlsProblems, type Control } from '../../../src/selftest/controls.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const REPO_ROOT = fileURLToPath(new URL('../../../..', import.meta.url));
const PACKS_DIR = join(REPO_ROOT, 'configs', 'semgrep');
const CANARIES_DIR = join(REPO_ROOT, 'configs', 'selftest');
const SRC = join(REPO_ROOT, 'mcp', 'src');
const PACKS = readdirSync(PACKS_DIR).filter((name) => name.endsWith('.yml')).sort();

/** Every `.ts` file below `dir`, relative to `src/`, with forward slashes. */
function sources(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...sources(path));
    else if (entry.name.endsWith('.ts')) out.push(relative(SRC, path).split(sep).join('/'));
  }
  return out;
}

/**
 * The module specifiers a source file imports: `import … from '…'` and
 * `export … from '…'` statements (which may span lines), a bare `import '…'`,
 * and `import('…')` anywhere. Statements only — a sentence that says "from"
 * before a quoted word is not an import.
 */
function importsOf(file: string): string[] {
  const text = readFileSync(file, 'utf8');
  const specs: string[] = [];
  for (const m of text.matchAll(/^(?:import|export)\b[^;'"]*?\bfrom\s+['"]([^'"]+)['"]/gm)) specs.push(m[1] ?? '');
  for (const m of text.matchAll(/^import\s+['"]([^'"]+)['"]/gm)) specs.push(m[1] ?? '');
  for (const m of text.matchAll(/\bimport\(\s*['"]([^'"]+)['"]\s*\)/g)) specs.push(m[1] ?? '');
  return specs;
}

describe('the core controls', () => {
  it('T-02 one control per rule pack, plus gitleaks, the two Trivy scans and the five hook checks, each id once', () => {
    expect(PACKS.length).toBeGreaterThanOrEqual(15);
    const packControls = CORE_CONTROLS.filter((c) => c.kind === 'semgrep-pack');
    expect(packControls.map((c) => c.pack).sort()).toEqual(PACKS);
    expect(packControls.map((c) => c.id).sort()).toEqual(PACKS.map((p) => `semgrep:${p.replace(/\.yml$/, '')}`).sort());
    for (const c of packControls) expect(c.scanner, c.id).toBe('semgrep');

    const others = CORE_CONTROLS.filter((c) => c.kind !== 'semgrep-pack');
    expect(others.map((c) => [c.id, c.kind, c.scanner])).toEqual([
      ['gitleaks', 'gitleaks', 'gitleaks'],
      ['trivy:deps', 'trivy-deps', 'trivy'],
      ['trivy:iac', 'trivy-iac', 'trivy'],
      ['hooks:bash-block', 'hook', 'hooks'],
      ['hooks:powershell-block', 'hook', 'hooks'],
      ['hooks:settings-guard', 'hook', 'hooks'],
      ['hooks:secret-warning', 'hook', 'hooks'],
      ['hooks:install-vet', 'hook', 'hooks'],
    ]);
    expect(new Set(CORE_CONTROLS.map((c) => c.id)).size).toBe(CORE_CONTROLS.length);
    expect(CORE_CONTROLS).toHaveLength(PACKS.length + 8);
    for (const c of CORE_CONTROLS) expect(c.timeoutMs, c.id).toBeGreaterThan(0);
  });

  it('T-15 every pack has a control, a shipped canary that carries the marker, and a pinned rule the pack holds', () => {
    expect(controlsProblems({ packsDir: PACKS_DIR, canariesDir: CANARIES_DIR })).toEqual([]);
    const packControls = CORE_CONTROLS.filter((c) => c.kind === 'semgrep-pack');
    expect(packControls).toHaveLength(PACKS.length);
    for (const c of packControls) {
      const shipped = join(CANARIES_DIR, 'project', ...`${c.canary ?? ''}${CANARY_SUFFIX}`.split('/'));
      expect(existsSync(shipped), `${c.id}: ${shipped}`).toBe(true);
      expect(readFileSync(shipped, 'utf8'), `${c.id}: the probe rule finds a canary by its marker`).toContain(CANARY_MARKER);
      expect(ruleIdsInFile(join(PACKS_DIR, c.pack ?? '')), c.id).toContain(c.expect);
    }
  });

  it('T-15 a pack with no control, a rule the pack does not hold and a canary that is not shipped are each named', () => {
    const packs = makeTempDir('selftest-packs-');
    cpSync(PACKS_DIR, packs, { recursive: true });
    writeFileSync(
      join(packs, 'zz-extra.yml'),
      'rules:\n  - id: zz-extra-rule\n    languages: [python]\n    severity: WARNING\n    message: extra\n    pattern: zz_extra()\n',
    );
    const extra = controlsProblems({ packsDir: packs, canariesDir: CANARIES_DIR });
    expect(extra).toHaveLength(1);
    expect(extra[0]).toContain('zz-extra.yml');

    const first = CORE_CONTROLS.find((c) => c.kind === 'semgrep-pack');
    expect(first).toBeDefined();
    const renamed: Control[] = CORE_CONTROLS.map((c) => (c === first ? { ...c, expect: 'a-rule-this-pack-does-not-hold' } : c));
    const wrongRule = controlsProblems({ packsDir: PACKS_DIR, canariesDir: CANARIES_DIR, controls: renamed });
    expect(wrongRule).toHaveLength(1);
    expect(wrongRule[0]).toContain('a-rule-this-pack-does-not-hold');
    expect(wrongRule[0]).toContain(first?.pack ?? 'no pack');

    const noCanaries = controlsProblems({ packsDir: PACKS_DIR, canariesDir: makeTempDir('selftest-empty-') });
    for (const c of CORE_CONTROLS.filter((x) => x.canary !== null)) {
      expect(noCanaries.some((p) => p.includes(c.id) && p.includes(c.canary ?? '')), c.id).toBe(true);
    }

    const twice = controlsProblems({ packsDir: PACKS_DIR, canariesDir: CANARIES_DIR, controls: [...CORE_CONTROLS, ...CORE_CONTROLS.slice(-1)] });
    expect(twice.some((p) => p.includes('hooks:install-vet'))).toBe(true);
  });
});

describe('where the selftest sits', () => {
  it('T-41 nothing in the scan pipeline imports selftest/, and the server reads only what it saved', () => {
    const all = sources(SRC);
    const importers = all.filter((file) => !file.startsWith('selftest/') && importsOf(join(SRC, file)).some((spec) => /(^|\/)selftest\//.test(spec)));
    // The two tools that SHOW the last result, and the CLI's loader. Nothing under runners/, ci/, history/ or the scan tools.
    expect(importers.sort()).toEqual(['cli.ts', 'tools/checkToolchain.ts', 'tools/healthStatus.ts']);
    for (const tool of ['tools/checkToolchain.ts', 'tools/healthStatus.ts']) {
      const specs = importsOf(join(SRC, tool)).filter((spec) => /(^|\/)selftest\//.test(spec));
      // The read side and the paths: never the orchestrator, never a runner.
      for (const spec of specs) expect(spec, tool).toMatch(/selftest\/(store|paths)\.js$/);
    }
  });

  it('T-41 the CLI reaches the selftest through the engine: it imports Node built-ins and mcp/dist/engine.js, nothing else', () => {
    const cli = join(REPO_ROOT, 'cli', 'dev-guardian.mjs');
    const specs = importsOf(cli);
    expect(specs.length).toBeGreaterThan(5);
    for (const spec of specs) expect(spec === '../mcp/dist/engine.js' || spec.startsWith('node:'), spec).toBe(true);
    expect(readFileSync(cli, 'utf8')).toMatch(/'loadSelftestModules'/);
    expect(readFileSync(join(SRC, 'cli.ts'), 'utf8')).toMatch(/export async function loadSelftestModules\(/);
  });
});
