/**
 * Content locks for the shared configs `init_project` ships (task 15, brief
 * item 5): stale pre-commit pins, the bandit `-c pyproject.toml` hard
 * failure, the deprecated Renovate `matchPackagePatterns` field, and the
 * gitleaks allowlist that used to drop `docs/`, `examples/` and `tests/`
 * entirely (never just `fixtures/`).
 *
 * These are plain text/parse assertions over the files under `configs/` —
 * no MCP tooling involved. The gitleaks allowlist narrowing was ALSO
 * validated empirically (a real `gitleaks detect` run against a fixture with
 * a key-shaped string in both `docs/` and `fixtures/`: the standard config
 * reports only `docs/`, the paranoid one reports both) — see the task
 * report for that run's output; that behavioural evidence does not fit a
 * vitest assertion, so it lives in the report instead of here.
 */

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { describe, expect, it } from 'vitest';

const here = dirname(fileURLToPath(import.meta.url));
/** configs -> unit -> test -> mcp -> repo root. */
const REPO_ROOT = resolve(here, '..', '..', '..', '..');

function readConfig(rel: string): string {
  return readFileSync(resolve(REPO_ROOT, rel), 'utf8');
}

describe('configs/pre-commit/pre-commit-config.yaml', () => {
  const text = readConfig('configs/pre-commit/pre-commit-config.yaml');
  const doc = parseYaml(text) as { repos: Array<{ repo: string; rev?: string; hooks: Array<Record<string, unknown>> }> };

  function repoByUrl(url: string) {
    const r = doc.repos.find((r) => r.repo === url);
    if (!r) throw new Error(`no repo entry for ${url} — repos: ${doc.repos.map((x) => x.repo).join(', ')}`);
    return r;
  }

  it('pins gitleaks to a current release, not v8.18.4', () => {
    expect(repoByUrl('https://github.com/gitleaks/gitleaks').rev).toBe('v8.30.1');
  });

  it('uses the semgrep/semgrep repo (returntocorp/semgrep is a stale org name), current release', () => {
    expect(doc.repos.some((r) => r.repo === 'https://github.com/returntocorp/semgrep')).toBe(false);
    expect(repoByUrl('https://github.com/semgrep/semgrep').rev).toBe('v1.178.0');
  });

  it('pins ruff-pre-commit to a current release, not v0.5.0', () => {
    expect(repoByUrl('https://github.com/astral-sh/ruff-pre-commit').rev).toBe('v0.16.9');
  });

  it('pins hadolint to a current release, not the v2.13.0-beta', () => {
    expect(repoByUrl('https://github.com/hadolint/hadolint').rev).toBe('v2.15.1');
  });

  it('runs bandit without a hard-coded -c pyproject.toml (bandit exits 2 when that file is absent)', () => {
    expect(doc.repos.some((r) => r.repo === 'https://github.com/PyCQA/bandit')).toBe(false);
    const local = doc.repos.filter((r) => r.repo === 'local');
    const banditHook = local.flatMap((r) => r.hooks).find((h) => h['id'] === 'bandit');
    expect(banditHook).toBeDefined();
    const entry = String(banditHook?.['entry'] ?? '');
    expect(entry).toContain('if [ -f pyproject.toml ]');
    expect(entry).toContain('-c pyproject.toml');
    // The unconditional invocation (the else branch) must never carry -c.
    const elseBranch = entry.split('else')[1] ?? '';
    expect(elseBranch).not.toContain('-c pyproject.toml');
  });
});

describe('configs/gitleaks/gitleaks.toml', () => {
  const text = readConfig('configs/gitleaks/gitleaks.toml');
  // The `paths` array itself, not the file's explanatory comment (which
  // deliberately quotes the old, too-broad pattern for context).
  const pathsBlock = /paths = \[([\s\S]*?)\]/.exec(text)?.[1] ?? '';

  it('no longer excludes whole docs/examples/tests trees from every rule', () => {
    expect(pathsBlock).not.toMatch(/docs\?/);
    expect(pathsBlock).not.toMatch(/examples\?/);
    expect(pathsBlock).not.toMatch(/\btest\|tests\b/);
  });

  it('still excludes fixtures (deliberately fake data)', () => {
    expect(pathsBlock).toMatch(/fixtures\?/);
  });
});

describe('configs/gitleaks/gitleaks-paranoid.toml', () => {
  const text = readConfig('configs/gitleaks/gitleaks-paranoid.toml');

  it('suppresses nothing by content: no fixtures path, no placeholder regexes, no stopwords', () => {
    expect(text).not.toMatch(/fixtures\?/);
    expect(text).toMatch(/regexes = \[\]/);
    expect(text).toMatch(/stopwords = \[\]/);
  });

  it('still excludes generated/vendored trees (noise, not secret-hiding)', () => {
    expect(text).toContain('node_modules/');
    expect(text).toContain('vendor/');
  });
});

describe('configs/renovate/renovate.json', () => {
  const doc = JSON.parse(readConfig('configs/renovate/renovate.json')) as {
    packageRules: Array<Record<string, unknown>>;
  };

  it('has no matchPackagePatterns left (removed from Renovate; matchPackageNames replaces it)', () => {
    const text = JSON.stringify(doc);
    expect(text).not.toContain('matchPackagePatterns');
  });

  it('every automerge:true rule has a minimumReleaseAge of at least 3 days', () => {
    const automergeRules = doc.packageRules.filter((r) => r['automerge'] === true);
    expect(automergeRules.length).toBeGreaterThan(0);
    for (const rule of automergeRules) {
      expect(rule['minimumReleaseAge']).toBe('3 days');
    }
  });
});

describe('configs/renovate/renovate-paranoid.json', () => {
  const doc = JSON.parse(readConfig('configs/renovate/renovate-paranoid.json')) as {
    packageRules: Array<Record<string, unknown>>;
  };

  it('never automerges anything', () => {
    expect(doc.packageRules.some((r) => r['automerge'] === true)).toBe(false);
  });
});
