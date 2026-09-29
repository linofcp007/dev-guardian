/**
 * Content locks for `configs/ci/pinned.json` (Task 21 coordinator review,
 * "reuse" pass) — the one data file `dev-guardian ci-init` reads every
 * action SHA and scanner checksum/archive layout from.
 *
 * Two things this file exists to catch, that a template-rendering test
 * cannot:
 *   - `pinned.json`'s `scanners.trivy.version` and `installCatalog.ts`'s
 *     `TRIVY_INSTALL_TAG` name the SAME release by two independent strings
 *     in two different files; nothing stops them drifting apart the moment
 *     either one is bumped alone. Asserting they agree here is cheaper and
 *     more robust than making one runtime-read the other (a CLI script at
 *     the repo root reading into `mcp/src/`, or vice versa, would need the
 *     same bundled/unbundled path-depth trick `platform/version.ts` needs
 *     for the identical reason — not worth it for one string).
 *   - `archive_member` (trivy/gitleaks/actionlint) is data this task
 *     verified by hand against the real downloaded tarball (`tar -tzf`,
 *     2026-09-25 — see pinned.json's own `_readme`), not something this
 *     test can re-verify without a network call. Locking the CURRENT,
 *     hand-verified value here means a careless edit to it — not a real
 *     version bump, which by definition changes `linux_amd64_url` too and
 *     is exactly when `archive_member` is supposed to be re-checked — fails
 *     the suite instead of silently shipping a `tar -xzf` that extracts
 *     nothing at the path the template expects.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { TRIVY_INSTALL_TAG } from '../../../src/runners/installCatalog.js';

const here = fileURLToPath(new URL('.', import.meta.url));
/** configs -> unit -> test -> mcp -> repo root. */
const REPO_ROOT = resolve(here, '..', '..', '..', '..');

interface ActionEntry {
  repo: string;
  version: string;
  sha: string;
}
interface ScannerEntry {
  version: string;
  linux_amd64_url?: string;
  linux_amd64_sha256?: string;
  archive_member?: string;
}
interface Pinned {
  actions: Record<string, ActionEntry>;
  scanners: Record<string, ScannerEntry>;
}

function readPinned(): Pinned {
  const text = readFileSync(resolve(REPO_ROOT, 'configs', 'ci', 'pinned.json'), 'utf8');
  return JSON.parse(text) as Pinned;
}

const FULL_SHA = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;

describe('configs/ci/pinned.json: actions', () => {
  const pinned = readPinned();

  it.each([
    'checkout',
    'setup_node',
    'upload_sarif',
    'setup_dotnet',
    'attest_build_provenance',
    'upload_artifact',
    'download_artifact',
  ])('%s is pinned by a full 40-hex commit SHA, never a floating tag', (key) => {
    expect(pinned.actions[key]?.sha).toMatch(FULL_SHA);
    expect(pinned.actions[key]?.version).toMatch(/^v\d+\.\d+\.\d+$/);
  });

  // `ci-init --attest`'s three actions. The SHAs were resolved with
  // `gh api repos/<repo>/tags` and cross-checked with `git ls-remote`
  // (2026-09-28) — locked here so a careless edit, not a deliberate bump
  // that changes version and SHA together, fails the suite.
  it.each([
    ['attest_build_provenance', 'actions/attest-build-provenance', 'v4.2.2', '4d101475d8b20a2381f78447822ac1eab6504dd8'],
    ['upload_artifact', 'actions/upload-artifact', 'v7.0.1', '043fb46d1a93c77aae656e7c1c64a875d1fc6a0a'],
    ['download_artifact', 'actions/download-artifact', 'v8.0.1', '3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c'],
  ])('%s is %s %s at the commit that tag named when it was pinned', (key, repo, version, sha) => {
    expect(pinned.actions[key]).toMatchObject({ repo, version, sha });
  });
});

describe('configs/ci/pinned.json: scanners with a downloaded binary', () => {
  const pinned = readPinned();

  it.each(['trivy', 'gitleaks', 'actionlint'])('%s has a 64-hex sha256 and a linux amd64 URL', (key) => {
    expect(pinned.scanners[key]?.linux_amd64_sha256).toMatch(SHA256);
    expect(pinned.scanners[key]?.linux_amd64_url).toMatch(/^https:\/\//);
  });

  // Hand-verified against the real downloaded tarball via `tar -tzf`
  // (2026-09-25) — see the module doc comment for why this is a locked
  // value, not a live check.
  it('archive_member matches what tar -tzf actually found at the archive root', () => {
    expect(pinned.scanners['trivy']?.archive_member).toBe('trivy');
    expect(pinned.scanners['gitleaks']?.archive_member).toBe('gitleaks');
    expect(pinned.scanners['actionlint']?.archive_member).toBe('actionlint');
  });

  it("trivy's version matches installCatalog.ts's TRIVY_INSTALL_TAG (single source of truth, enforced)", () => {
    expect(`v${pinned.scanners['trivy']?.version}`).toBe(TRIVY_INSTALL_TAG);
  });
});

describe('configs/ci/pinned.json: pip-distributed scanners', () => {
  const pinned = readPinned();

  it.each(['bandit', 'semgrep', 'zizmor'])('%s is pinned by exact version, no downloaded binary', (key) => {
    expect(pinned.scanners[key]?.version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(pinned.scanners[key]?.linux_amd64_url).toBeUndefined();
    expect(pinned.scanners[key]?.linux_amd64_sha256).toBeUndefined();
  });
});
