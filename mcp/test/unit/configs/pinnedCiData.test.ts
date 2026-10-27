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

import { readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { ACTIONLINT_VERSION, PINNED_RELEASES, PSALM_PHAR_SHA256, PSALM_VERSION, TRIVY_INSTALL_TAG } from '../../../src/runners/installCatalog.js';

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
    'setup_go',
    'attest_build_provenance',
    'upload_artifact',
    'download_artifact',
  ])('%s is pinned by a full 40-hex commit SHA, never a floating tag', (key) => {
    expect(pinned.actions[key]?.sha).toMatch(FULL_SHA);
    expect(pinned.actions[key]?.version).toMatch(/^v\d+\.\d+\.\d+$/);
  });

  // `ci-init --attest`'s three actions. The SHAs were resolved with
  // `gh api repos/<repo>/tags` and cross-checked with `git ls-remote`
  // (2026-09-28; upload/download-artifact's bumps on 2026-10-24, `git
  // ls-remote` and the GitHub API agreeing) — locked here so a careless edit, not a deliberate bump
  // that changes version and SHA together, fails the suite.
  it.each([
    ['attest_build_provenance', 'actions/attest-build-provenance', 'v4.2.2', '4d101475d8b20a2381f78447822ac1eab6504dd8'],
    ['upload_artifact', 'actions/upload-artifact', 'v7.0.2', 'cf430e030ddbb5b0abf93d22962f4752f3646cd9'],
    ['download_artifact', 'actions/download-artifact', 'v8.0.2', '9000827ccba6bdab643e8b6fd33ac0654aef8333'],
  ])('%s is %s %s at the commit that tag named when it was pinned', (key, repo, version, sha) => {
    expect(pinned.actions[key]).toMatchObject({ repo, version, sha });
  });
});

describe('configs/ci/pinned.json: scanners with a downloaded binary', () => {
  const pinned = readPinned();

  it.each(['trivy', 'gitleaks', 'actionlint', 'gosec', 'psalm'])('%s has a 64-hex sha256 and a linux amd64 URL', (key) => {
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
    expect(pinned.scanners['gosec']?.archive_member).toBe('gosec');
  });

  it("gosec is the release installCatalog.ts pins, at the same Linux amd64 archive and sum", () => {
    const r = PINNED_RELEASES.gosec;
    const a = r.assets['linux-amd64'];
    expect(pinned.scanners['gosec']).toMatchObject({
      version: r.version,
      linux_amd64_url: `${r.base}/${a.file}`,
      linux_amd64_sha256: a.sha256,
    });
  });

  it("psalm is the PHAR installCatalog.ts pins, at the same URL and sum (no archive: run by php)", () => {
    expect(pinned.scanners['psalm']).toMatchObject({
      version: PSALM_VERSION,
      linux_amd64_url: `https://github.com/vimeo/psalm/releases/download/${PSALM_VERSION}/psalm.phar`,
      linux_amd64_sha256: PSALM_PHAR_SHA256,
    });
    expect(pinned.scanners['psalm']?.archive_member).toBeUndefined();
  });

  it("actionlint is the tag installCatalog.ts's Linux go install names", () => {
    expect(pinned.scanners['actionlint']?.version).toBe(ACTIONLINT_VERSION);
    expect(pinned.scanners['actionlint']?.linux_amd64_url).toContain(`/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz`);
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

// 3.7.0: the templates install the three with every dependency from a hashed
// lock per Python (`pip install --require-hashes -r`), read from the clone the
// job verified against the release commit. `pipx install semgrep==X` pinned
// the three alone, and pipx upgraded its own pip from PyPI on first use. The
// locks are uv's output (`uv pip compile`, the command in each header); a bump
// of pinned.json that is not recompiled would install the old version.
const LOCK_DIR = resolve(REPO_ROOT, 'configs', 'ci', 'python');
/** The Pythons the templates run on: ubuntu-24.04, node:22-trixie, ubuntu-26.04. */
const LOCK_PYTHONS = ['3.12', '3.13', '3.14'];
const PIP_SCANNERS = ['bandit', 'semgrep', 'zizmor'];

interface LockedPackage {
  version: string;
  hashes: string[];
  /** Named by `-r configs/ci/python/requirements.in` in uv's `# via` annotation: a top-level requirement. */
  topLevel: boolean;
}

/** uv's `name==version \`, its `--hash=sha256:` lines and `# via` annotation, per package. */
function readLock(file: string): Map<string, LockedPackage> {
  const out = new Map<string, LockedPackage>();
  let current: LockedPackage | null = null;
  for (const line of readFileSync(resolve(LOCK_DIR, file), 'utf8').split('\n')) {
    const pin = /^([a-z0-9][a-z0-9._-]*)==(\S+)/.exec(line);
    if (pin?.[1] !== undefined && pin[2] !== undefined) {
      current = { version: pin[2], hashes: [], topLevel: false };
      out.set(pin[1], current);
      continue;
    }
    const hash = /^\s+--hash=sha256:(\S+?)\s*\\?$/.exec(line)?.[1];
    if (hash !== undefined) current?.hashes.push(hash);
    else if (current !== null && /^\s+#\s+(?:via\s+)?-r configs\/ci\/python\/requirements\.in$/.test(line)) current.topLevel = true;
  }
  return out;
}

describe('configs/ci/python: the hashed locks the templates install bandit, Semgrep and zizmor from', () => {
  const pinned = readPinned();

  it('there is one lock per Python a template runs on, and no other', () => {
    const locks = readdirSync(LOCK_DIR, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name).sort();
    expect(locks).toEqual([...LOCK_PYTHONS].sort());
    for (const py of LOCK_PYTHONS) expect(readdirSync(resolve(LOCK_DIR, py)), py).toEqual(['requirements.txt']);
  });

  it("requirements.in names the three at pinned.json's versions, and nothing else", () => {
    const lines = readFileSync(resolve(LOCK_DIR, 'requirements.in'), 'utf8')
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l !== '' && !l.startsWith('#'));
    expect(lines).toEqual(['bandit[toml]', 'semgrep', 'zizmor'].map((name) => `${name}==${pinned.scanners[name.replace(/\[.*$/, '')]?.version ?? '?'}`));
  });

  it.each(LOCK_PYTHONS)("%s/requirements.txt: its top-level requirements are the three, at pinned.json's versions", (py) => {
    const lock = readLock(`${py}/requirements.txt`);
    const topLevel = [...lock].filter(([, p]) => p.topLevel).map(([name, p]) => `${name}==${p.version}`);
    expect(topLevel.sort()).toEqual(PIP_SCANNERS.map((name) => `${name}==${pinned.scanners[name]?.version ?? '?'}`));
  });

  it.each(LOCK_PYTHONS)('%s/requirements.txt: every package pinned by == with at least one sha256, nothing else in it', (py) => {
    const text = readFileSync(resolve(LOCK_DIR, `${py}/requirements.txt`), 'utf8');
    const lock = readLock(`${py}/requirements.txt`);
    expect(lock.size).toBeGreaterThan(PIP_SCANNERS.length);
    for (const [name, p] of lock) {
      expect(p.version, name).toMatch(/^[0-9][0-9A-Za-z.+!]*$/);
      expect(p.hashes.length, name).toBeGreaterThan(0);
      for (const h of p.hashes) expect(h, name).toMatch(SHA256);
    }
    // No option line (an index URL, `--trusted-host`, an include) and no
    // reference by URL or path: pip would follow it.
    const other = text.split('\n').filter((l) => l.trim() !== '' && !/^\s*#/.test(l) && !/^[a-z0-9][a-z0-9._-]*==\S+ \\$/.test(l) && !/^\s+--hash=sha256:[0-9a-f]{64}( \\)?$/.test(l));
    expect(other).toEqual([]);
  });

  it.each(LOCK_PYTHONS)('%s/requirements.txt says how it was made: uv pip compile, for that Python, hashed, wheels only', (py) => {
    const header = readFileSync(resolve(LOCK_DIR, `${py}/requirements.txt`), 'utf8').split('\n').slice(0, 2).join('\n');
    expect(header).toContain('autogenerated by uv');
    expect(header).toContain(`uv pip compile configs/ci/python/requirements.in --python-version ${py} `);
    expect(header).toContain('--generate-hashes');
    expect(header).toContain('--only-binary :all:');
    expect(header).toContain(`-o configs/ci/python/${py}/requirements.txt`);
  });
});
