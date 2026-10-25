#!/usr/bin/env node
/**
 * `npm run pins` — every version dev-guardian pins, against the latest
 * release upstream. A maintainer's check, never a test (it needs the
 * network): the pins are bumped by hand, with their sums, on purpose — after
 * the March 2026 Trivy compromise the pins exist so that "latest" never
 * reaches a user unreviewed (`src/runners/installCatalog.ts`).
 *
 * Read: `configs/ci/pinned.json` (the CI templates' actions and scanners),
 * `PINNED_RELEASES`, `COSIGN_VERSION`, `PSALM_VERSION`, `WP_CLI_VERSION`,
 * `ACTIONLINT_VERSION` and the versions `installCatalog.ts` keeps unexported
 * (cppcheck, govulncheck, detekt, SpotBugs, FindSecBugs, RuboCop). Asked:
 * GitHub's newest release tagged with a version (never a pre-release), PyPI, RubyGems, the Go module proxy. For a binary with a newer release, the sha256 GitHub records
 * for each asset of that release is printed under its pinned file name — a
 * starting point, never the check itself: hash the download independently and
 * match the release's own checksums (and its signature, when it has one), as
 * the comments beside each pin record.
 *
 * Exit 0: every pin is the latest; 1: one or more is behind; 2: a lookup
 * failed (the table says which). `GITHUB_TOKEN` / `GH_TOKEN`, when set, lifts
 * GitHub's limit of 60 unauthenticated calls an hour.
 *
 * Run under tsx (`tsx scripts/checkPins.mjs`): it imports `src/` directly.
 */

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ACTIONLINT_VERSION, COSIGN_VERSION, PINNED_RELEASES, PSALM_VERSION, WP_CLI_VERSION } from '../src/runners/installCatalog.js';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..', '..');
const catalogSource = readFileSync(resolve(here, '..', 'src', 'runners', 'installCatalog.ts'), 'utf8');
/** @type {{ actions: Record<string, { repo?: string; version?: string }>; scanners: Record<string, { version?: string }> }} */
const pinned = JSON.parse(readFileSync(resolve(repo, 'configs', 'ci', 'pinned.json'), 'utf8'));

/** @param {RegExp} re */
function fromCatalog(re) {
  const m = re.exec(catalogSource);
  if (m?.[1] === undefined) throw new Error(`installCatalog.ts no longer matches ${re}`);
  return m[1];
}

const token = process.env['GITHUB_TOKEN'] || process.env['GH_TOKEN'] || '';

/**
 * @param {string} url
 * @returns {Promise<unknown>}
 */
async function getJson(url) {
  /** @type {Record<string, string>} */
  const headers = { accept: 'application/json', 'user-agent': 'dev-guardian-check-pins' };
  if (token !== '' && url.startsWith('https://api.github.com/')) headers['authorization'] = `Bearer ${token}`;
  const res = await fetch(url, { headers, signal: AbortSignal.timeout(20_000) });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}

/** @param {unknown} o @param {string} key */
const field = (o, key) => (o !== null && typeof o === 'object' ? /** @type {Record<string, unknown>} */ (o)[key] : undefined);

/** `v1.2.3`, `version-1.2.3`, `1.2.3` → `1.2.3`. @param {string} tag */
const bare = (tag) => tag.replace(/^(?:version-|v)/, '');

/**
 * The newest release of `ownerRepo` whose tag is a plain version (`v1.2.3`,
 * `1.2.3`, `version-1.2.3`), never a pre-release — not `/releases/latest`:
 * github/codeql-action marks its CodeQL bundles (`codeql-bundle-v2.27.3`) the
 * latest release. With the sha256 GitHub records for each of its assets.
 *
 * @param {string} ownerRepo
 */
async function latestRelease(ownerRepo) {
  const list = await getJson(`https://api.github.com/repos/${ownerRepo}/releases?per_page=100`);
  if (!Array.isArray(list)) throw new Error(`${ownerRepo}: no release list`);
  /** @type {{ version: string; assets: unknown } | null} */
  let best = null;
  for (const r of list) {
    const tag = field(r, 'tag_name');
    if (typeof tag !== 'string' || field(r, 'prerelease') === true || field(r, 'draft') === true) continue;
    if (!/^(?:v|version-)?\d+\.\d+(?:\.\d+)?$/.test(tag)) continue;
    if (best === null || compareVersions(bare(tag), best.version) > 0) best = { version: bare(tag), assets: field(r, 'assets') };
  }
  if (best === null) throw new Error(`${ownerRepo}: no release tagged with a version`);
  /** @type {Map<string, string>} */
  const digests = new Map();
  if (Array.isArray(best.assets)) {
    for (const a of best.assets) {
      const name = field(a, 'name');
      const digest = field(a, 'digest');
      if (typeof name === 'string' && typeof digest === 'string') digests.set(name, digest.replace(/^sha256:/, ''));
    }
  }
  return { version: best.version, digests };
}

/** @param {string} name */
async function latestPypi(name) {
  const v = field(field(await getJson(`https://pypi.org/pypi/${name}/json`), 'info'), 'version');
  if (typeof v !== 'string') throw new Error(`${name}: no version on PyPI`);
  return v;
}

/** @param {string} name */
async function latestGem(name) {
  const v = field(await getJson(`https://rubygems.org/api/v1/versions/${name}/latest.json`), 'version');
  if (typeof v !== 'string') throw new Error(`${name}: no version on RubyGems`);
  return v;
}

/** @param {string} module */
async function latestGoModule(module) {
  const v = field(await getJson(`https://proxy.golang.org/${module}/@latest`), 'Version');
  if (typeof v !== 'string') throw new Error(`${module}: no version on the module proxy`);
  return bare(v);
}

/**
 * @typedef {{ name: string; pinned: string; latest: () => Promise<{ version: string; digests?: Map<string, string>; note?: string }>; files?: string[] }} Pin
 */

/** @type {Pin[]} */
const pins = [];
/** @param {string} ownerRepo */
const fromGithub = (ownerRepo) => () => latestRelease(ownerRepo);

const RELEASE_REPOS = { syft: 'anchore/syft', trivy: 'aquasecurity/trivy', gitleaks: 'gitleaks/gitleaks', gosec: 'securego/gosec', shellcheck: 'koalaman/shellcheck' };
for (const [name, release] of Object.entries(PINNED_RELEASES)) {
  const ownerRepo = RELEASE_REPOS[/** @type {keyof typeof RELEASE_REPOS} */ (name)];
  pins.push({ name: `${name} (install_toolchain)`, pinned: release.version, latest: fromGithub(ownerRepo), files: Object.values(release.assets).map((a) => a.file) });
}
pins.push({ name: 'cosign (install_toolchain)', pinned: COSIGN_VERSION, latest: fromGithub('sigstore/cosign') });
pins.push({ name: 'psalm (install_toolchain)', pinned: PSALM_VERSION, latest: fromGithub('vimeo/psalm'), files: ['psalm.phar'] });
pins.push({ name: 'wp-cli (install_toolchain)', pinned: WP_CLI_VERSION, latest: fromGithub('wp-cli/wp-cli'), files: [`wp-cli-${WP_CLI_VERSION}.phar`] });
pins.push({ name: 'actionlint (go install)', pinned: ACTIONLINT_VERSION, latest: fromGithub('rhysd/actionlint') });
pins.push({ name: 'cppcheck (scoop, winget)', pinned: fromCatalog(/const CPPCHECK_VERSION = '([^']+)'/), latest: fromGithub('danmar/cppcheck') });
pins.push({ name: 'detekt (install_toolchain)', pinned: fromCatalog(/const DETEKT_VERSION = '([^']+)'/), latest: fromGithub('detekt/detekt') });
pins.push({ name: 'spotbugs (install_toolchain)', pinned: fromCatalog(/const SPOTBUGS_VERSION = '([^']+)'/), latest: fromGithub('spotbugs/spotbugs') });
pins.push({ name: 'findsecbugs (install_toolchain)', pinned: fromCatalog(/const FINDSECBUGS_VERSION = '([^']+)'/), latest: fromGithub('find-sec-bugs/find-sec-bugs') });
pins.push({
  name: 'rubocop (install_toolchain, gem)',
  pinned: fromCatalog(/const RUBOCOP_VERSION = '([^']+)'/),
  latest: async () => ({ version: await latestGem('rubocop') }),
});
pins.push({
  name: 'govulncheck (go install)',
  pinned: bare(fromCatalog(/golang\.org\/x\/vuln\/cmd\/govulncheck@(v[^']+)'/)),
  latest: async () => ({ version: await latestGoModule('golang.org/x/vuln') }),
});

const CI_REPOS = { trivy: 'aquasecurity/trivy', gitleaks: 'gitleaks/gitleaks', actionlint: 'rhysd/actionlint', gosec: 'securego/gosec', psalm: 'vimeo/psalm' };
/** pipx installs from PyPI; the pin is the newest version with a release tag upstream too (pinned.json's semgrep note). */
const PYPI = { bandit: 'PyCQA/bandit', semgrep: 'semgrep/semgrep', zizmor: 'zizmorcore/zizmor' };
for (const [name, entry] of Object.entries(pinned.scanners)) {
  if (name.startsWith('_') || typeof entry.version !== 'string') continue;
  const version = entry.version;
  const tagged = PYPI[/** @type {keyof typeof PYPI} */ (name)];
  if (tagged !== undefined) {
    pins.push({
      name: `${name} (CI, pipx)`,
      pinned: version,
      latest: async () => {
        const [onPypi, release] = await Promise.all([latestPypi(name), latestRelease(tagged)]);
        return compareVersions(onPypi, release.version) > 0
          ? { version: release.version, note: `PyPI has ${onPypi}, with no release tag in ${tagged}` }
          : { version: onPypi };
      },
    });
    continue;
  }
  const ownerRepo = CI_REPOS[/** @type {keyof typeof CI_REPOS} */ (name)];
  if (ownerRepo === undefined) throw new Error(`configs/ci/pinned.json: no upstream known for the scanner ${name} — add it to CI_REPOS`);
  const url = /** @type {{ linux_amd64_url?: string }} */ (entry).linux_amd64_url;
  pins.push({ name: `${name} (CI)`, pinned: bare(version), latest: fromGithub(ownerRepo), ...(url !== undefined ? { files: [url.split('/').pop() ?? ''] } : {}) });
}
for (const [key, action] of Object.entries(pinned.actions)) {
  if (key.startsWith('_') || typeof action.repo !== 'string' || typeof action.version !== 'string') continue;
  pins.push({ name: `${action.repo} (CI action)`, pinned: bare(action.version), latest: fromGithub(action.repo) });
}

/** -1, 0, 1 — numeric parts compared as numbers. @param {string} a @param {string} b */
function compareVersions(a, b) {
  const pa = a.split(/[.-]/);
  const pb = b.split(/[.-]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    const x = pa[i] ?? '0';
    const y = pb[i] ?? '0';
    const nx = Number(x);
    const ny = Number(y);
    const c = Number.isNaN(nx) || Number.isNaN(ny) ? x.localeCompare(y) : nx - ny;
    if (c !== 0) return c < 0 ? -1 : 1;
  }
  return 0;
}

let behind = 0;
let failed = 0;
/** @type {string[]} */
const sums = [];
const results = await Promise.all(
  pins.map(async (pin) => {
    try {
      return { pin, latest: await pin.latest() };
    } catch (e) {
      return { pin, error: e instanceof Error ? e.message : String(e) };
    }
  }),
);
const width = Math.max(...pins.map((p) => p.name.length));
for (const r of results) {
  const label = r.pin.name.padEnd(width);
  if ('error' in r) {
    failed += 1;
    console.log(`${label}  ${r.pin.pinned.padEnd(10)}  ?           lookup failed: ${r.error}`);
    continue;
  }
  const order = compareVersions(r.pin.pinned, r.latest.version);
  const status = order === 0 ? 'current' : order < 0 ? 'BEHIND' : 'ahead of upstream (check the tag)';
  if (order < 0) behind += 1;
  console.log(`${label}  ${r.pin.pinned.padEnd(10)}  ${r.latest.version.padEnd(10)}  ${status}${r.latest.note !== undefined ? ` — ${r.latest.note}` : ''}`);
  if (order < 0 && r.pin.files !== undefined && r.latest.digests !== undefined) {
    for (const file of r.pin.files) {
      const next = file.split(r.pin.pinned).join(r.latest.version);
      const digest = r.latest.digests.get(next);
      sums.push(`  ${r.pin.name}: ${next}  ${digest ?? '(no digest recorded by GitHub)'}`);
    }
  }
}
if (sums.length > 0) {
  console.log('\nThe sha256 GitHub records for the newer assets — a starting point; hash each download yourself:');
  for (const line of sums) console.log(line);
}
console.log(`\n${pins.length} pins: ${behind} behind, ${failed} not looked up`);
process.exitCode = failed > 0 ? 2 : behind > 0 ? 1 : 0;
