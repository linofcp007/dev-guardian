/**
 * The Wordfence Intelligence v3 vulnerability feed: fetch, disk cache, and
 * matching against a {@link WpSourceInventory}.
 *
 * ---- The endpoint, verified live 2026-09-25 ---------------------------
 *
 * `GET https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production`,
 * `Authorization: Bearer <token>`. v1/v2 were anonymous and free; both now
 * return HTTP 410 Gone. v3 requires a token for every caller — there is no
 * keyless fallback the way WPScan's public DB has one. A free token is
 * requested at https://www.wordfence.com/products/wordfence-intelligence/.
 * Free AND commercial use are both permitted (Wordfence's own 2022
 * announcement, "Wordfence Launches Free Vulnerability Database For
 * Commercial Use"); a consumer must surface the MITRE copyright notice
 * `copyrights.message` carries for any CVE record it displays.
 *
 * Confirmed against `wordfence/wordfence-cli` (GPLv3, the reference
 * implementation)'s own `wordfence/api/intelligence.py`: base URL, the
 * `/vulnerabilities/{production,scanner}` paths, and the exact response
 * schema below (its `get_production_vulnerability_feed_validator()`). That
 * client sends `Bearer cli-<key>` — the `cli-` prefix is that PRODUCT's own
 * namespacing of its (now-discontinued; WF-CLI stopped issuing new licenses,
 * EOL 2026-10-14) free CLI license, not part of the token format itself: the
 * independent third-party client `pepperonas/wp-shield` sends a Wordfence
 * Intelligence token as plain `Bearer <token>`, which is what this module
 * does. If Wordfence's backend turns out to gate on a product-specific
 * prefix after all, this is a one-line change.
 *
 * The production feed is large — over 100 MB of JSON as of October 2025 — so
 * it is cached whole on disk in the OS user-cache directory (never in
 * SQLite: Task 19's CISA KEV cache uses `runtime_meta` for exactly this
 * reason, but that catalog is a few hundred KB; this one is three orders of
 * magnitude bigger), refreshed at most once per {@link WORDFENCE_FEED_TTL_MS}
 * REGARDLESS of how many callers or projects ask — the same "one shared
 * clock, not one per caller" fix `intel/kevCache.ts` made for the KEV
 * catalog, and for the same reason: without it, a CI pipeline calling this
 * tool once per commit re-downloads a 100+ MB feed on every commit.
 *
 * Response shape (root: an object keyed by vulnerability UUID — order is not
 * meaningful, so it is read as a plain object and iterated by `Object.values`):
 *   `{ [uuid]: { id, title, description, software: [{ type: 'core'|'plugin'
 *   |'theme', name, slug, affected_versions: { [id]: { from_version,
 *   from_inclusive, to_version, to_inclusive } }, patched, patched_versions,
 *   remediation }], cve, cve_link, cvss: { vector, score, rating } | null,
 *   cwe: {...} | null, informational?, published, updated, references[],
 *   copyrights } }`.
 * Core's software slug is `'wordpress'` (confirmed:
 * `wordfence/intel/vulnerabilities.py`'s `SLUG_WORDPRESS = 'wordpress'`).
 * `from_version` / `to_version` may be `'*'` (unbounded on that side).
 */

import { mkdirSync, renameSync, writeFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { makeFinding, type ParserCveInput } from '../runners/scannerParsers/index.js';
import type { Finding, Severity } from '../types.js';
import type { WpComponentInventory, WpSourceInventory } from './sourceInventory.js';

/** Written to `findings.tool` for every match this module produces. */
export const WORDFENCE_TOOL_NAME = 'wordfence';

const WORDFENCE_BASE_URL = 'https://www.wordfence.com/api/intelligence/v3';
const WORDFENCE_PRODUCTION_PATH = '/vulnerabilities/production';

/** The feed is refreshed at most this often, in aggregate across every
 *  caller — see the module header. */
export const WORDFENCE_FEED_TTL_MS = 24 * 60 * 60 * 1000;

/** The feed is tens of MB over the wire; a default long enough for a slow
 *  connection to finish, short enough not to hang a tool call forever. */
const DEFAULT_FEED_TIMEOUT_MS = 60_000;

const VERSION_ANY = '*';

// ---------------------------------------------------------------------- version comparison

/** One entry of a `software[].affected_versions` map. */
export interface WordfenceVersionRange {
  from_version: string;
  from_inclusive: boolean;
  to_version: string;
  to_inclusive: boolean;
}

/**
 * PHP's `version_compare()` ordering, ported from
 * `wordfence/util/versioning.py#compare_php_versions` (the reference
 * implementation's own algorithm — not a semver library, because WordPress
 * plugin versions routinely are not semver: `1.2`, `1.2.3.4`, `2.0-RC1`).
 *
 * A version splits into components at `.`, `_`, `-`, `+`, and at every
 * digit/non-digit boundary (`"1.0beta1"` → `["1","0","beta","1"]`). Each
 * component ranks by tier, not raw text: unrecognized-string(1) <
 * dev(2) < alpha/a(3) < beta/b(4) < RC/rc(5) < a plain number(6) < pl/p(7).
 * Two components of the same non-numeric tier compare equal (`alpha` ==
 * `a`, `beta1` == `b1`) — a documented PHP quirk this reproduces
 * deliberately, not a shortcut. A missing trailing component compares as
 * numeric `0`, so `"1.2"` == `"1.2.0"`. Matching is case-insensitive on the
 * alpha tokens (`dev`/`DEV`, `rc`/`RC`) — the Python original hardcodes both
 * cases only for `RC`; case-insensitive on all of them is the more robust
 * reading of "handle sanely" for real-world plugin version strings, which
 * mix case freely.
 */
export function comparePhpVersions(a: string, b: string): number {
  const ca = splitVersion(a);
  const cb = splitVersion(b);
  const n = Math.max(ca.length, cb.length);
  for (let i = 0; i < n; i++) {
    const x = ca[i] ?? DEFAULT_COMPONENT;
    const y = cb[i] ?? DEFAULT_COMPONENT;
    const c = compareComponents(x, y);
    if (c !== 0) return c;
  }
  return 0;
}

const TIER_UNRECOGNIZED = 1;
const TIER_NUMBER = 6;
const LOWER_TIERS: Readonly<Record<string, number>> = { dev: 2, alpha: 3, a: 3, beta: 4, b: 4, rc: 5 };
const HIGHER_TIERS: Readonly<Record<string, number>> = { pl: 7, p: 7 };

interface VersionComponent {
  tier: number;
  numeric: number;
}

const DEFAULT_COMPONENT: VersionComponent = { tier: TIER_NUMBER, numeric: 0 };

function splitVersion(version: string): VersionComponent[] {
  let v = version.replace(/[_+-]/g, '.');
  v = v.replace(/[^0-9.]+/g, (m) => `.${m}.`);
  v = v.replace(/\.{2,}/g, '.');
  v = v.replace(/^\.+|\.+$/g, '');
  const parts = v === '' ? ['0'] : v.split('.');
  return parts.map(componentOf);
}

function componentOf(raw: string): VersionComponent {
  if (/^[0-9]+$/.test(raw)) return { tier: TIER_NUMBER, numeric: parseInt(raw, 10) };
  const lower = raw.toLowerCase();
  if (lower in LOWER_TIERS) return { tier: LOWER_TIERS[lower] as number, numeric: 0 };
  if (lower in HIGHER_TIERS) return { tier: HIGHER_TIERS[lower] as number, numeric: 0 };
  return { tier: TIER_UNRECOGNIZED, numeric: 0 };
}

function compareComponents(a: VersionComponent, b: VersionComponent): number {
  if (a.tier !== b.tier) return a.tier < b.tier ? -1 : 1;
  if (a.tier !== TIER_NUMBER) return 0;
  if (a.numeric === b.numeric) return 0;
  return a.numeric < b.numeric ? -1 : 1;
}

/**
 * Whether `version` falls inside `range`. Mirrors
 * `wordfence/intel/vulnerabilities.py#VersionRange.includes`: `'*'` on
 * either side means unbounded on that side.
 */
export function versionInRange(version: string, range: WordfenceVersionRange): boolean {
  if (range.from_version !== VERSION_ANY) {
    const c = comparePhpVersions(range.from_version, version);
    const ok = c === -1 || (range.from_inclusive && c === 0);
    if (!ok) return false;
  }
  if (range.to_version !== VERSION_ANY) {
    const c = comparePhpVersions(range.to_version, version);
    const ok = c === 1 || (range.to_inclusive && c === 0);
    if (!ok) return false;
  }
  return true;
}

// ---------------------------------------------------------------------- feed shape

export type WordfenceSoftwareType = 'core' | 'plugin' | 'theme';

export interface WordfenceSoftwareEntry {
  type: WordfenceSoftwareType;
  name: string;
  slug: string;
  affected_versions: Record<string, WordfenceVersionRange>;
  patched: boolean;
  patched_versions: string[];
  /** Production feed only. */
  remediation?: string;
}

export interface WordfenceCvss {
  vector: string;
  score: number;
  rating: string;
}

export interface WordfenceVulnerabilityRecord {
  id: string;
  title: string;
  description?: string;
  software: WordfenceSoftwareEntry[];
  cve?: string | null;
  cve_link?: string | null;
  cvss?: WordfenceCvss | null;
  informational?: boolean;
}

/** Root shape: an object keyed by vulnerability UUID. */
export type WordfenceFeed = Record<string, WordfenceVulnerabilityRecord>;

// ---------------------------------------------------------------------- network fetch

export type WordfenceFetchResult =
  | { ok: true; feed: WordfenceFeed }
  | { ok: false; reason: string };

export interface WordfenceFetchOptions {
  apiKey: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  signal?: AbortSignal;
}

/** One HTTP round trip to the production feed. No caching, no offline check
 *  — {@link getWordfenceFeed} below wraps this with both. */
export async function fetchWordfenceFeed(opts: WordfenceFetchOptions): Promise<WordfenceFetchResult> {
  const fetchImpl = opts.fetchImpl ?? (typeof fetch === 'function' ? fetch : undefined);
  if (fetchImpl === undefined) return { ok: false, reason: 'no fetch implementation available' };

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeoutMs ?? DEFAULT_FEED_TIMEOUT_MS);
  if (opts.signal) {
    if (opts.signal.aborted) controller.abort();
    else opts.signal.addEventListener('abort', () => controller.abort(), { once: true });
  }
  try {
    const res = await fetchImpl(`${WORDFENCE_BASE_URL}${WORDFENCE_PRODUCTION_PATH}`, {
      signal: controller.signal,
      headers: { Authorization: `Bearer ${opts.apiKey}`, Accept: 'application/json' },
    });
    if (!res.ok) return { ok: false, reason: `Wordfence Intelligence API returned http ${res.status}` };
    const json = (await res.json()) as unknown;
    if (json === null || typeof json !== 'object' || Array.isArray(json)) {
      return { ok: false, reason: 'Wordfence Intelligence API response was not a JSON object' };
    }
    return { ok: true, feed: json as WordfenceFeed };
  } catch (e) {
    return { ok: false, reason: describeFetchError(e) };
  } finally {
    clearTimeout(timeout);
  }
}

function describeFetchError(e: unknown): string {
  if (e instanceof Error) {
    if (e.name === 'AbortError') return 'Wordfence Intelligence API request timed out';
    return e.message;
  }
  return 'Wordfence Intelligence API request failed';
}

// ---------------------------------------------------------------------- disk cache

interface CachedFeedFile {
  fetched_at: string;
  feed: WordfenceFeed;
}

export type WordfenceFeedResult =
  | { ok: true; feed: WordfenceFeed; stale: boolean; fetched_at: string }
  | { ok: false; reason: string };

export interface GetWordfenceFeedOptions {
  /** Wordfence Intelligence API token. Falls back to `WORDFENCE_API_KEY`
   *  env when omitted (via `opts.env`, default `process.env`). No key at
   *  all (env unset and no override) is reported as `{ ok: false }` with a
   *  reason that says so — v3 has no keyless path, unlike WPScan's public DB. */
  apiKey?: string;
  now?: number;
  offline?: boolean;
  env?: Record<string, string | undefined>;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  signal?: AbortSignal;
  /** Where the cache file lives. Default: the OS user-cache directory. Tests
   *  pass a temp directory so they never touch the real one. */
  cacheDir?: string;
  /** Test-only injection point; defaults to the real {@link fetchWordfenceFeed}. */
  fetchWordfenceFeedImpl?: (opts: WordfenceFetchOptions) => Promise<WordfenceFetchResult>;
}

const CACHE_FILE_NAME = 'wordfence-vulnerabilities-production.json';

/** `%LOCALAPPDATA%\dev-guardian\cache` on Windows, `~/Library/Caches/dev-guardian`
 *  on macOS, `$XDG_CACHE_HOME/dev-guardian` (default `~/.cache/dev-guardian`)
 *  elsewhere — the conventional per-OS user cache location, never the
 *  project directory (this feed is shared across every project scanned). */
export function defaultWordfenceCacheDir(env: Record<string, string | undefined> = process.env): string {
  if (process.platform === 'win32') {
    const base = env['LOCALAPPDATA'] ?? join(homedir(), 'AppData', 'Local');
    return join(base, 'dev-guardian', 'cache');
  }
  if (process.platform === 'darwin') {
    return join(homedir(), 'Library', 'Caches', 'dev-guardian');
  }
  const base = env['XDG_CACHE_HOME'] ?? join(homedir(), '.cache');
  return join(base, 'dev-guardian');
}

/**
 * The feed: served from the on-disk cache when within
 * {@link WORDFENCE_FEED_TTL_MS}; otherwise refreshed (unless `offline`, or
 * no API key is available) and re-cached. A refresh that fails falls back to
 * a stale cached feed (`stale: true`) when one exists, else `{ ok: false }`
 * — never a fabricated empty-but-ok feed, which would read as "0
 * vulnerabilities" instead of "not measured". Mirrors
 * `intel/kevCache.ts#getKevCatalog`'s shape and reasoning; see this module's
 * header for why the cache itself is a disk file rather than `runtime_meta`.
 */
export async function getWordfenceFeed(opts: GetWordfenceFeedOptions = {}): Promise<WordfenceFeedResult> {
  const now = opts.now ?? Date.now();
  const env = opts.env ?? process.env;
  const cacheDir = opts.cacheDir ?? defaultWordfenceCacheDir(env);
  const cachePath = join(cacheDir, CACHE_FILE_NAME);

  const cached = await readCachedFeed(cachePath);
  const cachedFresh = cached !== null && now - Date.parse(cached.fetched_at) < WORDFENCE_FEED_TTL_MS;
  if (cachedFresh && cached !== null) {
    return { ok: true, feed: cached.feed, stale: false, fetched_at: cached.fetched_at };
  }

  const offline = opts.offline ?? env['GUARDIAN_OFFLINE'] === '1';
  if (offline) {
    if (cached !== null) return { ok: true, feed: cached.feed, stale: true, fetched_at: cached.fetched_at };
    return { ok: false, reason: 'network disabled (GUARDIAN_OFFLINE=1)' };
  }

  const apiKey = opts.apiKey ?? env['WORDFENCE_API_KEY'];
  if (apiKey === undefined || apiKey.length === 0) {
    if (cached !== null) return { ok: true, feed: cached.feed, stale: true, fetched_at: cached.fetched_at };
    return { ok: false, reason: 'no Wordfence Intelligence API key (set WORDFENCE_API_KEY)' };
  }

  const fetchWordfenceFeedImpl = opts.fetchWordfenceFeedImpl ?? fetchWordfenceFeed;
  const netOpts: WordfenceFetchOptions = { apiKey };
  if (opts.fetchImpl !== undefined) netOpts.fetchImpl = opts.fetchImpl;
  if (opts.timeoutMs !== undefined) netOpts.timeoutMs = opts.timeoutMs;
  if (opts.signal !== undefined) netOpts.signal = opts.signal;
  const fetched = await fetchWordfenceFeedImpl(netOpts);

  if (fetched.ok) {
    const fetchedAt = new Date(now).toISOString();
    await writeCachedFeed(cachePath, { fetched_at: fetchedAt, feed: fetched.feed });
    return { ok: true, feed: fetched.feed, stale: false, fetched_at: fetchedAt };
  }
  if (cached !== null) return { ok: true, feed: cached.feed, stale: true, fetched_at: cached.fetched_at };
  return { ok: false, reason: fetched.reason };
}

async function readCachedFeed(cachePath: string): Promise<CachedFeedFile | null> {
  let raw: string;
  try {
    raw = await readFile(cachePath, 'utf8');
  } catch {
    return null;
  }
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (parsed === null || typeof parsed !== 'object') return null;
    const rec = parsed as Record<string, unknown>;
    if (typeof rec['fetched_at'] !== 'string') return null;
    const feed = rec['feed'];
    if (feed === null || typeof feed !== 'object' || Array.isArray(feed)) return null;
    return { fetched_at: rec['fetched_at'], feed: feed as WordfenceFeed };
  } catch {
    // A damaged cache file (partial write, foreign content) reads as "never
    // cached", never as a crash — same discipline as `intel/kevCache.ts`.
    return null;
  }
}

/** Write-to-temp-then-rename: a reader never observes a partially written
 *  ~100 MB file, and a crash mid-write leaves the previous cache intact. */
async function writeCachedFeed(cachePath: string, payload: CachedFeedFile): Promise<void> {
  mkdirSync(join(cachePath, '..'), { recursive: true });
  const tmpPath = `${cachePath}.${randomUUID()}.tmp`;
  writeFileSync(tmpPath, JSON.stringify(payload), 'utf8');
  renameSync(tmpPath, cachePath);
}

// ---------------------------------------------------------------------- matching

export interface WordfenceMatch {
  vulnId: string;
  title: string;
  cve: string | null;
  cveLink: string | null;
  severity: Severity;
  componentType: WordfenceSoftwareType;
  slug: string;
  name: string;
  installedVersion: string;
  fixedVersion: string | null;
  patchedVersions: string[];
  remediation: string | null;
}

/** Core's slug in the feed — confirmed against `wordfence-cli`'s own
 *  `SLUG_WORDPRESS = 'wordpress'`. */
const CORE_SLUG = 'wordpress';
const CORE_NAME = 'WordPress';

/**
 * Every feed vulnerability whose `software[]` names an installed component
 * (by type + slug) at a version inside one of its `affected_versions`
 * ranges. A component with no readable version (inventory returned `null`)
 * cannot be matched against anything and is silently skipped — reported as
 * a coverage gap by the caller, not fabricated as "no vulnerabilities".
 */
export function matchInventoryAgainstFeed(
  inventory: WpSourceInventory,
  feed: WordfenceFeed,
): WordfenceMatch[] {
  const targets: Array<{ type: WordfenceSoftwareType; slug: string; name: string; version: string }> = [];
  if (inventory.core.version !== null) {
    targets.push({ type: 'core', slug: CORE_SLUG, name: CORE_NAME, version: inventory.core.version });
  }
  pushTargets(targets, 'plugin', inventory.plugins);
  pushTargets(targets, 'theme', inventory.themes);

  const matches: WordfenceMatch[] = [];
  for (const vuln of Object.values(feed)) {
    for (const software of vuln.software) {
      const target = targets.find((t) => t.type === software.type && t.slug === software.slug);
      if (target === undefined) continue;
      const inRange = Object.values(software.affected_versions).some((range) =>
        versionInRange(target.version, range),
      );
      if (!inRange) continue;
      matches.push({
        vulnId: vuln.id,
        title: vuln.title,
        cve: vuln.cve ?? null,
        cveLink: vuln.cve_link ?? null,
        severity: severityOf(vuln.cvss),
        componentType: software.type,
        slug: target.slug,
        name: software.name || target.name,
        installedVersion: target.version,
        fixedVersion: software.patched && software.patched_versions.length > 0 ? (software.patched_versions[0] as string) : null,
        patchedVersions: software.patched_versions,
        remediation: software.remediation ?? null,
      });
    }
  }
  return matches;
}

function pushTargets(
  targets: Array<{ type: WordfenceSoftwareType; slug: string; name: string; version: string }>,
  type: 'plugin' | 'theme',
  components: readonly WpComponentInventory[],
): void {
  for (const c of components) {
    if (c.version === null) continue;
    targets.push({ type, slug: c.slug, name: c.name ?? c.slug, version: c.version });
  }
}

/** CVSS v3.1 rating thresholds, matching `scannerParsers/wpscan.ts`'s own
 *  `severityFromVuln` — the two sources should read the same finding the
 *  same way if a component happens to be flagged by both. Rating text is
 *  preferred when present (Wordfence supplies it directly); score is the
 *  fallback, then a bare default. */
function severityOf(cvss: WordfenceCvss | null | undefined): Severity {
  const rating = cvss?.rating?.toLowerCase();
  if (rating === 'critical') return 'critical';
  if (rating === 'high') return 'high';
  if (rating === 'medium') return 'medium';
  if (rating === 'low') return 'low';
  if (rating === 'none') return 'info';
  const score = cvss?.score;
  if (typeof score === 'number') {
    if (score >= 9) return 'critical';
    if (score >= 7) return 'high';
    if (score >= 4) return 'medium';
    return 'low';
  }
  return 'medium';
}

/** One {@link Finding} + zero-or-one {@link ParserCveInput} per match —
 *  mirrors `scannerParsers/wpscan.ts#pushVuln`'s shape so the same
 *  vulnerability reads the same way regardless of which of the two tools
 *  found it. */
export function wordfenceMatchToFindingAndCve(
  match: WordfenceMatch,
): { finding: Finding; cve: ParserCveInput | null } {
  const componentLabel = `${match.slug}@${match.installedVersion}`;
  const subcategory =
    match.componentType === 'core'
      ? 'wordpress-core'
      : match.componentType === 'plugin'
        ? 'wordpress-plugin'
        : 'wordpress-theme';
  const finding = makeFinding({
    tool: WORDFENCE_TOOL_NAME,
    rule_id: match.cve ?? match.vulnId.slice(0, 64),
    severity: match.severity,
    category: 'security',
    subcategory,
    title: match.title,
    ...(match.remediation !== null ? { message: match.remediation } : {}),
    fix_available: match.fixedVersion !== null,
    file_path: componentLabel,
    snippet: `component:${componentLabel}`,
  });
  const cve: ParserCveInput | null =
    match.cve === null
      ? null
      : {
          cve_id: match.cve,
          package_name: match.slug,
          installed_version: match.installedVersion,
          ...(match.fixedVersion !== null ? { fixed_version: match.fixedVersion } : {}),
          severity: match.severity,
        };
  return { finding, cve };
}
