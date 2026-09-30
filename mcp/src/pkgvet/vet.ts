/**
 * Install-time package vetting: the engine behind `vet_packages` and the
 * PreToolUse install-command hook.
 *
 * Per package, against the PUBLIC registry and OSV:
 *
 *   exists           404 → `block` (a name nobody published is most likely a
 *                    hallucinated dependency — and the next thing an attacker
 *                    registers), unless a custom registry, an npmjs auth
 *                    token (scoped names), a local workspace package or a
 *                    registry configuration that could not be read
 *                    explains it (`privateRegistry.ts`), in which case
 *                    `unknown`. The HOOK further denies it only on a
 *                    confident command parse (`hookDecision.ts`)
 *   malicious        an OSV `MAL-` advisory on the version that would install
 *                    → `block`; npm's `0.0.x-security` takedown placeholder
 *                    → `block`. OSV is asked with the name it knows:
 *                    Packagist lower-cased, NuGet in canonical casing
 *   vulnerabilities  any other OSV advisory on that version → `warn`
 *   publish_age      that version published < 72 h ago → `warn` (the 2025–26
 *                    npm/PyPI worms spread as fresh patch releases)
 *   install_scripts  npm `preinstall`/`install`/`postinstall` → `warn`
 *   typosquat        near-miss of a popular name → `warn` (`typosquat.ts`)
 *
 * Verdict: `block` > `warn` > `unknown` > `ok`. A check that could not run
 * — offline, timeout, HTTP error, rate limit, a list that would not load —
 * is `unknown`, and a single `unknown` check keeps the verdict off `ok`:
 * nothing here ever reports a package as vetted when it was not.
 *
 * Network: two rounds, both inside ONE wall-clock budget enforced with an
 * AbortSignal — registry lookups in parallel, then OSV (one batch) plus the
 * per-version extras in parallel. The hook passes 3 s; the tool 10 s.
 *
 * Dependency-free (global `fetch`, node built-ins): the hook imports this
 * file from `mcp/dist/pkgvet/vet.js`.
 */

import { queryOsv, type OsvPackageQuery, type OsvResult } from '../runners/osv.js';
import { loadPopularIndex } from './popular.js';
import {
  customRegistryFor,
  isPublicRegistryUrl,
  MAX_WORKSPACE_DIRS,
  registryCache,
  type CustomRegistry,
  type RegistryContext,
} from './privateRegistry.js';
import {
  lookupRegistry,
  npmFullDocument,
  npmVersionScripts,
  nugetCanonicalId,
  nugetPublished,
  type HttpOptions,
  type RegistryInfo,
  type RegistryLookup,
} from './registry.js';
import { buildPopularIndex, findTyposquatTarget, type PopularIndex, type TyposquatMatch } from './typosquat.js';
import {
  OSV_ECOSYSTEM,
  type CheckResult,
  type PackageChecks,
  type PackageSpec,
  type PackageVetResult,
  type PkgEcosystem,
  type PkgVerdict,
} from './types.js';
import { isExactVersion, resolveVersion } from './versions.js';

export const FRESH_HOURS = 72;
export const HOOK_BUDGET_MS = 3000;
export const TOOL_BUDGET_MS = 10_000;

const HOUR = 3600 * 1000;
/** npm's takedown placeholder for a package removed as malicious: `0.0.1-security`, sometimes `0.0.2-security`. */
const NPM_PLACEHOLDER = /^0\.0\.\d+-security$/;
const INSTALL_SCRIPTS = ['preinstall', 'install', 'postinstall'];

const REGISTRY_NAME: Record<PkgEcosystem, string> = {
  npm: 'the npm registry',
  pypi: 'PyPI',
  packagist: 'Packagist',
  nuget: 'nuget.org',
};

export interface VetOptions {
  /** Defaults to the global `fetch`. */
  fetchImpl?: typeof fetch;
  /** Total wall-clock budget for all network work, in ms. Default {@link TOOL_BUDGET_MS}. */
  budgetMs?: number;
  /** An outer cancellation (the MCP host's), combined with the budget. */
  signal?: AbortSignal;
  /** Epoch ms used for publish-age arithmetic. Default `Date.now()`. */
  now?: number;
  /** No network at all. Default: `GUARDIAN_OFFLINE === '1'`. */
  offline?: boolean;
  /**
   * Popular-name lists by ecosystem, overriding the committed files (tests).
   * `null` simulates a list that could not be loaded.
   */
  popular?: Partial<Record<PkgEcosystem, readonly string[] | null>>;
  /** Directory holding `<ecosystem>.txt` lists. Default: `configs/popular-packages`. */
  popularDir?: string;
  /** Where to look for custom-registry configuration. */
  registry?: RegistryContext;
  /** Every registry / index named on the command line (`--registry`, `-i`, `--source`); any non-public one counts. */
  commandRegistries?: readonly string[] | undefined;
  /**
   * Epoch ms by which vetting must be done — the hook's one deadline for the
   * whole call (review I4). The network budget is cut to it, and what is left
   * when it passes reads `unknown` ("time budget"), never ok.
   */
  deadlineAt?: number | undefined;
}

/** The reason a check did not run because the vetting deadline had passed. */
export const TIME_BUDGET = 'vetting time budget exhausted';

function popularIndexFor(ecosystem: PkgEcosystem, opts: VetOptions): PopularIndex | null {
  const override = opts.popular?.[ecosystem];
  if (override === null) return null;
  if (override !== undefined) return buildPopularIndex(ecosystem, override);
  return opts.popularDir === undefined ? loadPopularIndex(ecosystem) : loadPopularIndex(ecosystem, opts.popularDir);
}

const pass = (detail?: string): CheckResult => (detail === undefined ? { status: 'pass' } : { status: 'pass', detail });
const warn = (detail: string): CheckResult => ({ status: 'warn', detail });
const fail = (detail: string): CheckResult => ({ status: 'fail', detail });
const unknown = (detail: string): CheckResult => ({ status: 'unknown', detail });
const na = (detail?: string): CheckResult => (detail === undefined ? { status: 'not_applicable' } : { status: 'not_applicable', detail });

function hoursAgo(iso: string, now: number): number | undefined {
  const t = Date.parse(iso);
  return Number.isFinite(t) ? (now - t) / HOUR : undefined;
}

/** Hours inside the 72 h window, then days to one decimal: ~60 h reads "60 h", never "3 days". */
export function ageText(hours: number): string {
  if (hours < FRESH_HOURS) return `${Math.max(0, Math.round(hours))} h ago`;
  const days = hours / 24;
  return days < 10 ? `${Math.round(days * 10) / 10} days ago` : `${Math.round(days)} days ago`;
}

interface Work {
  spec: PackageSpec;
  typo: TyposquatMatch | null;
  popularLoaded: boolean;
  /**
   * What explains a 404 — looked for only when the registry does not have the
   * name, after the network (review I4: it was looked for for every package,
   * before the network, walking a large workspace each time).
   */
  custom?: CustomRegistry | null;
  lookup?: RegistryLookup;
  version?: string;
  /** An exact version was asked for and the registry does not have it. */
  versionMissing?: boolean;
  /** Publish time of `version`, once known. */
  publishedAt?: string;
  /** Reason the publish time could not be established. */
  ageError?: string;
  /** npm: the package document has not changed within the fresh window. */
  quietSince?: string;
  scripts?: string[];
  scriptsError?: string;
  osvIndex?: number;
  osvVersioned?: boolean;
  /** The name the OSV query used (see `osvNameFor`). */
  osvName?: string;
}

function customFor(spec: PackageSpec, opts: VetOptions): CustomRegistry | null {
  const onCommandLine = (opts.commandRegistries ?? []).find((u) => !isPublicRegistryUrl(spec.ecosystem, u));
  if (onCommandLine !== undefined) return { kind: 'registry', source: 'the command line', url: onCommandLine };
  return customRegistryFor(spec.ecosystem, spec.name, opts.registry ?? {});
}

function resolveFor(w: Work, info: RegistryInfo): void {
  const ctx = { versions: info.versions, latest: info.latest, tags: info.tags ?? {} };
  const v = resolveVersion(w.spec.ecosystem, w.spec.range, ctx);
  if (v !== undefined) w.version = v;
  else if (isExactVersion(w.spec.ecosystem, w.spec.range)) w.versionMissing = true;
  const published = v === undefined ? undefined : info.times[v];
  if (published !== undefined) w.publishedAt = published;
}

async function extrasFor(w: Work, info: RegistryInfo, http: HttpOptions, now: number): Promise<void> {
  const v = w.version;
  if (v === undefined) return;
  if (w.spec.ecosystem === 'npm') {
    const modifiedHours = info.modified === undefined ? undefined : hoursAgo(info.modified, now);
    const needFull = modifiedHours === undefined || modifiedHours < FRESH_HOURS;
    const hasScript = info.installScript[v] === true;
    if (!needFull && info.modified !== undefined) w.quietSince = info.modified;
    if (needFull) {
      const full = await npmFullDocument(w.spec.name, http);
      if (full.kind === 'ok') {
        const t = full.times[v];
        if (t !== undefined) w.publishedAt = t;
        else w.ageError = 'the registry document has no publish time for this version';
        const s = full.scripts[v];
        if (hasScript) w.scripts = s === undefined ? [] : INSTALL_SCRIPTS.filter((k) => s[k] !== undefined);
      } else {
        w.ageError = full.reason;
        if (hasScript) w.scriptsError = full.reason;
      }
    } else if (hasScript) {
      const s = await npmVersionScripts(w.spec.name, v, http);
      if (s.kind === 'ok') w.scripts = INSTALL_SCRIPTS.filter((k) => s.scripts[k] !== undefined);
      else w.scriptsError = s.reason;
    }
    return;
  }
  if (w.spec.ecosystem === 'nuget') {
    const p = await nugetPublished(w.spec.name, v, http);
    if (p.kind === 'ok' && p.published !== undefined) w.publishedAt = p.published;
    else w.ageError = p.kind === 'error' ? p.reason : 'the registration entry has no publish time';
    return;
  }
  if (w.publishedAt === undefined) w.ageError = 'the registry document has no publish time for this version';
}

function osvIds(osv: OsvResult | undefined, w: Work): string[] {
  if (osv === undefined || w.osvIndex === undefined) return [];
  const eco = OSV_ECOSYSTEM[w.spec.ecosystem];
  const name = w.osvName ?? w.spec.name;
  const hit = osv.vulnerable_packages.find(
    (g) => g.ecosystem === eco && g.name === name && (w.osvVersioned ? g.version === w.version : g.version === undefined),
  );
  return hit?.vuln_ids ?? [];
}

/**
 * The name OSV knows the package by. OSV matches Packagist and NuGet names
 * case-sensitively: Packagist names are lower case (`laravel/framework`);
 * NuGet ids keep their canonical casing (`Newtonsoft.Json`), which the flat
 * container does not report, so it comes from nuget.org's search — and,
 * failing that, the id as typed.
 */
function osvNameFor(w: Work, canonical: string | undefined): string {
  if (w.spec.ecosystem === 'packagist') return w.spec.name.toLowerCase();
  if (w.spec.ecosystem === 'nuget') return canonical ?? w.spec.name;
  return w.spec.name;
}

function buildResult(w: Work, osv: OsvResult | undefined, osvError: string | undefined, now: number, offlineReason: string | undefined): PackageVetResult {
  const { spec } = w;
  const eco = spec.ecosystem;
  const registry = REGISTRY_NAME[eco];
  const lookup = w.lookup;
  const info = lookup?.kind === 'found' ? lookup.info : undefined;
  const extraWarn: string[] = [];
  const extraUnknown: string[] = [];

  const typosquat: CheckResult = !w.popularLoaded
    ? unknown('popular-packages list unavailable — typosquat check not run')
    : w.typo !== null
      ? warn(`name is ${w.typo.distance} edit${w.typo.distance === 1 ? '' : 's'} from the popular package '${w.typo.similar_to}' — possible typosquat`)
      : pass();

  const ids = osvIds(osv, w);
  const malIds = ids.filter((id) => id.startsWith('MAL-'));
  const vulnIds = ids.filter((id) => !id.startsWith('MAL-'));
  const osvDown = offlineReason ?? (osv === undefined || !osv.online ? `OSV lookup failed: ${osvError ?? osv?.error ?? 'no answer'}` : undefined);

  let exists: CheckResult;
  let malicious: CheckResult;
  let vulnerabilities: CheckResult;
  let publishAge: CheckResult;
  let installScripts: CheckResult = eco === 'npm' ? unknown('not checked') : na('install-script check is npm-only');

  if (lookup === undefined) {
    const why = offlineReason ?? 'registry not consulted';
    exists = unknown(why);
    malicious = unknown(why);
    vulnerabilities = unknown(why);
    publishAge = unknown(why);
    if (eco === 'npm') installScripts = unknown(why);
  } else if (lookup.kind === 'error') {
    exists = unknown(`${registry} lookup failed: ${lookup.reason}`);
    // OSV was asked about the NAME (no version could be resolved): no MAL-
    // advisory on any version is a real pass; one on some version is a warning.
    malicious =
      osvDown !== undefined
        ? unknown(osvDown)
        : malIds.length > 0
          ? warn(`OSV lists malicious advisories for this name (${malIds.join(', ')}); the version could not be determined`)
          : pass('no OSV malicious-package advisory for any version');
    vulnerabilities = unknown(`version unknown: ${lookup.reason}`);
    publishAge = unknown(`version unknown: ${lookup.reason}`);
    if (eco === 'npm') installScripts = unknown(`version unknown: ${lookup.reason}`);
  } else if (lookup.kind === 'not_found') {
    const didYouMean = w.typo !== null ? ` Did you mean '${w.typo.similar_to}'?` : '';
    const custom = w.custom ?? null;
    if (custom !== null) {
      const where = `${custom.source}${custom.url !== undefined ? `: ${custom.url}` : ''}`;
      const why =
        custom.kind === 'auth'
          ? `an npmjs auth token is configured (${where}) and a private scoped package answers 404 to an anonymous lookup`
          : custom.kind === 'workspace'
            ? `it is a local workspace package (${where})`
            : custom.kind === 'unchecked'
              ? custom.cut === 'time'
                ? `whether a private registry or a local workspace package explains it could not be checked (${TIME_BUDGET})`
                : `the workspace at ${custom.source} has more than ${MAX_WORKSPACE_DIRS} directories and was not read to its end — it may hold the package`
              : custom.kind === 'unreadable'
                ? custom.what === 'workspace manifest'
                  ? `workspace manifest at ${custom.source} could not be read — possibly a local workspace package`
                  : custom.what === 'directory'
                    ? `directory ${custom.source} could not be listed — it may hold registry configuration`
                    : `registry configuration at ${custom.source} could not be read — possibly a private registry`
                : `a custom registry is configured (${where})`;
      exists = unknown(`not on ${registry}, but ${why} — possibly a private or local package; not vetted.${didYouMean}`);
    } else {
      exists = fail(`does not exist on ${registry} — most likely a hallucinated or mistyped name.${didYouMean}`);
    }
    // A private registry that is KNOWN to be configured may be serving the
    // real package under this name, so a removed malicious one only warns; a
    // configuration that merely could not be read is no such evidence, and the
    // malicious name is still denied (Part Y fix round 1).
    malicious =
      malIds.length > 0
        ? custom !== null && custom.kind !== 'unreadable' && custom.kind !== 'unchecked'
          ? warn(`OSV lists this name as a malicious package (${malIds.join(', ')}) removed from ${registry}`)
          : fail(`OSV lists this name as a malicious package (${malIds.join(', ')}), removed from ${registry}`)
        : osvDown !== undefined
          ? unknown(osvDown)
          : na();
    vulnerabilities = na();
    publishAge = na();
    if (eco === 'npm') installScripts = na();
  } else {
    exists = pass();
    const placeholderVersion = [w.version, info?.latest].find((x): x is string => x !== undefined && NPM_PLACEHOLDER.test(x));
    const placeholder = eco === 'npm' && placeholderVersion !== undefined;
    const v = w.version;
    if (w.versionMissing === true) extraWarn.push(`requested version ${spec.range ?? ''} is not published on ${registry} — possibly a hallucinated version`);
    else if (v === undefined) extraUnknown.push(`no published version matches '${spec.range ?? ''}'`);
    const versionUnknown = v === undefined ? `could not determine which version '${spec.range ?? 'latest'}' installs` : undefined;

    if (placeholder) {
      malicious = fail(`npm replaced this package with a security placeholder (${placeholderVersion ?? 'x-security'}): it was taken down as malicious`);
    } else if (osvDown !== undefined) {
      malicious = unknown(osvDown);
    } else if (malIds.length > 0) {
      malicious = w.osvVersioned
        ? fail(`OSV malicious-package advisory for ${v ?? 'this version'}: ${malIds.join(', ')}`)
        : warn(`OSV lists malicious advisories for some versions of this package (${malIds.join(', ')}) — which version installs could not be determined`);
    } else {
      malicious = pass();
    }

    if (osvDown !== undefined) vulnerabilities = unknown(osvDown);
    else if (vulnIds.length > 0) {
      vulnerabilities = w.osvVersioned
        ? warn(`${vulnIds.length} known vulnerabilit${vulnIds.length === 1 ? 'y' : 'ies'} in ${v ?? 'this version'}: ${vulnIds.slice(0, 5).join(', ')}${vulnIds.length > 5 ? ', …' : ''}`)
        : unknown(`${vulnIds.length} advisories exist for some versions — which version installs could not be determined`);
    } else vulnerabilities = pass();

    if (versionUnknown !== undefined) publishAge = unknown(versionUnknown);
    else if (w.publishedAt !== undefined) {
      const h = hoursAgo(w.publishedAt, now);
      publishAge =
        h === undefined
          ? unknown('unparseable publish time')
          : h < FRESH_HOURS
            ? warn(
                `${v ?? ''} was published ${ageText(h)} (< ${FRESH_HOURS} h) — fresh releases are how the 2025-26 npm/PyPI worms spread; ` +
                  'consider pinning the previous version until this one has aged',
              )
            : pass(`published ${ageText(h)}`);
    } else if (w.quietSince !== undefined) {
      publishAge = pass(`no change to the package since ${w.quietSince.slice(0, 10)}`);
    } else publishAge = unknown(w.ageError ?? 'publish time unavailable');

    if (eco === 'npm') {
      if (versionUnknown !== undefined) installScripts = unknown(versionUnknown);
      else if (info?.installScript[v ?? ''] === true) {
        const names =
          w.scripts !== undefined && w.scripts.length > 0
            ? w.scripts.join(', ')
            : w.scriptsError !== undefined
              ? `names unavailable (${w.scriptsError})`
              : 'install (e.g. a native build)';
        installScripts = warn(`${v ?? ''} runs install scripts on install: ${names}`);
      } else installScripts = pass();
    }
  }

  const checks: PackageChecks = {
    exists,
    malicious,
    vulnerabilities,
    publish_age: publishAge,
    install_scripts: installScripts,
    typosquat,
  };
  const all = Object.values(checks);
  const reasonsOf = (status: CheckResult['status']): string[] =>
    all.filter((c) => c.status === status && c.detail !== undefined).map((c) => c.detail ?? '');
  const reasons = [...reasonsOf('fail'), ...reasonsOf('warn'), ...extraWarn, ...reasonsOf('unknown'), ...extraUnknown];
  let verdict: PkgVerdict = 'ok';
  if (all.some((c) => c.status === 'fail')) verdict = 'block';
  else if (all.some((c) => c.status === 'warn') || extraWarn.length > 0) verdict = 'warn';
  else if (all.some((c) => c.status === 'unknown') || extraUnknown.length > 0) verdict = 'unknown';

  const result: PackageVetResult = { ecosystem: eco, name: spec.name, verdict, reasons: [...new Set(reasons)], checks };
  if (spec.range !== undefined) result.requested = spec.range;
  if (w.version !== undefined) result.version = w.version;
  if (w.publishedAt !== undefined) result.published_at = w.publishedAt;
  if (malIds.length > 0) result.malicious_ids = malIds;
  if (vulnIds.length > 0) result.vulnerability_ids = vulnIds;
  if (w.scripts !== undefined && w.scripts.length > 0) result.install_scripts = w.scripts;
  if (w.typo !== null) result.similar_to = w.typo.similar_to;
  if (lookup?.kind === 'not_found') result.not_on_public_registry = true;
  if (w.versionMissing === true) result.requested_version_unpublished = true;
  return result;
}

/**
 * Vets each package. Never throws for a network or registry failure — those
 * become `unknown` checks. Results are in the order of `specs`.
 */
export async function vetPackages(specs: readonly PackageSpec[], opts: VetOptions = {}): Promise<PackageVetResult[]> {
  const now = opts.now ?? Date.now();
  const offline = opts.offline ?? process.env['GUARDIAN_OFFLINE'] === '1';

  // Every lookup of this call shares one cache: each registry file is read,
  // and each workspace walked, once however many packages there are (I4).
  const registry: RegistryContext = {
    ...(opts.registry ?? {}),
    cache: opts.registry?.cache ?? registryCache(),
    deadlineAt: opts.deadlineAt ?? opts.registry?.deadlineAt,
  };
  const withCache: VetOptions = { ...opts, registry };

  const indexes = new Map<PkgEcosystem, PopularIndex | null>();
  const work: Work[] = specs.map((spec) => {
    if (!indexes.has(spec.ecosystem)) indexes.set(spec.ecosystem, popularIndexFor(spec.ecosystem, opts));
    const index = indexes.get(spec.ecosystem) ?? null;
    return {
      spec,
      typo: index === null ? null : findTyposquatTarget(index, spec.name),
      popularLoaded: index !== null,
    };
  });

  if (offline) {
    return work.map((w) => buildResult(w, undefined, undefined, now, 'network disabled (GUARDIAN_OFFLINE=1)'));
  }

  const fetchImpl = opts.fetchImpl ?? (typeof fetch === 'function' ? fetch : undefined);
  if (fetchImpl === undefined) {
    return work.map((w) => buildResult(w, undefined, undefined, now, 'no fetch implementation available'));
  }
  const left = opts.deadlineAt === undefined ? Number.POSITIVE_INFINITY : opts.deadlineAt - Date.now();
  if (left <= 0) return work.map((w) => buildResult(w, undefined, undefined, now, TIME_BUDGET));
  const budgetMs = Math.max(1, Math.min(opts.budgetMs ?? TOOL_BUDGET_MS, left));
  const deadline = Date.now() + budgetMs;
  // A plain, REF'd timer rather than `AbortSignal.timeout()`: that one is
  // unref'd, so a hook process whose only pending work is a request that
  // never answers can exit before the budget fires — or, where something
  // else keeps the loop alive, the abort is simply never observed in time.
  const budget = new AbortController();
  const timer = setTimeout(() => budget.abort(new Error('network budget exhausted')), budgetMs);
  const signal = opts.signal === undefined ? budget.signal : AbortSignal.any([opts.signal, budget.signal]);
  const http: HttpOptions = { fetchImpl, signal };
  try {
    return await networkRounds(work, http, signal, deadline, now, (w) => explain404(w, withCache));
  } finally {
    clearTimeout(timer);
  }
}

/**
 * What explains a name the registry does not have — looked for once the
 * network is done, so reading files can never eat into its budget, and only
 * while the deadline has not passed (review I4).
 */
function explain404(w: Work, opts: VetOptions): void {
  if (w.custom !== undefined) return;
  const deadlineAt = opts.registry?.deadlineAt;
  if (deadlineAt !== undefined && Date.now() > deadlineAt) {
    const onCommandLine = (opts.commandRegistries ?? []).find((u) => !isPublicRegistryUrl(w.spec.ecosystem, u));
    w.custom =
      onCommandLine !== undefined
        ? { kind: 'registry', source: 'the command line', url: onCommandLine }
        : { kind: 'unchecked', source: 'the vetting deadline', cut: 'time' };
    return;
  }
  w.custom = customFor(w.spec, opts);
}

async function networkRounds(
  work: Work[],
  http: HttpOptions,
  signal: AbortSignal,
  deadline: number,
  now: number,
  explain: (w: Work) => void,
): Promise<PackageVetResult[]> {
  const fetchImpl = http.fetchImpl;

  // Round 1: the registry, once per distinct name.
  const lookups = new Map<string, Promise<RegistryLookup>>();
  const pending = work.map((w) => {
    const key = `${w.spec.ecosystem}\u0000${w.spec.name.toLowerCase()}`;
    let p = lookups.get(key);
    if (p === undefined) {
      p = lookupRegistry(w.spec.ecosystem, w.spec.name, http);
      lookups.set(key, p);
    }
    return p;
  });
  // NuGet's canonical id casing, for OSV (see `osvNameFor`). Started now, in
  // parallel with the flat-container lookup, but only awaited by the OSV
  // query — never by round 1 — so a slow search cannot hold the registry
  // answers back.
  const canonical = new Map<string, Promise<string | undefined>>();
  for (const w of work) {
    const key = w.spec.name.toLowerCase();
    if (w.spec.ecosystem === 'nuget' && !canonical.has(key)) canonical.set(key, nugetCanonicalId(w.spec.name, http));
  }
  const answers = await Promise.all(pending);
  work.forEach((w, i) => {
    const answer = answers[i];
    if (answer !== undefined) w.lookup = answer;
    if (answer?.kind === 'found') resolveFor(w, answer.info);
  });

  // Round 2: one OSV batch, plus the per-version extras, in parallel.
  if (signal.aborted) {
    const why = 'network budget exhausted before OSV was consulted';
    for (const w of work) if (w.lookup?.kind === 'not_found') explain(w);
    return work.map((w) => buildResult(w, undefined, why, now, undefined));
  }
  let osvError: string | undefined;
  const osvPromise = (async (): Promise<OsvResult> => {
    const queries: OsvPackageQuery[] = [];
    for (const w of work) {
      const canonicalId = await (canonical.get(w.spec.name.toLowerCase()) ?? Promise.resolve(undefined));
      w.osvName = osvNameFor(w, canonicalId);
      const q: OsvPackageQuery = { ecosystem: OSV_ECOSYSTEM[w.spec.ecosystem], name: w.osvName };
      if (w.version !== undefined) q.version = w.version;
      w.osvVersioned = w.version !== undefined;
      w.osvIndex = queries.length;
      queries.push(q);
    }
    return queryOsv(queries, { fetchImpl, signal, timeoutMs: Math.max(1, deadline - Date.now()) });
  })().catch((e: unknown): OsvResult => {
    osvError = e instanceof Error ? e.message : String(e);
    return { online: false, queried: 0, vulnerable_packages: [] };
  });
  const extras = work.map((w) =>
    w.lookup?.kind === 'found' ? extrasFor(w, w.lookup.info, http, now).catch(() => undefined) : Promise.resolve(),
  );
  const [osv] = await Promise.all([osvPromise, ...extras]);
  if (signal.aborted && osv.online === false && osvError === undefined) {
    osvError = 'network budget exhausted before OSV answered';
  }
  for (const w of work) if (w.lookup?.kind === 'not_found') explain(w);
  return work.map((w) => buildResult(w, osv, osvError ?? (osv.online ? undefined : osv.error), now, undefined));
}

/** The worst verdict of a set: block > warn > unknown > ok. */
export function worstVerdict(results: readonly PackageVetResult[]): PkgVerdict {
  const rank: Record<PkgVerdict, number> = { ok: 0, unknown: 1, warn: 2, block: 3 };
  let worst: PkgVerdict = 'ok';
  for (const r of results) if (rank[r.verdict] > rank[worst]) worst = r.verdict;
  return worst;
}
