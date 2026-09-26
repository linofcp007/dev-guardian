/**
 * Shared types for install-time package vetting (`vet_packages` and the
 * PreToolUse install-command hook).
 *
 * Pure declarations. Everything under `pkgvet/` is imported by the hook
 * straight from `mcp/dist/pkgvet/*.js`, so nothing here may pull in a
 * dependency — Node built-ins only.
 */

export const PKG_ECOSYSTEMS = ['npm', 'pypi', 'packagist', 'nuget'] as const;
export type PkgEcosystem = (typeof PKG_ECOSYSTEMS)[number];

/** OSV's own spelling of each ecosystem (https://ossf.github.io/osv-schema/#affectedpackage-field). */
export const OSV_ECOSYSTEM: Record<PkgEcosystem, string> = {
  npm: 'npm',
  pypi: 'PyPI',
  packagist: 'Packagist',
  nuget: 'NuGet',
};

/** One package a command (or a tool call) asks to install. */
export interface PackageSpec {
  ecosystem: PkgEcosystem;
  /** The registry name, exactly as it will be looked up. */
  name: string;
  /**
   * The version, range or tag asked for (`1.2.3`, `^1`, `>=2,<3`, `next`).
   * Absent when none was given — the registry's default ("latest") applies.
   */
  range?: string;
  /** The token(s) this came from, for messages. */
  raw: string;
}

/** A command argument that is deliberately not looked up, and why. */
export interface SkippedSpec {
  raw: string;
  reason: string;
}

/**
 * `unknown` is a verdict in its own right and is never folded into `ok`: a
 * check that could not run (offline, timeout, HTTP error, rate limit) says
 * nothing about the package.
 */
export type PkgVerdict = 'block' | 'warn' | 'unknown' | 'ok';

export type CheckStatus = 'pass' | 'warn' | 'fail' | 'unknown' | 'not_applicable';

export interface CheckResult {
  status: CheckStatus;
  detail?: string;
}

export interface PackageChecks {
  exists: CheckResult;
  malicious: CheckResult;
  vulnerabilities: CheckResult;
  publish_age: CheckResult;
  install_scripts: CheckResult;
  typosquat: CheckResult;
}

export interface PackageVetResult {
  ecosystem: PkgEcosystem;
  name: string;
  requested?: string;
  /** The version the install would resolve to, when it could be determined. */
  version?: string;
  verdict: PkgVerdict;
  /** One line per finding that moved the verdict, most severe first. */
  reasons: string[];
  checks: PackageChecks;
  published_at?: string;
  malicious_ids?: string[];
  vulnerability_ids?: string[];
  install_scripts?: string[];
  similar_to?: string;
  /**
   * The public registry answered "no such package" — whether that became a
   * `block` (nothing explains it) or `unknown` (a custom registry, an npmjs
   * auth token for a scoped name, or a local workspace package does).
   */
  not_on_public_registry?: boolean;
  /** An exact version was requested and the registry does not publish it. */
  requested_version_unpublished?: boolean;
}
