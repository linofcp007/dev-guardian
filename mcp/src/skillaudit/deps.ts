/**
 * Dependency extraction from manifest files, for OSV.dev lookups.
 *
 * We parse the common manifests a skill/agent might ship and emit
 * `{ ecosystem, name, version }` tuples in OSV's vocabulary. Version ranges
 * are reduced to a concrete version where possible (OSV matches a point
 * version); when only a range/tag is available we drop the version and let
 * OSV report all known vulns for the package (over-reports, flagged as such
 * by the caller).
 *
 * Pure functions. No I/O — the caller supplies file contents.
 */

import type { OsvPackageQuery } from '../runners/osv.js';

export interface ManifestFile {
  relPath: string;
  content: string;
}

export function extractDependencies(files: ManifestFile[]): OsvPackageQuery[] {
  const out: OsvPackageQuery[] = [];
  for (const f of files) {
    const base = f.relPath.split('/').pop()?.toLowerCase() ?? '';
    if (base === 'package.json') out.push(...fromPackageJson(f.content));
    else if (base === 'requirements.txt') out.push(...fromRequirements(f.content));
    else if (base === 'go.mod') out.push(...fromGoMod(f.content));
    else if (base === 'cargo.toml') out.push(...fromCargoToml(f.content));
    else if (base === 'composer.json') out.push(...fromComposerJson(f.content));
    else if (base === 'gemfile.lock') out.push(...fromGemfileLock(f.content));
  }
  return dedupe(out);
}

function concreteVersion(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const m = raw.match(/(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?)/);
  return m ? m[1] : undefined;
}

function fromPackageJson(content: string): OsvPackageQuery[] {
  const out: OsvPackageQuery[] = [];
  try {
    const json = JSON.parse(content) as Record<string, unknown>;
    for (const key of ['dependencies', 'devDependencies', 'optionalDependencies']) {
      const deps = json[key];
      if (deps && typeof deps === 'object') {
        for (const [name, ver] of Object.entries(deps as Record<string, unknown>)) {
          if (typeof ver === 'string' && /^(git|http|file|link|workspace)/.test(ver)) continue;
          const q: OsvPackageQuery = { ecosystem: 'npm', name };
          const v = concreteVersion(typeof ver === 'string' ? ver : undefined);
          if (v) q.version = v;
          out.push(q);
        }
      }
    }
  } catch {
    /* malformed manifest — skip */
  }
  return out;
}

function fromRequirements(content: string): OsvPackageQuery[] {
  const out: OsvPackageQuery[] = [];
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.split('#')[0]?.trim() ?? '';
    if (!line || line.startsWith('-')) continue;
    const m = line.match(/^([A-Za-z0-9._-]+)\s*(?:==\s*([0-9][^\s;]*))?/);
    if (m && m[1]) {
      const q: OsvPackageQuery = { ecosystem: 'PyPI', name: m[1] };
      const v = concreteVersion(m[2]);
      if (v) q.version = v;
      out.push(q);
    }
  }
  return out;
}

function fromGoMod(content: string): OsvPackageQuery[] {
  const out: OsvPackageQuery[] = [];
  const re = /^\s*([\w./-]+)\s+v(\d+\.\d+\.\d+[\w.-]*)/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    if (m[1] === 'module' || m[1] === 'go') continue;
    const q: OsvPackageQuery = { ecosystem: 'Go', name: m[1]! };
    if (m[2]) q.version = m[2];
    out.push(q);
  }
  return out;
}

function fromCargoToml(content: string): OsvPackageQuery[] {
  const out: OsvPackageQuery[] = [];
  let inDeps = false;
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.startsWith('[')) {
      inDeps = /\[(dependencies|dev-dependencies|build-dependencies)\]/.test(line);
      continue;
    }
    if (!inDeps || !line || line.startsWith('#')) continue;
    const m = line.match(/^([A-Za-z0-9_-]+)\s*=\s*(?:"([^"]*)"|\{[^}]*version\s*=\s*"([^"]*)")/);
    if (m && m[1]) {
      const q: OsvPackageQuery = { ecosystem: 'crates.io', name: m[1] };
      const v = concreteVersion(m[2] ?? m[3]);
      if (v) q.version = v;
      out.push(q);
    }
  }
  return out;
}

function fromComposerJson(content: string): OsvPackageQuery[] {
  const out: OsvPackageQuery[] = [];
  try {
    const json = JSON.parse(content) as Record<string, unknown>;
    for (const key of ['require', 'require-dev']) {
      const deps = json[key];
      if (deps && typeof deps === 'object') {
        for (const [name, ver] of Object.entries(deps as Record<string, unknown>)) {
          if (!name.includes('/')) continue; // skip "php", "ext-*"
          const q: OsvPackageQuery = { ecosystem: 'Packagist', name };
          const v = concreteVersion(typeof ver === 'string' ? ver : undefined);
          if (v) q.version = v;
          out.push(q);
        }
      }
    }
  } catch {
    /* skip */
  }
  return out;
}

function fromGemfileLock(content: string): OsvPackageQuery[] {
  const out: OsvPackageQuery[] = [];
  const re = /^\s{4}([A-Za-z0-9._-]+)\s+\((\d+\.\d+[\w.]*)\)/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    const q: OsvPackageQuery = { ecosystem: 'RubyGems', name: m[1]! };
    if (m[2]) q.version = m[2];
    out.push(q);
  }
  return out;
}

function dedupe(queries: OsvPackageQuery[]): OsvPackageQuery[] {
  const seen = new Set<string>();
  const out: OsvPackageQuery[] = [];
  for (const q of queries) {
    const key = `${q.ecosystem}:${q.name}@${q.version ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(q);
  }
  return out;
}
