#!/usr/bin/env node
/**
 * Regenerates `configs/popular-packages/<ecosystem>.txt` — the lists the
 * package-vetting typosquat check (`mcp/src/pkgvet/typosquat.ts`) compares a
 * candidate name against.
 *
 * Developer tooling, not shipped logic: nothing at runtime runs this. The
 * committed `.txt` files are the product; this script is how they were made
 * and how anyone can remake them. Never type a list by hand — a name typed
 * from memory is exactly the kind of near-miss the check exists to catch.
 *
 * Source: ecosyste.ms (https://packages.ecosyste.ms), an open dataset that
 * indexes every one of these registries and exposes a names-only endpoint
 * sorted by download count:
 *
 *   GET https://packages.ecosyste.ms/api/v1/registries/<registry>/package_names
 *       ?sort=downloads&order=desc&per_page=1000&page=<n>
 *
 * One source for all four ecosystems, so the four lists mean the same thing
 * ("the N most-downloaded names") rather than four different definitions of
 * popular.
 *
 * Usage (from the repo root or from mcp/):
 *
 *   node mcp/scripts/generatePopularPackages.mjs            # every ecosystem
 *   node mcp/scripts/generatePopularPackages.mjs npm pypi   # a subset
 *
 * Needs network access; uses the global `fetch` (Node >= 22). Anonymous
 * ecosyste.ms access is rate limited (5000 requests/hour at the time of
 * writing) — a full run is a dozen requests.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = resolve(here, '..', '..', 'configs', 'popular-packages');

const BASE = 'https://packages.ecosyste.ms/api/v1/registries';
const PER_PAGE = 1000;

/**
 * `count` is how many of the top names each list keeps. Sized from the
 * self-collision measurement recorded in the directory README: large enough
 * to cover what typosquatters actually target, small enough that the list's
 * own legitimate near-neighbours stay a handful.
 */
const ECOSYSTEMS = {
  npm: { registry: 'npmjs.org', count: 2000, valid: /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/ },
  pypi: { registry: 'pypi.org', count: 2000, valid: /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/ },
  packagist: { registry: 'packagist.org', count: 2000, valid: /^[a-z0-9]([_.-]?[a-z0-9]+)*\/[a-z0-9](([_.]|-{1,2})?[a-z0-9]+)*$/ },
  nuget: { registry: 'nuget.org', count: 2000, valid: /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/ },
};

async function fetchPage(registry, page) {
  const url = `${BASE}/${registry}/package_names?sort=downloads&order=desc&per_page=${PER_PAGE}&page=${page}`;
  const res = await fetch(url, { headers: { accept: 'application/json' } });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  const body = await res.json();
  if (!Array.isArray(body)) throw new Error(`${url}: expected a JSON array`);
  return body.filter((x) => typeof x === 'string');
}

async function generate(eco) {
  const spec = ECOSYSTEMS[eco];
  if (!spec) throw new Error(`unknown ecosystem '${eco}' (expected one of ${Object.keys(ECOSYSTEMS).join(', ')})`);
  const names = [];
  const seen = new Set();
  let dropped = 0;
  for (let page = 1; names.length < spec.count; page += 1) {
    const batch = await fetchPage(spec.registry, page);
    if (batch.length === 0) break;
    for (const raw of batch) {
      const name = raw.trim();
      const key = name.toLowerCase();
      if (!spec.valid.test(name)) {
        dropped += 1;
        continue;
      }
      if (seen.has(key)) continue;
      seen.add(key);
      names.push(name);
      if (names.length >= spec.count) break;
    }
  }
  const date = new Date().toISOString().slice(0, 10);
  const header = [
    `# dev-guardian popular-packages list: ${eco}`,
    `# source: ${BASE}/${spec.registry}/package_names?sort=downloads&order=desc`,
    `# generated: ${date}`,
    `# count: ${names.length} (top by downloads; ${dropped} source entries dropped as invalid names)`,
    '# regenerate: node mcp/scripts/generatePopularPackages.mjs',
  ];
  mkdirSync(OUT_DIR, { recursive: true });
  const file = join(OUT_DIR, `${eco}.txt`);
  writeFileSync(file, `${header.join('\n')}\n${names.join('\n')}\n`);
  console.log(`${eco}: ${names.length} names (${dropped} dropped) -> ${file}`);
}

const requested = process.argv.slice(2);
for (const eco of requested.length > 0 ? requested : Object.keys(ECOSYSTEMS)) {
  await generate(eco);
}
