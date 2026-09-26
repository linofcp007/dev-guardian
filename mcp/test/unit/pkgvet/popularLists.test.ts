/**
 * The committed popular-packages lists, and the self-collision measurement
 * the typosquat thresholds were tuned against.
 *
 * "Self-collision" = run every entry of a list through the typosquat check
 * against the REST of the same list, with the popular-name exemption turned
 * off. It is a proxy for the false-positive rate on real, legitimate
 * packages: each hit is a pair of real packages the check would confuse if
 * one of them were not in the list. The numbers are pinned here and written
 * down in `configs/popular-packages/README.md`; a regenerated list or a
 * changed rule moves them, and both places must be updated together.
 */

import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { defaultPopularDir, loadPopularIndex, parsePopularList } from '../../../src/pkgvet/popular.js';
import { findTyposquatTarget } from '../../../src/pkgvet/typosquat.js';
import { PKG_ECOSYSTEMS, type PkgEcosystem } from '../../../src/pkgvet/types.js';

const here = dirname(fileURLToPath(import.meta.url));
const DIR = resolve(here, '..', '..', '..', '..', 'configs', 'popular-packages');

/** Measured 2026-09-25 on the committed lists (2000 names each). */
const SELF_COLLISIONS: Record<PkgEcosystem, number> = { npm: 49, pypi: 90, packagist: 2, nuget: 42 };

describe('configs/popular-packages', () => {
  it('the runtime resolver finds the committed directory', () => {
    expect(resolve(defaultPopularDir())).toBe(DIR);
  });

  it.each(PKG_ECOSYSTEMS)('%s: a generated list with a provenance header and 1000-5000 names', (eco) => {
    const text = readFileSync(join(DIR, `${eco}.txt`), 'utf8');
    expect(text).toMatch(/^# source: https:\/\/packages\.ecosyste\.ms\//m);
    expect(text).toMatch(/^# generated: \d{4}-\d{2}-\d{2}\r?$/m);
    expect(text).toMatch(/^# regenerate: node mcp\/scripts\/generatePopularPackages\.mjs\r?$/m);
    const names = parsePopularList(text);
    expect(names.length).toBeGreaterThanOrEqual(1000);
    expect(names.length).toBeLessThanOrEqual(5000);
    const count = /^# count: (\d+)/m.exec(text)?.[1];
    expect(Number(count)).toBe(names.length);
    expect(new Set(names.map((n) => n.toLowerCase())).size).toBe(names.length);
  });

  it.each(PKG_ECOSYSTEMS)('%s: self-collisions stay at the measured, documented number', (eco) => {
    const index = loadPopularIndex(eco, DIR);
    expect(index).not.toBeNull();
    if (index === null) return;
    const flagged = index.names.filter((n) => findTyposquatTarget(index, n, { exemptPopular: false }) !== null);
    expect(flagged.length).toBe(SELF_COLLISIONS[eco]);
    const readme = readFileSync(join(DIR, 'README.md'), 'utf8');
    expect(readme).toContain(`| ${eco} | ${index.names.length} | ${SELF_COLLISIONS[eco]} |`);
  });

  it('a missing list loads as null (typosquat check then reports unknown)', () => {
    expect(loadPopularIndex('npm', join(DIR, 'does-not-exist'))).toBeNull();
  });
});
