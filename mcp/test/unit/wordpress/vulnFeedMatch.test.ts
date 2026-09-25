/**
 * `matchInventoryAgainstFeed` — cross a {@link WpSourceInventory} against a
 * Wordfence feed excerpt and produce Findings + CVE rows, using fixture data
 * shaped exactly like the verified production-feed schema
 * (`wordfence/api/intelligence.py#get_production_vulnerability_feed_validator`).
 */

import { describe, expect, it } from 'vitest';
import {
  assessComponentCoverage,
  matchInventoryAgainstFeed,
  wordfenceMatchToFindingAndCve,
  type WordfenceFeed,
} from '../../../src/wordpress/vulnFeed.js';
import type { WpSourceInventory } from '../../../src/wordpress/sourceInventory.js';

function inventory(over: Partial<WpSourceInventory> = {}): WpSourceInventory {
  return {
    core: { version: '6.4.0' },
    plugins: [],
    themes: [],
    mu_plugins: [],
    warnings: [],
    ...over,
  };
}

const FEED: WordfenceFeed = {
  'core-vuln': {
    id: 'core-vuln',
    title: 'WordPress Core < 6.5 - XSS',
    software: [
      {
        type: 'core',
        name: 'WordPress',
        slug: 'wordpress',
        affected_versions: { r: { from_version: '0', from_inclusive: true, to_version: '6.5', to_inclusive: false } },
        patched: true,
        patched_versions: ['6.5'],
        remediation: 'Update WordPress core to version 6.5 or later.',
      },
    ],
    cve: 'CVE-2024-1111',
    cve_link: 'https://www.cve.org/CVERecord?id=CVE-2024-1111',
    cvss: { vector: 'AV:N/AC:L', score: 6.1, rating: 'Medium' },
  },
  'plugin-vuln': {
    id: 'plugin-vuln',
    title: 'Sample Plugin <= 1.0 - SQL Injection',
    software: [
      {
        type: 'plugin',
        name: 'Sample Plugin',
        slug: 'sample-plugin',
        affected_versions: { r: { from_version: '0', from_inclusive: true, to_version: '1.0', to_inclusive: true } },
        patched: true,
        patched_versions: ['1.0.1'],
        remediation: 'Update to 1.0.1 or later.',
      },
    ],
    cve: 'CVE-2024-2222',
    cvss: { vector: 'AV:N/AC:L', score: 9.8, rating: 'Critical' },
  },
  'plugin-vuln-out-of-range': {
    id: 'plugin-vuln-out-of-range',
    title: 'Sample Plugin <= 0.5 - Old bug',
    software: [
      {
        type: 'plugin',
        name: 'Sample Plugin',
        slug: 'sample-plugin',
        affected_versions: { r: { from_version: '0', from_inclusive: true, to_version: '0.5', to_inclusive: true } },
        patched: true,
        patched_versions: ['0.6'],
      },
    ],
    cve: 'CVE-2023-0000',
  },
  'theme-vuln': {
    id: 'theme-vuln',
    title: 'Sample Theme <= 2.0 - CSRF',
    software: [
      {
        type: 'theme',
        name: 'Sample Theme',
        slug: 'sample-theme',
        affected_versions: { r: { from_version: '*', from_inclusive: true, to_version: '2.0', to_inclusive: true } },
        patched: false,
        patched_versions: [],
      },
    ],
    cve: null,
  },
  'unrelated-plugin-vuln': {
    id: 'unrelated-plugin-vuln',
    title: 'Not Installed Plugin <= 9.0 - Something',
    software: [
      {
        type: 'plugin',
        name: 'Not Installed Plugin',
        slug: 'not-installed-plugin',
        affected_versions: { r: { from_version: '0', from_inclusive: true, to_version: '9.0', to_inclusive: true } },
        patched: false,
        patched_versions: [],
      },
    ],
    cve: 'CVE-2024-9999',
  },
};

describe('matchInventoryAgainstFeed', () => {
  it('matches core when the installed version falls inside an affected range', () => {
    const matches = matchInventoryAgainstFeed(inventory({ core: { version: '6.4.0' } }), FEED);
    const core = matches.filter((m) => m.componentType === 'core');
    expect(core).toHaveLength(1);
    expect(core[0]).toMatchObject({ cve: 'CVE-2024-1111', slug: 'wordpress', fixedVersion: '6.5' });
  });

  it('does not match core when the installed version is outside every range', () => {
    const matches = matchInventoryAgainstFeed(inventory({ core: { version: '6.5.0' } }), FEED);
    expect(matches.some((m) => m.componentType === 'core')).toBe(false);
  });

  it('matches an installed plugin by slug and version range', () => {
    const inv = inventory({
      plugins: [{ slug: 'sample-plugin', name: 'Sample Plugin', version: '0.9', path: '/x' }],
    });
    const matches = matchInventoryAgainstFeed(inv, FEED);
    const pluginMatches = matches.filter((m) => m.componentType === 'plugin');
    expect(pluginMatches).toHaveLength(1);
    expect(pluginMatches[0]).toMatchObject({
      slug: 'sample-plugin',
      cve: 'CVE-2024-2222',
      severity: 'critical',
      fixedVersion: '1.0.1',
    });
  });

  it('a patched-version installed plugin matches no range', () => {
    const inv = inventory({
      plugins: [{ slug: 'sample-plugin', name: 'Sample Plugin', version: '1.0.2', path: '/x' }],
    });
    const matches = matchInventoryAgainstFeed(inv, FEED);
    expect(matches.filter((m) => m.componentType === 'plugin')).toHaveLength(0);
  });

  it('matches a theme against an unbounded-from range', () => {
    const inv = inventory({
      themes: [{ slug: 'sample-theme', name: 'Sample Theme', version: '1.5', path: '/x' }],
    });
    const matches = matchInventoryAgainstFeed(inv, FEED);
    const themeMatches = matches.filter((m) => m.componentType === 'theme');
    expect(themeMatches).toHaveLength(1);
    expect(themeMatches[0]).toMatchObject({ slug: 'sample-theme', cve: null, fixedVersion: null });
  });

  it('never matches a component the inventory does not report a version for', () => {
    const inv = inventory({
      core: { version: null },
      plugins: [{ slug: 'sample-plugin', name: 'Sample Plugin', version: null, path: '/x' }],
    });
    const matches = matchInventoryAgainstFeed(inv, FEED);
    expect(matches).toHaveLength(0);
  });

  it('never matches a plugin that is not installed', () => {
    const inv = inventory({
      plugins: [{ slug: 'sample-plugin', name: 'Sample Plugin', version: '0.1', path: '/x' }],
    });
    const matches = matchInventoryAgainstFeed(inv, FEED);
    expect(matches.some((m) => m.slug === 'not-installed-plugin')).toBe(false);
  });

  // Fix round 1, item 3: mu-plugins are matched against the feed as
  // ordinary plugins (by slug), even though they are never wp.org-checked.
  it('matches a mu-plugin against the feed the same way as a regular plugin', () => {
    const inv = inventory({
      core: { version: null },
      mu_plugins: [{ slug: 'sample-plugin', name: 'Sample Plugin', version: '0.9', path: '/x' }],
    });
    const matches = matchInventoryAgainstFeed(inv, FEED);
    expect(matches).toHaveLength(1);
    expect(matches[0]).toMatchObject({ slug: 'sample-plugin', componentType: 'plugin', cve: 'CVE-2024-2222' });
  });
});

describe('assessComponentCoverage', () => {
  it('counts core + every plugin + every theme + every mu-plugin', () => {
    const inv = inventory({
      core: { version: '6.4.0' },
      plugins: [
        { slug: 'a', name: 'A', version: '1.0', path: '/a' },
        { slug: 'b', name: 'B', version: null, path: '/b' },
      ],
      themes: [{ slug: 't', name: 'T', version: null, path: '/t' }],
      mu_plugins: [{ slug: 'mu', name: 'MU', version: '1.0', path: '/mu' }],
    });

    const coverage = assessComponentCoverage(inv);

    expect(coverage.total).toBe(5); // core + a + b + t + mu
    expect(coverage.matchable).toBe(3); // core, a, mu
    expect(coverage.unmatched).toEqual(
      expect.arrayContaining([
        { type: 'plugin', slug: 'b' },
        { type: 'theme', slug: 't' },
      ]),
    );
    expect(coverage.unmatched).toHaveLength(2);
  });

  it('reports 0 matchable of N when every component is unversioned', () => {
    const inv = inventory({
      core: { version: null },
      plugins: [{ slug: 'a', name: 'A', version: null, path: '/a' }],
    });

    const coverage = assessComponentCoverage(inv);

    expect(coverage.total).toBe(2);
    expect(coverage.matchable).toBe(0);
  });

  it('reports full coverage when every component has a version', () => {
    const inv = inventory({
      core: { version: '6.4.0' },
      plugins: [{ slug: 'a', name: 'A', version: '1.0', path: '/a' }],
    });

    const coverage = assessComponentCoverage(inv);

    expect(coverage.total).toBe(2);
    expect(coverage.matchable).toBe(2);
    expect(coverage.unmatched).toEqual([]);
  });
});

describe('wordfenceMatchToFindingAndCve', () => {
  it('produces a Finding and a CVE row for a match with a CVE', () => {
    const [match] = matchInventoryAgainstFeed(
      inventory({
        core: { version: null },
        plugins: [{ slug: 'sample-plugin', name: 'Sample Plugin', version: '0.9', path: '/x' }],
      }),
      FEED,
    );
    if (match === undefined) throw new Error('expected a match');

    const { finding, cve } = wordfenceMatchToFindingAndCve(match);

    expect(finding.tool).toBe('wordfence');
    expect(finding.severity).toBe('critical');
    expect(finding.category).toBe('security');
    expect(finding.subcategory).toBe('wordpress-plugin');
    expect(finding.fix_available).toBe(true);
    expect(finding.file_path).toBe('sample-plugin@0.9');
    expect(cve).toEqual({
      cve_id: 'CVE-2024-2222',
      package_name: 'sample-plugin',
      installed_version: '0.9',
      fixed_version: '1.0.1',
      severity: 'critical',
    });
  });

  it('produces no CVE row when the vulnerability carries no CVE', () => {
    const [match] = matchInventoryAgainstFeed(
      inventory({
        core: { version: null },
        themes: [{ slug: 'sample-theme', name: 'Sample Theme', version: '1.5', path: '/x' }],
      }),
      FEED,
    );
    if (match === undefined) throw new Error('expected a match');

    const { finding, cve } = wordfenceMatchToFindingAndCve(match);

    expect(cve).toBeNull();
    expect(finding.fix_available).toBe(false);
  });
});
