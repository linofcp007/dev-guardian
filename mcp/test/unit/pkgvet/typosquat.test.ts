import { describe, expect, it } from 'vitest';

import {
  buildPopularIndex,
  damerauLevenshtein,
  findTyposquatTarget,
  normalizePackageName,
  typoThreshold,
} from '../../../src/pkgvet/typosquat.js';

describe('damerauLevenshtein (optimal string alignment, bounded)', () => {
  it('counts a transposition as one edit, not two', () => {
    expect(damerauLevenshtein('lodash', 'lodahs', 2)).toBe(1);
    expect(damerauLevenshtein('requests', 'reqeusts', 2)).toBe(1);
  });

  it('counts insertions, deletions and substitutions', () => {
    expect(damerauLevenshtein('express', 'expresss', 2)).toBe(1);
    expect(damerauLevenshtein('cross-env', 'crossenv', 2)).toBe(1);
    expect(damerauLevenshtein('kitten', 'sitting', 5)).toBe(3);
  });

  it('stops early and reports max + 1 once the bound is exceeded', () => {
    expect(damerauLevenshtein('abcdefgh', 'zyxwvuts', 2)).toBe(3);
    expect(damerauLevenshtein('short', 'a-much-longer-name', 1)).toBe(2);
  });

  it('is zero for identical strings', () => {
    expect(damerauLevenshtein('react', 'react', 2)).toBe(0);
  });
});

describe('typoThreshold — noise control by name length', () => {
  it('no check below 5 characters', () => {
    expect(typoThreshold(4)).toBe(0);
    expect(typoThreshold(1)).toBe(0);
  });
  it('distance 1 for 5-7 characters', () => {
    expect(typoThreshold(5)).toBe(1);
    expect(typoThreshold(7)).toBe(1);
  });
  it('distance 2 from 8 characters', () => {
    expect(typoThreshold(8)).toBe(2);
    expect(typoThreshold(30)).toBe(2);
  });
});

describe('normalizePackageName', () => {
  it('applies PEP 503 normalization to PyPI names', () => {
    expect(normalizePackageName('pypi', 'Typing_Extensions')).toBe('typing-extensions');
    expect(normalizePackageName('pypi', 'zope.interface')).toBe('zope-interface');
    expect(normalizePackageName('pypi', 'a__b-.c')).toBe('a-b-c');
  });
  it('lower-cases npm, Packagist and NuGet names', () => {
    expect(normalizePackageName('npm', 'JSONStream')).toBe('jsonstream');
    expect(normalizePackageName('nuget', 'Newtonsoft.Json')).toBe('newtonsoft.json');
    expect(normalizePackageName('packagist', 'Monolog/Monolog')).toBe('monolog/monolog');
  });
});

describe('findTyposquatTarget', () => {
  const npm = buildPopularIndex('npm', ['express', 'lodash', 'cross-env', '@types/node', '@aws-sdk/client-s3', 'react']);

  it('flags a near-miss of a popular name', () => {
    expect(findTyposquatTarget(npm, 'expresss')).toEqual({ similar_to: 'express', distance: 1 });
    expect(findTyposquatTarget(npm, 'lodahs')).toEqual({ similar_to: 'lodash', distance: 1 });
    expect(findTyposquatTarget(npm, 'crossenv')).toEqual({ similar_to: 'cross-env', distance: 1 });
  });

  it('never flags a name that is itself popular (exact match excluded)', () => {
    expect(findTyposquatTarget(npm, 'express')).toBeNull();
    expect(findTyposquatTarget(npm, 'EXPRESS')).toBeNull();
  });

  it('never flags names shorter than 5 characters', () => {
    const idx = buildPopularIndex('npm', ['ms', 'glob', 'chalk']);
    expect(findTyposquatTarget(idx, 'mss')).toBeNull();
    expect(findTyposquatTarget(idx, 'glb')).toBeNull();
  });

  it('allows only distance 1 for 5-7 character names', () => {
    const idx = buildPopularIndex('npm', ['chalk']);
    expect(findTyposquatTarget(idx, 'chalkk')).toEqual({ similar_to: 'chalk', distance: 1 });
    expect(findTyposquatTarget(idx, 'chakkk')).toBeNull();
  });

  it('compares an unscoped npm name only against unscoped popular names', () => {
    // `nodee` is distance 1 from `node` — but `@types/node` is scoped, and a
    // bare name is never compared against a scoped one's unscoped part.
    const idx = buildPopularIndex('npm', ['@types/node']);
    expect(findTyposquatTarget(idx, 'types-node')).toBeNull();
  });

  it('flags a scoped npm name whose SCOPE is the typo', () => {
    expect(findTyposquatTarget(npm, '@typse/node')).toEqual({ similar_to: '@types/node', distance: 1 });
  });

  it('never flags a scoped npm name against its own scope — only the scope owner can publish there', () => {
    expect(findTyposquatTarget(npm, '@aws-sdk/client-s4')).toBeNull();
  });

  it('never flags a Packagist name against the same vendor', () => {
    const idx = buildPopularIndex('packagist', ['symfony/console', 'monolog/monolog']);
    expect(findTyposquatTarget(idx, 'symfony/consolee')).toBeNull();
    expect(findTyposquatTarget(idx, 'monolgo/monolog')).toEqual({ similar_to: 'monolog/monolog', distance: 1 });
  });

  it('compares PyPI names after PEP 503 normalization', () => {
    const idx = buildPopularIndex('pypi', ['requests', 'python-dateutil']);
    expect(findTyposquatTarget(idx, 'Python_Dateutil')).toBeNull();
    expect(findTyposquatTarget(idx, 'reqeusts')).toEqual({ similar_to: 'requests', distance: 1 });
    expect(findTyposquatTarget(idx, 'python_dateutl')).toEqual({ similar_to: 'python-dateutil', distance: 1 });
  });

  it('compares NuGet ids case-insensitively', () => {
    const idx = buildPopularIndex('nuget', ['Newtonsoft.Json']);
    expect(findTyposquatTarget(idx, 'newtonsoft.json')).toBeNull();
    expect(findTyposquatTarget(idx, 'Newtonsoft.Jsom')).toEqual({ similar_to: 'newtonsoft.json', distance: 1 });
  });

  it('prefers the closest, then the most popular (earliest listed) target', () => {
    const idx = buildPopularIndex('npm', ['axios-retry', 'axios', 'axioss']);
    // `axiosss` is 1 from `axioss` and 2 from `axios` (threshold 1 at length 6-7).
    expect(findTyposquatTarget(idx, 'axiosss')).toEqual({ similar_to: 'axioss', distance: 1 });
  });

  describe('legitimate sibling families are not typos (measured on the lists themselves)', () => {
    it('only the numbers changed: a version / variant sibling', () => {
      const idx = buildPopularIndex('pypi', ['nvidia-nccl-cu12', 'uuid6']);
      expect(findTyposquatTarget(idx, 'nvidia-nccl-cu13')).toBeNull();
      expect(findTyposquatTarget(idx, 'uuid7')).toBeNull();
      const nuget = buildPopularIndex('nuget', ['Microsoft.NETFramework.ReferenceAssemblies.net472']);
      expect(findTyposquatTarget(nuget, 'Microsoft.NETFramework.ReferenceAssemblies.net48')).toBeNull();
    });

    it('an INSERTED number is still flagged — python3-dateutil was a real PyPI typosquat', () => {
      const idx = buildPopularIndex('pypi', ['python-dateutil']);
      expect(findTyposquatTarget(idx, 'python3-dateutil')).toEqual({ similar_to: 'python-dateutil', distance: 1 });
    });

    it('one short code swapped (locale / arch) is a sibling', () => {
      const idx = buildPopularIndex('nuget', ['Humanizer.Core.uk']);
      expect(findTyposquatTarget(idx, 'Humanizer.Core.sk')).toBeNull();
    });

    it('one word swapped for another at distance 2 is a different package', () => {
      const idx = buildPopularIndex('npm', ['is-stream', 'jest-diff']);
      expect(findTyposquatTarget(idx, 'zip-stream')).toBeNull();
      expect(findTyposquatTarget(idx, 'fast-diff')).toBeNull();
    });

    it('a one-edit change inside one segment is still flagged', () => {
      const idx = buildPopularIndex('npm', ['get-proto']);
      expect(findTyposquatTarget(idx, 'set-proto')).toEqual({ similar_to: 'get-proto', distance: 1 });
    });

    it('a separator-only change is still flagged (cross-env / crossenv, object-assign / object.assign)', () => {
      const idx = buildPopularIndex('npm', ['object-assign']);
      expect(findTyposquatTarget(idx, 'object.assign')).toEqual({ similar_to: 'object-assign', distance: 1 });
    });
  });

  it('can disable the popular-name exemption to measure a list against itself', () => {
    const idx = buildPopularIndex('npm', ['express', 'expresss']);
    expect(findTyposquatTarget(idx, 'express')).toBeNull();
    expect(findTyposquatTarget(idx, 'express', { exemptPopular: false })).toEqual({
      similar_to: 'expresss',
      distance: 1,
    });
  });
});
