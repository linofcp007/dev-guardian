/**
 * `buildPackList` — the `--config=` pack-list assembly extracted from
 * `bug_hunt`'s `invoke` so it is unit-testable without spawning Semgrep.
 * Same motive as `languagePacksFor` (see `bugHuntClassify.test.ts`) being
 * its own function rather than inlined.
 *
 * The local `bugfix-*.yml` rules must be in the pack list BY DEFAULT: a
 * registry pack (`p/bugs`) 404'd once and took `bug_hunt` down entirely,
 * because Semgrep aborts the WHOLE scan when any `--config` fails to load
 * (see `bugHunt.ts`'s header comment and `semgrepConfigFailure.ts`). A local
 * file cannot 404 — but it CAN be absent from a damaged or unusually pruned
 * checkout, and a `--config` pointing at a path that does not exist
 * reproduces that exact failure mode locally. So the omission path (third
 * describe block below) is exactly as load-bearing as the inclusion path.
 */
import { existsSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { describe, expect, it } from 'vitest';
import { resolveBugfixRules } from '../../../src/platform/configsDir.js';
import { BUG_HUNT_BASE_PACKS, buildPackList } from '../../../src/tools/bugHunt.js';

describe('bug_hunt config list', () => {
  it('includes the local bugfix rules by default, as an absolute path', () => {
    // Registry packs can 404 -- one did, and it took the whole tool down. A
    // local file cannot, so these rules must be in the DEFAULT set.
    const packs = buildPackList({ includeLanguagePacks: false, languages: ['typescript'] });
    const local = packs.filter((p) => p.includes('bugfix-'));
    expect(local.length).toBeGreaterThan(1);
    for (const p of local) expect(isAbsolute(p)).toBe(true);
  });

  it('the default local-rules entry is resolveBugfixRules()\'s real result, not a look-alike literal', () => {
    // A hard-coded string merely SHAPED like an absolute bugfix-js.yml path
    // would satisfy the two assertions above without ever consulting the
    // real resolver (or the real file). Pin it to the actual value AND to a
    // path that genuinely exists on disk, closing that gap.
    const packs = buildPackList({ includeLanguagePacks: false, languages: [] });
    const local = packs.filter((p) => p.includes('bugfix-'));
    expect(local).toEqual(resolveBugfixRules());
    expect(local.length).toBeGreaterThan(1);
    for (const p of local) expect(existsSync(p)).toBe(true);
  });

  it('still lists the base registry packs alongside it', () => {
    const packs = buildPackList({ includeLanguagePacks: false, languages: ['typescript'] });
    expect(packs).toEqual(expect.arrayContaining([...BUG_HUNT_BASE_PACKS]));
  });

  it('omits the local rules rather than passing a bad path when the file is missing', () => {
    // A --config pointing at a nonexistent file aborts the whole semgrep run --
    // exactly the p/bugs failure, reproduced locally.
    const packs = buildPackList({
      includeLanguagePacks: false,
      languages: ['typescript'],
      bugfixRulesPaths: [],
    });
    expect(packs.some((p) => p.includes('bugfix-'))).toBe(false);
  });

  it('passes an explicit override path through verbatim, without re-resolving it', () => {
    // Distinguishes "the field is read at all" from the default-resolution
    // tests above, which would also pass if buildPackList silently ignored
    // the field and always substituted resolveBugfixRules()'s own answer.
    const fake = '/fake/nowhere/bugfix-js.yml';
    const packs = buildPackList({
      includeLanguagePacks: false,
      languages: [],
      bugfixRulesPaths: [fake],
    });
    expect(packs).toContain(fake);
  });

  it('does not add a language pack when includeLanguagePacks is false, even for a matching language', () => {
    // Guards the extraction: this gating must survive moving the assembly
    // out of `invoke` and into buildPackList unchanged.
    const packs = buildPackList({ includeLanguagePacks: false, languages: ['python', 'go'] });
    expect(packs).not.toContain('p/python');
    expect(packs).not.toContain('p/golang');
  });

  it('adds the mapped language pack only when includeLanguagePacks is true', () => {
    const packs = buildPackList({ includeLanguagePacks: true, languages: ['python'] });
    expect(packs).toContain('p/python');
  });
});
