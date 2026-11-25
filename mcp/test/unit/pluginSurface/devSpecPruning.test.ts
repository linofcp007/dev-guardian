/**
 * An approved test pruning, as the router's dev-spec-driven reference tells it
 * (3.17.0, the gardening round).
 *
 * dev-spec-driven 1.41 can prune a test the user approved removing; its record
 * is the protected-test accept with a `pruned: …` reason, which the feature's
 * merge summary lists. dev-guardian still sees a deleted test file or fewer
 * assertions (`guardian-test-integrity`, medium): nothing it reports is
 * silenced. The reference says where the answer is, so the model points at the
 * accept instead of asking why the test went — and that the finding is still a
 * medium: below the default `--fail-on high`, a blocker at `--fail-on medium`
 * like any other (said on both plugins' sides).
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { REPO_ROOT } from './pluginDocs.js';

const REF = readFileSync(resolve(REPO_ROOT, 'skills/guardian/references/dev-spec.md'), 'utf8');

/** The paragraph that names the pruning, whitespace runs as one space. */
const PARA = (REF.split(/\r?\n\r?\n/).find((p) => p.includes('pruned: …')) ?? '').replace(/\s+/g, ' ');

describe("the router's dev-spec reference: an approved test pruning", () => {
  it('says a test-integrity finding on a file accepted as pruned is answered by that accept', () => {
    expect(PARA).toMatch(/A test-integrity finding/);
    expect(PARA).toMatch(/merge summary lists as accepted with a `pruned: …` reason is answered by that accept/);
  });

  it('keeps the finding a medium: never blocking at the default --fail-on high, blocking at --fail-on medium', () => {
    expect(PARA).toMatch(/It stays a medium finding/);
    expect(PARA).toMatch(/`--fail-on medium` it blocks like any other medium/);
  });

  it('silences nothing: the finding is still shown', () => {
    expect(PARA).toMatch(/say so beside the finding/);
    expect(PARA).not.toMatch(/skip|ignor|not report|suppress|hide/i);
  });
});
