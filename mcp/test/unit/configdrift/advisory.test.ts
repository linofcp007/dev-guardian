/**
 * The advisory is one line of prose, and its wording is the product.
 *
 * These assertions are about what the sentence must and must not say, not
 * about its exact phrasing, so rewording stays cheap while the three
 * distinctions stay enforced:
 *
 *   - a user who edited their own config is told nothing;
 *   - a user missing a shipped fix is told a fix may be missing, and how to
 *     get it;
 *   - a user whose file diverged is told a merge is coming, so the refresh
 *     writing a `.new` alongside is not a surprise.
 */

import { describe, expect, it } from 'vitest';
import { buildDriftAdvisory } from '../../../src/configdrift/advisory.js';
import type { DriftEntry, DriftReport } from '../../../src/configdrift/detect.js';

function entry(over: Partial<DriftEntry>): DriftEntry {
  return {
    target: '.semgrep.yml',
    source: 'semgrep/base.yml',
    state: 'in_sync',
    recorded_plugin_version: '1.7.0',
    current_plugin_version: '1.9.0',
    ...over,
  };
}

function report(entries: DriftEntry[]): DriftReport {
  return { manifest_present: true, entries };
}

describe('buildDriftAdvisory', () => {
  it('says nothing when there is no manifest', () => {
    expect(buildDriftAdvisory({ manifest_present: false, entries: [] })).toBeNull();
  });

  it('says nothing when everything is in sync', () => {
    expect(buildDriftAdvisory(report([entry({ state: 'in_sync' })]))).toBeNull();
  });

  it('says nothing when the only change is the user editing their own copy', () => {
    // Expected and correct. A warning here would be the one users learn to
    // ignore, taking the upstream_update warning down with it.
    expect(buildDriftAdvisory(report([entry({ state: 'local_edit' })]))).toBeNull();
  });

  it('says nothing about a deleted copy or an unreachable baseline', () => {
    expect(buildDriftAdvisory(report([entry({ state: 'target_missing' })]))).toBeNull();
    expect(buildDriftAdvisory(report([entry({ state: 'source_missing' })]))).toBeNull();
  });

  it('warns that a fix may be missing, and how to get it, when we shipped newer', () => {
    const line = buildDriftAdvisory(report([entry({ state: 'upstream_update' })]));
    if (line === null) throw new Error('expected an advisory for upstream_update');
    expect(line).toContain('.semgrep.yml');
    expect(line).toContain('1.7.0');
    expect(line).toContain('1.9.0');
    expect(line.toLowerCase()).toContain('fix');
    expect(line).toContain('init_project');
    expect(line).toContain('refresh');
  });

  it('is a single line — it goes into a warnings array, not a report', () => {
    const line = buildDriftAdvisory(
      report([
        entry({ state: 'upstream_update' }),
        entry({ target: '.gitleaks.toml', source: 'gitleaks/gitleaks.toml', state: 'diverged' }),
      ]),
    );
    if (line === null) throw new Error('expected an advisory');
    expect(line).not.toContain('\n');
  });

  it('words divergence differently from an upstream update, and says a merge is needed', () => {
    const diverged = buildDriftAdvisory(report([entry({ state: 'diverged' })]));
    const upstream = buildDriftAdvisory(report([entry({ state: 'upstream_update' })]));
    if (diverged === null || upstream === null) throw new Error('expected both advisories');
    expect(diverged).not.toBe(upstream);
    expect(diverged.toLowerCase()).toContain('merge');
    expect(diverged.toLowerCase()).toContain('both');
  });

  it('points at the delivered file, by name, while a merge is pending', () => {
    const line = buildDriftAdvisory(
      report([entry({ state: 'pending_merge', delivered_as: '.semgrep.yml.new' })]),
    );
    if (line === null) throw new Error('expected an advisory for pending_merge');
    expect(line).toContain('.semgrep.yml.new');
  });

  it('never presents itself as an error or a finding', () => {
    const line = buildDriftAdvisory(report([entry({ state: 'upstream_update' })]));
    if (line === null) throw new Error('expected an advisory');
    expect(line.toLowerCase()).not.toContain('error');
    expect(line.toLowerCase()).not.toContain('vulnerab');
    expect(line.toLowerCase()).not.toContain('failed');
  });
});
