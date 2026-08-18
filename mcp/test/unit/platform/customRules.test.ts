/**
 * `resolveCustomSemgrepConfigs` — the reading side of `register_custom_rules`.
 *
 * This half of the feature did not exist until 2026-08-18. `register_custom_rules`
 * persisted rule paths and told callers "scan_sast / bug_hunt will then pick
 * them up"; nothing in the codebase read the key back. The only other mention
 * of it anywhere was a test asserting it had been WRITTEN — which is why a
 * suite that was green for months never noticed the feature did nothing.
 *
 * So these tests deliberately cover the read path, not the write path, and the
 * `bugHuntConfigs` / `scanSast` suites cover that the readers actually splice
 * the result into the `--config` list.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  CUSTOM_RULES_META_KEY,
  resolveCustomSemgrepConfigs,
} from '../../../src/platform/customRules.js';
import type { PluginContext } from '../../../src/context.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

/** Minimal stand-in for the one method the resolver touches. */
function ctxWith(value: unknown, throws = false): PluginContext {
  const runtimeMeta = {
    getJson<T>(key: string): T | null {
      if (throws) throw new Error('runtime_meta unreadable');
      return key === CUSTOM_RULES_META_KEY ? (value as T) : null;
    },
  };
  return { storage: { runtimeMeta } } as unknown as PluginContext;
}

function realRuleDir(): string {
  const dir = makeTempDir('guardian-customrules-');
  writeFileSync(join(dir, 'rules.yml'), 'rules: []\n');
  return dir;
}

describe('resolveCustomSemgrepConfigs', () => {
  it('returns the registered paths that exist on disk', () => {
    const a = realRuleDir();
    const b = realRuleDir();
    expect(resolveCustomSemgrepConfigs(ctxWith([a, b]))).toEqual([a, b]);
  });

  it('drops a registered path that no longer exists, rather than passing it on', () => {
    // Load-bearing, not tidiness: semgrep aborts the WHOLE scan when any
    // --config fails to resolve (exit 7, results:[], paths.scanned:[]) — the
    // same failure the retired p/bugs pack caused. A user who registers
    // `.semgrep/` and later deletes it would otherwise break every subsequent
    // scan in the project, including ones unrelated to custom rules.
    const alive = realRuleDir();
    const dead = join(makeTempDir('guardian-customrules-'), 'deleted-subdir');
    expect(resolveCustomSemgrepConfigs(ctxWith([alive, dead]))).toEqual([alive]);
  });

  it('returns [] when nothing is registered', () => {
    expect(resolveCustomSemgrepConfigs(ctxWith(null))).toEqual([]);
  });

  it('returns [] for a hand-edited non-array value instead of throwing', () => {
    expect(resolveCustomSemgrepConfigs(ctxWith('.semgrep'))).toEqual([]);
    expect(resolveCustomSemgrepConfigs(ctxWith({ paths: [] }))).toEqual([]);
  });

  it('ignores non-string and empty entries inside the array', () => {
    const alive = realRuleDir();
    expect(resolveCustomSemgrepConfigs(ctxWith([alive, '', 42, null]))).toEqual([alive]);
  });

  it('degrades to [] when runtime_meta itself throws', () => {
    // A broken DB must not take every scan down with it.
    expect(resolveCustomSemgrepConfigs(ctxWith([realRuleDir()], true))).toEqual([]);
  });

  it('nested directories are returned verbatim, not rewritten', () => {
    const parent = makeTempDir('guardian-customrules-');
    const nested = join(parent, 'deep');
    mkdirSync(nested);
    writeFileSync(join(nested, 'r.yaml'), 'rules: []\n');
    expect(resolveCustomSemgrepConfigs(ctxWith([nested]))).toEqual([nested]);
  });
});
