/**
 * The project's own Semgrep rules — where they are, and whether it is safe to
 * hand them to Semgrep.
 *
 * ---- Why this exists -------------------------------------------------
 *
 * `init_project` writes `configs/semgrep/base.yml` into a project as
 * `.semgrep.yml` — thirteen security rules, presented to the user as the
 * baseline SAST config. **Nothing read it.** `scan_sast` ran
 * `--config=auto`, which does not pick up a project's `.semgrep.yml`, and the
 * shipped pre-commit hook ran the same flag. Measured on semgrep 1.164.0, on
 * a project holding that pack and one line of `<?php echo $_GET['name'];`:
 *
 *     --config=<the file>   1 finding (wp-unescaped-output), scanned 2
 *     --config=auto         0 findings,                      scanned 2
 *
 * The `wp-unescaped-output` rule was therefore dead twice over for
 * independent reasons — an uncompilable pattern (fixed in b51a2dc) and no
 * consumer at all — and the second only surfaced when someone went looking
 * for who read the file.
 *
 * ---- Why the manifest, and not just `.semgrep.yml` -------------------
 *
 * `.dev-guardian/configs.json` records where each shipped config was actually
 * installed. That is the honest source: the target is not required to be
 * `.semgrep.yml`, and following the record beats re-guessing a filename. The
 * conventional names are still probed, because a project can predate the
 * manifest — the same graceful-degradation rule the drift check follows.
 *
 * ---- Why every candidate is structurally checked first ---------------
 *
 * A `--config` Semgrep cannot load aborts the WHOLE run, not just that pack.
 * Measured, with `--config=auto` also present:
 *
 *     path does not exist          paths.scanned: []   exit 7
 *     malformed YAML               paths.scanned: []   exit 7
 *     valid YAML, no `rules` key   paths.scanned: []   exit 7
 *     `rules: []`                  paths.scanned: []   exit 0
 *     rule with a bad pattern      paths.scanned: 3    exit 2
 *
 * Until now a broken `.semgrep.yml` was harmless because nothing read it. The
 * moment `scan_sast` starts passing it, one stray character in a file the
 * user owns turns every SAST scan into a silent "0 findings" — the exact
 * failure shape this module was written to end. So candidates are parsed and
 * shape-checked here, and a bad one is dropped *and reported* rather than
 * passed through.
 *
 * The last row is deliberately NOT filtered: a rule that fails to compile is
 * a real scan that lost one rule, which `scan_sast` surfaces via Semgrep's
 * exit 2 rather than by refusing the config.
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { readManifest } from '../configdrift/manifest.js';

export interface ProjectSemgrepConfig {
  /** Absolute path, ready to be interpolated into `--config=`. */
  path: string;
  /** Project-relative path, for messages the user reads. */
  target: string;
  /** How we knew about it. */
  via: 'manifest' | 'convention';
}

export interface UnusableSemgrepConfig {
  target: string;
  /** Short phrase naming the defect, for a `tools_run` reason. */
  reason: string;
}

export interface ProjectSemgrepInspection {
  usable: ProjectSemgrepConfig[];
  /**
   * Candidates that exist but would abort the scan. Reported rather than
   * silently dropped — a user whose rules stopped running deserves to know
   * which file and why, and the alternative is a clean-looking scan that
   * quietly covers less than it did.
   */
  unusable: UnusableSemgrepConfig[];
}

/**
 * Filenames Semgrep users conventionally use, probed when the manifest does
 * not name one. `.yml` first so a project carrying both gets the spelling
 * `init_project` installs.
 */
const CONVENTIONAL_TARGETS = ['.semgrep.yml', '.semgrep.yaml'];

/** Manifest entries under this `configs/` prefix are Semgrep rule files. */
const SEMGREP_SOURCE_PREFIX = 'semgrep/';

export function inspectProjectSemgrepConfigs(projectPath: string): ProjectSemgrepInspection {
  const usable: ProjectSemgrepConfig[] = [];
  const unusable: UnusableSemgrepConfig[] = [];
  const seen = new Set<string>();

  for (const candidate of candidates(projectPath)) {
    const absolute = join(projectPath, candidate.target);
    const key = absolute.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);

    // A recorded target that is no longer on disk is drift, not breakage —
    // `detectConfigDrift` reports it as `target_missing` and the advisory
    // stays quiet about it, so saying it a second time here would be noise.
    if (!existsSync(absolute)) continue;

    const verdict = classify(absolute);
    if (verdict.ok) {
      usable.push({ path: absolute, target: candidate.target, via: candidate.via });
    } else {
      unusable.push({ target: candidate.target, reason: verdict.reason });
    }
  }

  return { usable, unusable };
}

/** The configs safe to pass to Semgrep. */
export function resolveProjectSemgrepConfigs(projectPath: string): ProjectSemgrepConfig[] {
  return inspectProjectSemgrepConfigs(projectPath).usable;
}

/**
 * Whether Semgrep can load this file without aborting the run.
 *
 * A non-empty top-level `rules` list is the whole check. It is not a rule
 * schema validation and does not try to be: `semgrep --validate` is a second
 * process per scan, and the failures it would catch beyond this one degrade
 * to a lost rule (exit 2, everything still scanned) rather than a lost scan.
 */
export function isLoadableSemgrepConfig(path: string): boolean {
  return classify(path).ok;
}

type Verdict = { ok: true } | { ok: false; reason: string };

function classify(path: string): Verdict {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    return { ok: false, reason: 'unreadable' };
  }
  let doc: unknown;
  try {
    doc = parseYaml(text);
  } catch {
    return { ok: false, reason: 'not valid YAML' };
  }
  if (typeof doc !== 'object' || doc === null) {
    return { ok: false, reason: 'no `rules:` list' };
  }
  const rules = (doc as Record<string, unknown>)['rules'];
  if (!Array.isArray(rules)) return { ok: false, reason: 'no `rules:` list' };
  if (rules.length === 0) {
    // Measured: Semgrep exits 0 but scans zero files for an empty rule list.
    return { ok: false, reason: 'empty `rules:` list' };
  }
  return { ok: true };
}

interface Candidate {
  target: string;
  via: ProjectSemgrepConfig['via'];
}

function candidates(projectPath: string): Candidate[] {
  const out: Candidate[] = [];
  const manifest = readManifest(projectPath);
  for (const entry of manifest?.entries ?? []) {
    if (entry.source.startsWith(SEMGREP_SOURCE_PREFIX)) {
      out.push({ target: entry.target, via: 'manifest' });
    }
  }
  for (const target of CONVENTIONAL_TARGETS) {
    out.push({ target, via: 'convention' });
  }
  return out;
}
