/**
 * End-to-end test of the REAL chain `validate_finding` exists to sit at the
 * end of: `map_attack_surface` (real Semgrep, against the in-repo
 * multi-language fixture) feeding `validate_finding` (the real `static`
 * provider) over findings seeded into the same storage instance.
 *
 * Every other test of `validate_finding`
 * (`mcp/test/integration/validateFinding.test.ts`, `mcp/test/unit/validate/*`)
 * either hand-builds an `AttackSurfaceSnapshot` or drives the pure modules
 * directly. Those prove the logic is right for the shapes it is given; this
 * file proves the two tools actually compose — that a snapshot `map_attack_
 * surface` persists from a REAL Semgrep run is one `validate_finding` can
 * read back and root a graph at, with the real path conventions (`routes[].
 * file` absolute + native-separator, `imports[]` project-relative POSIX —
 * see `staticProvider.ts`'s own doc comment on why that mismatch has already
 * caused two silent-universal-negative defects in this feature).
 *
 * ---- Both directions, measured -----------------------------------------
 *
 * The fixture (`test/fixtures/surface/apps/node-nest/`) carries two purpose-
 * built files: `orphan.util.ts`, imported by nothing and importing nothing
 * (a genuine orphan — see its own doc comment), and a three-hop chain
 * `users.controller.ts` (the route, hop 0) -> `users.service.ts` (hop 1) ->
 * `identifiers.util.ts` (hop 2) -> `slug.util.ts` (hop 3). A finding is
 * seeded in each, and the assertions below pin the verdict AND, for the
 * reachable case, the exact hop count — not just "reachable", which would
 * also pass for a chain miscounted at 2 or 4 hops.
 *
 * ---- Why the hop-count assertion parses evidence, not a field ----------
 *
 * `FindingValidation` carries no structured `hops` field — hop count is
 * folded into the human-readable evidence sentence (`staticProvider.ts`'s
 * `buildReachableEvidence`). `parseReachableEvidence` below extracts it with
 * a regexp anchored on that exact template, so a wrong hop count fails loudly
 * as a wrong NUMBER, not as a substring match that could pass by accident
 * (e.g. "1 hop" containing "1").
 *
 * ---- Same skip discipline as rulePackFixture.test.ts --------------------
 *
 * Skipped, not passed, when Semgrep is unavailable — see that file's header
 * for why `console.warn` + `return` is the wrong pattern and `it.skipIf` is
 * the right one. `GUARDIAN_REQUIRE_SEMGREP=1` turns absence into a hard
 * failure; the fixture tree is copied outside any `test/`-named path first,
 * because Semgrep's default ignore list skips those.
 */

import { cpSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';

import type { PluginContext } from '../../src/context.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { TOOLS } from '../../src/tools/index.js';
import '../../src/tools/mapAttackSurface.js';
import '../../src/tools/validateFinding.js';
import type { Finding } from '../../src/types.js';
import type { FindingValidation } from '../../src/validate/types.js';
import { okResult } from '../helpers/toolResult.js';
import { makeTempDir, cleanupTempDirs } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

afterAll(cleanupTempDirs);

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, '..', '..', '..');
const FIXTURE = resolve(here, '..', 'fixtures', 'surface', 'apps');
const SCRIPTS_DIR = resolve(ROOT, 'scripts');

const ORPHAN_FINGERPRINT = 'e2e-orphan-1';
const ORPHAN_FILE = 'node-nest/orphan.util.ts';
const THREE_HOP_FINGERPRINT = 'e2e-three-hop-1';
const THREE_HOP_FILE = 'node-nest/slug.util.ts';
const ROOT_CONTROLLER_FILE = 'node-nest/users.controller.ts';

/**
 * One helper per non-JS resolvable language, each imported DIRECTLY by a file
 * that declares routes in the same language — so the correct answer is
 * `reachable` at exactly 1 hop, and the answer a broken resolver gives is
 * `unreachable`, which is the verdict this tool must never fabricate.
 *
 * This is the regression test for the defect that shipped: `map_attack_
 * surface` fed the module-edge resolvers absolute paths while every candidate
 * they build from an import specifier is project-relative, so Python, Go and
 * Rust resolved ZERO edges. Every gate passed (JS/TS resolved, so the graph
 * was non-empty; route extraction was fine, so coverage read `ok`) and all
 * three languages came back `unreachable` with full confidence. Only an
 * assertion in each language can see it — which is why the fixture now
 * carries one resolvable intra-project import per language.
 *
 * Each arm's anchor is derived from the SPECIFIER, never from the importing
 * file's own path: a dotted Python module, a Go package directory, and a
 * Rust `crate::` path (Cargo's `src/` root). That is what makes them
 * discriminate. An anchor taken from the importing file — `./x` in JS/TS,
 * `self::x` in Rust — is already in whatever path space that file is in, so
 * it resolves in both and proves nothing about which space the resolver was
 * handed. The Rust arm was `self::`-anchored at first and had exactly that
 * blind spot.
 */
const REACHABLE_BY_LANGUAGE: { fingerprint: string; file: string; root: string }[] = [
  { fingerprint: 'e2e-py-1', file: 'pylib/textutil.py', root: 'py-fastapi/main.py' },
  { fingerprint: 'e2e-go-1', file: 'go-api/pkg/util/shout.go', root: 'go-api/main.go' },
  { fingerprint: 'e2e-rs-1', file: 'src/settings.rs', root: 'rust-actix/main.rs' },
];

/**
 * A Python file nothing imports. The NEGATIVE direction, in a language where
 * it was fabricated for every file until the resolver was fixed — so this
 * pins that `unreachable` is genuinely available in Python, and that the
 * per-language coverage gate (staticProvider gate 6) does not over-block once
 * the language resolves at least one edge.
 */
const PY_ORPHAN_FINGERPRINT = 'e2e-py-orphan-1';
const PY_ORPHAN_FILE = 'py-django/helpers.py';


/** Resolved once at collection time so `it.skipIf` reports a skip as a skip. */
const FIXTURE_PRESENT = existsSync(FIXTURE);
const SEMGREP_INSTALLED = await isInstalled('semgrep');
const SEMGREP_AVAILABLE = FIXTURE_PRESENT && SEMGREP_INSTALLED;
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

function makeContext(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: null,
    scriptsDir: SCRIPTS_DIR,
    progressNotifier: { send: () => {} } as unknown as PluginContext['progressNotifier'],
  };
}

function tool(name: string) {
  const found = TOOLS.find((t) => t.name === name);
  if (!found) throw new Error(`${name} is not registered`);
  return found;
}

function seedFinding(over: Pick<Finding, 'fingerprint' | 'file_path'>): Finding {
  return {
    tool: 'semgrep',
    severity: 'high',
    category: 'security',
    title: 'seeded for validate_finding e2e reachability check',
    fix_available: false,
    ...over,
  };
}

interface SurfaceResult {
  ok: boolean;
  snapshot_id: number | null;
  tools_run: { name: string; status: string; reason?: string }[];
}

type ValidationWithStale = FindingValidation & { stale: boolean };

interface ValidateOk {
  ok: true;
  validations: ValidationWithStale[];
  summary: { counts_by_verdict: Record<string, number> };
}

interface ValidateErr {
  ok: false;
  error: { code: string; message: string };
}

function expectOk(r: ValidateOk | ValidateErr): ValidateOk {
  if (!r.ok) throw new Error(`validate_finding refused: ${r.error.code}: ${r.error.message}`);
  return r;
}

/**
 * Pulls `{ hops, nearestFile }` out of a `reachable` verdict's first evidence
 * sentence, built by `staticProvider.ts`'s `buildReachableEvidence` as
 * `reachable in ${hopWord(hops)} via ${method} ${path} (${nearestFile})`.
 * Anchored (`^...$`), so a template change that stops emitting this exact
 * shape fails here rather than silently matching a substring.
 */
function parseReachableEvidence(v: FindingValidation): { hops: number; nearestFile: string } {
  const detail = v.evidence[0]?.detail ?? '';
  const m = /^reachable in (\d+) hops? via \S+ .+ \(([^)]+)\)$/.exec(detail);
  if (m === null) {
    throw new Error(`evidence did not match the expected "reachable in N hop(s) via..." shape: ${detail}`);
  }
  const hopsText = m[1];
  const nearestFile = m[2];
  if (hopsText === undefined || nearestFile === undefined) {
    throw new Error(`regexp matched but did not capture both groups: ${detail}`);
  }
  return { hops: Number(hopsText), nearestFile };
}

describe('E2E — the real chain: map_attack_surface then validate_finding', () => {
  // Present in every run so the gate itself is visible; only *executed* when
  // GUARDIAN_REQUIRE_SEMGREP=1 asks for it. Same reasoning as
  // rulePackFixture.test.ts's own copy of this test.
  it.runIf(REQUIRE_SEMGREP)('GUARDIAN_REQUIRE_SEMGREP=1 — this suite must be runnable', () => {
    expect(
      SEMGREP_INSTALLED,
      'GUARDIAN_REQUIRE_SEMGREP=1 but semgrep is not on PATH. On Windows it is usually in ' +
        '%APPDATA%\\Roaming\\Python\\Python3xx\\Scripts.',
    ).toBe(true);
    expect(
      FIXTURE_PRESENT,
      `GUARDIAN_REQUIRE_SEMGREP=1 but the fixture tree is missing at ${FIXTURE}.`,
    ).toBe(true);
  });

  it.skipIf(!SEMGREP_AVAILABLE)(
    'answers unreachable for a genuine orphan and reachable at exactly 3 hops for a deep import chain',
    async () => {
      // Outside any `test/` path — Semgrep's default ignore list skips those
      // (see rulePackFixture.test.ts's header for the full explanation).
      const work = makeTempDir('guardian-validate-e2e-');
      cpSync(FIXTURE, work, { recursive: true });

      const ctx = makeContext();

      // Step 1 of the real chain: a real Semgrep run persists a real
      // snapshot, with real absolute-native routes[].file and real
      // relative-POSIX imports[].
      const surface = okResult<SurfaceResult>(
        await tool('map_attack_surface').handler({ project_path: work, force: true }, ctx),
      );

      // A degraded run persists nothing and every finding below would come
      // back `no_surface_snapshot` — fail here, with a reason, rather than on
      // an opaque refusal three steps down.
      expect(surface.tools_run.map((t) => `${t.name}:${t.status}`)).toContain('semgrep:ok');
      expect(surface.snapshot_id).not.toBeNull();
      if (surface.snapshot_id === null) return;

      // Seed exactly the two findings the design's e2e requirement asks for:
      // one in a genuinely orphaned file, one three hops deep. A real SAST
      // scan is not what this test measures — the import graph and the
      // provider are — so the findings are inserted directly, the same
      // technique validateFinding.test.ts uses throughout.
      const scanId = 'e2e-sast-scan';
      ctx.storage.scans.insert({
        scan_id: scanId,
        scan_type: 'sast',
        project_path: work,
        tree_hash: 'e2e-scan-tree',
      });
      ctx.storage.findings.bulkInsert(
        [
          seedFinding({ fingerprint: ORPHAN_FINGERPRINT, file_path: ORPHAN_FILE }),
          seedFinding({ fingerprint: THREE_HOP_FINGERPRINT, file_path: THREE_HOP_FILE }),
        ].map((f) => ({ ...f, scan_id: scanId })),
      );
      ctx.storage.scans.finalize({
        scan_id: scanId,
        status: 'completed',
        tools_run: [],
        missing_tools: [],
      });

      // Step 2 of the real chain: validate_finding reads the snapshot Step 1
      // just persisted and the findings just seeded, from the SAME ctx.
      const raw = await tool('validate_finding').handler({ project_path: work }, ctx);
      const result = expectOk(raw as unknown as ValidateOk | ValidateErr);

      const byFingerprint = new Map(result.validations.map((v) => [v.fingerprint, v]));
      const orphan = byFingerprint.get(ORPHAN_FINGERPRINT);
      const threeHop = byFingerprint.get(THREE_HOP_FINGERPRINT);
      expect(orphan, `no validation for ${ORPHAN_FINGERPRINT}`).toBeDefined();
      expect(threeHop, `no validation for ${THREE_HOP_FINGERPRINT}`).toBeDefined();
      if (orphan === undefined || threeHop === undefined) return;

      /* ---- Direction 1: genuinely unreached ------------------------- */
      // The wrong-but-plausible implementation answers `unknown` here (an
      // over-cautious gate misfiring on a real, non-empty graph) or
      // `reachable` (a path-convention bug that makes every root and every
      // target fail to compare equal, which importGraph.ts's own reachFrom
      // would report as "found nowhere" — not this failure — or a resolver
      // bug that fabricates a spurious edge INTO the orphan). Exact verdict,
      // exact evidence sentence: both fail loudly against either.
      expect(orphan.verdict).toBe('unreachable');
      expect(orphan.confidence).toBe('medium'); // never 'high' — see staticProvider.ts
      expect(orphan.evidence).toEqual([
        { detail: `no route imports '${ORPHAN_FILE}', directly or transitively` },
      ]);
      expect(orphan.stale).toBe(false);

      /* ---- Direction 2: reachable at EXACTLY three hops --------------- */
      // The wrong-but-plausible implementation answers `reachable` at the
      // WRONG hop count (2 or 4 — an off-by-one in shortestDistance's
      // level-synchronous BFS, or a root/target path-convention mismatch
      // that happens to still find SOME path through an unrelated edge).
      // `toBe(3)`, not a truthy/substring check, is what catches that.
      expect(threeHop.verdict).toBe('reachable');
      const { hops, nearestFile } = parseReachableEvidence(threeHop);
      expect(hops).toBe(3);
      expect(nearestFile).toBe(ROOT_CONTROLLER_FILE);
      expect(threeHop.confidence).toBe('medium'); // hops !== 0
      expect(threeHop.stale).toBe(false);

      // Nothing else landed in either bucket — pins the batch to exactly
      // these two findings and these two verdicts, catching a stray third
      // verdict (e.g. `unknown`) that per-finding assertions alone would miss.
      expect(result.summary.counts_by_verdict).toEqual({
        reachable: 1,
        unreachable: 1,
        unknown: 0,
        confirmed: 0,
      });
    },
    6 * 60_000,
  );

  it.skipIf(!SEMGREP_AVAILABLE)(
    'answers reachable in Python, Go and Rust — not only in JS/TS',
    async () => {
      const work = makeTempDir('guardian-validate-lang-');
      cpSync(FIXTURE, work, { recursive: true });

      const ctx = makeContext();
      const surface = okResult<SurfaceResult>(
        await tool('map_attack_surface').handler({ project_path: work, force: true }, ctx),
      );
      expect(surface.tools_run.map((t) => `${t.name}:${t.status}`)).toContain('semgrep:ok');
      expect(surface.snapshot_id).not.toBeNull();
      if (surface.snapshot_id === null) return;

      const scanId = 'e2e-lang-scan';
      ctx.storage.scans.insert({
        scan_id: scanId,
        scan_type: 'sast',
        project_path: work,
        tree_hash: 'e2e-lang-tree',
      });
      ctx.storage.findings.bulkInsert(
        [
          ...REACHABLE_BY_LANGUAGE.map((c) =>
            seedFinding({ fingerprint: c.fingerprint, file_path: c.file }),
          ),
          seedFinding({ fingerprint: PY_ORPHAN_FINGERPRINT, file_path: PY_ORPHAN_FILE }),
        ].map((f) => ({ ...f, scan_id: scanId })),
      );
      ctx.storage.scans.finalize({
        scan_id: scanId,
        status: 'completed',
        tools_run: [],
        missing_tools: [],
      });

      const result = expectOk(
        (await tool('validate_finding').handler(
          { project_path: work },
          ctx,
        )) as unknown as ValidateOk | ValidateErr,
      );
      const byFingerprint = new Map(result.validations.map((v) => [v.fingerprint, v]));

      /* ---- The positive direction, once per language ------------------ */
      for (const expected of REACHABLE_BY_LANGUAGE) {
        const v = byFingerprint.get(expected.fingerprint);
        expect(v, `no validation for ${expected.fingerprint}`).toBeDefined();
        if (v === undefined) continue;
        // The exact verdict AND the exact hop count and root: "reachable" on
        // its own would also pass for a spurious edge from somewhere else.
        expect(v.verdict, `${expected.file} verdict`).toBe('reachable');
        const { hops, nearestFile } = parseReachableEvidence(v);
        expect(hops, `${expected.file} hops`).toBe(1);
        expect(nearestFile, `${expected.file} nearest route file`).toBe(expected.root);
      }

      /* ---- The negative direction, in one of those languages ---------- */
      const pyOrphan = byFingerprint.get(PY_ORPHAN_FINGERPRINT);
      expect(pyOrphan?.verdict).toBe('unreachable');
      expect(pyOrphan?.evidence).toEqual([
        { detail: `no route imports '${PY_ORPHAN_FILE}', directly or transitively` },
      ]);

      expect(result.summary.counts_by_verdict).toEqual({
        reachable: 3,
        unreachable: 1,
        unknown: 0,
        confirmed: 0,
      });
    },
    6 * 60_000,
  );
});
