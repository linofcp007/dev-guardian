# `create_fix_pr` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the fixes the scanners already produced — `deps_update_plan`'s pinned version bumps and Semgrep's `--autofix` — in an isolated git worktree, prove them with a scan differential and a test differential, and open one pull request per ecosystem or scanner.

> **Checkbox audit — 2026-08-22.** These boxes were ticked retrospectively, by
> reconciling every step against the shipped code, its tests and `git log`. They
> were **not** ticked during execution, so they are an audit of the result, not a
> live record of the run. Steps whose only product is an observation ("run the
> test, expected: FAIL", "RED first", "commit with this subject") cannot be
> verified after the fact; each was ticked on the artefact it was meant to leave
> behind — the named test file, or the named commit in `git log` — never on
> evidence that anyone watched it go red.
>
> **Left unticked: Task 1, Step 3 ("Add the error code").** `'worktree_failed'`
> is not in `DOMAIN_ERROR_CODES` (`mcp/src/types.ts`). It was added there as this
> step instructs and then deliberately deleted during the task-7 review: the
> per-group result shape the feature settled on has no top-level use for it, and
> the string now names a `GroupOutcome` in `mcp/src/tools/createFixPr.ts`, which
> documents the removal and its reason. The step is therefore superseded rather
> than skipped, but the tree does not contain what it describes, so the box stays
> empty.

**Architecture:** Pure decision modules (`candidates.ts`, `testCommand.ts`) carry everything testable without git, network or scanners. Side-effecting modules (`worktree.ts`, `apply.ts`, `verify.ts`, `pr.ts`) each own one external interaction and go through the existing `runProcess`. The tool wires them together and defaults to not pushing.

**Tech Stack:** TypeScript (ESM, NodeNext), `runProcess` (execa), the local `gh` CLI, vitest. No new runtime dependencies.

## Global Constraints

Copied from the design of record (`docs/superpowers/specs/2026-08-16-create-fix-pr-design.md`) and `CLAUDE.md`:

- **Only fixes a scanner produced.** This tool never authors a patch. Sources are `deps_update_plan`'s `upgrade_command` strings and Semgrep `--autofix`.
- **Verification is double, and either half failing means no PR.** The scan differential requires the target finding **gone** *and* **no new finding**. The test differential is lazy: run the suite after the fix; only if it fails, run it on the base commit.
- **The test command is derived from the manifest, never accepted as a parameter.** An agent fills a tool's parameters from a context that includes the repository under analysis.
- **The worktree is removed on every path, including every failure path.**
- **`apply` defaults to `false`.** Commit, push and PR creation sit behind it; everything else runs regardless. A dry run leaves nothing behind — no branch, no commit, no worktree.
- **No silent caps.** Groups beyond `max_prs` are reported by name with a count and a reason.
- **Idempotency, without repeating two known defects:** an existence check that **fails** must cause a refusal, not an assumption of absence; and the search covers pull requests in **every** state, not only open ones.
- **A failed verification is `ok: true` with a verdict**, not a `DomainError`. Only "the tool could not do its job" is `ok: false`.
- **`fix_applied` stays a dead column.** No `UPDATE findings` is added; `findings` rows stay immutable.
- TypeScript: ESM `.js` import specifiers, `noUncheckedIndexedAccess`, **no `!`, no `any`** (tests too), **no new runtime dependencies**.
- **`mcp/dist/` is rebuilt and staged in the SAME commit as any `mcp/src/` change.**
- Markdownlint clean for `skills/`, `commands/` and `README.md`.

## Codebase facts the implementers need

Verified against the tree before this plan was written:

- **Calling another tool:** `TOOLS.find((t) => t.name === 'deps_update_plan')` then `await subTool.handler(input, ctx)`. Reference: `mcp/src/tools/auditExecutive.ts:114-125`.
- **`failDomain` is not a shared export.** Every tool defines it locally, four lines: `mcp/src/tools/auditExecutive.ts:302-307`, `checkToolchain.ts:144-148`, `createGithubIssues.ts`. Follow that pattern; do not invent a shared helper.
- **`UpgradeStep` is not exported** from `depsUpdatePlan.ts` (line 36, no `export`). Do not import it. Read the handler's JSON result and declare the shape locally in `fixpr/types.ts`, the way `auditExecutive` treats sub-tool results.
- **`compareFindings(from, to, cap)`** lives at `mcp/src/dashboard/delta.ts:20`, taking `{ scan_id: string; findings: readonly Finding[] }` on both sides and returning `{ delta, truncation }`.
- **`runProcess`** (`mcp/src/runners/processRunner.ts`) never throws — `reject: false`. Callers inspect `result.outcome`, which is `'completed' | 'failed' | 'cancelled' | 'output_too_large' | 'timed_out'`. `shell: false`, stdin closed.
- **`StackSnapshot`** (`mcp/src/types.ts:161`) carries `languages`, `package_managers`, `frameworks` — **no test command**. Test commands are derived from manifest files directly.
- **`DOMAIN_ERROR_CODES`** (`mcp/src/types.ts`) currently has 16 entries. Task 1 adds one.

---

## File Structure

| File | Kind | Responsibility |
| --- | --- | --- |
| `mcp/src/fixpr/types.ts` | types | Every shape this feature uses, plus the local `UpgradeStep` mirror. |
| `mcp/src/fixpr/candidates.ts` | **pure** | Findings + upgrade steps → groups of applicable fixes, ordered and capped. |
| `mcp/src/fixpr/testCommand.ts` | **pure** | Manifest contents → a derived test command, or `null`. |
| `mcp/src/fixpr/worktree.ts` | git | Create and destroy an isolated worktree; teardown on every path. |
| `mcp/src/fixpr/apply.ts` | process | Run a group's fix commands inside the worktree. |
| `mcp/src/fixpr/verify.ts` | process | The scan differential and the lazy test differential. |
| `mcp/src/fixpr/pr.ts` | git + gh | Branch, commit, push, existence checks, `gh pr create`. |
| `mcp/src/tools/createFixPr.ts` | tool | Wiring, `apply` gating, the result envelope. |
| `mcp/src/types.ts` | modify | One new `DomainErrorCode`. |

---

### Task 1: Types, the new error code, and the candidate grouping

**Files:**

- Create: `mcp/src/fixpr/types.ts`
- Create: `mcp/src/fixpr/candidates.ts`
- Modify: `mcp/src/types.ts` (add `'worktree_failed'` to `DOMAIN_ERROR_CODES`)
- Test: `mcp/test/unit/fixpr/candidates.test.ts`

**Interfaces:**

- Consumes: `Finding`, `Severity`, `SEVERITY_ORDER` from `mcp/src/types.ts`.
- Produces:

```ts
/** Mirrors depsUpdatePlan's un-exported UpgradeStep. Read from its JSON result. */
export interface UpgradeStep {
  package_name: string;
  installed_version: string;
  latest_version: string;
  classification: 'security' | 'patch' | 'minor' | 'major';
  ecosystem: 'npm' | 'pip' | 'composer' | 'cargo' | 'go' | 'rubygems' | 'dotnet' | 'unknown';
  reason?: string;
  upgrade_command: string;
}

export type FixSource = 'deps' | 'semgrep';

export interface FixCandidate {
  source: FixSource;
  /** Fingerprints this candidate is expected to resolve. */
  fingerprints: string[];
  /** Highest severity among those findings. */
  severity: Severity;
  /** For deps: the pinned upgrade command. For semgrep: null — the group runs one autofix pass. */
  command: string | null;
  /** Human label: "lodash 4.17.20 -> 4.17.21", or the rule id for semgrep. */
  label: string;
}

export interface FixGroup {
  source: FixSource;
  /** 'npm' | 'pip' | … for deps; 'semgrep' for semgrep. One PR per group. */
  key: string;
  candidates: FixCandidate[];
  /** Highest severity across the group — the ordering key. */
  severity: Severity;
  /** Deterministic: sha256 of the sorted fingerprints, first 12 hex chars. */
  hash: string;
}

export interface GroupSelection {
  selected: FixGroup[];
  /** Groups the cap excluded. NEVER silently dropped. */
  deferred: { key: string; source: FixSource; severity: Severity; finding_count: number }[];
  deferred_reason: string | null;   // null iff deferred is empty
}

export function buildGroups(input: {
  findings: readonly Finding[];
  upgradeSteps: readonly UpgradeStep[];
  sources: readonly FixSource[];
  severityMin: Severity;
}): FixGroup[];

export function selectGroups(groups: readonly FixGroup[], maxPrs: number): GroupSelection;
```

- [x] **Step 1: Write the failing test**

```ts
import { describe, expect, it } from 'vitest';
import { buildGroups, selectGroups } from '../../../src/fixpr/candidates.js';
import type { UpgradeStep } from '../../../src/fixpr/types.js';
import type { Finding } from '../../../src/types.js';

function finding(over: Partial<Finding> = {}): Finding {
  return {
    fingerprint: 'f'.repeat(64), tool: 'trivy', rule_id: 'CVE-2021-1',
    severity: 'high', category: 'security', subcategory: null,
    title: 'lodash vulnerable', message: 'm', file_path: 'package.json',
    line_start: 1, line_end: 1, snippet: null,
    fix_available: true, fix_applied: false, raw: {},
    ...over,
  } as unknown as Finding;
}

function step(over: Partial<UpgradeStep> = {}): UpgradeStep {
  return {
    package_name: 'lodash', installed_version: '4.17.20', latest_version: '4.17.21',
    classification: 'security', ecosystem: 'npm',
    upgrade_command: 'npm install lodash@4.17.21',
    ...over,
  };
}

describe('buildGroups', () => {
  it('pairs a dependency finding with its upgrade step and keeps the pinned command verbatim', () => {
    const groups = buildGroups({
      findings: [finding({ title: 'lodash vulnerable' })],
      upgradeSteps: [step()],
      sources: ['deps'], severityMin: 'high',
    });
    expect(groups).toHaveLength(1);
    expect(groups[0]?.key).toBe('npm');
    expect(groups[0]?.candidates[0]?.command).toBe('npm install lodash@4.17.21');
  });

  it('drops a finding with no fix_available rather than inventing a fix for it', () => {
    // The wrong implementation groups everything and then fails at apply time,
    // which is a much later and much more confusing place to find out.
    const groups = buildGroups({
      findings: [finding({ fix_available: false })],
      upgradeSteps: [step()], sources: ['deps'], severityMin: 'high',
    });
    expect(groups).toEqual([]);
  });

  it('honours severityMin against SEVERITY_ORDER, not alphabetically', () => {
    const groups = buildGroups({
      findings: [finding({ severity: 'medium' })],
      upgradeSteps: [step()], sources: ['deps'], severityMin: 'high',
    });
    expect(groups).toEqual([]);
  });

  it('honours the sources filter', () => {
    const groups = buildGroups({
      findings: [finding()], upgradeSteps: [step()],
      sources: ['semgrep'], severityMin: 'high',
    });
    expect(groups).toEqual([]);
  });

  it('puts each ecosystem in its own group, so one revert cannot drag another', () => {
    const groups = buildGroups({
      findings: [
        finding({ fingerprint: 'a'.repeat(64), title: 'lodash vulnerable' }),
        finding({ fingerprint: 'b'.repeat(64), title: 'requests vulnerable' }),
      ],
      upgradeSteps: [
        step(),
        step({ package_name: 'requests', ecosystem: 'pip',
          upgrade_command: 'pip install -U requests==2.32.0' }),
      ],
      sources: ['deps'], severityMin: 'high',
    });
    expect(groups.map((g) => g.key).sort()).toEqual(['npm', 'pip']);
  });

  it('gives the same findings the same hash across runs, and different findings a different one', () => {
    // The branch name is derived from this. An unstable hash means a repeat run
    // cannot recognise its own earlier branch, and idempotency is gone.
    const args = {
      upgradeSteps: [step()], sources: ['deps'] as const, severityMin: 'high' as const,
    };
    const a = buildGroups({ findings: [finding({ fingerprint: 'a'.repeat(64) })], ...args });
    const b = buildGroups({ findings: [finding({ fingerprint: 'a'.repeat(64) })], ...args });
    const c = buildGroups({ findings: [finding({ fingerprint: 'c'.repeat(64) })], ...args });
    expect(a[0]?.hash).toBe(b[0]?.hash);
    expect(a[0]?.hash).not.toBe(c[0]?.hash);
    expect(a[0]?.hash).toMatch(/^[0-9a-f]{12}$/);
  });

  it('hashes the fingerprint SET, so ordering does not change the branch name', () => {
    const two = (order: string[]) => buildGroups({
      findings: order.map((f) => finding({ fingerprint: f })),
      upgradeSteps: [step(), step({ package_name: 'axios',
        upgrade_command: 'npm install axios@1.7.0' })],
      sources: ['deps'], severityMin: 'high',
    })[0]?.hash;
    expect(two(['a'.repeat(64), 'b'.repeat(64)]))
      .toBe(two(['b'.repeat(64), 'a'.repeat(64)]));
  });
});

describe('selectGroups', () => {
  function group(key: string, severity: Finding['severity']) {
    return buildGroups({
      findings: [finding({ severity, fingerprint: key.padEnd(64, '0') })],
      upgradeSteps: [step({ ecosystem: key as UpgradeStep['ecosystem'] })],
      sources: ['deps'], severityMin: 'info',
    })[0];
  }

  it('orders by severity so the cap drops the least urgent, not an arbitrary slice', () => {
    const groups = [group('npm', 'low'), group('pip', 'critical')]
      .filter((g): g is NonNullable<typeof g> => g !== undefined);
    const sel = selectGroups(groups, 1);
    expect(sel.selected[0]?.key).toBe('pip');
  });

  it('names what the cap excluded instead of dropping it silently', () => {
    // A bounded output that does not say it is bounded reads as "this is
    // everything". The wrong implementation returns `selected` and nothing else.
    const groups = [group('npm', 'critical'), group('pip', 'high')]
      .filter((g): g is NonNullable<typeof g> => g !== undefined);
    const sel = selectGroups(groups, 1);
    expect(sel.deferred).toHaveLength(1);
    expect(sel.deferred[0]?.key).toBe('pip');
    expect(sel.deferred_reason).toMatch(/max_prs/);
  });

  it('reports no deferral when nothing was cut', () => {
    const groups = [group('npm', 'high')]
      .filter((g): g is NonNullable<typeof g> => g !== undefined);
    const sel = selectGroups(groups, 5);
    expect(sel.deferred).toEqual([]);
    expect(sel.deferred_reason).toBeNull();
  });
});
```

- [x] **Step 2: Run to verify it fails**

Run: `cd mcp && npx vitest run test/unit/fixpr/candidates.test.ts`
Expected: FAIL — cannot resolve `../../../src/fixpr/candidates.js`.

- [ ] **Step 3: Add the error code**

In `mcp/src/types.ts`, append `'worktree_failed'` to `DOMAIN_ERROR_CODES`. Append; do not reorder — other code compares against these strings.

- [x] **Step 4: Implement `types.ts` and `candidates.ts`**

Pairing a finding to an upgrade step: match on `package_name` appearing in the finding's `title` or `message`, and on the finding's `tool` being a dependency scanner (`trivy`, `npm-audit`, `wpscan`). A finding with `fix_available === false` is never a candidate. Semgrep candidates are findings whose `tool === 'semgrep'` and `fix_available === true`; they form a single group keyed `'semgrep'` with `command: null`, because one `--autofix` pass handles all of them.

The hash is `createHash('sha256').update([...fingerprints].sort().join('\n')).digest('hex').slice(0, 12)`.

- [x] **Step 5: Run to verify it passes, then the suite**

Run: `cd mcp && npx vitest run test/unit/fixpr/candidates.test.ts && npm test`
Expected: PASS.

- [x] **Step 6: Build and commit**

```bash
cd mcp && npm run build
cd .. && git add mcp/src mcp/test mcp/dist
git commit -m "feat(fixpr): fix candidates, grouped per ecosystem and capped out loud"
```

---

### Task 2: Deriving the test command

**Files:**

- Create: `mcp/src/fixpr/testCommand.ts`
- Test: `mcp/test/unit/fixpr/testCommand.test.ts`

**Interfaces:**

- Produces:

```ts
export interface DerivedTestCommand {
  command: string;
  args: string[];
  /** Where it came from — rendered into the PR body. */
  origin: string;      // e.g. 'package.json scripts.test'
}

/**
 * `files` maps a project-relative filename to its contents, for the manifests
 * that were found. The caller reads them; this stays pure.
 */
export function deriveTestCommand(files: Readonly<Record<string, string>>): DerivedTestCommand | null;

/** The manifests deriveTestCommand knows how to read. The caller reads exactly these. */
export const TEST_MANIFESTS: readonly string[];
```

- [x] **Step 1: Write the failing test**

```ts
import { describe, expect, it } from 'vitest';
import { deriveTestCommand, TEST_MANIFESTS } from '../../../src/fixpr/testCommand.js';

describe('deriveTestCommand', () => {
  it('reads scripts.test out of package.json', () => {
    const r = deriveTestCommand({
      'package.json': JSON.stringify({ scripts: { test: 'vitest run' } }),
    });
    expect(r).toEqual({ command: 'npm', args: ['test', '--silent'],
      origin: 'package.json scripts.test' });
  });

  it('returns null when package.json declares no test script', () => {
    // npm's default `test` script exits 1 with "no test specified". Running it
    // would report every project without tests as a broken build.
    expect(deriveTestCommand({ 'package.json': JSON.stringify({ scripts: { build: 'tsc' } }) }))
      .toBeNull();
  });

  it('returns null for npm\'s placeholder test script', () => {
    expect(deriveTestCommand({
      'package.json': JSON.stringify({
        scripts: { test: 'echo "Error: no test specified" && exit 1' },
      }),
    })).toBeNull();
  });

  it('derives cargo test from Cargo.toml', () => {
    expect(deriveTestCommand({ 'Cargo.toml': '[package]\nname = "x"' }))
      .toEqual({ command: 'cargo', args: ['test'], origin: 'Cargo.toml' });
  });

  it('derives go test from go.mod', () => {
    expect(deriveTestCommand({ 'go.mod': 'module x' }))
      .toEqual({ command: 'go', args: ['test', './...'], origin: 'go.mod' });
  });

  it('derives pytest from pyproject.toml only when pytest is actually configured', () => {
    expect(deriveTestCommand({ 'pyproject.toml': '[tool.pytest.ini_options]\n' }))
      .toEqual({ command: 'pytest', args: [], origin: 'pyproject.toml [tool.pytest]' });
    // A pyproject with no pytest section proves nothing about how to test it.
    expect(deriveTestCommand({ 'pyproject.toml': '[project]\nname = "x"\n' })).toBeNull();
  });

  it('returns null on unparseable JSON rather than guessing', () => {
    expect(deriveTestCommand({ 'package.json': '{not json' })).toBeNull();
  });

  it('returns null when nothing is recognised', () => {
    expect(deriveTestCommand({})).toBeNull();
    expect(deriveTestCommand({ 'Makefile': 'test:\n\techo hi' })).toBeNull();
  });

  it('lists exactly the manifests it reads, so the caller cannot drift from it', () => {
    expect([...TEST_MANIFESTS].sort())
      .toEqual(['Cargo.toml', 'go.mod', 'package.json', 'pyproject.toml']);
  });

  it('never returns a command assembled from manifest text', () => {
    // The whole reason the command is derived rather than accepted: nothing a
    // repository file CONTAINS may become something we execute. A malicious
    // scripts.test selects `npm test`; it does not become the argv.
    const r = deriveTestCommand({
      'package.json': JSON.stringify({ scripts: { test: 'rm -rf / # pwned' } }),
    });
    expect(r?.command).toBe('npm');
    expect(r?.args).toEqual(['test', '--silent']);
  });
});
```

- [x] **Step 2: Run to verify it fails**

Run: `cd mcp && npx vitest run test/unit/fixpr/testCommand.test.ts`
Expected: FAIL — module not found.

- [x] **Step 3: Implement `testCommand.ts`**

Precedence: `package.json` → `Cargo.toml` → `go.mod` → `pyproject.toml`. The last test is the load-bearing one: a manifest's *contents* select which known command to run; they never become the command. `npm test` runs whatever `scripts.test` says, which is the project's own business — but that string never reaches our argv.

- [x] **Step 4: Run to verify it passes**

Run: `cd mcp && npx vitest run test/unit/fixpr/testCommand.test.ts`
Expected: PASS.

- [x] **Step 5: Build and commit**

```bash
cd mcp && npm run build
cd .. && git add mcp/src mcp/test mcp/dist
git commit -m "feat(fixpr): derive the test command from the manifest, never from a parameter"
```

---

### Task 3: The isolated worktree

**Files:**

- Create: `mcp/src/fixpr/worktree.ts`
- Test: `mcp/test/integration/fixprWorktree.test.ts`

**Interfaces:**

```ts
export interface Worktree {
  /** Absolute path to the worktree directory. */
  path: string;
  /** The branch created inside it. */
  branch: string;
  /** Idempotent. Removes the worktree and prunes. Safe to call twice. */
  remove(): Promise<{ removed: boolean; warning: string | null }>;
}

export async function createWorktree(opts: {
  projectPath: string;
  branch: string;
  timeoutMs?: number;
}): Promise<{ ok: true; worktree: Worktree } | { ok: false; reason: string }>;
```

- [x] **Step 1: Write the failing test**

Tests run against a **real throwaway git repository** created in the system temp
directory — a mock proves nothing about `git worktree`.

```ts
import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createWorktree } from '../../src/fixpr/worktree.js';

let repo: string;

function git(...args: string[]) {
  return execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8' });
}

beforeEach(() => {
  repo = mkdtempSync(join(tmpdir(), 'fixpr-repo-'));
  execFileSync('git', ['init', '-q', '-b', 'main', repo]);
  execFileSync('git', ['-C', repo, 'config', 'user.email', 't@example.com']);
  execFileSync('git', ['-C', repo, 'config', 'user.name', 'T']);
  writeFileSync(join(repo, 'a.txt'), 'one\n');
  git('add', '.');
  git('commit', '-q', '-m', 'first');
});

afterEach(() => { rmSync(repo, { recursive: true, force: true }); });

describe('createWorktree', () => {
  it('creates a worktree on a new branch from committed HEAD', async () => {
    const r = await createWorktree({ projectPath: repo, branch: 'dev-guardian/fix-npm-abc' });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(existsSync(join(r.worktree.path, 'a.txt'))).toBe(true);
    expect(git('worktree', 'list')).toContain(r.worktree.path);
    await r.worktree.remove();
  });

  it('leaves the user\'s uncommitted work untouched and out of the worktree', async () => {
    // The whole point of branching from HEAD rather than the working tree.
    writeFileSync(join(repo, 'a.txt'), 'dirty\n');
    writeFileSync(join(repo, 'untracked.txt'), 'mine\n');
    const r = await createWorktree({ projectPath: repo, branch: 'dev-guardian/fix-npm-abc' });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(existsSync(join(r.worktree.path, 'untracked.txt'))).toBe(false);
    // and the user's tree is unchanged
    expect(git('status', '--porcelain')).toContain('a.txt');
    await r.worktree.remove();
  });

  it('removes the worktree and deregisters it', async () => {
    const r = await createWorktree({ projectPath: repo, branch: 'dev-guardian/fix-npm-abc' });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const p = r.worktree.path;
    const out = await r.worktree.remove();
    expect(out.removed).toBe(true);
    expect(existsSync(p)).toBe(false);
    // Observing the world, not the finally block.
    expect(git('worktree', 'list')).not.toContain(p);
  });

  it('removes a worktree that has uncommitted changes in it', async () => {
    // `git worktree remove` refuses a dirty worktree without --force. A fix
    // that failed halfway leaves exactly that, and it must still be removable.
    const r = await createWorktree({ projectPath: repo, branch: 'dev-guardian/fix-npm-abc' });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    writeFileSync(join(r.worktree.path, 'a.txt'), 'changed by a half-applied fix\n');
    const out = await r.worktree.remove();
    expect(out.removed).toBe(true);
    expect(git('worktree', 'list')).not.toContain(r.worktree.path);
  });

  it('is idempotent — a second remove() does not throw or report failure', async () => {
    // It is called from a finally and may already have run on the error path.
    const r = await createWorktree({ projectPath: repo, branch: 'dev-guardian/fix-npm-abc' });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    await r.worktree.remove();
    await expect(r.worktree.remove()).resolves.toEqual(
      expect.objectContaining({ removed: true }),
    );
  });

  it('refuses cleanly when the path is not a git repository', async () => {
    const notRepo = mkdtempSync(join(tmpdir(), 'fixpr-notrepo-'));
    const r = await createWorktree({ projectPath: notRepo, branch: 'x' });
    expect(r.ok).toBe(false);
    rmSync(notRepo, { recursive: true, force: true });
  });

  it('refuses when the branch already exists, rather than reusing it', async () => {
    // Reusing a branch would silently build on someone else's commits.
    git('branch', 'dev-guardian/fix-npm-abc');
    const r = await createWorktree({ projectPath: repo, branch: 'dev-guardian/fix-npm-abc' });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/exists/i);
  });
});
```

- [x] **Step 2: Run to verify it fails**

Run: `cd mcp && npx vitest run test/integration/fixprWorktree.test.ts`
Expected: FAIL — module not found.

- [x] **Step 3: Implement `worktree.ts`**

`git -C <project> worktree add -b <branch> <mkdtemp path> HEAD`, through `runProcess`.
`remove()` runs `git -C <project> worktree remove --force <path>` then
`git -C <project> worktree prune`, and returns `removed: true` when the path is
gone afterwards — including when it was already gone, which is what makes it
idempotent. A removal that leaves the path behind returns
`{ removed: false, warning }` rather than throwing.

- [x] **Step 4: Run to verify it passes**

Run: `cd mcp && npx vitest run test/integration/fixprWorktree.test.ts`
Expected: PASS.

- [x] **Step 5: Build and commit**

```bash
cd mcp && npm run build
cd .. && git add mcp/src mcp/test mcp/dist
git commit -m "feat(fixpr): an isolated worktree that is always torn down"
```

---

### Task 4: Applying a group's fixes

**Files:**

- Create: `mcp/src/fixpr/apply.ts`
- Test: `mcp/test/unit/fixpr/apply.test.ts`

**Interfaces:**

- Consumes: `FixGroup` (Task 1), `Worktree` (Task 3).
- Produces:

```ts
export interface ApplyResult {
  applied: boolean;
  /** The commands actually run, for the PR body. */
  commands: string[];
  /** Set when applied === false. */
  failure: { command: string; outcome: string; exit_code: number | null; stderr_head: string } | null;
}

export async function applyGroup(opts: {
  group: FixGroup;
  worktreePath: string;
  /** Injected so tests can supply a fake. Defaults to the real runProcess. */
  run?: typeof runProcess;
  timeoutMs?: number;
  /** True when no test command was derived, so the lockfile-only path is allowed. */
  lockfileOnly: boolean;
}): Promise<ApplyResult>;
```

- [x] **Step 1: Write the failing test**

The runner is injected, so these are unit tests with a fake — the *real* process
execution is exercised in Task 7's end-to-end test.

```ts
import { describe, expect, it } from 'vitest';
import { applyGroup } from '../../../src/fixpr/apply.js';
import type { FixGroup } from '../../../src/fixpr/types.js';

function group(over: Partial<FixGroup> = {}): FixGroup {
  return {
    source: 'deps', key: 'npm', severity: 'high', hash: 'abc123def456',
    candidates: [{ source: 'deps', fingerprints: ['a'.repeat(64)], severity: 'high',
      command: 'npm install lodash@4.17.21', label: 'lodash 4.17.20 -> 4.17.21' }],
    ...over,
  };
}

function fakeRun(script: { outcome: string; exitCode: number | null; stderr?: string }[]) {
  const calls: { command: string; args: string[] }[] = [];
  let i = 0;
  const run = async (opts: { command: string; args?: string[] }) => {
    calls.push({ command: opts.command, args: opts.args ?? [] });
    const next = script[i++] ?? { outcome: 'completed', exitCode: 0 };
    return { outcome: next.outcome, exitCode: next.exitCode,
      stdout: '', stderr: next.stderr ?? '', truncated: false };
  };
  return { run: run as never, calls };
}

describe('applyGroup', () => {
  it('splits the pinned upgrade command into argv — never through a shell', () => {
    // `runProcess` is shell:false, so a command string must be split. A version
    // string is attacker-influenced input in the sense that it comes from a
    // registry; it must never be interpolated into a command line.
    const { run, calls } = fakeRun([{ outcome: 'completed', exitCode: 0 }]);
    return applyGroup({ group: group(), worktreePath: '/w', run, lockfileOnly: false })
      .then((r) => {
        expect(r.applied).toBe(true);
        expect(calls[0]?.command).toBe('npm');
        expect(calls[0]?.args).toEqual(['install', 'lodash@4.17.21']);
      });
  });

  it('adds --package-lock-only when no test command exists, and not otherwise', async () => {
    const a = fakeRun([{ outcome: 'completed', exitCode: 0 }]);
    await applyGroup({ group: group(), worktreePath: '/w', run: a.run, lockfileOnly: true });
    expect(a.calls[0]?.args).toContain('--package-lock-only');

    const b = fakeRun([{ outcome: 'completed', exitCode: 0 }]);
    await applyGroup({ group: group(), worktreePath: '/w', run: b.run, lockfileOnly: false });
    expect(b.calls[0]?.args).not.toContain('--package-lock-only');
  });

  it('runs one semgrep --autofix pass for the whole group, not one per finding', async () => {
    const g = group({
      source: 'semgrep', key: 'semgrep',
      candidates: [
        { source: 'semgrep', fingerprints: ['a'.repeat(64)], severity: 'high',
          command: null, label: 'rule.one' },
        { source: 'semgrep', fingerprints: ['b'.repeat(64)], severity: 'high',
          command: null, label: 'rule.two' },
      ],
    });
    const { run, calls } = fakeRun([{ outcome: 'completed', exitCode: 0 }]);
    const r = await applyGroup({ group: g, worktreePath: '/w', run, lockfileOnly: false });
    expect(r.applied).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.command).toBe('semgrep');
    expect(calls[0]?.args).toContain('--autofix');
  });

  it('reports the failing command, not just "failed"', async () => {
    // "The fix failed" sends the reader nowhere. The command, the outcome, the
    // exit code and the first stderr line send them somewhere.
    const { run } = fakeRun([{ outcome: 'failed', exitCode: 1,
      stderr: 'npm ERR! 404 Not Found\nnpm ERR! more\n' }]);
    const r = await applyGroup({ group: group(), worktreePath: '/w', run, lockfileOnly: false });
    expect(r.applied).toBe(false);
    expect(r.failure?.command).toBe('npm install lodash@4.17.21');
    expect(r.failure?.exit_code).toBe(1);
    expect(r.failure?.stderr_head).toBe('npm ERR! 404 Not Found');
  });

  it('stops at the first failure instead of running the rest', async () => {
    const g = group({ candidates: [
      { source: 'deps', fingerprints: ['a'.repeat(64)], severity: 'high',
        command: 'npm install a@1', label: 'a' },
      { source: 'deps', fingerprints: ['b'.repeat(64)], severity: 'high',
        command: 'npm install b@2', label: 'b' },
    ] });
    const { run, calls } = fakeRun([
      { outcome: 'failed', exitCode: 1, stderr: 'boom\n' },
      { outcome: 'completed', exitCode: 0 },
    ]);
    const r = await applyGroup({ group: g, worktreePath: '/w', run, lockfileOnly: false });
    expect(r.applied).toBe(false);
    expect(calls).toHaveLength(1);
  });

  it('treats a timeout as a failure and says so', async () => {
    const { run } = fakeRun([{ outcome: 'timed_out', exitCode: null }]);
    const r = await applyGroup({ group: group(), worktreePath: '/w', run, lockfileOnly: false });
    expect(r.applied).toBe(false);
    expect(r.failure?.outcome).toBe('timed_out');
  });
});
```

- [x] **Step 2: Run to verify it fails**

Run: `cd mcp && npx vitest run test/unit/fixpr/apply.test.ts`
Expected: FAIL — module not found.

- [x] **Step 3: Implement `apply.ts`**

Split `upgrade_command` on whitespace into `command` + `args`; `runProcess` is
`shell: false`, so nothing is ever interpreted. For npm with `lockfileOnly`,
insert `--package-lock-only`. Semgrep groups run one pass:
`semgrep --config auto --autofix --quiet` in the worktree.

- [x] **Step 4: Run to verify it passes**

Run: `cd mcp && npx vitest run test/unit/fixpr/apply.test.ts`
Expected: PASS.

- [x] **Step 5: Build and commit**

```bash
cd mcp && npm run build
cd .. && git add mcp/src mcp/test mcp/dist
git commit -m "feat(fixpr): apply a group's fixes as argv, never through a shell"
```

---

### Task 5: The two differentials

**Files:**

- Create: `mcp/src/fixpr/verify.ts`
- Test: `mcp/test/unit/fixpr/verify.test.ts`

**Interfaces:**

- Consumes: `compareFindings` from `mcp/src/dashboard/delta.ts`; `DerivedTestCommand` (Task 2).
- Produces:

```ts
export interface ScanVerdict {
  passed: boolean;
  resolved: string[];       // fingerprints
  still_present: string[];  // targets that did not go away
  new_findings: { fingerprint: string; severity: string; title: string }[];
}

export type TestOutcome = 'passed' | 'broken_by_fix' | 'already_failing' | 'not_run';

export interface TestVerdict {
  outcome: TestOutcome;
  /** Null when outcome === 'not_run'. */
  command: string | null;
  origin: string | null;
  /** First lines of failure output, when there was a failure. */
  output_head: string | null;
}

export function judgeScan(
  targets: readonly string[],
  before: { scan_id: string; findings: readonly Finding[] },
  after: { scan_id: string; findings: readonly Finding[] },
): ScanVerdict;

export async function judgeTests(opts: {
  derived: DerivedTestCommand | null;
  worktreePath: string;
  projectPath: string;
  run?: typeof runProcess;
  timeoutMs?: number;
}): Promise<TestVerdict>;

/** A PR may be opened only when this is true. */
export function mayOpenPr(scan: ScanVerdict, tests: TestVerdict): boolean;
```

- [x] **Step 1: Write the failing test**

```ts
import { describe, expect, it } from 'vitest';
import { judgeScan, judgeTests, mayOpenPr } from '../../../src/fixpr/verify.js';
import type { Finding } from '../../../src/types.js';

function f(fingerprint: string, over: Partial<Finding> = {}): Finding {
  return {
    fingerprint, tool: 'trivy', rule_id: 'r', severity: 'high', category: 'security',
    subcategory: null, title: 't', message: 'm', file_path: 'p', line_start: 1,
    line_end: 1, snippet: null, fix_available: true, fix_applied: false, raw: {},
    ...over,
  } as unknown as Finding;
}

const A = 'a'.repeat(64), B = 'b'.repeat(64), C = 'c'.repeat(64);

describe('judgeScan', () => {
  it('passes when the target is gone and nothing new appeared', () => {
    const v = judgeScan([A],
      { scan_id: 'before', findings: [f(A), f(B)] },
      { scan_id: 'after', findings: [f(B)] });
    expect(v.passed).toBe(true);
    expect(v.resolved).toEqual([A]);
    expect(v.new_findings).toEqual([]);
  });

  it('FAILS when the target went away but something new arrived', () => {
    // The heart of the design. A bump that trades CVE-A for CVE-B is not a fix,
    // and the wrong implementation only checks that the target is resolved.
    const v = judgeScan([A],
      { scan_id: 'before', findings: [f(A)] },
      { scan_id: 'after', findings: [f(C, { title: 'new CVE' })] });
    expect(v.passed).toBe(false);
    expect(v.new_findings).toEqual([
      { fingerprint: C, severity: 'high', title: 'new CVE' },
    ]);
  });

  it('fails when the target is still present', () => {
    const v = judgeScan([A],
      { scan_id: 'before', findings: [f(A)] },
      { scan_id: 'after', findings: [f(A)] });
    expect(v.passed).toBe(false);
    expect(v.still_present).toEqual([A]);
  });

  it('requires every target to be resolved, not just one of them', () => {
    const v = judgeScan([A, B],
      { scan_id: 'before', findings: [f(A), f(B)] },
      { scan_id: 'after', findings: [f(B)] });
    expect(v.passed).toBe(false);
    expect(v.still_present).toEqual([B]);
  });
});

describe('judgeTests', () => {
  function fakeRun(results: { outcome: string; exitCode: number | null; stdout?: string }[]) {
    const calls: string[] = [];
    let i = 0;
    const run = async (opts: { command: string; cwd: string }) => {
      calls.push(opts.cwd);
      const next = results[i++] ?? { outcome: 'completed', exitCode: 0 };
      return { outcome: next.outcome, exitCode: next.exitCode,
        stdout: next.stdout ?? '', stderr: '', truncated: false };
    };
    return { run: run as never, calls };
  }

  const derived = { command: 'npm', args: ['test', '--silent'],
    origin: 'package.json scripts.test' };

  it('is not_run when no command could be derived', async () => {
    const v = await judgeTests({ derived: null, worktreePath: '/w',
      projectPath: '/p', run: fakeRun([]).run });
    expect(v.outcome).toBe('not_run');
    expect(v.command).toBeNull();
  });

  it('passes without ever touching the base commit', async () => {
    // The laziness is the point: the second run costs minutes and is only
    // needed to assign blame for a failure that has not happened.
    const { run, calls } = fakeRun([{ outcome: 'completed', exitCode: 0 }]);
    const v = await judgeTests({ derived, worktreePath: '/w', projectPath: '/p', run });
    expect(v.outcome).toBe('passed');
    expect(calls).toEqual(['/w']);
  });

  it('blames the fix only after checking the base commit was green', async () => {
    const { run, calls } = fakeRun([
      { outcome: 'failed', exitCode: 1, stdout: '3 failing\n' },   // worktree
      { outcome: 'completed', exitCode: 0 },                        // base
    ]);
    const v = await judgeTests({ derived, worktreePath: '/w', projectPath: '/p', run });
    expect(v.outcome).toBe('broken_by_fix');
    expect(calls).toEqual(['/w', '/p']);
    expect(v.output_head).toContain('3 failing');
  });

  it('does NOT blame the fix when the base commit was already red', async () => {
    // Otherwise every project with a pre-existing failure has our fix blamed
    // for it, and the report is worse than useless.
    const { run } = fakeRun([
      { outcome: 'failed', exitCode: 1 },
      { outcome: 'failed', exitCode: 1 },
    ]);
    const v = await judgeTests({ derived, worktreePath: '/w', projectPath: '/p', run });
    expect(v.outcome).toBe('already_failing');
  });

  it('treats a timed-out suite as broken_by_fix only if the base completed', async () => {
    const { run } = fakeRun([
      { outcome: 'timed_out', exitCode: null },
      { outcome: 'completed', exitCode: 0 },
    ]);
    const v = await judgeTests({ derived, worktreePath: '/w', projectPath: '/p', run });
    expect(v.outcome).toBe('broken_by_fix');
  });
});

describe('mayOpenPr', () => {
  const okScan = { passed: true, resolved: [A], still_present: [], new_findings: [] };
  const badScan = { passed: false, resolved: [], still_present: [A], new_findings: [] };
  const t = (outcome: 'passed'|'broken_by_fix'|'already_failing'|'not_run') =>
    ({ outcome, command: null, origin: null, output_head: null });

  it('opens on a passing scan with passing, absent, or pre-existing-failing tests', () => {
    expect(mayOpenPr(okScan, t('passed'))).toBe(true);
    expect(mayOpenPr(okScan, t('not_run'))).toBe(true);
    expect(mayOpenPr(okScan, t('already_failing'))).toBe(true);
  });

  it('never opens when the fix broke the tests', () => {
    expect(mayOpenPr(okScan, t('broken_by_fix'))).toBe(false);
  });

  it('never opens when the scan differential failed, whatever the tests say', () => {
    expect(mayOpenPr(badScan, t('passed'))).toBe(false);
    expect(mayOpenPr(badScan, t('not_run'))).toBe(false);
  });
});
```

- [x] **Step 2: Run to verify it fails**

Run: `cd mcp && npx vitest run test/unit/fixpr/verify.test.ts`
Expected: FAIL — module not found.

- [x] **Step 3: Implement `verify.ts`**

`judgeScan` calls `compareFindings(before, after, Number.MAX_SAFE_INTEGER)` and
derives its verdict from `delta.new_findings` and set membership. **Do not write
a second comparator.**

`judgeTests` runs the derived command in the worktree; on a non-`completed`
outcome *or* a non-zero exit it runs the same command in `projectPath` and
returns `broken_by_fix` only when that second run completed with exit 0.

- [x] **Step 4: Run to verify it passes**

Run: `cd mcp && npx vitest run test/unit/fixpr/verify.test.ts`
Expected: PASS.

- [x] **Step 5: Build and commit**

```bash
cd mcp && npm run build
cd .. && git add mcp/src mcp/test mcp/dist
git commit -m "feat(fixpr): the scan differential and the lazy test differential"
```

---

### Task 6: Branch, push, and the pull request

**Files:**

- Create: `mcp/src/fixpr/pr.ts`
- Test: `mcp/test/unit/fixpr/pr.test.ts`

**Interfaces:**

```ts
export interface PrOutcome {
  status: 'created' | 'exists' | 'refused' | 'push_failed' | 'create_failed';
  url: string | null;
  /** Always set when status !== 'created'. Names the pushed branch when one exists. */
  detail: string | null;
}

export function branchName(source: FixSource, key: string, hash: string): string;

export async function prExists(opts: {
  projectPath: string; branch: string; run?: typeof runProcess;
}): Promise<{ known: true; exists: boolean } | { known: false; reason: string }>;

export async function openPr(opts: {
  projectPath: string; worktreePath: string; branch: string;
  title: string; body: string; run?: typeof runProcess;
}): Promise<PrOutcome>;
```

- [x] **Step 1: Write the failing test**

```ts
import { describe, expect, it } from 'vitest';
import { branchName, prExists, openPr } from '../../../src/fixpr/pr.js';

function fakeRun(script: Record<string, { outcome: string; exitCode: number | null;
  stdout?: string; stderr?: string }>) {
  const calls: string[][] = [];
  const run = async (opts: { command: string; args?: string[] }) => {
    const args = opts.args ?? [];
    calls.push([opts.command, ...args]);
    // Match on a PREFIX, not a fixed arity: `git push -u origin b` must match
    // the key `git push`, and a three-token key like `gh pr create` must still
    // beat the two-token `gh pr`. Longest key first.
    const line = [opts.command, ...args].join(' ');
    const key = Object.keys(script)
      .sort((a, b) => b.length - a.length)
      .find((k) => line.startsWith(k));
    const hit = (key === undefined ? undefined : script[key])
      ?? { outcome: 'completed', exitCode: 0 };
    return { outcome: hit.outcome, exitCode: hit.exitCode,
      stdout: hit.stdout ?? '', stderr: hit.stderr ?? '', truncated: false };
  };
  return { run: run as never, calls };
}

describe('branchName', () => {
  it('is deterministic and namespaced', () => {
    expect(branchName('deps', 'npm', 'abc123def456'))
      .toBe('dev-guardian/fix-npm-abc123def456');
  });
});

describe('prExists', () => {
  it('searches every state, not just open', async () => {
    // create_github_issues searches `gh issue list`, which defaults to OPEN, so
    // a closed issue for the same finding gets re-filed. Not repeated here.
    const { run, calls } = fakeRun({
      'gh pr list': { outcome: 'completed', exitCode: 0, stdout: '[]' },
    });
    await prExists({ projectPath: '/p', branch: 'b', run });
    expect(calls[0]?.join(' ')).toContain('--state all');
  });

  it('reports NOT KNOWN when the check itself fails', async () => {
    // create_github_issues returns `false` on any non-completed outcome, so a
    // network error reads as "does not exist" and creates a duplicate. Here,
    // not knowing must be distinguishable from knowing there is nothing.
    const { run } = fakeRun({
      'gh pr list': { outcome: 'failed', exitCode: 1, stderr: 'network unreachable\n' },
    });
    const r = await prExists({ projectPath: '/p', branch: 'b', run });
    expect(r.known).toBe(false);
  });

  it('reports exists when the search returns a row', async () => {
    const { run } = fakeRun({
      'gh pr list': { outcome: 'completed', exitCode: 0, stdout: '[{"number":7}]' },
    });
    const r = await prExists({ projectPath: '/p', branch: 'b', run });
    expect(r).toEqual({ known: true, exists: true });
  });
});

describe('openPr', () => {
  const base = { projectPath: '/p', worktreePath: '/w', branch: 'dev-guardian/fix-npm-abc',
    title: 'T', body: 'B' };

  it('refuses rather than duplicating when existence cannot be determined', async () => {
    const { run, calls } = fakeRun({
      'gh pr list': { outcome: 'failed', exitCode: 1, stderr: 'boom\n' },
    });
    const r = await openPr({ ...base, run });
    expect(r.status).toBe('refused');
    expect(calls.some((c) => c.includes('push'))).toBe(false);
  });

  it('names the pushed branch when pr create fails after a successful push', async () => {
    // The one path that leaves remote state. A report that does not name the
    // branch leaves the user with an unexplained branch on their remote.
    const { run } = fakeRun({
      'gh pr list': { outcome: 'completed', exitCode: 0, stdout: '[]' },
      'gh pr create': { outcome: 'failed', exitCode: 1, stderr: 'no upstream repo\n' },
    });
    const r = await openPr({ ...base, run });
    expect(r.status).toBe('create_failed');
    expect(r.detail).toContain('dev-guardian/fix-npm-abc');
  });

  it('reports push_failed without attempting to create a PR', async () => {
    const { run, calls } = fakeRun({
      'gh pr list': { outcome: 'completed', exitCode: 0, stdout: '[]' },
      'git push': { outcome: 'failed', exitCode: 1, stderr: 'permission denied\n' },
    });
    const r = await openPr({ ...base, run });
    expect(r.status).toBe('push_failed');
    expect(calls.some((c) => c.join(' ').includes('pr create'))).toBe(false);
  });

  it('returns the URL on success', async () => {
    const { run } = fakeRun({
      'gh pr list': { outcome: 'completed', exitCode: 0, stdout: '[]' },
      'gh pr create': { outcome: 'completed', exitCode: 0,
        stdout: 'https://github.com/o/r/pull/12\n' },
    });
    const r = await openPr({ ...base, run });
    expect(r).toEqual({ status: 'created', url: 'https://github.com/o/r/pull/12',
      detail: null });
  });
});
```

- [x] **Step 2: Run to verify it fails**

Run: `cd mcp && npx vitest run test/unit/fixpr/pr.test.ts`
Expected: FAIL — module not found.

- [x] **Step 3: Implement `pr.ts`**

Order: `prExists` → refuse if `known: false` or `exists: true` → commit in the
worktree (`git -C <worktree> add -A`, then `commit -m`) → `git -C <worktree> push
-u origin <branch>` → `gh pr create --head <branch> --title --body`, run with
`cwd: projectPath`. The search is
`gh pr list --head <branch> --state all --json number --limit 5`.
The URL is the first stdout line starting with `https://`.

- [x] **Step 4: Run to verify it passes**

Run: `cd mcp && npx vitest run test/unit/fixpr/pr.test.ts`
Expected: PASS.

- [x] **Step 5: Build and commit**

```bash
cd mcp && npm run build
cd .. && git add mcp/src mcp/test mcp/dist
git commit -m "feat(fixpr): branch, push and open a PR, refusing when existence is unknown"
```

---

### Task 7: The tool

**Files:**

- Create: `mcp/src/tools/createFixPr.ts`
- Modify: `mcp/src/registerAll.ts` (register the new module, following the existing imports)
- Test: `mcp/test/integration/createFixPr.test.ts`

**Interfaces:**

- Consumes: everything from Tasks 1–6.
- Input schema:

```ts
{
  project_path: ProjectPath,                                  // from ../schemas.js
  severity_min: z.enum(['info','low','medium','high','critical']).optional(),  // default 'high'
  sources: z.array(z.enum(['deps','semgrep'])).optional(),    // default both
  max_prs: z.number().int().min(1).max(10).optional(),        // default 3
  apply: z.boolean().optional(),                              // default FALSE
}
```

- Output: `ok: true` with `{ applied, groups: GroupResult[], deferred, deferred_reason }`,
  where each `GroupResult` carries the group's key, findings, commands run, the
  `ScanVerdict`, the `TestVerdict`, and the `PrOutcome` — or `pr: null` with the
  reason when none was attempted.

- [x] **Step 1: Write the failing test**

Against a real throwaway git repository, with a **stub `gh` on `PATH`**.

```ts
import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, chmodSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDatabase } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import '../../src/registerAll.js';

let repo: string; let binDir: string; let ghLog: string;

beforeEach(() => {
  repo = mkdtempSync(join(tmpdir(), 'fixpr-tool-'));
  execFileSync('git', ['init', '-q', '-b', 'main', repo]);
  execFileSync('git', ['-C', repo, 'config', 'user.email', 't@example.com']);
  execFileSync('git', ['-C', repo, 'config', 'user.name', 'T']);
  writeFileSync(join(repo, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0' }));
  execFileSync('git', ['-C', repo, 'add', '.']);
  execFileSync('git', ['-C', repo, 'commit', '-q', '-m', 'first']);

  // A stub `gh` that records every invocation and fails loudly if asked to push.
  binDir = mkdtempSync(join(tmpdir(), 'fixpr-bin-'));
  ghLog = join(binDir, 'gh.log');
  const script = process.platform === 'win32'
    ? `@echo off\r\n>>"${ghLog}" echo %*\r\nexit /b 0\r\n`
    : `#!/bin/sh\necho "$@" >> "${ghLog}"\nexit 0\n`;
  const ghPath = join(binDir, process.platform === 'win32' ? 'gh.cmd' : 'gh');
  writeFileSync(ghPath, script);
  if (process.platform !== 'win32') chmodSync(ghPath, 0o755);
  process.env['PATH'] = `${binDir}${process.platform === 'win32' ? ';' : ':'}${process.env['PATH'] ?? ''}`;
});

afterEach(() => {
  rmSync(repo, { recursive: true, force: true });
  rmSync(binDir, { recursive: true, force: true });
});

function ctx() {
  const db = openDatabase({ inMemory: true });
  runMigrations(db);
  return { storage: new Storage(db) };
}

describe('create_fix_pr', () => {
  it('is registered', () => {
    expect(TOOLS.find((t) => t.name === 'create_fix_pr')).toBeTruthy();
  });

  it('refuses cleanly outside a git repository', async () => {
    const notRepo = mkdtempSync(join(tmpdir(), 'fixpr-notrepo-'));
    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    const res = await mod?.handler({ project_path: notRepo }, ctx() as never);
    expect(res).toMatchObject({ ok: false, error: { code: 'not_a_git_repo' } });
    rmSync(notRepo, { recursive: true, force: true });
  });

  it('with no findings, reports nothing to do and creates no worktree', async () => {
    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    const res = await mod?.handler({ project_path: repo }, ctx() as never);
    expect(res).toMatchObject({ ok: true, groups: [] });
    expect(execFileSync('git', ['-C', repo, 'worktree', 'list'], { encoding: 'utf8' })
      .trim().split('\n')).toHaveLength(1);
  });

  it('apply:false never invokes gh for push or pr create', async () => {
    // The safety story. If this ever regresses, a dry run starts publishing.
    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    await mod?.handler({ project_path: repo, apply: false }, ctx() as never);
    const log = existsSync(ghLog) ? readFileSync(ghLog, 'utf8') : '';
    expect(log).not.toMatch(/pr create/);
  });

  it('leaves no worktree behind on any path', async () => {
    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    await mod?.handler({ project_path: repo, apply: false }, ctx() as never);
    const list = execFileSync('git', ['-C', repo, 'worktree', 'list'], { encoding: 'utf8' });
    expect(list.trim().split('\n')).toHaveLength(1);
  });
});
```

- [x] **Step 2: Run to verify it fails**

Run: `cd mcp && npx vitest run test/integration/createFixPr.test.ts`
Expected: FAIL — the tool is not registered.

- [x] **Step 3: Implement `createFixPr.ts`**

Flow: resolve the project path → refuse if not a git repo (`isGitRepo` from
`mcp/src/tools/gitState.ts`) → read findings via `findings.listOpenForProject` →
call `deps_update_plan`'s handler through `TOOLS.find(...)` when `sources`
includes `deps` → `buildGroups` → `selectGroups` → for each selected group:
create the worktree, `applyGroup`, re-scan, `judgeScan`, `judgeTests`,
`mayOpenPr`, and only then — and only when `apply` is true — `openPr`. **The
worktree is removed in a `finally` per group.**

`failDomain` is defined locally in this file, four lines, matching
`auditExecutive.ts:302-307`.

The PR body states: the findings covered, the exact commands run, the scan
differential, and the test verdict — including, verbatim when the outcome is
`not_run`, **"behaviour was not verified: this project declares no test
command"**.

- [x] **Step 4: Run to verify it passes, then the suite**

Run: `cd mcp && npx vitest run test/integration/createFixPr.test.ts && npm test`
Expected: PASS.

- [x] **Step 5: Build and commit**

```bash
cd mcp && npm run build
cd .. && git add mcp/src mcp/test mcp/dist
git commit -m "feat(fixpr): the create_fix_pr tool"
```

---

### Task 8: Documentation and the gate

**Files:**

- Modify: `README.md` (EN/PT/ES), `CHANGELOG.md`, `host-rules/AGENTS.md` and its paired host files, `commands/` if a slash command is added

- [x] **Step 1: Measure the tool count and sweep every place it appears**

```bash
cd mcp && node -e "import('./dist/registerAll.js').then(()=>import('./dist/tools/index.js')).then(m=>console.log(m.TOOLS.length))"
cd .. && git grep -n "5[0-9] \(tools\|MCP\|herramientas\|ferramentas\)"
```

**This task adds one tool: the count goes 53 → 54.** Every place that states it
must change. Use no `--include` filter and search across EN/PT/ES — a previous
sweep on this repo missed files on two axes, language (a Spanish
"herramientas") and extension (files with no `.md`/`.json`).

- [x] **Step 2: Document the tool and its boundaries**

In all three README languages, `host-rules/AGENTS.md` and its paired host files:
what it does, that `apply` defaults to `false`, and the intent→tool mapping entry.

- [x] **Step 3: CHANGELOG entry carrying the limitations from design §10**

Only what a scanner already produces; `deps_update_plan`'s ecosystem gaps
(**maven and gradle unsupported**); Semgrep's autofix quality is Semgrep's, and
the scan differential will call a careless rewrite resolved; the test
differential is only as good as the project's tests; and **`fix_applied` remains
a dead column — the pull request is the record**.

- [x] **Step 4: Full verification gate**

```bash
cd mcp && npm run build
cd mcp && GUARDIAN_REQUIRE_SEMGREP=1 npm test
cd mcp && GUARDIAN_REQUIRE_SEMGREP=1 npm run test:coverage
cd .. && npx markdownlint-cli2 "skills/**/*.md" "commands/**/*.md" "README.md"
```

Semgrep is installed but **not on PATH** — `%APPDATA%\Roaming\Python\Python314\Scripts`.
The env var does **not** propagate past `&&` in a POSIX shell, so each command
carries it. Report the exact skip count (**target zero**) and all four coverage
numbers against 70/62/72/70.

- [x] **Step 5: Commit**

```bash
git add -A
git commit -m "docs(fixpr): document create_fix_pr and what it will not do"
```

---

## Self-Review Notes

Checked against the spec:

- §1 not a patch author, first git writes → Tasks 3 and 6; no patch-application
  code is introduced anywhere.
- §2 the two sources → Task 1's grouping and Task 4's application.
- §3 worktree isolation, teardown on every path → Task 3, whose tests assert
  `git worktree list` is clean rather than reading the `finally`.
- §4.1 the scan differential, both halves, reusing `compareFindings` → Task 5.
- §4.2 the derived test command and the lazy differential → Tasks 2 and 5,
  including the three-verdict table.
- §4.3 lockfile-only when no tests exist → Task 4's `lockfileOnly` flag.
- §5 branch naming and the two idempotency clauses → Tasks 1 (hash) and 6.
- §6 inputs, `apply: false`, no silent caps → Tasks 1 (`selectGroups`) and 7.
- §7 the eight failure paths → Tasks 3, 4, 6 and 7.
- §8 modules → the file structure table.
- §9 testing → the test files named in each task, including the stub `gh`.
- §10 limitations → Task 8's CHANGELOG entry.

Type consistency: `FixGroup` and `FixCandidate` are defined in Task 1 and
consumed by Tasks 4, 6 and 7. `DerivedTestCommand` is defined in Task 2 and
consumed by Task 5. `ScanVerdict`/`TestVerdict` are defined in Task 5 and
consumed by Task 7. `Worktree` is defined in Task 3 and consumed by Task 7.
`run?: typeof runProcess` is the injection point in Tasks 4, 5 and 6 alike.

One thing this plan deliberately does **not** do: it adds no `UPDATE findings`
and no new table. §10 requires `fix_applied` to stay dead, and the pull request
to be the record.
