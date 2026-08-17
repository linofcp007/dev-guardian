# `create_fix_pr` — design of record

**Date:** 2026-08-16
**Status:** approved
**Item 7 of 7** in the dev-guardian ↔ strix gap project, and the last of them.

## 1. What this is, and what it is not

A tool that takes fixes **the scanners themselves already produced**, applies them
in an isolated git worktree, proves they worked, and opens a pull request.

It is **not** a patch author. `dev-guardian` has never written code into a user's
project and does not start here. `suggest_fix` gathers context so the *calling
model* can synthesise a patch; this tool does something narrower and more
verifiable — it applies machine-generated fixes and checks the result.

It is also the first code in this repository that **writes** through git. Every
git invocation that exists today is a read: `status --porcelain`, `rev-parse`,
`diff --name-only`, `ls-files`, `symbolic-ref`, and one `clone` into a temp dir
for auditing third-party skills. Branch, commit and push are new capability, and
the design treats them as a boundary being crossed rather than a feature being
extended.

## 2. The two fix sources

Both are fixes a tool computed, not fixes we invented.

**Dependency version bumps.** `deps_update_plan` already emits `UpgradeStep`
records carrying `package_name`, `installed_version`, `latest_version`,
`classification` and a literal `upgrade_command` with the version pinned —
`npm install lodash@4.17.21`, `pip install -U requests==2.32.0`. Nothing in the
repo executes those strings today; this tool executes them, in a worktree.

**Semgrep `--autofix`.** Already wired: the `auto_fix` input on the SAST scan
tools appends `--autofix`, and `scanToolFactory.ts:152-168` guards it behind
`isWorkingTreeClean()`. Semgrep rewrites the source in place from the `fix:`
field on a rule. This tool runs that same mechanism somewhere it cannot hurt
anyone.

Fixes are grouped and **one pull request is opened per ecosystem or scanner** —
all npm bumps together, all Semgrep rewrites together. Grouped by nature, so a
revert does not drag unrelated changes with it.

## 3. Isolation — the worktree

All work happens in a git worktree created from the project's committed `HEAD`,
in a temporary directory, on a fresh branch. The user's working tree is never
touched, read for its uncommitted state, or required to be clean.

This is a better property than the existing `auto_fix` guard, which protects the
user by **refusing to run** when the tree is dirty. Here there is nothing to
protect against: we branch from committed state, which is what a pull request is
against anyway, so uncommitted work is simply irrelevant.

**The worktree is removed on every path, including every failure path.** This is
the literal lesson from the CI feature's application runner, where a scan that
threw had to not leave the user's app running. Here: a pull request that fails
must not leave a worktree registered in the user's repository. Removal is
`git worktree remove --force` followed by `git worktree prune`, in a `finally`,
and a removal that itself fails is reported rather than swallowed.

## 4. Verification — the core of the design

A fix is not applied-and-hoped. It is applied and then **proved**, twice, and
either proof failing means no pull request.

### 4.1 The scan differential

Re-run the originating scanner inside the worktree and compare finding sets by
fingerprint. Success requires **both**:

- the target finding is **gone**, and
- **no new finding appeared**.

The second half is not decoration. A version bump that trades CVE-A for CVE-B is
not a fix, and a pull request presenting it as one is precisely the failure this
project has spent six features eliminating: something that did not happen
acquiring the appearance of having happened.

The comparison reuses `compareFindings(from, to, cap)` from
`mcp/src/dashboard/delta.ts`, which already returns `new` / `resolved` /
`unchanged` over fingerprint sets. **No second comparator is written.**

**The two halves compare on different keys, and they have to.** A fingerprint
hashes the line and the snippet, so a fix that shifts lines changes the
fingerprint of every other finding in the file. Measured: one inserted line
changed four of four. Comparing the "no new finding" half by fingerprint would
therefore mark every untouched finding as new after any Semgrep autofix,
withholding every pull request it could produce and naming pre-existing findings
as introduced.

So:

- **target resolved** — compared by **fingerprint**, because there we are asking
  about one specific finding we set out to fix;
- **no new finding** — compared by **`(rule_id, file_path)`**, which survives a
  line shift.

The cost is stated rather than hidden: a genuine *second* instance of the same
rule in the same file does not register as new. That is a real weakening, and it
is the right trade, because the alternative is a check that fires on every line
shift and therefore carries no information at all.

### 4.2 The test differential

The scan differential proves the finding is gone. It cannot prove the code still
works — a bump that breaks the build passes it. So the project's own tests run
too, and this is what makes "verified" mean something.

**The command is derived, never accepted as a parameter.** `scripts.test` in
`package.json`, `cargo test`, `go test ./...`, `pytest` — read from the manifest,
with `detect_stack`'s existing knowledge of the stack. Accepting a `test_command`
string would reopen the hazard the DAST work closed: an agent fills a tool's
parameters from a context that includes the repository under analysis, so an
injected instruction in a README would have somewhere to point. Deriving it is
both safer and more convenient.

**The differential is lazy, because a project whose tests already fail will fail
after the fix too, and blaming the bump for that would be the same dishonesty in
another costume.** Run the suite *after* the fix first; only if it fails, run it
again on the base commit to find out who broke it.

Three verdicts, three outcomes:

| After the fix | On the base commit | Outcome |
| --- | --- | --- |
| passes | *(not run)* | PR opened; the body states the suite passed |
| fails | passes | **No PR.** We broke it. The report names the failing tests |
| fails | fails | PR opened; the body states the suite **already failed before this change** and names the tests, so the reviewer does not spend time investigating us |
| no command derivable | — | PR opened; the body states **"behaviour was not verified: this project declares no test command"** |

The last row is deliberate. Plenty of projects have no tests, and refusing to
help them would make the tool useless where it is often needed most. But the
absence is **stated**, never left to be inferred from silence.

### 4.3 What this costs

Running tests requires a real dependency install in the worktree, so the
`npm install --package-lock-only` shortcut — which would update the manifest and
lockfile without materialising `node_modules` — is not available when a test
command exists. Verification goes from seconds to minutes. That is the honest
price of a proof that discriminates, and it is paid.

When **no** test command is derivable, the lockfile-only path is used, because
nothing needs the installed tree: `npm audit` and Trivy read the lockfile.

## 5. Branch naming and idempotency

The branch is deterministic: `dev-guardian/fix-<ecosystem-or-scanner>-<short-hash>`,
where the hash covers the sorted set of finding fingerprints in the group. The
same findings always produce the same branch name, so a repeat run is
recognisable.

Before pushing, the tool checks whether that branch already exists on the remote
and whether a pull request already exists for it. **Two known defects in
`create_github_issues` are not repeated here**, and this is a binding
requirement rather than an aspiration:

- That tool's `issueExistsByFingerprint` returns `false` on **any** non-completed
  `gh` outcome, so a network error reads as "does not exist" and creates a
  duplicate. Here, an existence check that **fails** causes the tool to
  **refuse**, not to assume absence. Not knowing is not the same as knowing there
  is nothing.
- That tool searches with `gh issue list`, which defaults to **open** issues, so
  a closed issue for the same finding is silently re-filed. Here the search
  covers pull requests in **every** state.

## 6. Inputs and outputs

```ts
{
  project_path?: string;
  severity_min?: 'info'|'low'|'medium'|'high'|'critical';   // default 'high'
  sources?: ('deps'|'semgrep')[];                            // default both
  max_prs?: number;                                          // 1–10, default 3
  apply?: boolean;                                           // default FALSE
}
```

**`apply` defaults to `false`, and that is the whole safety story.** Everything
expensive and everything verifiable still runs: candidates are computed, the
worktree is created, the fix is applied, the scan differential and the test
differential both execute, and the result is reported. What sits behind the flag
is only the part that leaves the machine — **commit, push and PR creation**. This
follows `observability_setup`'s existing `apply` convention and the principle
already approved for the CI work: anything outward-facing goes behind an explicit
flag. With `apply: false` the worktree is still removed at the end, so a dry run
leaves nothing behind at all — not a branch, not a commit, not a worktree.

**`max_prs` caps how many groups are opened, and the cap is never silent.** When
more groups qualify than the cap allows, each group beyond it is still reported —
its key, its source, the highest severity it covers, and how many findings it
carries — together with a reason saying the cap is why. A bounded output that
does not say it is bounded reads as "this is everything", which is the same class
of defect as the rest of this design. Groups are ordered by highest severity
covered, so the cap drops the least urgent work rather than an arbitrary slice.

The deferral carries counts rather than the findings themselves, deliberately. A
deferred group is one nothing was done to, so what a reader needs is that it
exists, what it covers, how urgent it is, and how to reach it — by re-running
with a higher `max_prs`. The findings are already addressable through
`guardian://findings/open`, and duplicating them here would bloat every result
for no decision it helps anyone make.

The return carries, per group: the findings covered, the fix commands run, the
scan differential (resolved, new), the test verdict, and either the PR URL or the
precise reason none was opened.

Transport is the local **`gh` CLI**, as `create_github_issues` already uses. No
tokens, no REST, no Octokit. This repository has never handled a GitHub
credential and does not begin here — `gh` uses the user's own local auth.

## 7. Failure paths

None of these opens a pull request, and all of them remove the worktree:

1. **Not a git repository** — refuse, with the reason.
2. **`gh` not installed** — the dry-run path still runs in full; `apply: true`
   refuses.
3. **Worktree creation failed** — refuse; nothing was created.
4. **The fix command failed** (`npm install` errored, Semgrep exited non-zero) —
   report its `outcome`, exit code and first stderr line.
5. **The scan differential failed** — report the target's state and name every
   new finding that appeared.
6. **The test differential failed and the base commit was green** — report the
   failing tests.
7. **Push failed** — report; the worktree is gone, and the local branch is named
   so nothing is orphaned silently.
8. **`gh pr create` failed after a successful push** — this is the one that
   leaves remote state. The report **names the pushed branch** so the user can
   open the pull request by hand, rather than leaving a branch on the remote with
   no explanation.

## 8. Modules

```text
mcp/src/fixpr/
  types.ts        — FixCandidate, FixGroup, ScanVerdict, TestVerdict, FixPrResult
  candidates.ts   — pure: findings + deps plan → groups of applicable fixes
  testCommand.ts  — pure: manifest + stack snapshot → a derived test command | null
  worktree.ts     — create and destroy; teardown on every path
  apply.ts        — run the fix commands inside the worktree
  verify.ts       — the scan differential and the test differential
  pr.ts           — branch, commit, push, gh pr create, existence checks
mcp/src/tools/createFixPr.ts
```

`candidates.ts` and `testCommand.ts` are pure and carry the decisions worth
testing without git, a network, or a scanner. Every external command goes through
the existing `runProcess` (`mcp/src/runners/processRunner.ts`), which already
gives timeouts, output caps, `shell: false`, and a process-tree kill on win32.

## 9. Testing

- **Pure modules** get unit tests: which findings become candidates, how they
  group, which manifest yields which test command, and what happens when none
  does.
- **The verification logic** is tested against fixture finding sets, including
  the case that matters most — the target resolved but a new finding appeared —
  asserted as *"no PR was opened"*, not merely as a boolean on a struct.
- **The worktree lifecycle** is tested against a real throwaway git repository,
  including a forced failure mid-apply, asserting `git worktree list` is clean
  afterwards. This is the appRunner lesson applied: teardown is verified by
  observing the world, not by reading the `finally`.
- **The `gh` interactions** are tested with a stub `gh` on `PATH` that returns
  scripted responses, including the two idempotency cases: an existence check
  that *fails* must refuse, and a closed PR must count as existing.
- **`apply: false` writes nothing outward.** A test runs the whole flow with a
  stub `gh` that fails loudly if invoked for `pr create` or `push`.

## 10. Limitations, stated plainly

- **Only what a scanner already produces.** Semgrep rules without a `fix:` field,
  and findings from gitleaks, bandit, jscpd, the DAST passes and the .NET tools —
  none of which set `fix_available` — are out of reach. This tool cannot fix them
  and does not pretend to.
- **`deps_update_plan`'s ecosystem coverage is inherited**, including its
  documented gaps: **maven and gradle are unsupported**.
- **Semgrep's autofix quality is Semgrep's.** We verify the outcome; we do not
  review the rewrite. A rule with a careless `fix:` produces a careless patch,
  and the scan differential will happily call it resolved.
- **A second instance of the same rule in the same file is not seen as new.**
  §4.1 explains why: fingerprints move when lines move, so the "no new finding"
  half compares by `(rule_id, file_path)`. A fix that shifts lines therefore
  cannot be distinguished from one that introduced another hit of a rule already
  firing in that file.
- **A dry run still runs the verification scan**, and that scan is scoped so it
  does not become the project’s latest scan. Nothing the tool does in dry-run
  mode may change what `guardian://findings/open` or `risk_score` report.
- **The test differential is only as good as the project's tests.** A green suite
  with no coverage of the changed code proves very little, and the tool cannot
  tell the difference.
- **`fix_applied` stays a dead column.** It is `NOT NULL DEFAULT 0` on `findings`,
  nothing has ever written `1` to it, and `findings` rows are immutable —
  keyed `(fingerprint, scan_id)` with no `UPDATE` statement anywhere in the repo.
  Recording that a fix was applied would mean either mutating history or adding a
  table. **This design does neither**, and the column stays exactly as dead as it
  was; the pull request is the record.
