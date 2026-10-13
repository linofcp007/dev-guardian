---
name: guardian-review
description: "Review pending changes before a PR or merge — review_pr scans the diff and records it, plus a scoped bug hunt, a quality check and a correctness / security / tests checklist, ending in a merge verdict. Not for a whole-project audit (guardian-security) or a deploy go / no-go (/guardian-release)."
---

# Guardian Review

A senior-style review before a PR, a merge or a deploy: security, bugs and quality, read against *what changed*
and *where it is going*. Respond in the user's language.

For a periodic audit with no specific change, use `guardian-security` or `guardian-quality`; for a quick scan
before a push, `/guardian-scan --unpushed`; to check that the human understands the diff's domain decisions, add
`/guardian-grill`.

## In a dev-spec-driven project

When the project has a `.specs/` folder and dev-spec-driven's tools are available, call
`spec_next_action { name: "<feature>" }` first for the feature this branch implements (`spec_status {}` lists
them). Your verdict then covers **security and quality only**: unticked tasks, the execution sign-off and spec
conformance are dev-spec-driven's (`/spec-review`, typed by the user). Closing the feature is `/spec-finish`,
which runs the project's checks — dev-guardian's gate among them when it is on (dev-spec-driven 1.29+). Say
"ready for `/spec-finish`", never "ready to merge", for a feature branch.

## Flow

### 1. The diff

Ask, or infer: against `main` (a PR), the last commit (pre-commit) or the last tag (pre-release).

```bash
git diff origin/main...HEAD     # PR
git diff --staged               # pre-commit
git diff <last-tag>..HEAD       # pre-release
```

### 2. Automated checks

1. `review_pr { project_path: "<project>", base_ref: "<base>" }` — `base_ref` defaults to `origin/HEAD`, then
   `main`, then `master`; `head_ref` to `HEAD`. It runs Semgrep (`scan_sast`'s rules) on every added, modified or
   renamed file, gitleaks on the PR's commits (`base..head`), Bandit on changed `.py` files, and Trivy when a
   dependency manifest changed. Files are read at `head` — the working tree when it is checked out, otherwise a
   temporary checkout. An unknown ref is an error, never "no changed files". `local_only: true` avoids Semgrep's
   registry.
2. Bugs and quality on **the diff's files only** (`review_pr` does not run them), with `head` checked out:
   - `bug_hunt { project_path: "<project>", scope: { diff: { base: "<base>" } } }`
   - `quality_check { project_path: "<project>", scope: { diff: { base: "<base>" } } }`

   For a pre-commit review of what is staged, `scope: { diff: { staged: true } }` in both.
3. Tests and CI: **no tool runs the tests.** Run the suite (or the affected modules' tests) yourself and check
   the CI status (`gh pr checks` when the GitHub CLI is there). Never claim "tests pass" you did not see.

### 3. Checklist

- **Correctness** — each new function makes sense for its input; obvious edge cases (empty, null, negative,
  Unicode, very large); no race or async bug; specific error handling, not a swallow-all.
- **Security** — no secret in the diff (key, password, token, URL with credentials); user input validated
  before the database, a shell or HTML; authentication / authorisation where needed; no CSP / CORS / other
  defence disabled without a reason; no sensitive data (PII, tokens) logged.
- **Tests** — the new behaviour is tested; the existing tests pass; reasonable coverage of the new code; a
  regression test for each bug the diff fixes.
- **Quality** — small functions, clear names; no commented-out code or leftover debug prints; imports used;
  consistent with the project's style.
- **Dependencies** — each new dependency is needed; licences compatible (no GPL in a closed commercial
  product); no `*` or open ranges.
- **AI / LLM features** (when the diff calls a model) — `review_pr` runs the plugin's LLM pack (model output
  reaching `eval` / `exec`, a shell or SQL; request data in the system prompt; OpenAI calls with no token limit).
  Read the rest: untrusted input (from users, documents, web pages, tool results) kept apart from the
  instructions, and model-proposed tool arguments validated; nothing the model returns executed, written to the
  database, sent to an external API or rendered as HTML unvalidated, with a limit or a human confirmation
  proportional to the possible damage; `max_tokens` set, capped retries, per-user or per-request quotas, no
  agent loop without an iteration limit.
- **Migrations / breaking changes** — reversible migrations without long locks; changed public APIs versioned
  or marked breaking; safe defaults for new configuration; a clear rollback.
- **Docs and build** — README / docs updated when public behaviour changed; a CHANGELOG entry where the project
  keeps one; reproducible builds (no `latest` base images).

### 4. Verdict

Short and direct:

```markdown
# Review: <branch> → main · <N> files · +<add> -<del>

## Verdict: 🟡 Approve with small changes
(or 🟢 Ready to merge / 🔴 Do not merge)

## Blockers 🔴
[None] or [each with a suggested fix]

## Fix before merge 🟡
- src/api/users.ts:42 — `password` goes to the log. Remove or redact it.
- migrations/0042.sql — ADD COLUMN NOT NULL on a large table with no default: it will lock.

## Nice to have 🟢
- The same validation helper appears in 3 new places — consider extracting it.

## Good work ✨
- Coverage of the orders module went from 56% to 64%.
```

### 5. Dependabot / Renovate PRs

When the PR only updates dependencies (details in `guardian-deps`): read the new version's changelog; mark it
**patch** (safe), **minor** (probably safe) or **major** (needs a manual check — find your uses of the changed
APIs); confirm the tests still pass; suggest merge, hold or manual review.

### 6. Before a deploy

The full go / no-go is `/guardian-release predeploy`. In the review, add: feature flags enabled only in staging,
new environment variables set in production, migrations (backup taken? possible lock?), monitoring for the new
endpoint, a clear rollback and smoke tests.

## Discussion, not application

By default this skill discusses and proposes; it applies nothing. When the user says "apply the fixes you
listed", apply them one at a time, showing each diff first. Offer a PR description (What · Why · Testing · Risk)
when the user writes one.

## Don't

- Approve without having read the files — a blind "ok" is worse than no review.
- Demand 100% coverage.
- Nitpick style a configured linter owns.
- Block the merge on changes outside the diff's scope.
