# dev-guardian

[English](#english) · [Português](#português) · [Español](#español)

---

## English

All-in-one **100% open-source** plugin for Claude Code / Cowork. Handles security, bug detection and fixing, code quality, dependency management, observability, performance and compliance for any dev project. Stack-aware (Node, Python, PHP/WordPress, Go, Rust, Ruby, Java, **C# / .NET**), trilingual triggers (EN + PT + ES) — responds in the user's language.

Under the hood it ships a Claude Code plugin (13 skills + 48 slash commands) **and** an MCP server with **54 tools and 18 resources**, with persistent SQLite state for baselines, deltas and suppressions. It also vets **third-party AI skills / MCP servers / agents before you install them** — the supply-chain check for the agent ecosystem.

### Skills (Claude Code front-end)

| Skill                    | Slash command          | What it does                                              |
| ------------------------ | ---------------------- | --------------------------------------------------------- |
| `guardian`               | `/guardian`            | Main router — dispatches to the right module              |
| `guardian-init`          | `/guardian-init`       | Initial bootstrap — installs and configures everything    |
| `guardian-security`      | `/guardian-scan`       | SAST + secrets + CVEs + container + IaC                   |
| `guardian-bugfix`        | `/guardian-fix`        | Hunts and fixes implementation bugs                       |
| `guardian-quality`       | `/guardian-quality`    | Complexity, duplication, tech debt                        |
| `guardian-review`        | `/guardian-review`     | Deep pre-PR / pre-deploy review                           |
| `guardian-deps`          | `/guardian-deps`       | Renovate setup + CVE scan + supply chain                  |
| `guardian-observability` | `/guardian-observe`    | Structured logging, metrics, error tracking               |
| `guardian-performance`   | `/guardian-perf`       | Performance budgets, k6, Lighthouse                       |
| `guardian-compliance`    | `/guardian-compliance` | GDPR, licenses, SBOM, privacy policy                      |
| `guardian-scanskill`     | `/guardian-scanskill`  | Vet a 3rd-party skill / MCP server / agent before install |
| `guardian-grill`         | `/guardian-grill`      | Understanding gate — grills you on the diff before merge  |
| `guardian-improve`       | `/guardian-improve`    | Turns measured tech debt into improvement specs           |
| (combines 3 of them)     | `/guardian-audit`      | Executive report: security + quality + deps               |

You can also trigger everything via **natural language** (EN, PT or ES). Skills fire on descriptions — *"audit the project"*, *"check for vulnerabilities"*, *"before merge"*, *"audita o projeto"*, *"vê se há vulnerabilidades"*, *"antes de fazer merge"*, *"audita el proyecto"*, *"comprueba vulnerabilidades"*, *"antes del merge"*.

### MCP server (54 tools, 18 resources)

The plugin registers an MCP server on stdio that Claude Code launches automatically. The tools group into:

- **Cross-stack security** (10) — `security_scan_full`, `scan_sast`, `scan_deps`, `scan_secrets`, `scan_containers`, `scan_iac`, `deps_audit`, `bug_hunt` (Semgrep `p/r2c-bug-scan` + `p/security-audit`, plus an always-on local rule pack for JS/TS — `configs/semgrep/bugfix-js.yml`, fourteen hand-authored rules covering all six bug subcategories the tool classifies: race conditions, null/undefined safety, off-by-one, memory leaks, swallowed error handling, and two edge cases. `/guardian-fix` also names "broken happy paths" as a focus; that's a category of consequence, not a syntactic shape, so only its commonest concrete form is covered — an un-awaited mutating call inside an async function (declarations, arrow functions, class/object methods — NOT async function expressions, a Semgrep engine limitation) — and nothing covers the rest. These are Semgrep OSS pattern rules: they match syntax, not dataflow, so a bug two functions from its guard stays invisible to them, and the heuristic tier (`WARNING`/`INFO`) produces false positives by construction — `floating-mutation` matches on the method name alone, so it can't tell a real mutation like `repo.save()` from an unrelated call that just shares the name, like `ctx.save()` (Canvas 2D's synchronous state-stack push, nothing to do with persistence) — both fire identically, which is why `severity_min` exists. Python has its own pack too — `configs/semgrep/bugfix-py.yml`, ten hand-authored rules across the same six classes, each measured against the 32 Python rules `p/r2c-bug-scan` already runs and confirmed to fire where those do not. Its known gaps are stated rather than implied: there is no general "coroutine not awaited" rule (that is not expressible in Semgrep OSS — only the four named `asyncio` primitives are covered, so a forgotten `await` on your own `async def` is not caught), the Django N+1 rule matches `for` statements but not list comprehensions, does not know SQLAlchemy or Peewee, and requires the queryset inline in the `for` header — `qs = Book.objects.all()` followed by `for book in qs:` is silent, arguably the commoner shape — `toctou-exists-open` keys only on `os.path.exists`, so `os.path.isfile`, `os.path.isdir` and `pathlib.Path(p).exists()` are all silent, and `none-deref-dict-get` excludes HTTP clients by receiver name *substring*, not name, so any receiver whose name *contains* `requests`, `session`, `client`, `httpx`, `aiohttp` or `urllib` is skipped — `session_data`, `clients` and `urllib_cache` are false negatives too, not only a dict named exactly `client`. Two exclusions are worth naming as false negatives rather than leaving implied: `get-without-doesnotexist` counts a broad `except Exception:` as a guard, so an `.objects.get()` wrapped in `except Exception: pass` is silent here even though that is worse code than an unguarded `get` (the swallowing is caught separately by `except-pass`, but nothing joins the two up); and `open-without-context` never flags attribute targets, so `self.handle = open(path)` is skipped by design — its `close()` usually lives in another method, out of a syntactic rule's reach — which means a class that genuinely never closes its handle is missed, and that is the commonest way a long-lived file leak really looks. Go has one too — `configs/semgrep/bugfix-go.yml`, ten hand-authored rules across the same six classes, and Go is the language where the registry pack leaves the biggest hole: `p/r2c-bug-scan` ships 5 Go rules and only 2 land in a bug class, both integer-overflow, so `error_handling` — in the language where `if err != nil` *is* the error model — `race_condition`, `null_safety`, `memory_leak` and `edge_case` were all empty. Its gaps are stated rather than implied: there is **no goroutine-leak rule**, and **no loop-variable-capture rule** — that one was built and verified working, then deliberately excluded, because Go 1.22 made loop variables per-iteration and Semgrep cannot read `go.mod`, so on any modern module it would accuse correct code; `body-not-closed` only recognises `http.Get`, so `http.Post` and `client.Do(req)` leak identically and are not covered; `lock-without-defer` accepts any `defer mu.Unlock()` in the block, so it cannot tell a correctly scoped unlock from one deferred in the wrong branch; `err-blank-assign` fires on deliberate discards like `_ = os.Remove(tmp)` in a cleanup path, which is why it is `WARNING`; `lock-without-defer` matches the literal `Lock()`/`Unlock()` method names, not `RLock()`/`RUnlock()`, so a `sync.RWMutex` read-lock without `defer` — a common Go idiom — is entirely outside its reach; and `nil-map-write` only catches a locally `var`-declared map — a nil map arriving as a function parameter, a struct field, or a return value panics identically on write and is not covered, arguably the commoner real-world shape, the same kind of gap `open-without-context` has for attribute targets in the Python pack above. Java has one too — `configs/semgrep/bugfix-java.yml`, eight hand-authored rules across the same six classes, and Java is the emptiest language of the four: `p/r2c-bug-scan` ships 4 Java rules and **none** of them lands in a bug class — all four are equality and comparison style — so every subcategory was at zero, in the language whose most famous defect is the `NullPointerException`. Its gaps are stated rather than implied: there is **no `Integer ==` rule**, because expressing it needs type inference Semgrep OSS does not have and the attempt fired on `v == null` and on primitive comparison — a rule that flags `v == null` would be uninstalled within a day; `stream-not-closed` only recognises `new FileInputStream(...)` — and only by that simple name, so `FileOutputStream`, `FileReader`, `Socket` and every other closeable leak identically and are not covered, and so does a fully-qualified `new java.io.FileInputStream(...)`, which the pattern does not see (measured); `static-dateformat` only recognises `SimpleDateFormat`, so a shared `Calendar` or `Matcher` in a static field is not covered; `map-get-deref` cannot tell a nullable map from one whose keys are guaranteed present, so a map populated immediately above the read is still flagged; and `modify-during-iteration` only matches the enhanced-for form, so an indexed loop removing from the list it indexes has the same defect and is missed. Two rules restrict the receiver by DECLARED type, which buys precision and costs recall: `metavariable-type` matches the exact declared type with no subtyping — measured, `type: List` does **not** match a `CopyOnWriteArrayList`, which is precisely what keeps the rule off it — so `map-get-deref`, which enumerates `Map`, `HashMap`, `TreeMap`, `LinkedHashMap` and `ConcurrentHashMap`, is silent on a map behind a project interface or a generic type parameter (`<M extends Map<K,V>> … m.get(k).f()`), though a raw `Map` still fires (measured); and `modify-during-iteration`, which enumerates `List`, `ArrayList`, `LinkedList`, `Set`, `HashSet`, `LinkedHashSet` and `Collection`, is silent on a `Deque`, a `Queue`, a `SortedSet` or a project collection type. `empty-catch` honours the Checkstyle / IntelliJ convention and never fires when the exception variable is named `ignore`, `ignored` or `expected` — the flip side being that a genuinely swallowed exception escapes the rule simply by being named `ignored`. `optional-get-no-ispresent` is **WARNING, not ERROR**, and that follows the pack's own tier rule rather than bending it: ERROR is for a pattern that is a bug regardless of intent, and `o.get()` is a bug only when *unguarded*. The rule recognises guards written **inline against the same `Optional` variable** — `if (isPresent())`, an early `return` / `throw` / `continue` / `break` under `!isPresent()` or `isEmpty()`, the three ternary forms (a ternary needing its own clauses because it is a conditional *expression*, a different AST node from an `if` statement), and `if (o.filter(p).isPresent())` — and it misses **any guard that reaches the check through another method or another variable**. The concrete case is a guard delegated to a helper, `if (!present(o)) { return d; }`, which needs interprocedural analysis Semgrep OSS does not do: that shape is a false positive and always will be, which is exactly why the rule sits at WARNING instead of carrying an ever-longer exclusion list. Four false positives are accepted rather than fixed, each reproduced on correct code: `stream-not-closed` on `open(); try { … } finally { close(); }` (already the stated reason it is WARNING); `static-dateformat` on a `static final SimpleDateFormat` whose every access goes through a `synchronized` method (proving *all* accesses are synchronized is whole-program analysis, which Semgrep OSS does not do, and a shared formatter serialises every caller anyway); `loop-lte-length` on `i <= a.length` where the body guards with `i < a.length` or never indexes `a`; and `printstacktrace-only` on the one place the call is right — the fallback when the logger itself threw. **JS/TS, Python, Go and Java**: the remaining languages have no local pack yet. A hand-broken local rule file degrades instead of failing the whole scan, whether the break is invalid YAML or a single bad rule pattern), `suggest_fix`, `register_custom_rules`
- **WordPress** (9) — `scan_wordpress` (Semgrep PHP + WP rule pack + Trivy + gitleaks + PHPCS-WPCS), `wp_audit` (live install: checksums + admins + config flags via WP-CLI), `wp_vuln_check` (WPScan DB), `wp_plugin_check`, `wp_cron_audit`, `wp_rest_audit`, `wp_recommend_hardening`, `wp_describe_setup`, `bulk_audit_wordpress_sites`
- **C# / .NET** (4 dedicated + branches) — `scan_dotnet_secrets`, `dotnet_target_framework_check`, `dotnet_efcore_audit`, `dotnet_describe_setup`; `scan_sast` runs `p/csharp` + parses security-code-scan output; `deps_update_plan` runs `dotnet list package --outdated`; `observability_setup` emits Serilog + prometheus-net templates
- **Quality, deps, prioritisation** (5) — `quality_check`, `deps_update_plan`, `triage_findings`, `prioritize_findings`, `risk_score`
- **Compliance & SBOM** (5) — `compliance_check` (GDPR/RGPD), `compliance_evidence`, `generate_sbom` (Syft), `sbom_diff`, `license_compatibility`
- **Observability & perf** (3) — `observability_setup` (Pino/structlog/Monolog/Serilog + Prometheus), `health_status`, `perf_check` (k6 / Lighthouse)
- **Lifecycle / PR / governance** (11) — `init_project`, `precommit_install`, `review_pr`, `set_baseline`, `diff_scans`, `regression_alert`, `report_export` (Markdown default / branded **HTML** with dark/light toggle / **SARIF 2.1.0** / JSON), `create_github_issues`, `create_fix_pr` (applies fixes a scanner already produced — `deps_update_plan` pinned bumps, Semgrep `--autofix` — inside an isolated git worktree, proves each with a scan differential and a test run, and opens one pull request per ecosystem/scanner via the local `gh` CLI; **`apply` defaults to `false`** — a dry run still creates the worktree, applies the fix and runs both differentials, but opens no PR and leaves nothing behind, not even a branch, and its own verification scan never becomes the project's latest scan, so previewing can't repoint `guardian://findings/open` or `risk_score` either; maven and gradle bumps are out of reach, inherited from `deps_update_plan`'s own ecosystem gap; a second hit of the same rule in a file it already fixed is not seen as new — the no-new-finding check compares `(rule_id, file_path)`, not fingerprint, since a fingerprint moves whenever the fix shifts a line; and `fix_applied` never flips to `1`, a dead column on `findings` — the opened pull request is the record instead), `suppress_finding`, `audit_executive`
- **AI-agent supply chain** (1) — `scan_skill`: vet a third-party **skill / MCP server / agent before you install it**. Accepts a directory, file, `.zip`, or git/HTTP(S) URL and runs 16 threat categories (prompt injection, data exfiltration, privilege escalation, supply chain, excessive agency, output handling, system-prompt leakage, memory poisoning, tool misuse, rogue agent, trigger abuse, dangerous code, taint, signatures, MCP least-privilege, MCP tool poisoning), a **YARA-style signature engine**, taint-light source→sink, hidden-Unicode detection, and **OSV.dev** CVE lookups — rolled up into a **0-100 risk score** and a **SAFE → DO NOT INSTALL** verdict
- **Attack surface** (1) — `map_attack_surface`: static inventory of routes, env vars and declared ports across all 8 stacks, with per-language coverage reporting. Also discovers and imports OpenAPI 3.x and Swagger 2.0 documents (JSON or YAML — **Postman collections are not supported**), tags every route with its provenance (`code` or `spec`), and diffs the two: **shadow endpoints** (in the code, undocumented), **dead documentation** (documented, no code implements it) and matched routes. No spec found means no diff — `spec_diff: null`, never a diff that reports every route as undocumented — and a route whose full path cannot be resolved is never reported as a shadow endpoint or as dead documentation; how many findings were withheld for that reason is reported alongside the diff
- **Active DAST** (1) — `scan_dast`: the follow-up to `map_attack_surface` — sends real HTTP requests to an **already-running** application (never starts, builds or stops it) and checks the route inventory for reachability, anonymous access to auth-required routes, differential authorization, CORS, security headers, information disclosure, undocumented HTTP methods and off-origin redirects, plus an opt-in rate-limit burst and an optional **nuclei** pass. Safety envelope: **loopback-only** unless the caller attests `authorized_target: true`; **read-only** methods (GET/HEAD/OPTIONS) unless `allow_write_methods` is set, and even then with empty bodies, plus the opt-in `probe_rate_limit` burst — the one exception — which sends POST to exactly one route; no injection payloads, no credential guessing. The own engine does **not** test for injection — that's delegated to nuclei's `-dast` fuzzing mode, excluded by default — so **a clean result is not evidence of injection safety**, and nuclei's default template set exercises the origin, not this project's specific routes
- **Reachability** (1) — `validate_finding`: the other follow-up to `map_attack_surface` — answers, per finding, whether anything outside the process can reach the file it lives in, from a file-level import graph rooted at the route-declaring files. Returns `reachable` / `unreachable` / `unknown` per finding with concrete evidence (nearest reaching route, hop count, how many routes reach the file, any live-confirmed anonymous exposure) plus the coverage gaps behind it. **Report-only**: never suppresses a finding and never touches severity. `unreachable` is never emitted for Ruby, Java, C#, or PHP (all four resolve code at runtime, not by import). It **is** emitted — and can be wrong — for a file reached only by a CLI/cron/queue entry point, or wherever a dynamic import — `import(expr)`, `require(variable)`, reflection, a plugin registry — cannot be resolved
- **Meta / host** (3) — `detect_stack`, `check_toolchain`, `install_toolchain`

**Resources** — `guardian://wp/audit/latest`, `guardian://wp/audit/{scan_id}`, `guardian://wp/cron`, `guardian://dotnet/target-frameworks`, `guardian://dotnet/efcore`, `guardian://surface/latest`, `guardian://surface/{id}`.

**Storage** — SQLite at `.guardian/guardian.db`. Tables: `scans`, `findings`, `cves`, `baselines`, `suppressions`, `stack_snapshots`, `surface_snapshots`, `finding_validations`. Enables baseline tracking, scan-to-scan deltas, time-bounded suppressions, regression alerts.

### Guardrail hooks (auto-active)

With the plugin enabled, Claude Code auto-loads `hooks/hooks.json` — three **dependency-free, fail-open** guardrails that run in milliseconds (no native modules, never break your workflow):

- **SessionStart** — briefs the agent with the project's security posture: branch, uncommitted changes, last-scan age, and whether the project is guardian-initialized.
- **PostToolUse (Write/Edit/MultiEdit)** — scans the text just written for hard-coded secrets (AWS, GitHub, GitLab, Anthropic, OpenAI, Stripe, Google, Slack, private keys, …) and warns with a **redacted** preview. The authoritative full-history scan stays `scan_secrets` (gitleaks) via `/guardian-scan`.
- **PreToolUse (Bash)** — **denies catastrophic commands by default** (`rm -rf /`, `curl … | sh`, raw-disk `dd`/`mkfs`, fork bombs); **warns** on merely risky ones (force-push, hard reset, `sudo`, `chmod 777`).

Blocking secret *writes* is **opt-in**: set `"secrets": { "block": true }` in `.guardian/hooks.config.json`. Tune every behaviour there, allowlist false positives in `.guardian/hooks-allowlist.json`, or kill all hooks with `GUARDIAN_HOOKS=off`. The same detectors run on the CLI for terminal / CI use: `node cli/dev-guardian.mjs check --file <path>` and `--bash "<command>"` (exit 1 on a finding).

### Open-source tools orchestrated

Semgrep · Trivy · OSV.dev · gitleaks · Renovate · nuclei · Playwright · Pino / structlog / Monolog / Serilog · Prometheus + Grafana · GlitchTip · Uptime Kuma · k6 · Artillery · Lighthouse · Syft · WPScan · WP-CLI · PHPCS + WPCS · security-code-scan · dotnet-outdated · ruff · bandit · jscpd · eslint · hadolint · shellcheck.

### Plugin installation

#### A) Via marketplace (recommended) — Claude Code CLI

```text
/plugin marketplace add https://github.com/linofcp007/dev-guardian
/plugin install dev-guardian@dev-guardian
```

Works with any git URL (HTTPS or SSH) or local folder path containing [`.claude-plugin/marketplace.json`](.claude-plugin/marketplace.json).

> ⚠️ **Claude Desktop app limitation.** The Desktop client currently rejects third-party marketplaces with `External plugin sources are not yet supported` (the feature is gated server-side). This is a Claude Desktop limitation, not a problem with this plugin — installing from any GitHub-hosted marketplace fails the same way today. Tracking issues: [anthropics/claude-code#41653](https://github.com/anthropics/claude-code/issues/41653) (remote sources), [anthropics/claude-code#52147](https://github.com/anthropics/claude-code/issues/52147) (local paths). Until parity ships, use option **B** below or install via the Claude Code CLI.

#### B) Manual folder copy (works everywhere)

Copy the whole folder to:

- **Linux / macOS**: `~/.claude/plugins/dev-guardian/`
- **Windows**: `%USERPROFILE%\.claude\plugins\dev-guardian\`

Then inside Claude Code, run `/plugin` and enable `dev-guardian`. Alternatively, add to your `~/.claude/settings.json`:

```json
{
  "enabledPlugins": { "dev-guardian@dev-guardian": true }
}
```

> The MCP server runs from `mcp/dist/`. On first install run `cd mcp && npm install && npm run build` once. The plugin manifest then launches it automatically via `node ${CLAUDE_PLUGIN_ROOT}/mcp/dist/server.js`.
>
> `.sh` scripts in `scripts/` run natively on Linux/macOS. On Windows native you need **WSL2** or Git Bash; the skills/commands themselves work on any OS.

### Other AI hosts (Cursor · Windsurf · Copilot · Codex · Gemini · Cline · Claude Desktop)

The real engine is the **MCP server**, so any MCP-capable host can use dev-guardian — not just Claude Code. The **`mcp-config` CLI** wires a host up from a plain terminal — no MCP connection needed (no chicken-and-egg). It fills in the absolute path to the server for you, and either prints the block to paste or, with `--write`, merges it into the project and drops the rules file. Idempotent.

From a terminal in your project (after `cd mcp && npm install && npm run build` once):

```text
node cli/dev-guardian.mjs mcp-config cursor          # print the block to paste
node cli/dev-guardian.mjs mcp-config all             # every host
node cli/dev-guardian.mjs mcp-config codex --write   # write + merge into the project
node cli/dev-guardian.mjs mcp-config all --scope global
```

| Host | MCP config file (project / global) | Rules file |
| ---- | ---------------------------------- | ---------- |
| **Cursor** | `.cursor/mcp.json` / `~/.cursor/mcp.json` | `.cursor/rules/dev-guardian.mdc` |
| **Windsurf** | `~/.codeium/windsurf/mcp_config.json` (global) | `.windsurfrules` |
| **GitHub Copilot** | `.vscode/mcp.json` (`servers` key, `type:"stdio"`) | `.github/copilot-instructions.md` |
| **Codex CLI** | `.codex/config.toml` / `~/.codex/config.toml` | `AGENTS.md` |
| **Gemini CLI** | `.gemini/settings.json` / `~/.gemini/settings.json` | `GEMINI.md` |
| **Cline** | manual — the tool returns a snippet to paste | `.clinerules` |
| **Claude Desktop** | `claude_desktop_config.json` (OS-specific, global) | — (paste `AGENTS.md` into a Project's instructions) |

**Manual fallback** (if you'd rather not let the tool edit configs): paste one of the blocks below, replacing the path with the **absolute** path to `mcp/dist/server.js`.

```jsonc
// Cursor / Windsurf / Gemini / Claude Desktop  (mcpServers)
{ "mcpServers": { "dev-guardian": {
  "command": "node", "args": ["/abs/path/to/dev-guardian/mcp/dist/server.js"], "env": {}
} } }
```

```jsonc
// GitHub Copilot  (.vscode/mcp.json — note the "servers" key + type)
{ "servers": { "dev-guardian": {
  "type": "stdio", "command": "node", "args": ["/abs/path/to/dev-guardian/mcp/dist/server.js"]
} } }
```

```toml
# Codex CLI  (~/.codex/config.toml — single-quoted path avoids Windows escaping)
[mcp_servers.dev-guardian]
command = "node"
args = ['/abs/path/to/dev-guardian/mcp/dist/server.js']
enabled = true
```

> Claude Desktop has no rules-file mechanism — paste the contents of `host-rules/AGENTS.md` (or `GEMINI.md`) into a **Project's custom instructions**. Claude Code / Cowork need none of this: the plugin registers the server automatically.

### Run scans in CI (headless, no MCP host needed)

`node cli/dev-guardian.mjs scan` runs the same scan pipeline as an interactive session — no Claude Code, no MCP connection — and gates the result against a **committed baseline**. `dev-guardian baseline update` is the only command that writes that baseline, and only on request:

```text
node cli/dev-guardian.mjs baseline update --project .      # adopt current findings once
node cli/dev-guardian.mjs scan --project . --fail-on high --sarif results.sarif
```

Exit codes: `0` pass, `1` gate failed (a finding new to the baseline, at or above `--fail-on`), `2` **incomplete scan** (an expected scanner did not run — never read this as a pass), `3` usage/configuration error. For the DAST pass, `--start-command <cmd>` starts the app under test — it requires `--base-url` alongside it (the same URL is both the health-check target and the `scan_dast` origin) — and it is accepted **only on the command line, never from `.guardian/ci.json`**: a pull request from a fork could otherwise edit that file and run arbitrary code on the runner. Run the CLI with no arguments for the full flag reference.

> **Distribution is `git clone`, not `npx`.** This ships as a Claude Code plugin repository, not an npm package, so there is no one-line installer yet (a publishable form is being investigated separately, gated on it actually passing the Claude Desktop plugin validator). Clone at a pinned tag with `--depth 1` — `v1.3.0` here, or whichever release you want to track — then run `npm ci` once inside `mcp/`: `mcp/dist/` is committed so nothing needs *building*, but `mcp/node_modules` is gitignored like everywhere else in this repo, and `scan`/`baseline update` still import a couple of runtime packages (`execa`, `yaml`) the committed build does not bundle.

A copy-pasteable job — findings land as annotations on the pull request diff, not buried in a log. **`ubuntu-latest` ships none of Semgrep, gitleaks or Trivy**, so the job installs them itself; skip that step (or let it fail) and every run reports `coverage: none` / exit `2` — not a malfunction, that is the designed response to a scan that did not actually scan anything:

```yaml
name: dev-guardian

on:
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 22

      # Cloned OUTSIDE the checkout so dev-guardian's own source is never
      # itself part of the scan.
      - name: Clone dev-guardian
        run: |
          git clone --depth 1 --branch v1.3.0 \
            https://github.com/linofcp007/dev-guardian.git "$RUNNER_TEMP/dev-guardian"
          cd "$RUNNER_TEMP/dev-guardian/mcp" && npm ci

      # None of these ship on ubuntu-latest. Semgrep alone has a Docker
      # fallback inside dev-guardian's own scanners, but gitleaks and Trivy
      # do not, so skipping this step still caps every run below coverage:
      # full. pipx is preinstalled on ubuntu-latest; sudo is passwordless
      # for the runner user.
      - name: Install scanners (Semgrep, gitleaks, Trivy)
        run: |
          pipx install semgrep
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"

          GL_TAG=$(curl -sL -o /dev/null -w '%{url_effective}' https://github.com/gitleaks/gitleaks/releases/latest)
          GL_TAG=$(basename "$GL_TAG")
          curl -sL "https://github.com/gitleaks/gitleaks/releases/download/${GL_TAG}/gitleaks_${GL_TAG#v}_linux_x64.tar.gz" \
            | sudo tar -xz -C /usr/local/bin gitleaks

          wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg
          echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" \
            | sudo tee /etc/apt/sources.list.d/trivy.list > /dev/null
          sudo apt-get update -qq && sudo apt-get install -y trivy

      - name: Scan
        id: scan
        run: |
          set +e
          node "$RUNNER_TEMP/dev-guardian/cli/dev-guardian.mjs" scan --project . --sarif results.sarif
          echo "exit_code=$?" >> "$GITHUB_OUTPUT"

      # Upload whatever SARIF exists even when the step above "failed" — a
      # gate failure and an incomplete scan both still produce a report.
      # SARIF's own executionSuccessful flag says WHETHER coverage was full;
      # it can't say WHICH scanner was missing — that's exit 2 and the log above.
      # Requires the repository to be public, or GitHub Code Security on a
      # private one — otherwise drop this step and use --format json instead.
      - uses: github/codeql-action/upload-sarif@v3
        if: always() && hashFiles('results.sarif') != ''
        with:
          sarif_file: results.sarif

      - name: Fail the build on a real gate failure or a usage error
        if: steps.scan.outputs.exit_code == '1' || steps.scan.outputs.exit_code == '3'
        run: exit 1

      - name: Warn (don't fail) on incomplete coverage
        if: steps.scan.outputs.exit_code == '2'
        run: echo "::warning::dev-guardian scan was incomplete — see the step log above for which scanner did not run"
```

Three things this snippet cannot hide from you:

- **A CI run leaves `.guardian/` in the workspace.** `security_scan_full` and `map_attack_surface` write their raw scanner output under `.guardian/reports/` in the project being scanned, exactly as they do interactively — only the SQLite database is ephemeral. The MCP server adds `.guardian/` to `.gitignore` automatically every time it starts against a project (an interactive session, any host) — that never happens from the CLI, so a repository that only ever scans through CI must add the line by hand, or a later pipeline step that asserts a clean working tree will fail for a reason that looks like nothing:

  ```text
  .guardian/
  ```

- **SARIF alone cannot tell you *which* scanner is missing.** Its `invocation.executionSuccessful` flag flips to `false` whenever coverage isn't full — so a consumer reading only the upload can already tell an incomplete run from a clean one — but SARIF has no *general-purpose* field for this prose, so the scanner name and reason live only in exit code `2` and the step's own human/JSON output. Treat an uploaded SARIF with zero results as inconclusive, not clean, until you've checked the exit code.

- **Code-scanning upload needs a public repository, or GitHub Code Security on a private one.** Without either, the `upload-sarif` step fails the job for a reason that has nothing to do with findings. On a private repository without that licence, drop the upload step and use `--format json` plus the exit code instead.

### Local dashboard (`status`, `dashboard`)

Two read-only views over the same `.guardian/guardian.db`, for a developer at their own laptop — not a CI artifact (that's the SARIF above) and not a client deliverable (that's `report_export`'s branded HTML):

```text
node cli/dev-guardian.mjs status --project .        # one terminal screen
node cli/dev-guardian.mjs dashboard --project .      # self-contained HTML, opens in a browser
```

`status` prints the risk score and band, open findings and CVEs by severity, both deltas (since the previous scan of the same type, since the active baseline), up to 3 finding hotspots (ranked by count, not severity), which scanners are missing and what that leaves out of the numbers, and active suppressions — one screen, no more. `dashboard` renders the identical snapshot as `.guardian/dashboard.html` — no CDN, no font fetch, no network call of any kind — with client-side filtering and column sorting; it opens automatically only when stdout is a TTY (`--no-open` suppresses that, `--out <path>` relocates the file). Neither command runs a scan, mutates the database, or opens a socket, and **both always exit `0` once they render** — including over a project full of criticals, or one that's never been scanned (`3` on a usage error only). They report; `scan` is what gates.

Worth knowing before trusting what's on screen: **the page is a snapshot, not live** — it reflects the scan that had completed when you ran the command and does not update when a later scan runs, so regenerate it to see one — and the window itself is just as bounded: the latest scan plus two deltas, never a multi-week trend (`/guardian-trend` still asks for history nothing here computes). A clean screen is also only as clean as `missing_tools` says: a scanner that ran and silently produced nothing looks identical, at this layer, to one that found nothing wrong.

### Philosophy

- **Pragmatic by default** — doesn't block work over cosmetics
- **Paranoid when critical** — prod secrets, RCE, SQLi → halt and alert
- **Stack-aware** — detects your language and only configures what's relevant
- **Cross-platform** — Linux, macOS, Windows (with WSL)
- **Zero lock-in** — every tool used is open-source and self-hostable
- **Idempotent** — running `guardian init` twice doesn't duplicate anything
- **Graceful degradation** — missing scanners are reported, never crash a scan

### Supported stacks

JavaScript / TypeScript (Node, Next, React, Vue, Svelte, Angular), Python (Django, Flask, FastAPI), PHP (Laravel, Symfony, **WordPress + Kadence + WooCommerce + Tutor LMS**), **C# / .NET (ASP.NET Core, EF Core, central package management)**, Go, Rust, Ruby, Java / Kotlin, Docker, Terraform, Kubernetes, Ansible, GitHub Actions.

For languages not explicitly supported, the skills fall back to Semgrep `--config=auto` (covers 30+ languages) and generic secret rules.

### Repository structure

```text
dev-guardian/
├── .claude-plugin/
│   ├── plugin.json              # declares the MCP server + plugin metadata
│   └── marketplace.json
├── commands/                    # 48 slash commands
├── skills/                      # 13 skills (one per router target)
├── hooks/                       # hooks.json + guardian-hook.mjs (auto-active guardrails)
├── cli/                         # dev-guardian.mjs CLI (mcp-config, check, scan, baseline)
├── mcp/                         # MCP server (TypeScript + SQLite)
│   ├── src/                     # tools/, resources/, runners/, storage/, platform/, hooks/
│   ├── test/                    # 1094 unit + integration + e2e tests
│   ├── scripts/                 # smoke.mjs, smoke-wp-dotnet.mjs
│   └── dist/                    # built artifact (node dist/server.js)
├── scripts/
│   ├── detect/detect-stack.sh   # language/framework detection
│   ├── install/                 # install-linux.sh, install-macos.sh
│   └── scan/                    # full-security-scan, review-scan, etc.
├── configs/
│   ├── renovate/, gitleaks/, semgrep/, pre-commit/
├── host-rules/                  # AGENTS.md, cursor.mdc, copilot-instructions.md, …
└── README.md
```

### License

MIT — use it, modify it, share it freely.

### Author

Carlos Pereira · prodigitalkey.com

---

## Português

Plugin all-in-one **100% open-source** para Claude Code / Cowork. Faz segurança, deteção e correção de bugs, qualidade de código, gestão de dependências, observability, performance e compliance em qualquer projeto de desenvolvimento. Stack-aware (Node, Python, PHP/WordPress, Go, Rust, Ruby, Java, **C# / .NET**), triggers trilingues (EN + PT + ES) — responde no idioma do utilizador.

Por baixo do capot fornece um plugin Claude Code (13 skills + 48 slash commands) **e** um servidor MCP com **54 tools e 18 resources**, com estado persistente em SQLite para baselines, deltas e supressões. Também faz **vet de skills / MCP servers / agentes de terceiros antes de os instalares** — a verificação de supply-chain do ecossistema de agentes.

### Skills (front-end Claude Code)

| Skill                    | Slash command          | O que faz                                                |
| ------------------------ | ---------------------- | -------------------------------------------------------- |
| `guardian`               | `/guardian`            | Router principal — encaminha para o módulo certo         |
| `guardian-init`          | `/guardian-init`       | Bootstrap inicial — instala e configura tudo             |
| `guardian-security`      | `/guardian-scan`       | SAST + secrets + CVEs + container + IaC                  |
| `guardian-bugfix`        | `/guardian-fix`        | Caça e corrige bugs de implementação                     |
| `guardian-quality`       | `/guardian-quality`    | Complexidade, duplicação, tech debt                      |
| `guardian-review`        | `/guardian-review`     | Revisão profunda pré-PR / pré-deploy                     |
| `guardian-deps`          | `/guardian-deps`       | Renovate setup + scan de CVEs + supply chain             |
| `guardian-observability` | `/guardian-observe`    | Logging estruturado, métricas, error tracking            |
| `guardian-performance`   | `/guardian-perf`       | Performance budgets, k6, Lighthouse                      |
| `guardian-compliance`    | `/guardian-compliance` | RGPD, licenças, SBOM, privacy policy                     |
| `guardian-scanskill`     | `/guardian-scanskill`  | Vet de skill / MCP / agente antes de instalar            |
| `guardian-grill`         | `/guardian-grill`      | Sabatina de compreensão ao diff antes do merge           |
| `guardian-improve`       | `/guardian-improve`    | Transforma dívida técnica medida em specs de melhoria    |
| (combina os 3)           | `/guardian-audit`      | Relatório executivo: security + quality + deps           |

Também podes invocar tudo em **linguagem natural** (PT, EN ou ES). As skills disparam por descrição — *"audita o projeto"*, *"vê se há vulnerabilidades"*, *"antes de fazer merge"*, *"audit the project"*, *"check for vulnerabilities"*, *"before merge"*, *"audita el proyecto"*, *"comprueba vulnerabilidades"*, *"antes del merge"*.

### Servidor MCP (54 tools, 18 resources)

O plugin regista um servidor MCP em stdio que o Claude Code arranca automaticamente. As tools agrupam-se em:

- **Segurança transversal** (10) — `security_scan_full`, `scan_sast`, `scan_deps`, `scan_secrets`, `scan_containers`, `scan_iac`, `deps_audit`, `bug_hunt` (Semgrep `p/r2c-bug-scan` + `p/security-audit`, mais um pack local sempre ativo para JS/TS — `configs/semgrep/bugfix-js.yml`, catorze regras hand-authored que cobrem as seis subcategorias de bug que a ferramenta classifica: race conditions, null/undefined safety, off-by-one, memory leaks, error handling engolido, e dois edge cases. O `/guardian-fix` também nomeia "broken happy paths" como foco; isso é uma categoria de consequência, não uma forma sintática, por isso só a sua forma concreta mais comum é coberta — uma chamada que muta estado sem `await` numa função async (declarações, arrow functions, métodos de classe/objeto — NÃO cobre function expressions async, uma limitação do motor do Semgrep) — e mais nada cobre o resto. São regras Semgrep OSS: casam sintaxe, não fazem dataflow, por isso um bug a duas funções do guard continua invisível para elas, e a camada heurística (`WARNING`/`INFO`) produz falsos positivos por construção — `floating-mutation` casa pelo nome do método, por isso não distingue uma mutação real como `repo.save()` de uma chamada sem relação que só partilha o nome, como `ctx.save()` (o push síncrono de estado do Canvas 2D, sem relação com persistência) — ambas disparam da mesma forma; por isso o `severity_min` existe. Python tem também o seu pack — `configs/semgrep/bugfix-py.yml`, dez regras hand-authored nas mesmas seis classes, cada uma medida contra as 32 regras Python que o `p/r2c-bug-scan` já corre e confirmada a disparar onde essas não disparam. As lacunas conhecidas são ditas em vez de subentendidas: não há regra geral de "corotina não aguardada" (não é exprimível em Semgrep OSS — só os quatro primitivos `asyncio` nomeados são cobertos, por isso um `await` esquecido numa `async def` do próprio projeto não é apanhado), a regra de N+1 do Django casa ciclos `for` mas não list comprehensions, não conhece SQLAlchemy nem Peewee, e exige o queryset dentro do próprio cabeçalho do `for` — `qs = Book.objects.all()` seguido de `for book in qs:` fica silencioso, e essa forma ligada a variável é provavelmente a mais comum na prática — a `toctou-exists-open` só reage a `os.path.exists`, por isso `os.path.isfile`, `os.path.isdir` e `pathlib.Path(p).exists()` ficam todos silenciosos, e a `none-deref-dict-get` exclui clientes HTTP pela SUBSTRING do nome do receiver, não pelo nome, por isso qualquer receiver cujo nome CONTENHA `requests`, `session`, `client`, `httpx`, `aiohttp` ou `urllib` é ignorado — `session_data`, `clients` e `urllib_cache` também são falsos negativos, não só um dicionário chamado exatamente `client`. Há duas exclusões que vale a pena nomear como falsos negativos em vez de as deixar subentendidas: a `get-without-doesnotexist` conta um `except Exception:` largo como guarda, por isso um `.objects.get()` dentro de `except Exception: pass` fica silencioso aqui, apesar de ser pior código do que um `get` sem guarda nenhuma (o engolir do erro é apanhado à parte pela `except-pass`, mas nada liga as duas coisas); e a `open-without-context` nunca marca targets que são atributos, por isso `self.handle = open(path)` é ignorado de propósito — o `close()` vive normalmente noutro método, fora do alcance de uma regra sintática — o que significa que uma classe que nunca fecha mesmo o handle passa despercebida, e é essa a forma mais comum de um leak de ficheiro de longa duração. O Go também tem o seu — `configs/semgrep/bugfix-go.yml`, dez regras hand-authored nas mesmas seis classes, e o Go é a linguagem onde o pack do registo deixa o maior buraco: o `p/r2c-bug-scan` traz 5 regras Go e só 2 caem numa classe de bug, ambas de integer overflow, por isso `error_handling` — na linguagem em que `if err != nil` É o modelo de erros — `race_condition`, `null_safety`, `memory_leak` e `edge_case` estavam todas vazias. As lacunas são ditas em vez de subentendidas: **não há regra para goroutines que ficam penduradas** nem **regra para a captura da variável do ciclo** — essa foi construída e verificada a funcionar, e depois deliberadamente excluída, porque o Go 1.22 passou a dar a cada iteração a sua própria variável e o Semgrep não lê o `go.mod`, por isso em qualquer módulo moderno acusaria código correto; a `body-not-closed` só reconhece `http.Get`, portanto `http.Post` e `client.Do(req)` perdem ligações da mesma maneira e não são apanhados; a `lock-without-defer` aceita qualquer `defer mu.Unlock()` no bloco, por isso não distingue um unlock bem colocado de um adiado no ramo errado; a `err-blank-assign` dispara em descartes deliberados como `_ = os.Remove(tmp)` numa limpeza, e é por isso que é `WARNING`; a `lock-without-defer` casa pelos nomes literais `Lock()`/`Unlock()`, não `RLock()`/`RUnlock()`, por isso um read-lock de `sync.RWMutex` sem `defer` — um idioma comum em Go — fica totalmente fora do seu alcance; e a `nil-map-write` só apanha um mapa declarado localmente com `var` — um mapa nil que chega como parâmetro de função, campo de struct, ou valor de retorno entra em panic da mesma forma ao escrever e não é coberto, provavelmente a forma mais comum na prática real, o mesmo tipo de lacuna que a `open-without-context` tem para targets de atributo no pack Python acima. O Java também tem o seu — `configs/semgrep/bugfix-java.yml`, oito regras hand-authored nas mesmas seis classes, e o Java é a linguagem mais vazia das quatro: o `p/r2c-bug-scan` traz 4 regras Java e **nenhuma** cai numa classe de bug — são todas de igualdade e comparação — por isso todas as subcategorias estavam a zero, na linguagem cujo defeito mais famoso é o `NullPointerException`. As lacunas são ditas em vez de subentendidas: **não há regra para `Integer ==`**, porque exprimi-la exige inferência de tipos que o Semgrep OSS não tem e a tentativa disparava em `v == null` e em comparação de primitivos — uma regra que acusa `v == null` seria desinstalada no primeiro dia; a `stream-not-closed` só reconhece `new FileInputStream(...)` — e só por esse nome simples, por isso `FileOutputStream`, `FileReader`, `Socket` e todos os outros closeables perdem descritores da mesma maneira e não são apanhados, e o mesmo acontece a um `new java.io.FileInputStream(...)` totalmente qualificado, que o padrão não vê (medido); a `static-dateformat` só reconhece `SimpleDateFormat`, por isso um `Calendar` ou um `Matcher` partilhados num campo estático não são apanhados; a `map-get-deref` não distingue um mapa que pode ter nulos de um cujas chaves estão garantidas, por isso um mapa preenchido na linha acima é marcado na mesma; e a `modify-during-iteration` só casa a forma for-each, por isso um ciclo indexado que remove da lista que indexa tem o mesmo defeito e escapa. Duas regras restringem o recetor pelo TIPO DECLARADO, o que compra precisão e custa recall: o `metavariable-type` casa o tipo declarado exato, sem subtipagem — medido, `type: List` **não** casa uma `CopyOnWriteArrayList`, e é exatamente isso que mantém a regra afastada dela — por isso a `map-get-deref`, que enumera `Map`, `HashMap`, `TreeMap`, `LinkedHashMap` e `ConcurrentHashMap`, fica silenciosa sobre um mapa atrás de uma interface do próprio projeto ou de um parâmetro de tipo genérico (`<M extends Map<K,V>> … m.get(k).f()`), embora um `Map` cru continue a disparar (medido); e a `modify-during-iteration`, que enumera `List`, `ArrayList`, `LinkedList`, `Set`, `HashSet`, `LinkedHashSet` e `Collection`, fica silenciosa sobre um `Deque`, uma `Queue`, um `SortedSet` ou uma coleção do próprio projeto. A `empty-catch` respeita a convenção do Checkstyle / IntelliJ e nunca dispara quando a variável da exceção se chama `ignore`, `ignored` ou `expected` — o reverso é que uma exceção genuinamente engolida escapa à regra só por se chamar `ignored`. A `optional-get-no-ispresent` é **WARNING, não ERROR**, e isso aplica o critério de tiers do próprio pack em vez de o dobrar: ERROR é para o padrão que é bug independentemente da intenção, e um `o.get()` só é bug quando está *sem guarda*. A regra reconhece guardas escritas **inline sobre a mesma variável `Optional`** — `if (isPresent())`, um `return` / `throw` / `continue` / `break` antecipado sob `!isPresent()` ou `isEmpty()`, as três formas ternárias (o ternário precisou de cláusulas próprias por ser uma *expressão* condicional, um nó da AST diferente de um `if`), e `if (o.filter(p).isPresent())` — e falha **qualquer guarda que chegue ao teste através de outro método ou de outra variável**. O caso concreto é a guarda delegada a um helper, `if (!present(o)) { return d; }`, que exige análise interprocedimental que o Semgrep OSS não faz: essa forma é falso positivo e vai continuar a ser, e é precisamente por isso que a regra está em WARNING em vez de carregar uma lista de exclusões sem fim. Quatro falsos positivos são aceites em vez de corrigidos, cada um reproduzido em código correto: a `stream-not-closed` em `open(); try { … } finally { close(); }` (já é a razão declarada para ser WARNING); a `static-dateformat` num `static final SimpleDateFormat` cujos acessos passam todos por um método `synchronized` (provar que *todos* os acessos estão sincronizados é análise do programa inteiro, que o Semgrep OSS não faz, e um formatter partilhado serializa todos os chamadores de qualquer maneira); a `loop-lte-length` em `i <= a.length` quando o corpo se protege com `i < a.length` ou nunca indexa `a`; e a `printstacktrace-only` no único sítio onde a chamada está certa — o fallback quando foi o próprio logger que lançou. **JS/TS, Python, Go e Java**: as restantes linguagens ainda não têm pack local. Um ficheiro de regras local partido à mão degrada em vez de fazer falhar o scan inteiro, seja a quebra um YAML inválido ou um único padrão de regra mal formado), `suggest_fix`, `register_custom_rules`
- **WordPress** (9) — `scan_wordpress` (Semgrep PHP + rule pack WP + Trivy + gitleaks + PHPCS-WPCS), `wp_audit` (instalação viva: checksums + admins + flags de config via WP-CLI), `wp_vuln_check` (WPScan DB), `wp_plugin_check`, `wp_cron_audit`, `wp_rest_audit`, `wp_recommend_hardening`, `wp_describe_setup`, `bulk_audit_wordpress_sites`
- **C# / .NET** (4 dedicadas + branches) — `scan_dotnet_secrets`, `dotnet_target_framework_check`, `dotnet_efcore_audit`, `dotnet_describe_setup`; `scan_sast` corre `p/csharp` + parse da saída do security-code-scan; `deps_update_plan` corre `dotnet list package --outdated`; `observability_setup` gera templates Serilog + prometheus-net
- **Qualidade, deps, priorização** (5) — `quality_check`, `deps_update_plan`, `triage_findings`, `prioritize_findings`, `risk_score`
- **Compliance & SBOM** (5) — `compliance_check` (RGPD/GDPR), `compliance_evidence`, `generate_sbom` (Syft), `sbom_diff`, `license_compatibility`
- **Observability & perf** (3) — `observability_setup` (Pino/structlog/Monolog/Serilog + Prometheus), `health_status`, `perf_check` (k6 / Lighthouse)
- **Lifecycle / PR / governance** (11) — `init_project`, `precommit_install`, `review_pr`, `set_baseline`, `diff_scans`, `regression_alert`, `report_export` (Markdown default / branded **HTML** with dark/light toggle / **SARIF 2.1.0** / JSON), `create_github_issues`, `create_fix_pr` (aplica fixes que um scanner já produziu — bumps do `deps_update_plan`, `--autofix` do Semgrep — dentro de uma worktree git isolada, prova cada um com um differential de scan e uma corrida de testes, e abre um pull request por ecossistema/scanner via `gh` local; **`apply` tem valor por defeito `false`** — um dry run continua a criar a worktree, a aplicar o fix e a correr os dois differentials, mas não abre PR nenhum e não deixa nada para trás, nem sequer um branch, e o seu próprio scan de verificação nunca se torna o scan mais recente do projeto, pelo que um preview não pode redirecionar `guardian://findings/open` nem `risk_score`; os bumps de maven e gradle estão fora de alcance, uma lacuna herdada do próprio `deps_update_plan`; uma segunda ocorrência da mesma regra num ficheiro já corrigido não é vista como nova — a verificação "no new finding" compara `(rule_id, file_path)`, não o fingerprint, porque o fingerprint muda sempre que o fix desloca uma linha; e `fix_applied` nunca passa a `1`, uma coluna morta em `findings` — o pull request aberto é o registo), `suppress_finding`, `audit_executive`
- **AI-agent supply chain** (1) — `scan_skill`: vet a third-party **skill / MCP server / agent before you install it**. Accepts a directory, file, `.zip`, or git/HTTP(S) URL and runs 16 threat categories (prompt injection, data exfiltration, privilege escalation, supply chain, excessive agency, output handling, system-prompt leakage, memory poisoning, tool misuse, rogue agent, trigger abuse, dangerous code, taint, signatures, MCP least-privilege, MCP tool poisoning), a **YARA-style signature engine**, taint-light source→sink, hidden-Unicode detection, and **OSV.dev** CVE lookups — rolled up into a **0-100 risk score** and a **SAFE → DO NOT INSTALL** verdict
- **Superfície de ataque** (1) — `map_attack_surface`: inventário estático de rotas, variáveis de ambiente e portas declaradas nas 8 stacks suportadas, com relatório de cobertura por linguagem. Também descobre e importa documentos OpenAPI 3.x e Swagger 2.0 (JSON ou YAML — **coleções Postman não são suportadas**), marca cada rota com a sua proveniência (`code` ou `spec`) e compara as duas: **endpoints shadow** (existem no código, não documentados), **documentação morta** (documentada, sem código que a implemente) e rotas correspondidas. Sem spec encontrada não há diff — `spec_diff: null`, nunca um diff que reporta todas as rotas como não documentadas — e uma rota cujo caminho completo não pode ser resolvido nunca é reportada como endpoint shadow nem como documentação morta; quantos resultados foram retidos por esse motivo é reportado junto do diff
- **DAST ativo** (1) — `scan_dast`: o passo seguinte ao `map_attack_surface` — envia pedidos HTTP reais a uma aplicação **já em execução** (nunca a arranca, constrói ou pára) e verifica o inventário de rotas quanto a acessibilidade, acesso anónimo a rotas que exigem autenticação, autorização diferencial, CORS, cabeçalhos de segurança, divulgação de informação, métodos HTTP não documentados e redirecionamentos fora da origem, mais um burst opcional de rate-limit e uma passagem opcional de **nuclei**. Envelope de segurança: **apenas loopback** salvo se quem chama atestar `authorized_target: true`; métodos **só de leitura** (GET/HEAD/OPTIONS) salvo se `allow_write_methods` estiver ativo, e mesmo assim com corpo vazio, mais o burst opcional `probe_rate_limit` — a única exceção — que envia POST a exatamente uma rota; sem payloads de injeção, sem adivinhar credenciais. O motor próprio **não** testa injeção — isso fica a cargo do modo `-dast` do nuclei, excluído por defeito — pelo que **um resultado limpo não é prova de segurança contra injeção**, e o conjunto de templates por defeito do nuclei testa a origem, não as rotas específicas deste projeto
- **Alcançabilidade** (1) — `validate_finding`: o outro passo seguinte ao `map_attack_surface` — responde, por finding, se algo fora do processo consegue alcançar o ficheiro onde este vive, a partir de um grafo de imports ao nível do ficheiro, com raiz nos ficheiros que declaram rotas. Devolve `reachable` / `unreachable` / `unknown` por finding com evidência concreta (rota mais próxima, número de saltos, quantas rotas alcançam o ficheiro, exposição anónima confirmada em live) e os coverage gaps por trás dela. **Apenas relatório**: nunca suprime um finding nem altera a severidade. `unreachable` nunca é emitido para Ruby, Java, C# ou PHP (os quatro resolvem código em runtime, não por import). **É** emitido — e pode estar errado — para um ficheiro alcançado apenas por um CLI/cron/queue, ou sempre que um import dinâmico — `import(expr)`, `require(variable)`, reflection, um registo de plugins — não possa ser resolvido
- **Meta / host** (3) — `detect_stack`, `check_toolchain`, `install_toolchain`

**Resources** — `guardian://wp/audit/latest`, `guardian://wp/audit/{scan_id}`, `guardian://wp/cron`, `guardian://dotnet/target-frameworks`, `guardian://dotnet/efcore`, `guardian://surface/latest`, `guardian://surface/{id}`.

**Storage** — SQLite em `.guardian/guardian.db`. Tabelas: `scans`, `findings`, `cves`, `baselines`, `suppressions`, `stack_snapshots`, `surface_snapshots`, `finding_validations`. Permite tracking de baseline, deltas scan-a-scan, supressões com expiração, alertas de regressão.

### Hooks de proteção (auto-ativos)

Com o plugin ativo, o Claude Code carrega automaticamente `hooks/hooks.json` — três guardrails **dependency-free e fail-open**, em milissegundos (sem módulos nativos, nunca quebram o teu workflow):

- **SessionStart** — informa o agente da postura de segurança do projeto: branch, alterações não commitadas, idade do último scan e se o projeto está guardian-initialized.
- **PostToolUse (Write/Edit/MultiEdit)** — analisa o texto acabado de escrever à procura de secrets hardcoded (AWS, GitHub, GitLab, Anthropic, OpenAI, Stripe, Google, Slack, chaves privadas, …) e avisa com pré-visualização **redigida**. O scan completo do histórico continua em `scan_secrets` (gitleaks) via `/guardian-scan`.
- **PreToolUse (Bash)** — **bloqueia por defeito comandos catastróficos** (`rm -rf /`, `curl … | sh`, `dd`/`mkfs` em disco cru, fork bombs); **avisa** nos apenas arriscados (force-push, hard reset, `sudo`, `chmod 777`).

O bloqueio da *escrita* de secrets é **opt-in**: define `"secrets": { "block": true }` em `.guardian/hooks.config.json`. Ajusta tudo aí, faz allowlist de falsos positivos em `.guardian/hooks-allowlist.json`, ou desliga todos os hooks com `GUARDIAN_HOOKS=off`. Os mesmos detetores correm no CLI para terminal / CI: `node cli/dev-guardian.mjs check --file <path>` e `--bash "<command>"` (exit 1 ao encontrar algo).

### Ferramentas open-source orquestradas

Semgrep · Trivy · OSV.dev · gitleaks · Renovate · nuclei · Playwright · Pino / structlog / Monolog / Serilog · Prometheus + Grafana · GlitchTip · Uptime Kuma · k6 · Artillery · Lighthouse · Syft · WPScan · WP-CLI · PHPCS + WPCS · security-code-scan · dotnet-outdated · ruff · bandit · jscpd · eslint · hadolint · shellcheck.

### Instalação do plugin

#### A) Via marketplace (recomendado) — Claude Code CLI

```text
/plugin marketplace add https://github.com/linofcp007/dev-guardian
/plugin install dev-guardian@dev-guardian
```

Funciona com qualquer URL git (HTTPS ou SSH) ou caminho local de uma pasta que contenha [`.claude-plugin/marketplace.json`](.claude-plugin/marketplace.json).

> ⚠️ **Limitação da app Claude Desktop.** O cliente Desktop rejeita atualmente marketplaces de terceiros com `External plugin sources are not yet supported` (a feature está bloqueada server-side). É uma limitação do Claude Desktop, não um problema deste plugin — qualquer marketplace alojado no GitHub falha hoje da mesma forma. Issues a acompanhar: [anthropics/claude-code#41653](https://github.com/anthropics/claude-code/issues/41653) (fontes remotas), [anthropics/claude-code#52147](https://github.com/anthropics/claude-code/issues/52147) (paths locais). Até a paridade chegar, usa a opção **B** abaixo ou instala via Claude Code CLI.

#### B) Cópia manual da pasta (funciona em qualquer lado)

Copia a pasta inteira para:

- **Linux / macOS**: `~/.claude/plugins/dev-guardian/`
- **Windows**: `%USERPROFILE%\.claude\plugins\dev-guardian\`

Depois, dentro do Claude Code, corre `/plugin` e ativa o `dev-guardian`. Em alternativa, adiciona ao teu `~/.claude/settings.json`:

```json
{
  "enabledPlugins": { "dev-guardian@dev-guardian": true }
}
```

> O servidor MCP corre a partir de `mcp/dist/`. Na primeira instalação corre uma vez `cd mcp && npm install && npm run build`. Depois o plugin arranca-o automaticamente via `node ${CLAUDE_PLUGIN_ROOT}/mcp/dist/server.js`.
>
> Os scripts `.sh` em `scripts/` correm direto em Linux/macOS. No Windows nativo precisas de **WSL2** ou Git Bash; as skills/commands em si funcionam em qualquer SO.

### Outros hosts de IA (Cursor · Windsurf · Copilot · Codex · Gemini · Cline · Claude Desktop)

O motor real é o **servidor MCP**, por isso qualquer host com suporte MCP pode usar o dev-guardian — não só o Claude Code. A **CLI `mcp-config`** liga um host a partir de um terminal normal — sem precisar de ligação MCP (sem ovo-e-galinha). Preenche o caminho absoluto do servidor por ti e ou imprime o bloco para colar ou, com `--write`, funde-o no projeto e deixa o ficheiro de regras. Idempotente.

A partir de um terminal no teu projeto (depois de `cd mcp && npm install && npm run build` uma vez):

```text
node cli/dev-guardian.mjs mcp-config cursor          # imprime o bloco para colar
node cli/dev-guardian.mjs mcp-config all             # todos os hosts
node cli/dev-guardian.mjs mcp-config codex --write   # escreve + funde no projeto
node cli/dev-guardian.mjs mcp-config all --scope global
```

| Host | Ficheiro de config MCP (projeto / global) | Ficheiro de regras |
| ---- | ----------------------------------------- | ------------------ |
| **Cursor** | `.cursor/mcp.json` / `~/.cursor/mcp.json` | `.cursor/rules/dev-guardian.mdc` |
| **Windsurf** | `~/.codeium/windsurf/mcp_config.json` (global) | `.windsurfrules` |
| **GitHub Copilot** | `.vscode/mcp.json` (chave `servers`, `type:"stdio"`) | `.github/copilot-instructions.md` |
| **Codex CLI** | `.codex/config.toml` / `~/.codex/config.toml` | `AGENTS.md` |
| **Gemini CLI** | `.gemini/settings.json` / `~/.gemini/settings.json` | `GEMINI.md` |
| **Cline** | manual — a tool devolve um snippet para colar | `.clinerules` |
| **Claude Desktop** | `claude_desktop_config.json` (específico do SO, global) | — (cola o `AGENTS.md` nas instruções de um Project) |

**Fallback manual** (se preferires não deixar a tool editar configs): cola um dos blocos abaixo, substituindo o caminho pelo caminho **absoluto** para `mcp/dist/server.js`.

```jsonc
// Cursor / Windsurf / Gemini / Claude Desktop  (mcpServers)
{ "mcpServers": { "dev-guardian": {
  "command": "node", "args": ["/caminho/abs/para/dev-guardian/mcp/dist/server.js"], "env": {}
} } }
```

```jsonc
// GitHub Copilot  (.vscode/mcp.json — repara na chave "servers" + type)
{ "servers": { "dev-guardian": {
  "type": "stdio", "command": "node", "args": ["/caminho/abs/para/dev-guardian/mcp/dist/server.js"]
} } }
```

```toml
# Codex CLI  (~/.codex/config.toml — path em aspas simples evita escape no Windows)
[mcp_servers.dev-guardian]
command = "node"
args = ['/caminho/abs/para/dev-guardian/mcp/dist/server.js']
enabled = true
```

> O Claude Desktop não tem mecanismo de ficheiro de regras — cola o conteúdo de `host-rules/AGENTS.md` (ou `GEMINI.md`) nas **instruções personalizadas de um Project**. O Claude Code / Cowork não precisam disto: o plugin regista o servidor automaticamente.

### Corre scans em CI (headless, sem host MCP)

`node cli/dev-guardian.mjs scan` corre o mesmo pipeline de scan de uma sessão interativa — sem Claude Code, sem ligação MCP — e faz gate do resultado contra uma **baseline committed**. `dev-guardian baseline update` é o único comando que escreve essa baseline, e só quando pedido:

```text
node cli/dev-guardian.mjs baseline update --project .      # adota os findings atuais uma vez
node cli/dev-guardian.mjs scan --project . --fail-on high --sarif results.sarif
```

Exit codes: `0` passou, `1` gate falhou (finding novo na baseline, severidade >= `--fail-on`), `2` **scan incompleto** (um scanner esperado não correu — nunca leias isto como um passe), `3` erro de uso/configuração. Para o passo DAST, `--start-command <cmd>` arranca a app a testar — exige `--base-url` ao lado (o mesmo URL é o alvo do health-check e a origem do `scan_dast`) — e só é aceite **na linha de comandos, nunca a partir de `.guardian/ci.json`**: um pull request de um fork podia editar esse ficheiro e correr código arbitrário no runner. Corre a CLI sem argumentos para veres a referência completa de flags.

> **A distribuição é `git clone`, não `npx`.** Isto é distribuído como um repositório de plugin Claude Code, não como um pacote npm, por isso ainda não há instalador de uma linha (uma forma publicável está a ser investigada à parte, condicionada a passar de facto no validador de plugins do Claude Desktop). Faz clone a um tag fixo com `--depth 1` — `v1.3.0` aqui, ou o release que quiseres seguir — depois corre `npm ci` uma vez dentro de `mcp/`: o `mcp/dist/` vem committed, por isso não há nada para *compilar*, mas `mcp/node_modules` está no gitignore como o resto deste repo, e `scan`/`baseline update` continuam a importar alguns pacotes de runtime (`execa`, `yaml`) que o build committed não empacota.

Um job pronto a colar — os findings aparecem como anotações no diff do pull request, não perdidos num log. **O `ubuntu-latest` não traz Semgrep, gitleaks nem Trivy**, por isso o job instala-os ele próprio; salta esse passo (ou deixa-o falhar) e todos os runs reportam `coverage: none` / exit `2` — não é uma avaria, é a resposta desenhada para um scan que não scaneou nada:

```yaml
name: dev-guardian

on:
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 22

      # Clonado FORA do checkout para o próprio código do dev-guardian nunca
      # entrar no scan.
      - name: Clone dev-guardian
        run: |
          git clone --depth 1 --branch v1.3.0 \
            https://github.com/linofcp007/dev-guardian.git "$RUNNER_TEMP/dev-guardian"
          cd "$RUNNER_TEMP/dev-guardian/mcp" && npm ci

      # Nenhum destes vem no ubuntu-latest. O Semgrep sozinho tem fallback
      # via Docker dentro dos scanners do próprio dev-guardian, mas gitleaks
      # e Trivy não têm, por isso saltar este passo continua a limitar todos
      # os runs abaixo de coverage: full. O pipx já vem instalado no
      # ubuntu-latest; o sudo é sem password para o utilizador runner.
      - name: Install scanners (Semgrep, gitleaks, Trivy)
        run: |
          pipx install semgrep
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"

          GL_TAG=$(curl -sL -o /dev/null -w '%{url_effective}' https://github.com/gitleaks/gitleaks/releases/latest)
          GL_TAG=$(basename "$GL_TAG")
          curl -sL "https://github.com/gitleaks/gitleaks/releases/download/${GL_TAG}/gitleaks_${GL_TAG#v}_linux_x64.tar.gz" \
            | sudo tar -xz -C /usr/local/bin gitleaks

          wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg
          echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" \
            | sudo tee /etc/apt/sources.list.d/trivy.list > /dev/null
          sudo apt-get update -qq && sudo apt-get install -y trivy

      - name: Scan
        id: scan
        run: |
          set +e
          node "$RUNNER_TEMP/dev-guardian/cli/dev-guardian.mjs" scan --project . --sarif results.sarif
          echo "exit_code=$?" >> "$GITHUB_OUTPUT"

      # Faz upload do SARIF que existir mesmo quando o passo acima "falhou" —
      # um gate falhado e um scan incompleto continuam a produzir relatório.
      # O executionSuccessful do SARIF diz SE a cobertura foi total; não diz
      # QUAL scanner faltou — isso é o exit 2 e o log acima.
      # Exige que o repositório seja público, ou GitHub Code Security num
      # privado — caso contrário tira este passo e usa --format json.
      - uses: github/codeql-action/upload-sarif@v3
        if: always() && hashFiles('results.sarif') != ''
        with:
          sarif_file: results.sarif

      - name: Falha o build num gate falhado ou erro de uso real
        if: steps.scan.outputs.exit_code == '1' || steps.scan.outputs.exit_code == '3'
        run: exit 1

      - name: Avisa (sem falhar) numa cobertura incompleta
        if: steps.scan.outputs.exit_code == '2'
        run: echo "::warning::dev-guardian scan incompleto — vê o log do passo acima para saber qual scanner faltou"
```

Três coisas que este snippet não te consegue esconder:

- **Um scan em CI deixa `.guardian/` na working tree.** `security_scan_full` e `map_attack_surface` escrevem a saída bruta dos scanners em `.guardian/reports/` dentro do projeto scaneado, exatamente como fazem numa sessão interativa — só a base de dados SQLite é efémera. O servidor MCP adiciona `.guardian/` ao `.gitignore` automaticamente sempre que arranca contra um projeto (uma sessão interativa, qualquer host) — isso nunca acontece a partir da CLI, por isso um repositório que só corre a CLI em CI tem de adicionar a linha à mão, ou um passo posterior da pipeline que verifica uma working tree limpa vai falhar por um motivo que parece nada:

  ```text
  .guardian/
  ```

- **O SARIF sozinho não te diz *qual* scanner falta.** A flag `invocation.executionSuccessful` muda para `false` sempre que a cobertura não é total — por isso quem lê só o upload já consegue distinguir um run incompleto de um limpo — mas o SARIF não tem campo de *uso geral* para este texto, por isso o nome do scanner e o motivo só vivem no exit code `2` e na saída humana/JSON do próprio passo. Trata um SARIF carregado com zero resultados como inconclusivo, não como limpo, até verificares o exit code.

- **O upload de code-scanning exige um repositório público, ou GitHub Code Security num privado.** Sem um dos dois, o passo `upload-sarif` falha o job por um motivo que nada tem a ver com findings. Num repositório privado sem essa licença, tira o passo de upload e usa `--format json` mais o exit code.

### Dashboard local (`status`, `dashboard`)

Duas vistas read-only sobre o mesmo `.guardian/guardian.db`, para quem desenvolve no seu próprio portátil — não é um artefacto de CI (isso é o SARIF acima) nem um entregável para cliente (isso é o HTML branded do `report_export`):

```text
node cli/dev-guardian.mjs status --project .        # um ecrã de terminal
node cli/dev-guardian.mjs dashboard --project .      # HTML autocontido, abre no browser
```

O `status` imprime o risk score e a banda, os findings abertos e os CVEs por severidade, os dois deltas (desde o scan anterior do mesmo tipo, desde a baseline ativa), até 3 hotspots de findings (ordenados por contagem, não por severidade), quais scanners faltam e o que isso deixa de fora dos números, e as supressões ativas — um ecrã, nada mais. O `dashboard` renderiza o mesmo snapshot como `.guardian/dashboard.html` — sem CDN, sem fetch de fontes, sem nenhuma chamada de rede — com filtragem e ordenação de colunas no client-side; abre automaticamente só quando o stdout é um TTY (`--no-open` suprime isso, `--out <path>` muda o destino do ficheiro). Nenhum dos dois comandos corre um scan, altera a base de dados ou abre um socket, e **ambos terminam sempre com exit `0` assim que renderizam** — mesmo num projeto cheio de críticos, ou nunca scaneado (`3` só num erro de uso). Eles reportam; quem faz gate é o `scan`.

Vale a pena saber antes de confiar no que está no ecrã: **a página é um snapshot, não é ao vivo** — reflete o scan que tinha terminado quando correste o comando, e não atualiza quando um scan posterior corre, por isso volta a gerá-la para veres um novo — e a janela em si é igualmente limitada: o último scan mais dois deltas, nunca uma tendência de várias semanas (`/guardian-trend` continua a pedir um histórico que nada aqui calcula). Um ecrã limpo também só é tão fiável quanto o `missing_tools` que o acompanha: um scanner que correu e não produziu nada em silêncio parece, a este nível, idêntico a um que não encontrou nada de errado.

### Filosofia

- **Pragmático por defeito** — não bloqueia trabalho por nada cosmético
- **Paranoid quando crítico** — secrets em produção, RCE, SQLi → interrompe e alerta
- **Stack-aware** — detecta a tua linguagem e configura só o relevante
- **Cross-platform** — Linux, macOS, Windows (com WSL)
- **Zero lock-in** — todas as ferramentas usadas são open-source e self-hostable
- **Idempotente** — correr `guardian init` 2 vezes não duplica nada
- **Degradação graciosa** — scanners em falta são reportados, nunca crasham um scan

### Stacks suportadas

JavaScript / TypeScript (Node, Next, React, Vue, Svelte, Angular), Python (Django, Flask, FastAPI), PHP (Laravel, Symfony, **WordPress + Kadence + WooCommerce + Tutor LMS**), **C# / .NET (ASP.NET Core, EF Core, central package management)**, Go, Rust, Ruby, Java / Kotlin, Docker, Terraform, Kubernetes, Ansible, GitHub Actions.

Para linguagens não suportadas explicitamente, as skills caiem para Semgrep `--config=auto` (cobre 30+ linguagens) e regras genéricas para secrets.

### Estrutura do repositório

```text
dev-guardian/
├── .claude-plugin/
│   ├── plugin.json              # declara o servidor MCP + metadata
│   └── marketplace.json
├── commands/                    # 48 slash commands
├── skills/                      # 13 skills (uma por destino do router)
├── hooks/                       # hooks.json + guardian-hook.mjs (guardrails auto-ativos)
├── cli/                         # CLI dev-guardian.mjs (mcp-config, check, scan, baseline)
├── mcp/                         # Servidor MCP (TypeScript + SQLite)
│   ├── src/                     # tools/, resources/, runners/, storage/, platform/
│   ├── test/                    # 1094 testes unit + integration + e2e
│   ├── scripts/                 # smoke.mjs, smoke-wp-dotnet.mjs
│   └── dist/                    # artefacto compilado (node dist/server.js)
├── scripts/
│   ├── detect/detect-stack.sh   # deteção de linguagens/frameworks
│   ├── install/                 # install-linux.sh, install-macos.sh
│   └── scan/                    # full-security-scan, review-scan, etc.
├── configs/
│   ├── renovate/, gitleaks/, semgrep/, pre-commit/
├── host-rules/                  # AGENTS.md, cursor.mdc, copilot-instructions.md, …
└── README.md
```

### Licença

MIT — usa, modifica, partilha à vontade.

### Autor

Carlos Pereira · prodigitalkey.com

---

## Español

Plugin todo-en-uno **100% open-source** para Claude Code / Cowork. Cubre seguridad, detección y corrección de bugs, calidad de código, gestión de dependencias, observabilidad, rendimiento y cumplimiento para cualquier proyecto de desarrollo. Stack-aware (Node, Python, PHP/WordPress, Go, Rust, Ruby, Java, **C# / .NET**), triggers trilingües (EN + PT + ES) — responde en el idioma del usuario.

Bajo el capó incluye un plugin Claude Code (13 skills + 48 slash commands) **y** un servidor MCP con **54 herramientas y 18 recursos**, con estado persistente en SQLite para baselines, deltas y supresiones. También hace **vet de skills / MCP servers / agentes de terceros antes de instalarlos** — la verificación de supply-chain del ecosistema de agentes.

### Skills (front-end de Claude Code)

| Skill                    | Slash command          | Qué hace                                                 |
| ------------------------ | ---------------------- | -------------------------------------------------------- |
| `guardian`               | `/guardian`            | Router principal — dirige al módulo adecuado             |
| `guardian-init`          | `/guardian-init`       | Bootstrap inicial — instala y configura todo             |
| `guardian-security`      | `/guardian-scan`       | SAST + secretos + CVEs + contenedor + IaC                |
| `guardian-bugfix`        | `/guardian-fix`        | Caza y corrige bugs de implementación                    |
| `guardian-quality`       | `/guardian-quality`    | Complejidad, duplicación, deuda técnica                  |
| `guardian-review`        | `/guardian-review`     | Revisión profunda pre-PR / pre-despliegue                |
| `guardian-deps`          | `/guardian-deps`       | Setup de Renovate + escaneo de CVEs + supply chain       |
| `guardian-observability` | `/guardian-observe`    | Logging estructurado, métricas, error tracking           |
| `guardian-performance`   | `/guardian-perf`       | Performance budgets, k6, Lighthouse                      |
| `guardian-compliance`    | `/guardian-compliance` | RGPD/LOPD, licencias, SBOM, política de privacidad       |
| `guardian-scanskill`     | `/guardian-scanskill`  | Vet de skill / servidor MCP / agente antes de instalar   |
| `guardian-grill`         | `/guardian-grill`      | Interrogatorio de comprensión del diff antes del merge   |
| `guardian-improve`       | `/guardian-improve`    | Convierte deuda técnica medida en specs de mejora        |
| (combina 3 de ellas)     | `/guardian-audit`      | Informe ejecutivo: seguridad + calidad + deps            |

También puedes invocarlo todo en **lenguaje natural** (ES, EN o PT). Las skills se disparan por descripción — *"audita el proyecto"*, *"comprueba vulnerabilidades"*, *"antes del merge"*, *"audit the project"*, *"check for vulnerabilities"*, *"before merge"*, *"audita o projeto"*, *"vê se há vulnerabilidades"*, *"antes de fazer merge"*.

### Servidor MCP (54 herramientas, 18 recursos)

El plugin registra un servidor MCP en stdio que Claude Code arranca automáticamente. Las herramientas se agrupan en:

- **Seguridad transversal** (10) — `security_scan_full`, `scan_sast`, `scan_deps`, `scan_secrets`, `scan_containers`, `scan_iac`, `deps_audit`, `bug_hunt` (Semgrep `p/r2c-bug-scan` + `p/security-audit`, más un pack local siempre activo para JS/TS — `configs/semgrep/bugfix-js.yml`, catorce reglas hand-authored que cubren las seis subcategorías de bug que la herramienta clasifica: race conditions, null/undefined safety, off-by-one, memory leaks, manejo de errores silenciado, y dos edge cases. `/guardian-fix` también nombra "broken happy paths" como foco; eso es una categoría de consecuencia, no una forma sintáctica, así que solo se cubre su forma concreta más común — una llamada que muta estado sin `await` dentro de una función async (declaraciones, funciones flecha, métodos de clase/objeto — NO cubre function expressions async, una limitación del motor de Semgrep) — y nada cubre el resto. Son reglas Semgrep OSS: casan sintaxis, no hacen dataflow, así que un bug a dos funciones de su guard sigue siendo invisible para ellas, y la capa heurística (`WARNING`/`INFO`) produce falsos positivos por construcción — `floating-mutation` casa por el nombre del método, así que no distingue una mutación real como `repo.save()` de una llamada sin relación que solo comparte el nombre, como `ctx.save()` (el push síncrono de estado del Canvas 2D, sin relación con la persistencia) — ambas disparan igual; por eso existe `severity_min`. Python tiene también su propio pack — `configs/semgrep/bugfix-py.yml`, diez reglas hand-authored en las mismas seis clases, cada una medida contra las 32 reglas Python que `p/r2c-bug-scan` ya ejecuta y confirmada que dispara donde esas no lo hacen. Sus carencias conocidas se dicen en vez de insinuarse: no hay regla general de "corrutina no esperada" (no es expresable en Semgrep OSS — solo se cubren los cuatro primitivos `asyncio` nombrados, así que un `await` olvidado en un `async def` propio no se detecta), la regla de N+1 de Django casa bucles `for` pero no list comprehensions, no conoce SQLAlchemy ni Peewee, y exige el queryset dentro de la propia cabecera del `for` — `qs = Book.objects.all()` seguido de `for book in qs:` queda en silencio, y esa forma ligada a variable es probablemente la más común en la práctica — `toctou-exists-open` solo reacciona a `os.path.exists`, así que `os.path.isfile`, `os.path.isdir` y `pathlib.Path(p).exists()` quedan todos en silencio, y `none-deref-dict-get` excluye clientes HTTP por la SUBCADENA del nombre del receptor, no por el nombre, así que cualquier receptor cuyo nombre CONTENGA `requests`, `session`, `client`, `httpx`, `aiohttp` o `urllib` se omite — `session_data`, `clients` y `urllib_cache` también son falsos negativos, no solo un diccionario llamado exactamente `client`. Hay dos exclusiones que conviene nombrar como falsos negativos en vez de dejarlas implícitas: `get-without-doesnotexist` cuenta un `except Exception:` amplio como guarda, así que un `.objects.get()` dentro de `except Exception: pass` queda en silencio aquí, aunque sea peor código que un `get` sin guarda (el tragarse el error lo detecta aparte `except-pass`, pero nada une ambas cosas); y `open-without-context` nunca marca destinos que son atributos, así que `self.handle = open(path)` se omite a propósito — su `close()` suele vivir en otro método, fuera del alcance de una regla sintáctica — lo que significa que una clase que de verdad nunca cierra su handle se pierde, y esa es la forma más común de una fuga de fichero de larga duración. Go también tiene el suyo — `configs/semgrep/bugfix-go.yml`, diez reglas hand-authored en las mismas seis clases, y Go es el lenguaje donde el pack del registro deja el mayor hueco: `p/r2c-bug-scan` trae 5 reglas Go y solo 2 caen en una clase de bug, ambas de integer overflow, así que `error_handling` — en el lenguaje donde `if err != nil` ES el modelo de errores — `race_condition`, `null_safety`, `memory_leak` y `edge_case` estaban todas vacías. Sus carencias se dicen en vez de insinuarse: **no hay regla para goroutines colgadas** ni **regla para la captura de la variable del bucle** — esa se construyó, se verificó funcionando y luego se excluyó deliberadamente, porque Go 1.22 pasó a dar a cada iteración su propia variable y Semgrep no lee el `go.mod`, así que en cualquier módulo moderno acusaría código correcto; `body-not-closed` solo reconoce `http.Get`, así que `http.Post` y `client.Do(req)` filtran igual y no se cubren; `lock-without-defer` acepta cualquier `defer mu.Unlock()` en el bloque, así que no distingue un unlock bien colocado de uno diferido en la rama equivocada; `err-blank-assign` dispara en descartes deliberados como `_ = os.Remove(tmp)` en una limpieza, y por eso es `WARNING`; `lock-without-defer` casa por los nombres literales `Lock()`/`Unlock()`, no `RLock()`/`RUnlock()`, así que un read-lock de `sync.RWMutex` sin `defer` — un idioma común en Go — queda totalmente fuera de su alcance; y `nil-map-write` solo detecta un mapa declarado localmente con `var` — un mapa nil que llega como parámetro de función, campo de struct, o valor de retorno entra en panic igual al escribir y no está cubierto, probablemente la forma más común en la práctica real, el mismo tipo de hueco que `open-without-context` tiene para targets de atributo en el pack Python arriba. Java también tiene el suyo — `configs/semgrep/bugfix-java.yml`, ocho reglas hand-authored en las mismas seis clases, y Java es el lenguaje más vacío de los cuatro: `p/r2c-bug-scan` trae 4 reglas Java y **ninguna** cae en una clase de bug — todas son de igualdad y comparación — así que todas las subcategorías estaban a cero, en el lenguaje cuyo defecto más famoso es el `NullPointerException`. Sus carencias se dicen en vez de insinuarse: **no hay regla para `Integer ==`**, porque expresarla exige inferencia de tipos que Semgrep OSS no tiene y el intento disparaba en `v == null` y en comparación de primitivos — una regla que señala `v == null` se desinstalaría el primer día; `stream-not-closed` solo reconoce `new FileInputStream(...)` — y solo por ese nombre simple, así que `FileOutputStream`, `FileReader`, `Socket` y los demás closeables filtran igual y no se cubren, y lo mismo le pasa a un `new java.io.FileInputStream(...)` totalmente cualificado, que el patrón no ve (medido); `static-dateformat` solo reconoce `SimpleDateFormat`, así que un `Calendar` o un `Matcher` compartidos en un campo estático no se cubren; `map-get-deref` no distingue un mapa que puede tener nulos de uno con claves garantizadas, así que un mapa poblado en la línea anterior se marca igual; y `modify-during-iteration` solo casa la forma for-each, así que un bucle indexado que elimina de la lista que indexa tiene el mismo defecto y se escapa. Dos reglas restringen el receptor por el TIPO DECLARADO, lo que compra precisión y cuesta recall: `metavariable-type` casa el tipo declarado exacto, sin subtipado — medido, `type: List` **no** casa un `CopyOnWriteArrayList`, que es precisamente lo que mantiene la regla apartada de él — así que `map-get-deref`, que enumera `Map`, `HashMap`, `TreeMap`, `LinkedHashMap` y `ConcurrentHashMap`, queda en silencio ante un mapa detrás de una interfaz del propio proyecto o de un parámetro de tipo genérico (`<M extends Map<K,V>> … m.get(k).f()`), aunque un `Map` crudo sigue disparando (medido); y `modify-during-iteration`, que enumera `List`, `ArrayList`, `LinkedList`, `Set`, `HashSet`, `LinkedHashSet` y `Collection`, queda en silencio ante un `Deque`, una `Queue`, un `SortedSet` o una colección del propio proyecto. `empty-catch` respeta la convención de Checkstyle / IntelliJ y nunca dispara cuando la variable de la excepción se llama `ignore`, `ignored` o `expected` — el reverso es que una excepción genuinamente tragada escapa a la regla solo por llamarse `ignored`. `optional-get-no-ispresent` es **WARNING, no ERROR**, y eso aplica el criterio de tiers del propio pack en vez de doblarlo: ERROR es para el patrón que es bug independientemente de la intención, y un `o.get()` solo es bug cuando está *sin guarda*. La regla reconoce guardas escritas **inline sobre la misma variable `Optional`** — `if (isPresent())`, un `return` / `throw` / `continue` / `break` anticipado bajo `!isPresent()` o `isEmpty()`, las tres formas ternarias (el ternario necesitó cláusulas propias por ser una *expresión* condicional, un nodo de la AST distinto de un `if`), y `if (o.filter(p).isPresent())` — y falla **cualquier guarda que llegue a la comprobación a través de otro método o de otra variable**. El caso concreto es la guarda delegada a un helper, `if (!present(o)) { return d; }`, que exige análisis interprocedimental que Semgrep OSS no hace: esa forma es falso positivo y lo seguirá siendo, y por eso justamente la regla está en WARNING en vez de cargar una lista de exclusiones sin fin. Cuatro falsos positivos se aceptan en vez de corregirse, cada uno reproducido sobre código correcto: `stream-not-closed` en `open(); try { … } finally { close(); }` (ya es la razón declarada de que sea WARNING); `static-dateformat` en un `static final SimpleDateFormat` cuyos accesos pasan todos por un método `synchronized` (probar que *todos* los accesos están sincronizados es análisis de programa completo, que Semgrep OSS no hace, y un formatter compartido serializa a todos los llamadores de todos modos); `loop-lte-length` en `i <= a.length` cuando el cuerpo se protege con `i < a.length` o nunca indexa `a`; y `printstacktrace-only` en el único sitio donde la llamada es correcta — el fallback cuando fue el propio logger el que lanzó. **JS/TS, Python, Go y Java**: los demás lenguajes aún no tienen pack local. Un archivo de reglas local roto a mano degrada en vez de hacer fallar todo el escaneo, ya sea la rotura un YAML inválido o un único patrón de regla mal formado), `suggest_fix`, `register_custom_rules`
- **WordPress** (9) — `scan_wordpress` (Semgrep PHP + rule pack WP + Trivy + gitleaks + PHPCS-WPCS), `wp_audit` (instalación en vivo: checksums + admins + flags de configuración vía WP-CLI), `wp_vuln_check` (WPScan DB), `wp_plugin_check`, `wp_cron_audit`, `wp_rest_audit`, `wp_recommend_hardening`, `wp_describe_setup`, `bulk_audit_wordpress_sites`
- **C# / .NET** (4 dedicadas + ramas) — `scan_dotnet_secrets`, `dotnet_target_framework_check`, `dotnet_efcore_audit`, `dotnet_describe_setup`; `scan_sast` corre `p/csharp` + parsea la salida de security-code-scan; `deps_update_plan` corre `dotnet list package --outdated`; `observability_setup` genera plantillas Serilog + prometheus-net
- **Calidad, deps, priorización** (5) — `quality_check`, `deps_update_plan`, `triage_findings`, `prioritize_findings`, `risk_score`
- **Compliance & SBOM** (5) — `compliance_check` (RGPD/GDPR), `compliance_evidence`, `generate_sbom` (Syft), `sbom_diff`, `license_compatibility`
- **Observabilidad & rendimiento** (3) — `observability_setup` (Pino/structlog/Monolog/Serilog + Prometheus), `health_status`, `perf_check` (k6 / Lighthouse)
- **Lifecycle / PR / gobierno** (11) — `init_project`, `precommit_install`, `review_pr`, `set_baseline`, `diff_scans`, `regression_alert`, `report_export` (Markdown default / branded **HTML** with dark/light toggle / **SARIF 2.1.0** / JSON), `create_github_issues`, `create_fix_pr` (aplica fixes que un escáner ya produjo — bumps de `deps_update_plan`, `--autofix` de Semgrep — dentro de un worktree de git aislado, prueba cada uno con un differential de escaneo y una corrida de pruebas, y abre un pull request por ecosistema/escáner vía `gh` local; **`apply` tiene valor por defecto `false`** — un dry run sigue creando el worktree, aplicando el fix y corriendo los dos differentials, pero no abre ningún PR y no deja nada atrás, ni siquiera un branch, y su propio escaneo de verificación nunca se convierte en el escaneo más reciente del proyecto, así que una vista previa no puede redirigir `guardian://findings/open` ni `risk_score`; los bumps de maven y gradle quedan fuera de alcance, una brecha heredada del propio `deps_update_plan`; una segunda aparición de la misma regla en un archivo ya corregido no se ve como nueva — la comprobación "no new finding" compara `(rule_id, file_path)`, no el fingerprint, porque el fingerprint cambia cada vez que el fix desplaza una línea; y `fix_applied` nunca pasa a `1`, una columna muerta en `findings` — el pull request abierto es el registro), `suppress_finding`, `audit_executive`
- **Cadena de suministro de agentes IA** (1) — `scan_skill`: audita una **skill / servidor MCP / agente de terceros antes de instalarlo**. Acepta un directorio, archivo, `.zip` o URL git/HTTP(S) y corre 16 categorías de amenaza (prompt injection, exfiltración de datos, escalada de privilegios, supply chain, agencia excesiva, manejo de salida, fuga del system-prompt, envenenamiento de memoria, mal uso de tools, agente rogue, abuso de triggers, código peligroso, taint, firmas, MCP least-privilege, MCP tool poisoning), un motor de **firmas estilo YARA**, taint-light source→sink, detección de Unicode oculto y lookups de CVE en **OSV.dev** — todo agregado en una **puntuación de riesgo 0-100** y un veredicto **SAFE → DO NOT INSTALL**
- **Superficie de ataque** (1) — `map_attack_surface`: inventario estático de rutas, variables de entorno y puertos declarados en las 8 stacks soportadas, con informe de cobertura por lenguaje. También descubre e importa documentos OpenAPI 3.x y Swagger 2.0 (JSON o YAML — **las colecciones de Postman no son compatibles**), etiqueta cada ruta con su procedencia (`code` o `spec`) y compara ambas: **endpoints shadow** (existen en el código, no documentados), **documentación muerta** (documentada, sin código que la implemente) y rutas coincidentes. Sin spec encontrada no hay diff — `spec_diff: null`, nunca un diff que reporte todas las rutas como no documentadas — y una ruta cuyo camino completo no se puede resolver nunca se reporta como endpoint shadow ni como documentación muerta; cuántos resultados se retuvieron por ese motivo se reporta junto al diff
- **DAST activo** (1) — `scan_dast`: el paso siguiente a `map_attack_surface` — envía peticiones HTTP reales a una aplicación **ya en ejecución** (nunca la arranca, construye ni detiene) y comprueba el inventario de rutas en cuanto a accesibilidad, acceso anónimo a rutas que exigen autenticación, autorización diferencial, CORS, cabeceras de seguridad, divulgación de información, métodos HTTP no documentados y redirecciones fuera del origen, más un burst opcional de rate-limit y una pasada opcional de **nuclei**. Envolvente de seguridad: **solo loopback** salvo que quien llama certifique `authorized_target: true`; métodos **de solo lectura** (GET/HEAD/OPTIONS) salvo que `allow_write_methods` esté activo, y aun así con cuerpo vacío, más el burst opcional `probe_rate_limit` — la única excepción — que envía POST a exactamente una ruta; sin payloads de inyección, sin adivinar credenciales. El motor propio **no** prueba inyección — eso queda delegado al modo `-dast` de nuclei, excluido por defecto — así que **un resultado limpio no es evidencia de seguridad frente a inyección**, y el conjunto de plantillas por defecto de nuclei prueba el origen, no las rutas específicas de este proyecto
- **Alcanzabilidad** (1) — `validate_finding`: el otro paso siguiente a `map_attack_surface` — responde, por finding, si algo fuera del proceso puede alcanzar el archivo donde vive, a partir de un grafo de imports a nivel de archivo, con raíz en los archivos que declaran rutas. Devuelve `reachable` / `unreachable` / `unknown` por finding con evidencia concreta (ruta más cercana, número de saltos, cuántas rutas alcanzan el archivo, exposición anónima confirmada en vivo) y los coverage gaps detrás de ella. **Solo informe**: nunca suprime un finding ni cambia la severidad. `unreachable` nunca se emite para Ruby, Java, C# o PHP (los cuatro resuelven código en runtime, no por import). **Se** emite — y puede estar equivocado — para un archivo alcanzado solo por un CLI/cron/queue, o siempre que un import dinámico — `import(expr)`, `require(variable)`, reflection, un registro de plugins — no se pueda resolver
- **Meta / host** (3) — `detect_stack`, `check_toolchain`, `install_toolchain`

**Recursos** — `guardian://wp/audit/latest`, `guardian://wp/audit/{scan_id}`, `guardian://wp/cron`, `guardian://dotnet/target-frameworks`, `guardian://dotnet/efcore`, `guardian://surface/latest`, `guardian://surface/{id}`.

**Almacenamiento** — SQLite en `.guardian/guardian.db`. Tablas: `scans`, `findings`, `cves`, `baselines`, `suppressions`, `stack_snapshots`, `surface_snapshots`, `finding_validations`. Permite tracking de baseline, deltas scan-a-scan, supresiones con caducidad, alertas de regresión.

### Hooks de protección (auto-activos)

Con el plugin activo, Claude Code carga automáticamente `hooks/hooks.json` — tres guardrails **sin dependencias y fail-open**, en milisegundos (sin módulos nativos, nunca rompen tu flujo):

- **SessionStart** — informa al agente de la postura de seguridad del proyecto: rama, cambios sin commitear, antigüedad del último escaneo y si el proyecto está guardian-initialized.
- **PostToolUse (Write/Edit/MultiEdit)** — analiza el texto recién escrito buscando secretos hardcoded (AWS, GitHub, GitLab, Anthropic, OpenAI, Stripe, Google, Slack, claves privadas, …) y avisa con vista previa **redactada**. El escaneo completo del historial sigue en `scan_secrets` (gitleaks) vía `/guardian-scan`.
- **PreToolUse (Bash)** — **bloquea por defecto comandos catastróficos** (`rm -rf /`, `curl … | sh`, `dd`/`mkfs` en disco crudo, fork bombs); **avisa** en los meramente arriesgados (force-push, hard reset, `sudo`, `chmod 777`).

El bloqueo de la *escritura* de secretos es **opt-in**: define `"secrets": { "block": true }` en `.guardian/hooks.config.json`. Ajusta todo ahí, allowlist de falsos positivos en `.guardian/hooks-allowlist.json`, o desactiva todos los hooks con `GUARDIAN_HOOKS=off`. Los mismos detectores corren en el CLI para terminal / CI: `node cli/dev-guardian.mjs check --file <ruta>` y `--bash "<command>"` (exit 1 al encontrar algo).

### Herramientas open-source orquestadas

Semgrep · Trivy · OSV.dev · gitleaks · Renovate · nuclei · Playwright · Pino / structlog / Monolog / Serilog · Prometheus + Grafana · GlitchTip · Uptime Kuma · k6 · Artillery · Lighthouse · Syft · WPScan · WP-CLI · PHPCS + WPCS · security-code-scan · dotnet-outdated · ruff · bandit · jscpd · eslint · hadolint · shellcheck.

### Instalación del plugin

#### A) Vía marketplace (recomendado) — Claude Code CLI

```text
/plugin marketplace add https://github.com/linofcp007/dev-guardian
/plugin install dev-guardian@dev-guardian
```

Funciona con cualquier URL git (HTTPS o SSH) o ruta local de una carpeta que contenga [`.claude-plugin/marketplace.json`](.claude-plugin/marketplace.json).

> ⚠️ **Limitación de la app Claude Desktop.** El cliente Desktop rechaza actualmente marketplaces de terceros con `External plugin sources are not yet supported` (la funcionalidad está bloqueada server-side). Es una limitación de Claude Desktop, no un problema de este plugin — cualquier marketplace alojado en GitHub falla hoy de la misma forma. Issues a seguir: [anthropics/claude-code#41653](https://github.com/anthropics/claude-code/issues/41653) (fuentes remotas), [anthropics/claude-code#52147](https://github.com/anthropics/claude-code/issues/52147) (rutas locales). Hasta que llegue la paridad, usa la opción **B** abajo o instala vía el Claude Code CLI.

#### B) Copia manual de carpeta (funciona en todas partes)

Copia la carpeta entera a:

- **Linux / macOS**: `~/.claude/plugins/dev-guardian/`
- **Windows**: `%USERPROFILE%\.claude\plugins\dev-guardian\`

Luego, dentro de Claude Code, ejecuta `/plugin` y activa `dev-guardian`. Alternativamente, añade a tu `~/.claude/settings.json`:

```json
{
  "enabledPlugins": { "dev-guardian@dev-guardian": true }
}
```

> El servidor MCP corre desde `mcp/dist/`. En la primera instalación ejecuta una vez `cd mcp && npm install && npm run build`. Después el plugin lo arranca automáticamente vía `node ${CLAUDE_PLUGIN_ROOT}/mcp/dist/server.js`.
>
> Los scripts `.sh` en `scripts/` corren directamente en Linux/macOS. En Windows nativo necesitas **WSL2** o Git Bash; las skills/commands en sí funcionan en cualquier SO.

### Otros hosts de IA (Cursor · Windsurf · Copilot · Codex · Gemini · Cline · Claude Desktop)

El motor real es el **servidor MCP**, así que cualquier host compatible con MCP puede usar dev-guardian — no solo Claude Code. La **CLI `mcp-config`** conecta un host desde una terminal normal — sin necesidad de conexión MCP (sin huevo-y-gallina). Rellena la ruta absoluta del servidor por ti y o imprime el bloque para pegar o, con `--write`, lo fusiona en el proyecto y coloca el archivo de reglas. Idempotente.

Desde una terminal en tu proyecto (tras `cd mcp && npm install && npm run build` una vez):

```text
node cli/dev-guardian.mjs mcp-config cursor          # imprime el bloque para pegar
node cli/dev-guardian.mjs mcp-config all             # todos los hosts
node cli/dev-guardian.mjs mcp-config codex --write   # escribe + fusiona en el proyecto
node cli/dev-guardian.mjs mcp-config all --scope global
```

| Host | Archivo de config MCP (proyecto / global) | Archivo de reglas |
| ---- | ----------------------------------------- | ----------------- |
| **Cursor** | `.cursor/mcp.json` / `~/.cursor/mcp.json` | `.cursor/rules/dev-guardian.mdc` |
| **Windsurf** | `~/.codeium/windsurf/mcp_config.json` (global) | `.windsurfrules` |
| **GitHub Copilot** | `.vscode/mcp.json` (clave `servers`, `type:"stdio"`) | `.github/copilot-instructions.md` |
| **Codex CLI** | `.codex/config.toml` / `~/.codex/config.toml` | `AGENTS.md` |
| **Gemini CLI** | `.gemini/settings.json` / `~/.gemini/settings.json` | `GEMINI.md` |
| **Cline** | manual — la herramienta devuelve un snippet para pegar | `.clinerules` |
| **Claude Desktop** | `claude_desktop_config.json` (específico del SO, global) | — (pega `AGENTS.md` en las instrucciones de un Project) |

**Fallback manual** (si prefieres no dejar que la herramienta edite configs): pega uno de los bloques de abajo, sustituyendo la ruta por la ruta **absoluta** a `mcp/dist/server.js`.

```jsonc
// Cursor / Windsurf / Gemini / Claude Desktop  (mcpServers)
{ "mcpServers": { "dev-guardian": {
  "command": "node", "args": ["/ruta/abs/a/dev-guardian/mcp/dist/server.js"], "env": {}
} } }
```

```jsonc
// GitHub Copilot  (.vscode/mcp.json — fíjate en la clave "servers" + type)
{ "servers": { "dev-guardian": {
  "type": "stdio", "command": "node", "args": ["/ruta/abs/a/dev-guardian/mcp/dist/server.js"]
} } }
```

```toml
# Codex CLI  (~/.codex/config.toml — ruta entre comillas simples evita el escape en Windows)
[mcp_servers.dev-guardian]
command = "node"
args = ['/ruta/abs/a/dev-guardian/mcp/dist/server.js']
enabled = true
```

> Claude Desktop no tiene mecanismo de archivo de reglas — pega el contenido de `host-rules/AGENTS.md` (o `GEMINI.md`) en las **instrucciones personalizadas de un Project**. Claude Code / Cowork no necesitan nada de esto: el plugin registra el servidor automáticamente.

### Ejecuta escaneos en CI (headless, sin host MCP)

`node cli/dev-guardian.mjs scan` corre el mismo pipeline de escaneo que una sesión interactiva — sin Claude Code, sin conexión MCP — y hace gate del resultado contra una **baseline committeada**. `dev-guardian baseline update` es el único comando que escribe esa baseline, y solo cuando se pide:

```text
node cli/dev-guardian.mjs baseline update --project .      # adopta los findings actuales una vez
node cli/dev-guardian.mjs scan --project . --fail-on high --sarif results.sarif
```

Códigos de salida: `0` pasó, `1` el gate falló (finding nuevo en la baseline, severidad >= `--fail-on`), `2` **escaneo incompleto** (un scanner esperado no corrió — nunca leas esto como un pase), `3` error de uso/configuración. Para el paso DAST, `--start-command <cmd>` arranca la app a probar — exige `--base-url` junto a él (la misma URL es el objetivo del health-check y el origen de `scan_dast`) — y solo se acepta **en la línea de comandos, nunca desde `.guardian/ci.json`**: un pull request de un fork podría editar ese archivo y ejecutar código arbitrario en el runner. Ejecuta la CLI sin argumentos para ver la referencia completa de flags.

> **La distribución es `git clone`, no `npx`.** Esto se distribuye como un repositorio de plugin de Claude Code, no como un paquete npm, así que todavía no hay instalador de una línea (una forma publicable se está investigando aparte, condicionada a pasar de verdad el validador de plugins de Claude Desktop). Clona a un tag fijo con `--depth 1` — `v1.3.0` aquí, o el release que quieras seguir — luego ejecuta `npm ci` una vez dentro de `mcp/`: `mcp/dist/` viene committeado, así que no hay nada que *compilar*, pero `mcp/node_modules` está en el gitignore como el resto de este repo, y `scan`/`baseline update` siguen importando un par de paquetes de runtime (`execa`, `yaml`) que el build committeado no empaqueta.

Un job listo para copiar y pegar — los findings aparecen como anotaciones en el diff del pull request, no perdidos en un log. **`ubuntu-latest` no trae Semgrep, gitleaks ni Trivy**, así que el job los instala él mismo; sáltate ese paso (o deja que falle) y cada run reporta `coverage: none` / exit `2` — no es una avería, es la respuesta diseñada para un escaneo que no escaneó nada:

```yaml
name: dev-guardian

on:
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 22

      # Clonado FUERA del checkout para que el propio código de dev-guardian
      # nunca entre en el escaneo.
      - name: Clone dev-guardian
        run: |
          git clone --depth 1 --branch v1.3.0 \
            https://github.com/linofcp007/dev-guardian.git "$RUNNER_TEMP/dev-guardian"
          cd "$RUNNER_TEMP/dev-guardian/mcp" && npm ci

      # Ninguno de estos viene en ubuntu-latest. Semgrep solo tiene fallback
      # vía Docker dentro de los propios scanners de dev-guardian, pero
      # gitleaks y Trivy no, así que saltarse este paso igual limita cada
      # run por debajo de coverage: full. pipx ya viene instalado en
      # ubuntu-latest; sudo es sin contraseña para el usuario runner.
      - name: Install scanners (Semgrep, gitleaks, Trivy)
        run: |
          pipx install semgrep
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"

          GL_TAG=$(curl -sL -o /dev/null -w '%{url_effective}' https://github.com/gitleaks/gitleaks/releases/latest)
          GL_TAG=$(basename "$GL_TAG")
          curl -sL "https://github.com/gitleaks/gitleaks/releases/download/${GL_TAG}/gitleaks_${GL_TAG#v}_linux_x64.tar.gz" \
            | sudo tar -xz -C /usr/local/bin gitleaks

          wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg
          echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" \
            | sudo tee /etc/apt/sources.list.d/trivy.list > /dev/null
          sudo apt-get update -qq && sudo apt-get install -y trivy

      - name: Scan
        id: scan
        run: |
          set +e
          node "$RUNNER_TEMP/dev-guardian/cli/dev-guardian.mjs" scan --project . --sarif results.sarif
          echo "exit_code=$?" >> "$GITHUB_OUTPUT"

      # Sube el SARIF que exista aunque el paso de arriba haya "fallado" — un
      # gate fallido y un escaneo incompleto igual producen informe. El
      # executionSuccessful del SARIF dice SI la cobertura fue completa; no
      # dice QUÉ scanner faltó — eso es el exit 2 y el log de arriba.
      # Exige que el repositorio sea público, o GitHub Code Security en uno
      # privado — si no, quita este paso y usa --format json.
      - uses: github/codeql-action/upload-sarif@v3
        if: always() && hashFiles('results.sarif') != ''
        with:
          sarif_file: results.sarif

      - name: Falla el build en un gate fallido o error de uso real
        if: steps.scan.outputs.exit_code == '1' || steps.scan.outputs.exit_code == '3'
        run: exit 1

      - name: Avisa (sin fallar) en cobertura incompleta
        if: steps.scan.outputs.exit_code == '2'
        run: echo "::warning::dev-guardian scan incompleto — mira el log del paso de arriba para saber qué scanner faltó"
```

Tres cosas que este snippet no te puede esconder:

- **Un escaneo en CI deja `.guardian/` en el workspace.** `security_scan_full` y `map_attack_surface` escriben la salida cruda de los scanners en `.guardian/reports/` dentro del proyecto escaneado, igual que hacen en una sesión interactiva — solo la base de datos SQLite es efímera. El servidor MCP añade `.guardian/` al `.gitignore` automáticamente cada vez que arranca contra un proyecto (una sesión interactiva, cualquier host) — eso nunca pasa desde la CLI, así que un repositorio que solo escanea vía CI tiene que añadir la línea a mano, o un paso posterior del pipeline que comprueba un working tree limpio fallará por un motivo que no parece nada:

  ```text
  .guardian/
  ```

- **El SARIF por sí solo no te dice *qué* scanner falta.** Su flag `invocation.executionSuccessful` pasa a `false` siempre que la cobertura no sea completa — así que quien lea solo el upload ya puede distinguir un run incompleto de uno limpio — pero el SARIF no tiene campo de *uso general* para este texto, así que el nombre del scanner y el motivo solo viven en el exit code `2` y en la salida humana/JSON del propio paso. Trata un SARIF subido con cero resultados como inconcluso, no como limpio, hasta que compruebes el exit code.

- **La subida de code-scanning exige un repositorio público, o GitHub Code Security en uno privado.** Sin ninguno de los dos, el paso `upload-sarif` falla el job por un motivo que no tiene nada que ver con los findings. En un repositorio privado sin esa licencia, quita el paso de subida y usa `--format json` más el exit code.

### Panel local (`status`, `dashboard`)

Dos vistas de solo lectura sobre el mismo `.guardian/guardian.db`, para quien desarrolla en su propio portátil — no es un artefacto de CI (eso es el SARIF de arriba) ni un entregable para cliente (eso es el HTML de marca de `report_export`):

```text
node cli/dev-guardian.mjs status --project .        # una pantalla de terminal
node cli/dev-guardian.mjs dashboard --project .      # HTML autocontenido, se abre en el navegador
```

`status` imprime la puntuación de riesgo y su banda, los findings abiertos y los CVEs por severidad, ambos deltas (desde el escaneo anterior del mismo tipo, desde la baseline activa), hasta 3 hotspots de findings (ordenados por recuento, no por severidad), qué escáneres faltan y qué deja eso fuera de los números, y las supresiones activas — una pantalla, nada más. `dashboard` renderiza el mismo snapshot como `.guardian/dashboard.html` — sin CDN, sin fetch de fuentes, sin ninguna llamada de red — con filtrado y ordenación de columnas en el cliente; se abre automáticamente solo cuando stdout es un TTY (`--no-open` lo suprime, `--out <path>` reubica el archivo). Ninguno de los dos comandos ejecuta un escaneo, modifica la base de datos ni abre un socket, y **ambos siempre terminan con exit `0` en cuanto renderizan** — incluso en un proyecto lleno de críticos, o uno nunca escaneado (`3` solo ante un error de uso). Informan; quien hace de gate es `scan`.

Vale la pena saber antes de confiar en lo que hay en pantalla: **la página es un snapshot, no algo en vivo** — refleja el escaneo que había terminado cuando ejecutaste el comando, y no se actualiza cuando corre un escaneo posterior, así que vuelve a generarla para ver uno nuevo — y la ventana en sí está igual de acotada: el último escaneo más dos deltas, nunca una tendencia de varias semanas (`/guardian-trend` sigue pidiendo un historial que nada aquí calcula). Una pantalla limpia también es solo tan fiable como el `missing_tools` que la acompaña: un escáner que corrió y no produjo nada en silencio se ve, a este nivel, idéntico a uno que no encontró nada erróneo.

### Filosofía

- **Pragmático por defecto** — no bloquea el trabajo por cuestiones cosméticas
- **Paranoico cuando es crítico** — secretos en producción, RCE, SQLi → detiene y alerta
- **Stack-aware** — detecta tu lenguaje y configura solo lo relevante
- **Multiplataforma** — Linux, macOS, Windows (con WSL)
- **Cero lock-in** — todas las herramientas usadas son open-source y self-hostable
- **Idempotente** — ejecutar `guardian init` dos veces no duplica nada
- **Degradación elegante** — escáneres ausentes se reportan, nunca tumban un scan

### Stacks soportados

JavaScript / TypeScript (Node, Next, React, Vue, Svelte, Angular), Python (Django, Flask, FastAPI), PHP (Laravel, Symfony, **WordPress + Kadence + WooCommerce + Tutor LMS**), **C# / .NET (ASP.NET Core, EF Core, central package management)**, Go, Rust, Ruby, Java / Kotlin, Docker, Terraform, Kubernetes, Ansible, GitHub Actions.

Para lenguajes no soportados explícitamente, las skills recurren a Semgrep `--config=auto` (cubre más de 30 lenguajes) y reglas genéricas para secretos.

### Estructura del repositorio

```text
dev-guardian/
├── .claude-plugin/
│   ├── plugin.json              # declara el servidor MCP + metadatos
│   └── marketplace.json
├── commands/                    # 48 slash commands
├── skills/                      # 13 skills (una por destino del router)
├── hooks/                       # hooks.json + guardian-hook.mjs (guardrails auto-activos)
├── cli/                         # CLI dev-guardian.mjs (mcp-config, check, scan, baseline)
├── mcp/                         # Servidor MCP (TypeScript + SQLite)
│   ├── src/                     # tools/, resources/, runners/, storage/, platform/
│   ├── test/                    # 1094 tests unit + integration + e2e
│   ├── scripts/                 # smoke.mjs, smoke-wp-dotnet.mjs
│   └── dist/                    # artefacto compilado (node dist/server.js)
├── scripts/
│   ├── detect/detect-stack.sh   # detección de lenguajes/frameworks
│   ├── install/                 # install-linux.sh, install-macos.sh
│   └── scan/                    # full-security-scan, review-scan, etc.
├── configs/
│   ├── renovate/, gitleaks/, semgrep/, pre-commit/
├── host-rules/                  # AGENTS.md, cursor.mdc, copilot-instructions.md, …
└── README.md
```

### Licencia

MIT — úsalo, modifícalo, compártelo libremente.

### Autoría

Carlos Pereira · prodigitalkey.com
