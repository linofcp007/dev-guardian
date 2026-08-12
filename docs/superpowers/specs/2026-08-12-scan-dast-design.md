# Design — `scan_dast`, inventory-driven active DAST

Item 3 of 7 in the strix-gap project. The tool the whole sub-project (items 1
and 2) exists to feed: `map_attack_surface` builds a static route inventory,
the OpenAPI import cross-references it against declared specs, and `scan_dast`
takes that inventory and confirms — against a *running* application — what is
actually reachable, what is served without credentials, and what leaks.

## 1. Context

Every other tool in this server reads files. `scan_dast` is the one that sends
traffic to a live system. That single difference drives the entire design: the
target may be production, it may belong to someone other than the user, and the
inventory it consumes contains routes like `DELETE /users/{id}` and
`POST /admin/reset`. A tool that naively "tests the endpoints it is handed"
deletes real data on its first run. The safety envelope is therefore not a
feature of this design — it *is* the design.

The value proposition is the inverse of a conventional DAST scanner. A generic
scanner reports `GET https://host/api/orders → 200 no-auth` and cannot tell you
where that lives. Because every `RouteRecord` carries `file` and `line`, a
`scan_dast` finding points at `src/routes/orders.ts:42`. It enters the shared
`findings` table like any static finding, so it participates in dedupe, diff,
baseline, triage and suppression instead of living in a silo. A nuclei finding
that matches no route simply carries no file, and that absence is visible.

### What the inventory buys that a bare DAST does not

- `code_only` (shadow) route + **live** → a *confirmed* shadow endpoint, not a
  static suspicion.
- `spec_only` (dead-doc) route + **404** → *confirmed* dead documentation.
- `spec_only` route + **live** → not a project bug at all: a **coverage gap in
  `map_attack_surface` itself**, which the tool reports against its own
  extractor.
- Spec-derived `auth_hint: 'required'` + **live 2xx with no credentials** → an
  authentication bypass confirmed on both ends (the spec says it needs auth;
  the server serves it anonymously). This is the single strongest finding the
  tool can produce, and it exists only because item 2 populates `auth_hint`
  from an OpenAPI `security` declaration — no Semgrep rule populates it from
  code (see `mapAttackSurface.ts` and `surface/specImport.ts#authHint`).

### Non-goals (v1)

- **No injection payloads.** No SQLi, no XSS probes in the own engine. Real XSS
  needs a browser; blind SQLi needs timing or destructive probes. A fabricated
  injection finding is worse than none — and fabricated findings are the exact
  failure class the previous two features spent their whole review budget
  killing. Injection is delegated to nuclei's maintained templates, and only
  under `-dast` fuzzing, which the default envelope excludes.
- **No credential brute-force, no dictionary attacks, no rainbow tables.**
  Guessing real passwords against real accounts locks out those accounts (the
  very control being tested), generates traffic that *is* an attack, and
  answers "does rate limiting work?" no better than a benign burst does.
  Rainbow tables are an offline attack against stolen hashes — there is no hash
  in a live-target HTTP scan and nowhere to apply one. The legitimate goal
  ("verify the limiter works") is served by the rate-limit probe below.
- **No app lifecycle management.** The tool does not start, build, or stop the
  target application. It never executes a command from the project under test.
  See §3.
- **No DNS resolution.** Target classification is purely lexical. See §4.
- **No stateful crawling / spidering.** The route list is the plan. The tool
  does not discover new paths by following links; that is nuclei's job for the
  origin, and out of scope for the own engine.

## 2. Decisions taken during design

Locked with the user, in order:

1. **Target** — loopback (`localhost`, `127.0.0.0/8`, `::1`) probes directly;
   any other host requires an explicit `authorized_target: true` attestation
   that an agent does not invent on its own, and that attestation is recorded
   in the scan.
2. **Write envelope** — read-only by default (`GET`/`HEAD`/`OPTIONS`). The
   write methods (`POST`/`PUT`/`PATCH`/`DELETE`) are gated behind an explicit
   `allow_write_methods` flag, and even then are sent with an empty body: the
   `400`/`422`-vs-`401`/`403` signal answers the authorization question without
   writing. A `2xx` on a write method is reported as "may have mutated state".
3. **`ANY` expansion** — an `app.all()` / `ANY` route is the most permissive
   surface in the project, so it must not be under-probed. It expands to
   `GET`/`HEAD`/`OPTIONS` by default, and to all five methods when
   `allow_write_methods` is on. Expansion is *subordinate* to the write
   envelope, never an exception to it.
4. **Startup** — the user brings the app up; the tool probes `base_url` and, if
   nothing answers, returns a clear error ("nothing listening at X — start the
   app first") rather than zero findings. The MCP tool has **no** `start_command`
   parameter; automatic startup is deferred to the item-5 CLI, where the filler
   is a human writing a pipeline file, not a model reading the repository.
5. **Engine** — own inventory-driven engine (motor B) **plus** nuclei from v1.
6. **Credentials** — optional in v1, via `auth_header_env` (recommended: the
   *name* of an env var) or `auth_header` (literal). Never persisted, always
   redacted. Unlocks differential-authz detection, which needs no spec.
7. **Rate-limit probe** — opt-in, bounded burst against a synthetic
   non-existent username; the finding is the *absence* of a `429`/`Retry-After`.
   No brute-force.

## 3. Architecture

The boundary that survived both prior features: pure logic separated from I/O,
because every fabrication defect in items 1 and 2 was born in a layer that read
input *and* decided at the same time. Detection logic lives only in pure
modules; the orchestrator is glue with no detection in it.

### New files

| Module | Kind | Responsibility |
| --- | --- | --- |
| `mcp/src/dast/target.ts` | **pure** | Classify `base_url` (loopback / private / public) and decide allowed / needs-attestation / refused. No DNS. |
| `mcp/src/dast/plan.ts` | **pure** | `RouteRecord[]` + options → `ProbeRequest[]`. All the safety discipline lives here. |
| `mcp/src/dast/probe.ts` | I/O | Execute one `ProbeRequest` → `ProbeResult`. Never throws; a network failure is a recorded result. |
| `mcp/src/dast/analyze.ts` | **pure** | `ProbeResult[]` + inventory context → `Finding[]`. All detection logic. |
| `mcp/src/dast/nuclei.ts` | I/O | Invoke nuclei, read JSONL. Mirrors `surface/scanSemgrep.ts`. |
| `mcp/src/dast/normalizeNuclei.ts` | **pure** | nuclei JSONL → `Finding[]`, matched to routes when the URL maps to one. |
| `mcp/src/tools/scanDast.ts` | orchestrator | Wiring. Reads the surface snapshot, calls the above, persists findings. No detection logic. |

Storage touches `findingsRepo` only — no new table (contrast item 1, where "a
route is not a finding" justified `surface_snapshots`; here a DAST result *is* a
finding). `'dast'` is appended to `SCAN_TYPES` in `types.ts`. Findings use the
existing `Category` value `'security'` — no new category — with the check name
carried in `subcategory` so the eight checks stay individually filterable.

### Data flow

```text
surface snapshot (latest, for this tree)         auth env / header (optional)
         |                                                 |
         v                                                 v
   plan.ts ── ProbeRequest[] ──> probe.ts ── ProbeResult[] ──> analyze.ts ──> Finding[]
         ^                                                                        |
   target.ts (gate: refuse before any probe)                                     |
                                                                                  v
   nuclei.ts ── JSONL ──> normalizeNuclei.ts ── Finding[] ───────────────> findingsRepo
```

`target.ts` runs first and can refuse the whole run before a single packet is
sent. If the surface snapshot is missing, the orchestrator refuses with "run
`map_attack_surface` first" — zero routes probed must stay distinguishable from
zero problems found.

## 4. Target classification, without DNS

Purely lexical over the host string:

- **loopback** — `localhost`, any `127.0.0.0/8` literal, `::1`, `[::1]`.
- **private** — RFC1918 literals (`10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`), `169.254.0.0/16`, `fc00::/7`.
- **public** — everything else.

`private` and `public` are both gated identically — only loopback is
auto-allowed — so the distinction exists solely to word the refusal accurately:
"192.168.1.50 is on your private network" and "api.example.com is on the public
internet" call for different confirmations from the person reading it. The
classification must never widen what is allowed.

Loopback probes directly. Anything else requires `authorized_target: true`,
**including a hostname that happens to resolve to loopback**. DNS is not
resolved: resolving would open the door to DNS-rebinding (classify as loopback,
connect to something else on the retry) and would make the module impure. The
only possible error is asking for *too much* attestation, never too little —
the safe direction.

Attestation, when supplied, is recorded in the scan meta so an audit trail
shows a human (or an explicitly-configured agent) authorized the remote target.

## 5. The safety envelope — carved into `plan.ts`

Every item here is a property of the pure planner, unit-tested directly, so a
regression is a failing test rather than a live misfire:

- **`path_partial: true` is never probed.** The entire `unmatchable` discipline
  from item 2 exists because a DAST tool sends HTTP requests to whatever path it
  is handed. A partial/templated path (`servers[].url` with a variable, an
  unresolved mount prefix) is dropped from the plan, and the count of dropped
  routes is reported.
- **Synthetic path parameters.** `/users/{id}` → `/users/1`, `/items/{slug}` →
  `/items/sample`. A route whose parameters were filled synthetically **never**
  yields the "unreachable" finding: a `404` there is ambiguous ("route absent"
  vs "record 1 absent") and the ambiguity is reported, not guessed away.
  Substitution must handle all four parameter syntaxes the inventory can carry
  — `{id}` (OpenAPI/Spring), `:id` (Express/Rails), `<int:id>` (Flask),
  `(?P<id>…)` (WordPress) — by **reusing `surface/specDiff.ts#PARAM_SYNTAX`**,
  not by re-deriving the patterns. Two independent lists of the same four
  regexes drift, and a syntax missing from this one becomes a literal `:id`
  sent down the wire. If reuse requires exporting the constant, export it.
- **Redirects are not followed** (`redirect: 'manual'`). Following a redirect
  could carry the scanner off the authorized target (an open redirect →
  off-origin), so redirects are observed, not chased — and the open-redirect
  detection is itself a finding.
- **Write methods** only under `allow_write_methods`, always empty-bodied. A
  `2xx` is flagged "may have mutated state" so the reader knows a write may have
  landed.
- **`ANY`** expands per decision 3 (three read methods by default, five with
  writes enabled).
- **Zero credentials required.** Everything the tool reports is either
  anonymous-access truth, or (with optional creds) a differential between
  anonymous and authenticated.
- **Bounds, all reported when they cut**, never silent: max concurrency 4, per-
  request timeout 5s, a global request ceiling and a global wall-clock ceiling.
  A truncated run says so, the same discipline as the item-1 file caps. The
  global wall-clock ceiling is implemented by aborting the shared `AbortSignal`
  that `probe.ts` already honours, so probes cut by the deadline record
  `outcome: 'cancelled'` — distinct from `timeout`, which is the target
  failing to answer.

## 6. Checks (own engine)

| Check | Signal | Notes |
| --- | --- | --- |
| **Reachability** | live / absent / error, per route | Confirms item-2 static findings against the running app. |
| **Anonymous exposure** | `2xx` with no credentials on a route with `auth_hint: 'required'` | Auth bypass confirmed on both ends. Needs a spec-derived `auth_hint`. |
| **Differential authz** | anonymous response ≡ authenticated response (same status, same body hash) | Only with credentials; needs no spec. Doubles requests on covered routes. |
| **CORS** | reflected `Origin` **and** `Access-Control-Allow-Credentials: true` | Highest-severity CORS shape; entirely non-destructive. |
| **Security headers** | missing HSTS / CSP / `X-Content-Type-Options` / frame-ancestors | One finding **per origin**, not per route (else N routes = N duplicate findings). |
| **Info disclosure** | stack traces, framework/version banners in bodies or headers | |
| **Method surface** | `OPTIONS` `Allow` advertises methods the inventory does not list | The server admits a verb the static extractor never saw. |
| **Open redirect** | `3xx` with a `Location` off the target origin | Falls out for free from `redirect: 'manual'`. |
| **Rate-limit** (opt-in) | a bounded burst (default 30) to a synthetic non-existent username never yields `429`/`Retry-After` | Proves the limiter's presence without guessing a real secret or locking a real account. See below — it is the one check that crosses the write envelope. |

### The rate-limit probe, and its one deliberate exception

An authentication endpoint is almost always a `POST`, so this check would be
disabled by the default read-only envelope — the contradiction has to be
resolved on paper, not left for an implementer to reconcile. The resolution:

- `probe_rate_limit: true` **is itself the authorization** for the burst,
  independently of `allow_write_methods`. Its scope is exactly one route and
  nothing else — this does not open write methods for any other check.
- **Target selection is explicit-first.** `rate_limit_path` names the route. If
  omitted, the planner picks from the inventory by path shape (`/login`,
  `/signin`, `/auth`, `/token`, `/session` and their prefixed variants) and
  **reports which route it chose**. If nothing matches, the check reports
  `no_candidate` — it never falls back to bursting an arbitrary endpoint.
- The body is a fixed synthetic credential pair (a username of the form
  `dev-guardian-probe-<random>@invalid` and a constant password). It is designed
  not to match a real account, so the lockout control under test cannot lock out
  a real user.
- The burst is sequential-ish (respecting the concurrency cap) and stops early
  the moment a `429` appears — a working limiter costs a handful of requests,
  not thirty.
- Absence of `429` across the full burst is reported as **`no_rate_limit_observed`**,
  not "rate limiting is broken": a limiter with a threshold above the burst size
  is indistinguishable from none at this sample size, and the finding says so.

### Credentials and differential authz

Two parameters, one recommended:

- **`auth_header_env`** — the *name* of an environment variable holding the
  header value. The secret never appears in the conversation, the MCP request
  log, or the agent's context. **Recommended path.**
- **`auth_header`** — the literal header value, documented as landing in the
  transcript. For when there is no other option.

Either way: **never persisted** (not to SQLite, not to the evidence files),
and redacted from any request echoed into a finding. With credentials, each
covered route is probed twice — anonymous and authenticated — and equivalent
responses mean the endpoint ignores the credential (a broken-authz finding that
works even where `auth_hint` is always `'unknown'`, i.e. projects with no spec).

Equivalence is status **plus** a hash of the response body. Bodies legitimately
differ between two identical requests (timestamps, CSRF tokens, request ids),
which makes hash comparison noisy — but the noise runs in the safe direction:
the finding requires *equality*, so noise causes a missed finding, never a
fabricated one. This asymmetry is deliberate and must not be "fixed" by
loosening the comparison into a similarity heuristic.

## 7. nuclei integration, and an honest note about it

nuclei enters `TOOL_CATALOG` with `required_by: ['scan_dast']` and
**`default: false`** — it is an active scanner and a large template download;
opting in is deliberate. Absence is reported as a gap (a `tools_run` entry with
status `skipped`), never a silent zero, the same discipline as Semgrep.

Invocation: `-jsonl`, `-exclude-tags dos,fuzz,intrusive` under the read-only
envelope, a rate limit, and **`-no-interactsh` by default** — out-of-band
probes make the target contact a third-party server, an exfiltration channel
out of a scanner that runs against the user's internal network.

**The honest limitation, written here so the CHANGELOG does not over-claim it:**
most of nuclei's HTTP templates use `{{BaseURL}}` and append their own known
paths — they exercise the *origin*, not the project's routes. The inventory
only genuinely feeds nuclei in its `-dast` fuzzing mode, which sends injection
payloads and is excluded by the default envelope. nuclei brings real value
(component CVEs, exposed panels, misconfigurations) but it is **not** what tests
the project's own endpoints — the own engine is. The two are complementary, and
the tool result labels which findings came from which so the reader is never
misled into thinking nuclei validated their routes.

## 8. Data model and persistence

- Findings go to the existing `findings` table via `findingsRepo`, with
  `scan_type: 'dast'`. No new table.
- **Fingerprint** is stable over `(check, method, path_resolved, file)` and
  **never** includes the HTTP status, which changes between runs (a fixed app
  restart flipping 500→200 must not spawn a "new" finding). This keeps DAST
  findings diffable across runs like every other finding.
- **Severity** is a property of the check, not the response: anonymous exposure
  of an auth-required route is high; a missing security header is low. Fixed per
  check in `analyze.ts`.
- **Raw evidence** — the redacted request and response for each finding — is
  written under `.guardian/reports/dast-<short-scan-id>/`, pointed at by the
  finding, not inlined into the SQLite row.
- The tool **reads the latest surface snapshot** via `surfaceRepo.getLatest()`,
  *not* the snapshot keyed to the current tree hash. Tree-scoping would refuse
  after any edit to any file — a README change moves the tree hash while the
  route inventory is still perfectly valid — and refusing constantly is how a
  tool stops being used. Instead, a snapshot whose tree hash differs from the
  working tree is used **with a warning**, so the mismatch is stated rather
  than either hidden or fatal. No snapshot at all → refuse (see §3). It does not re-run
  `map_attack_surface`; composing the two is the caller's (or a future
  orchestrator's) job, keeping this tool single-purpose.

## 9. Tool contract

```text
scan_dast(
  project_path: string,            // to locate the surface snapshot + write reports
  base_url: string,                // e.g. http://localhost:3000
  authorized_target?: boolean,     // required for any non-loopback host
  allow_write_methods?: boolean,   // default false
  probe_rate_limit?: boolean,      // default false; the benign burst
  rate_limit_path?: string,        // explicit burst target; else inferred + reported
  auth_header_env?: string,        // name of env var holding a header value
  auth_header?: string,            // literal header value (documented as in-transcript)
  use_nuclei?: boolean,            // default false; requires nuclei installed
  max_requests?: number,           // global ceiling, reported when it cuts
  timeout_ms?: number,             // per-request, default 5000
)
```

Result: the standard `ScanResult` shape (so it flows through the existing
findings pipeline), which already carries `coverage: 'full' | 'partial' | 'none'`
derived from `tools_run` + `missing_tools` by `tools/scanCoverage.ts` — reused,
not reinvented. On top of it, a DAST summary: routes planned, probed and skipped
(with the reason per skip — partial-path, method-envelope, duplicate), plus a
**per-check status** (`ok` / `skipped_envelope` / `no_candidate` /
`needs_credentials` / `scanner_missing` / `target_error`) so a check that never ran is visible as
such rather than as a check that found nothing.

The consumer contract carried forward from item 1 verbatim: **a route count
without a `coverage` beside it is not an answer.** A refused target, a missing
snapshot, and a target that did not respond are three distinct outcomes and must
read as three distinct results, never as "0 findings".

## 10. Testing

- **Pure modules** (`target`, `plan`, `analyze`, `normalizeNuclei`) get
  exhaustive unit tests — this is where the safety envelope is enforced, so
  each rule (`path_partial` never probed, synthetic params never "unreachable",
  loopback-only auto-allow, write-method gating, `ANY` expansion) is a named
  test that fails if the rule regresses. Assertions must distinguish the correct
  implementation from the plausible-wrong one — the item-2 lesson
  (`every(r => r.line > 0)` passing for both 7 and 9) is a standing review
  criterion for every test in this feature.
- **`probe.ts`** is tested against a real `node:http` server stood up inside the
  test — real sockets, no mocks — because what fails here is network behaviour
  (redirect handling, timeout, connection refused, header casing).
- **e2e** uses a deliberately-vulnerable Express fixture app that trips each
  check (an auth-required route served anonymously, reflected-credentialed CORS,
  missing headers, a stack-trace leak, an open redirect, a route with no rate
  limit). It runs the whole tool against the running fixture.
- **nuclei tests** use `it.skipIf` with `GUARDIAN_REQUIRE_NUCLEI=1` turning
  absence into a hard failure — the exact fix applied after two Criticals
  reached a green suite via `console.warn` + bare `return` in items 1–2. A
  skipped test must read as a skip, never as a pass.

## 11. Known limitations at first release

- No injection testing in the own engine (delegated to nuclei `-dast`, excluded
  by default). A clean `scan_dast` is **not** evidence of injection safety.
- nuclei's route-awareness is limited to `{{BaseURL}}` origin testing for the
  default template set (§7).
- Differential authz compares status + body hash; an endpoint that returns
  identical-looking bodies but differs in a side effect (a write that authz
  should have blocked) is not caught by a read-only differential.
- Synthetic path parameters mean parametric routes get a best-effort reachability
  signal, never a definitive one; the ambiguity is surfaced, not resolved.
- Lexical target classification will refuse a legitimately-loopback hostname
  (asks for attestation it did not strictly need) — the deliberate safe-side
  error.
- The rate-limit probe's burst size bounds what it can conclude: a limiter whose
  threshold sits above the burst is indistinguishable from no limiter at all.
  The finding is named `no_rate_limit_observed` for exactly this reason and must
  never be reworded into "rate limiting is missing".

## 12. Definition of done

- All seven modules implemented, pure/impure split held.
- Full envelope enforced in `plan.ts` with a named test per rule.
- Findings flow through `findingsRepo` with stable, status-independent
  fingerprints; evidence written to `.guardian/reports/dast-*`.
- Refusal paths (non-loopback without attestation, missing snapshot, dead
  target) each return a distinct, self-explaining result.
- nuclei gated on `default: false`, absence reported not fabricated.
- Credentials never persisted, always redacted.
- `npm run build` clean, `npm test` green with zero skips under
  `GUARDIAN_REQUIRE_SEMGREP=1` (and `GUARDIAN_REQUIRE_NUCLEI=1` where nuclei is
  present), coverage thresholds held.
- `map_attack_surface` → `scan_dast` documented in `host-rules/AGENTS.md` and
  the tool description, so an agent can discover the two-step flow.
