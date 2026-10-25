# Static reachability — `validate_finding`

After the triage, `validate_finding` adds one more signal per finding. It never replaces the triage, and never
suppresses or changes a severity on its own. It answers whether anything outside the process can reach the file
a finding lives in, from an import graph rooted at the routes `map_attack_surface` mapped.

1. Run `map_attack_surface { project_path: "<project>" }` first if there is no snapshot — without one,
   `validate_finding` refuses with `no_surface_snapshot`.
2. Run `validate_finding { project_path: "<project>" }` — with no `fingerprint` it validates every open finding.
   It reads the project's open set — the latest completed scan of each kind, merged — so a later `scan_dast` or
   SBOM does not stand in for the SAST findings.
3. Read each verdict — `reachable` / `unreachable` / `unknown` — **beside** `coverage_gaps`, never alone: a count
   of verdicts without the gaps is not an answer. A dependency CVE (npm, PyPI) also gets the `dependency`
   provider's verdict: `reachable` (a file a route reaches imports the package), `imported` or `unknown` — never
   `unreachable`.
4. Use it as context with the user ("no route seems to reach this finding, but it is a static reading — keep it
   as a priority?"), never as an automatic reason to demote it.

Limits to state whenever you present an `unreachable`:

- It is **never** produced for Ruby, Java, C# or PHP — they resolve code at runtime (autoload, annotation
  injection, DI, a service container), not through imports.
- It **does not see dynamic imports** (`import(expr)`, `require(variable)`, reflection, plugin registries) in any
  stack — there an `unreachable` can be wrong with no way to tell.
- **Only HTTP routes count as entry points.** A file called only by a CLI, a cron job or a queue consumer reads
  `unreachable`-by-route; that is not a claim the code never runs.
- **File granularity, not function.** A finding in a helper nobody calls, in a file that is imported, reads
  `reachable`.
