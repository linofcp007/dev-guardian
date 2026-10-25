# DAST — `scan_dast`

A request for a "DAST scan" or a runtime pen test is answered with the `scan_dast` MCP tool, never by running
scanners by hand: the tool keeps baselines, diffs and the SQLite history a direct run does not.

`scan_dast` is the step after `map_attack_surface`: it probes the route inventory that tool produced, and
refuses with `no_surface_snapshot` when there is none. The app must already be running — the tool never
starts, builds or stops it.

1. Run `map_attack_surface { project_path: "<project>" }` first if there is no snapshot yet.
2. Ask for the URL of the app that is **already running** (staging, local dev, …).
3. Confirm authorisation. Loopback targets (localhost, 127.0.0.0/8, ::1) pass; any other host needs
   `authorized_target: true`, which the user must attest — never set it for them. The address a hostname
   resolves to is not pinned: each request resolves it again, so a name whose DNS changes mid-scan is probed
   wherever it points (with the credential, for authenticated probes). Where that matters, use an IP literal.
4. Run `scan_dast { project_path: "<project>", base_url: "<url>" }`. Optionally:
   - `auth_header_env` (recommended) for authenticated probes — the name of an environment variable, never
     the secret itself;
   - `probe_rate_limit: true` for the rate-limit burst;
   - `use_nuclei: true` for an extra pass with nuclei (installed by `install_toolchain`).
5. Read `coverage` before the findings: `partial` or `none` means the scan did not see everything, and
   "0 findings" there is not a clean result.
6. Summarise, prioritise, suggest fixes — and say that **a clean result is no proof of injection safety**: the
   built-in engine sends no injection payloads, and nuclei's default templates test the origin, not this
   project's routes.

Safety envelope (never work around it): read-only methods (GET / HEAD / OPTIONS) unless `allow_write_methods`
is on, and then with an empty body — plus the optional `probe_rate_limit` burst, the one exception, which sends
POST to exactly one route. Redirects are never followed — by nuclei either (`-disable-redirects`), which also
runs HTTP templates only (`-type http`), so it probes no other port or host than the URL. The open-redirect
check sends one more GET per path, offering `https://dev-guardian-redirect-probe.invalid/` in the usual redirect
parameters (`next`, `url`, `redirect`, `returnUrl`, …), and reports only a redirect there: a fixed one off the
origin (http→https, www, an SSO login) is no finding.
