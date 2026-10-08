# Real SARIF logs

Inputs for `mcp/test/e2e/importSarifRealLogs.test.ts` (test plan T-21, success
criterion SC-001 of the `sarif-import` feature). Every log here was written by
the tool named, not by hand; the only edits are listed below.

| File | Tool | Produced by |
| --- | --- | --- |
| `semgrep.sarif.json` | Semgrep OSS 1.176.1 (no `semgrep login`) | `semgrep scan --metrics=off --sarif --config configs/semgrep/base.yml src`, run on Windows over a copy of `mcp/test/fixtures/base/hits/` placed at `src/` |
| `trivy.sarif.json` | Trivy 0.69.3 | `trivy fs --skip-db-update --scanners vuln --format sarif .` over a directory holding only a `requirements.txt` that pins `requests==2.19.0`, `PyYAML==5.3` and `urllib3==1.24.1` (vulnerability DB of 2026-10-02) |
| `gitleaks.sarif.json` | gitleaks 8.30.1 | `gitleaks detect --no-git --report-format sarif --source .` over the same copy as Semgrep's, plus `config/settings.js` holding two fake tokens, the first of them on two lines |
| `codeql-valid.sarif.json` | CodeQL (two runs: `LGTM.com` 1.24.0-SNAPSHOT and `CodeQL command-line toolchain` 2.0.0) | `src/testdata/valid-sarif.sarif` of [github/codeql-action](https://github.com/github/codeql-action/blob/ddee374101380e1f4619b73bf9abb8b9f0032200/src/testdata/valid-sarif.sarif), unmodified |
| `codeql-fingerprinting2.sarif.json` | CodeQL command-line toolchain 2.0.0+202002031536 | `src/testdata/fingerprinting2.expected.sarif` of [github/codeql-action](https://github.com/github/codeql-action/blob/02e8dcfe9cac6b6ae038d8578b850d007c925682/src/testdata/fingerprinting2.expected.sarif), unmodified |

The files are named `.sarif.json` because the repository's `.gitignore`
ignores `*.sarif` (scan output), as `test/fixtures/scanners/dotnet-build.sarif.json`
already is.

The two CodeQL logs are github/codeql-action's own test data, published under
the MIT licence (Copyright GitHub, Inc.); they were fetched with
`gh api repos/github/codeql-action/contents/src/testdata/<file> -H "Accept: application/vnd.github.raw"`
on 2026-10-02.

## Edits

- `trivy.sarif.json`: Trivy writes the scanned directory's absolute path as
  `originalUriBaseIds.ROOTPATH` — on the machine that made it, a path in its
  temp directory. It is rewritten to `file:///ci/workspace/`, the shape a log
  arriving from a CI runner has (a checkout that is not this project), and the
  file is re-serialised with two-space indentation. Nothing else changed.

No other log contains a path of the machine that produced it.

## What each one exercises

- **Semgrep**: every result's only fingerprint is the literal
  `"matchBasedId/v1": "requires login"` (what Semgrep writes without a login),
  so a fingerprint shared by all 66 results must not fold them into one; URIs
  use Windows separators (`src\app.js`) under a `%SRCROOT%` the log never
  defines.
- **gitleaks**: with `--no-git`, every `partialFingerprints` value is the empty
  string, and the same token on two lines makes two results of one rule — so
  empty fingerprints must not fold them into one. The snippets hold fake
  credentials only — the private-key fragment
  and AWS's documentation key from `mcp/test/fixtures/base/hits/secrets.txt`,
  and the `ghp_…`/`sk_live_…` values the test suite already uses. None is a
  credential.
- **Trivy**: severities come from the rules' `security-severity`; `ROOTPATH`
  points outside the project, so the URIs are read relative to its root.
- **CodeQL**: two runs in one log; a file-level result with no region; an
  empty `partialFingerprints` object.

This directory is under `mcp/test/fixtures/`, which `.guardianignore` keeps
out of dev-guardian's own scans.
