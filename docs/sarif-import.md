# Importing SARIF

dev-guardian can record another analysis tool's findings in the project history, so they share baselines,
diffs, suppressions, triage, prioritisation, reports and gates with the native scanners. Two entry points
do the same work:

- the MCP tool `import_sarif`;
- the CLI subcommand `import-sarif <file>` (see [Exit codes](#exit-codes-of-import-sarif)).

The log must be SARIF 2.1.0. CodeQL, Snyk, Trivy, Semgrep, gitleaks and a dev-guardian export
(`scan --sarif`, `report_export`) have been imported from real logs.

## Inputs

| Input | Meaning |
| --- | --- |
| `sarif_path` | The log: absolute, or relative to `project_path` (on the CLI, to the current directory). |
| `allow_outside_project` | Read a log that is not under the project. Default `false`: such a path is refused (`outside_project`). |
| `max_results` | Results imported per run before stopping, 1 to 200000. Default 50000. |

The log is read once, through the bounded project reader: a regular file of at most **50 MiB**. A FIFO, a
device or a link that leads out of the project is refused (`refused_file`), and a missing file is `not_found`.

## What is recorded

Each `run` of the log becomes one scan of type `sarif_import`, named by the tool that wrote it
(`tool.driver.name`, plus its version). One finding is stored per result that is a finding.

An import of a tool becomes that tool's latest scan. It never touches the open findings of another tool, or
of the native scanners.

### One slot per source tool

Every distinct `source_tool` has its own slot for the latest scan and for the baseline. Four tools take a
`source_tool` argument to say which slot they read: `set_baseline`, `diff_scans`, `regression_alert` and
`report_export`.

- It is refused with any other `scan_type` than `sarif_import`, and next to an explicit scan id (which already
  names its tool).
- With exactly one imported tool in the project it is inferred.
- With several it is required, and the refusal lists the tools.
- `diff_scans` compares two scans of the same tool and refuses two different tools.

`suppress_finding`, `triage_findings` and `prioritize_findings` act on findings by fingerprint and work on
imported findings as on any other.

## Identity

A finding's identity decides what a diff calls new, resolved or unchanged.

- A log with `partialFingerprints` (or `fingerprints`) gets the identity
  `sha256(JSON.stringify(['sarif-v1', source_tool, ruleId, key]))`, where `key` is the fingerprints sorted by
  name. Two results of one rule on one line stay two findings.
- A log written by dev-guardian carries `partialFingerprints.devGuardianIdentity`; that value is used as it is,
  so an export imported back keeps the identities of the scan it came from.
- A result without usable fingerprints gets the identity the native scanners compute. These are counted in
  `identity_computed`. A fingerprint that is the same on every result (Semgrep without a login writes
  `requires login`) or an empty one (gitleaks `--no-git`) is not an identity and is ignored.

## Severity

| Source | dev-guardian severity |
| --- | --- |
| `security-severity` of 9.0 or more | critical |
| `security-severity` of 7.0 or more | high |
| `security-severity` of 4.0 or more | medium |
| `security-severity` above 0 | low |
| `security-severity` of 0 | info |
| no `security-severity`: `level` `error` | high |
| `level` `warning` | medium |
| `level` `note` | info |
| `level` `none` on a result with `kind: fail` | info (with no `kind`, `level: none` is not a finding) |
| `properties.severity` valid, from a dev-guardian export | that value |

## Counts

The response and the scan's `meta.counts` carry, per run (and `counts_total` for the whole log):

| Count | What it counts |
| --- | --- |
| `imported` | Findings stored. |
| `without_location` | Findings stored with no file: the result has no physical location inside the project (a Trivy image layer, say). |
| `skipped` | Results that could not be read, with the index and a fixed reason. |
| `suppressed_at_source` | Results whose `suppressions` hold an `accepted` entry: counted, not imported. |
| `not_findings` | Results that are not findings: a `kind` other than `fail` (`pass`, `notApplicable`, `informational`, `open`, `review`), or `level: none` with no `kind`. |
| `duplicates` | Results with an identity already seen in the run. |
| `truncated` | Results left out past `max_results`. |
| `identity_computed` | Findings whose identity was computed rather than taken from the log. |

### Coverage

The scan's coverage is `partial` only when results were **skipped** or the **results limit** was reached:
something the log held is not in the history, and a diff must not read it as resolved.

`without_location` is counted but does **not** make the scan partial. Such a result is imported whole (the
finding, rule, severity and message are there; only the place is not), so nothing is missing. Marking it partial
would also make every Trivy image log partial for good, and a diff of a partial scan reports the findings it no
longer sees as unmeasured instead of resolved.

## Secrets

The snippet of a result from a secret rule (a `secrets` tag, or a gitleaks log) is never stored.

## What is never opened

The log is untrusted input. Nothing it names is opened, fetched or run: not `helpUri`, not a remote
`originalUriBaseIds` entry, not `invocations`. Locations are resolved textually against the project root; a
result whose location resolves outside it is a `without_location` finding. No error message quotes the log.

## Exit codes of `import-sarif`

```text
node cli/dev-guardian.mjs import-sarif <file> [--project <dir>] [--allow-outside-project] [--max-results <n>]
```

| Exit | Meaning |
| --- | --- |
| 0 | Imported. |
| 1 | The log is invalid or refused: `invalid_sarif`, `outside_project`, `refused_file`, `not_found`. A log file that does not exist is a refused log. |
| 2 | Imported but partial: a run has `skipped` or `truncated` results. |
| 3 | Anything else: a usage error, a project not found, an unusable or in-memory database, any other tool error. |

Exit 3 is not misuse alone: a database fault is also 3. A pipeline that must tell them apart reads the message
on standard error. A log that is bad is always 1, so a 1 never means the tool or the database failed.
