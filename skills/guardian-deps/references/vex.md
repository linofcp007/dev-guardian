# VEX — what `export_vex` writes, and the one status only the user gives

Read this before calling `export_vex`, or before recording a `not_affected` with `suppress_finding`.

`export_vex { project_path: "<project>" }` writes an OpenVEX document (or CycloneDX, with `format: "cyclonedx"`)
to `.guardian/reports/vex-*/`: one statement per vulnerability (a CVE, or its own GHSA / PYSEC id, with the
aliases the scanner gave) and package version, from the latest dependency scan. It never invents a status:

- `not_affected` only when the user declared it: `suppress_finding` with `vex_status: "not_affected"` and an
  OpenVEX `justification` (for example `vulnerable_code_not_in_execute_path`), plus an optional
  `impact_statement`. Always ask the user for the justification — never choose it yourself. It must be on
  **every** copy of the vulnerability: when the answer carries `warning` and `vex.other_open_findings`, show them
  to the user. With `vex.exportable: false` (a finding with no package version, such as a nuclei template) the
  suppression is recorded but does not enter the document;
- `affected` when a file a route reaches imports the package and loads the vulnerable version, in a snapshot of
  the same tree as the dependency scan;
- `under_investigation` for the rest; `fixed` never.

Run `generate_sbom` first (it gives the purls) and `map_attack_surface` (it gives the reachability), and show the
user the `unknowns` list — it is what the document does not know.
