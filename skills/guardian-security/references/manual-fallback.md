# Without the MCP server — the raw commands

Only when the dev-guardian MCP server is not available. Tell the user that this way there is no baseline, no
delta and no history, and prefer the tools as soon as the server is back.

```bash
# SAST — note BOTH --config flags (below)
semgrep --config=auto --config=.semgrep.yml --json --output=.guardian/sast.json .

# Secrets: the git history (the tool also scans uncommitted files, from a temporary copy with --no-git)
gitleaks detect --no-banner --report-format=json --report-path=.guardian/secrets.json

# Dependencies
trivy fs --scanners vuln,license --format json --output .guardian/deps.json .

# Container (when there is a Dockerfile)
[ -f Dockerfile ] && trivy config --format json --output .guardian/dockerfile.json Dockerfile

# IaC (when there is any)
trivy config --format json --output .guardian/iac.json .
```

- `--config=auto` does **not** load the project's `.semgrep.yml`: the rules `init_project` installs there have no
  consumer unless a second `--config` names them. `scan_sast` loads them itself (from `.dev-guardian/configs.json`
  or the conventional names).
- A `--config` Semgrep cannot load aborts the **whole** run (`paths.scanned: []`, exit 7), not just that pack; a
  rule that does not compile is exit 2 and loses only that rule. The tool validates each file's structure first and
  reports what it dropped in `tools_run`.
- `--config=auto` fetches the rules from Semgrep's registry and sends usage metrics as a condition of it:
  `--metrics=off` with it fails ("Cannot create auto config when metrics are off"). Say so when the user asks
  whether anything leaves the machine.
