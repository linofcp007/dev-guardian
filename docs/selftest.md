# The selftest — does each scanner detect on this machine?

`check_toolchain` asks every scanner for its version. That proves a scanner is **installed**; it does not prove that
it **sees**. A scanner can run to the end, exit 0 and report nothing because it read nothing, loaded no rule or was
handed a rule pack it could not use — and "0 findings" from it looks exactly like "nothing to find".

`dev-guardian selftest` answers the other question. It seeds a temporary project with **canaries** — one small file
per control, each with one known defect —, runs every core control the way a scan runs it, and says, control by
control, whether dev-guardian found the canary here.

```bash
node "<plugin root>/cli/dev-guardian.mjs" selftest             # the table
node "<plugin root>/cli/dev-guardian.mjs" selftest --json      # one JSON document (schema 1)
node "<plugin root>/cli/dev-guardian.mjs" selftest --history   # the saved runs, newest first; runs nothing
```

`health_status` gives the exact line for this install in `selftest.command`. It is a CLI command and not an MCP tool:
a whole run does not fit a tool call. The server only **shows** the last result.

## The core controls

| Control | What is run | The canary |
| --- | --- | --- |
| `semgrep:<pack>` — one per file of `configs/semgrep/` | Semgrep with that pack alone, as `scan_sast` runs it | a few lines in a language of the pack; a pinned rule of the pack must report it |
| `gitleaks` | the secret scan's directory pass | a properties file holding a synthetic access key id |
| `trivy:deps` | Trivy's dependency audit | a lockfile with one old, vulnerable dependency |
| `trivy:iac` | Trivy's IaC scan | a Dockerfile with a misconfiguration |
| `hooks:bash-block`, `hooks:powershell-block` | the installed hook dispatcher, handed a catastrophic command as text | it must answer `deny` |
| `hooks:settings-guard` | the dispatcher, handed a write that switches the hooks off in Claude Code's settings | it must answer `deny` |
| `hooks:secret-warning` | the dispatcher, handed a write that holds the synthetic key | it must warn |
| `hooks:install-vet` | the dispatcher, handed the install of a package npm took down (`npm install crossenv`) as text | it must answer `deny` |

There are five hook checks, and `hooks:install-vet` is the only one that uses the network. The dispatcher vets that
install as it vets any other: it asks the public npm registry for the document of `crossenv` and OSV about that name
— normally one request each, about that one package and with nothing of yours. `crossenv` is a package npm replaced
by its security placeholder, and that is what the hook denies. Nothing is installed: see "What it touches", below.

Each rule pack runs alone, so its verdict depends on nothing but itself. Before the packs, one **probe run** with the
selftest's own rule tells which canaries Semgrep can read on this path: that is what separates a blind pack from an
ignored directory (see `unverified`, below).

Every other installed scanner — Bandit, gosec, cppcheck, Psalm, SpotBugs, detekt, RuboCop, hadolint and the rest — is
listed as `no_canary`: installed, **not verified** by this command.

## The verdicts

| Verdict | What it means | What to do |
| --- | --- | --- |
| `detected` | The control ran to the end and reported its canary. | Nothing. |
| `silent` | It ran to the end, **read** the canary and reported nothing. A scan of that area with 0 findings proves nothing on this machine. | Follow the control's `next` line: the scanner's version, the pack's file, a configuration of the scanner's own. |
| `missing` | The scanner is not installed. | The `next` line has the install command (`install_toolchain` does it too). |
| `unverified` | The run cannot be taken to a verdict: it failed, timed out, was partial, never read the canary, had no vulnerability database, or was not started offline. For `hooks:install-vet` it is usually the network, not the guard: the registry and OSV were not asked (`GUARDIAN_OFFLINE=1`), or one of them did not answer and the reason is the hook's own "could not vet" line. Never `detected`, never `silent`. | Read the reason, fix it, run again. |
| `no_canary` | An installed scanner the selftest has no canary for. | Nothing: it says only that this command did not test it. |
| `disabled_by_user` | A guard answered more softly because you switched it off (`GUARDIAN_HOOKS=off`, `GUARDIAN_HOOKS_BASH_BLOCK=0`, `GUARDIAN_PKG_VET=0`, or `"enabled": false`, `"bash": {"block": false}`, `"secrets": {"warn": false}` in `~/.config/dev-guardian/hooks.json`). With package vetting switched off, `hooks:install-vet` is not started at all: it asks the network nothing. | Nothing: your decision, named. |

A control that was `detected` in the saved run before this one and is `silent`, `unverified` or `missing` now is
marked **regressed**, with what changed between the two runs — the plugin's version, the scanner's, the platform.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Every core control detected (`no_canary` and `disabled_by_user` do not count against it). |
| 1 | At least one control is `silent`. |
| 2 | None is silent, and at least one is `unverified` or `missing` — or the temporary directory could not be removed. |
| 3 | Usage error. |

## What it proves, and what it does not

- **A canary proves that a control sees on this machine, not that it sees everything.** One file, one rule. The
  quality of the rules is the ablation harness's job (`docs/maintainers/ablation.md`), not this command's.
- **The hook checks prove that the installed detectors answer** when the dispatcher is run. They do not prove that
  the host runs it: a Claude Code too old to start plugin hooks passes all five. Whether the hooks started in a
  session is `health_status`'s `hooks` field ([hooks.md](hooks.md), "The session mark").
- **`hooks:install-vet` proves that the install guard denies an install it is given cause to deny; it does not prove
  the registry.** `detected` is any deny of the canary: npm's security placeholder, a malicious-package advisory
  from OSV, or — behind a proxy that answers "no such package" — a name the registry does not have. Whoever controls
  the network between this machine and the registry controls what the hook is told. `unverified` says that no
  verdict was reached — for this check, usually that the hook could not run one of its checks of the canary,
  whichever it was.
- **A `silent` `hooks:install-vet` may be the canary, not the guard.** Should npm serve an ordinary package under
  `crossenv` again, the hook has nothing to deny and the control reads `silent`: what the registry serves for
  `crossenv` is the first place to look. A name the registry no longer has at all is denied for that reason, and
  still reads `detected`; a network that is down reads `unverified`, not `silent`.
- **What `silent` catches:** a pack whose rules no longer match its canary, a pack from which Semgrep loaded nothing
  and scanned no file, a scanner that returns an empty report with exit 0, a hooks bundle that fails open. A pack
  that Semgrep **rejects** (not YAML, an unknown language, a pattern that does not parse) is `unverified` with
  Semgrep's own error: a scan with it fails too, and says so.
- **A directory Semgrep does not scan is not a blind pack.** With the temporary directory inside a git work tree
  that ignores it, Semgrep reads nothing there; neither the probe rule nor any pack reports a canary, and every pack
  is `unverified` — "Semgrep does not scan this temporary directory" — never `silent`.

## What is saved

Unless `--no-save` is given, the result is saved **per install**, in dev-guardian's data directory
(`%LOCALAPPDATA%\dev-guardian\selftest\` on Windows, `~/.local/share/dev-guardian/selftest/` elsewhere, or
`GUARDIAN_DATA_DIR`): `last.json`, and `history.json` with the newest 50 runs. Not in a project's database: a
selftest is about the machine.

A saved run holds the date, the plugin's version, the platform and, per control, its id, its verdict, the scanner's
version and a reason. It holds no path, no value of the environment, no scanner output and never the canary key:
a reason loses all of them before it is printed or saved.

- `health_status` returns `selftest` — `never_run`, `ok` or `stale`, the date, the count per verdict, the `silent` and
  the `regressed` controls, and the command line — and `selftest_warning`, set when the last run has a silent or
  regressed control.
- `check_toolchain` adds `selftest` to `semgrep`, `gitleaks` and `trivy`: the scanner's worst verdict and the date,
  `stale` when another version is installed now, or `never_verified`.

A result of another plugin version, or older than 30 days, is `stale`: shown, never offered as a verification of the
install as it is. A file that cannot be read, is not the shape dev-guardian writes or is dated in the future is
treated as no result.

Nothing in the scan pipeline reads these files. They only inform.

## What it touches

- **A temporary directory** (`dev-guardian-selftest-…` under the system's), made exclusively and private to the
  user, removed when the command ends — also when a control fails or the command is interrupted. `--keep` keeps it
  and prints its path. If it cannot be removed, the report names it and the exit code is not 0.
- **No database, no project.** It opens no `guardian.db`, reads no baseline and no suppression, and writes nothing
  where it is run from.
- **Nothing in `~/.semgrep`.** Every Semgrep run rewrites its settings file and truncates its log. Each run of the
  selftest is given its own pair inside the temporary directory, so yours are not written — and three runs at a time
  do not race on one file.
- **Not inside a repository.** If the system's temporary directory is inside a git work tree, the secret scan would
  read that repository's history: the `gitleaks` control is then not run and says why (`unverified`), and Semgrep
  reads nothing where git ignores the directory. Point `TMPDIR` (`TEMP` on Windows) outside any repository.
- **Nothing is executed.** The canaries are never run, built or installed; the hook checks' commands are text in a
  payload on the dispatcher's standard input; scanners are started with their arguments as a list, with no shell.
  The install that `hooks:install-vet` names is read, never run: no package manager is started, and nothing is
  downloaded, extracted or installed.
- **The network a normal scan uses, and the install check's:** Trivy's vulnerability database and checks bundle,
  when its cache is stale; and, for `hooks:install-vet`, the dispatcher's requests to the public npm registry and to
  OSV about the one package name `crossenv` — normally one each. With `GUARDIAN_OFFLINE=1` neither the dependency
  audit nor the install check is started, and both are `unverified`.
- **The secret canary is synthetic.** It has the format of an AWS access key id, is put together at run time from
  two halves, exists only in the temporary directory, and is in no file of the plugin.

The canaries themselves are in [`configs/selftest/`](../configs/selftest/README.md).
