# Guardrail hooks

With the plugin enabled, Claude Code loads [`hooks/hooks.json`](../hooks/hooks.json) automatically. Every hook runs one dispatcher, [`hooks/guardian-hook.mjs`](../hooks/guardian-hook.mjs), which imports only Node built-ins and the pre-compiled detectors in `mcp/dist/` — no `npm install`, no native module.

Two rules hold for all of them:

- **Fail open.** Any error inside a hook exits 0 with no output. A guardrail that breaks must not break your session. `GUARDIAN_HOOKS_DEBUG=1` prints what went wrong on stderr.
- **Only what just happened.** A hook assesses the text just written or the command about to run — it never scans the repository. It does read a little around it: SessionStart runs `git status` and checks `.guardian/`, and the install hook reads registry configuration (`.npmrc`, `pip.conf`, `package.json` workspaces, … — listed below). The authoritative scans stay in the MCP tools (`scan_secrets`, `vet_packages`, …).

Each hook has a 15 s timeout in `hooks.json`.

## What runs when

| Event | Matcher | What it does | Default |
| --- | --- | --- | --- |
| `SessionStart` | — | Briefs the agent: plugin version, branch, uncommitted changes, whether the project has a `.guardian/` directory and when the database last changed — and, when the project's hook config asked to loosen a guardrail, that it was ignored. | on |
| `PostToolUse` | `Write`, `Edit`, `MultiEdit`, `NotebookEdit` | Scans the inserted text for hard-coded secrets (medium confidence and up) and adds a warning with a **redacted** preview. | warn |
| `PreToolUse` | `Bash`, `PowerShell` | Assesses the command: **denies** catastrophic ones, warns on risky ones, then vets any package it would install. | deny catastrophic |
| `PreToolUse` | `Write`, `Edit`, `MultiEdit` | **Denies** any edit of the guard's own configuration (below). | always — unless every hook is switched off at user level |
| `PreToolUse` | `Write`, `Edit`, `MultiEdit`, `NotebookEdit` | Denies writing a high-confidence provider token (AWS, GitHub, Stripe, …). | off — opt in with `"secrets": { "block": true }` |

## The shell guard

The same detector serves `Bash` and `PowerShell` and the CLI's `check --bash`. It splits a command line into statements and also reads text that is fed to a shell (`bash <<EOF … EOF`, `echo '…' | sh`); a heredoc handed to a non-shell command (`git commit -F - <<EOF`) stays inert.

- **Denied** (unless the block is switched off): recursive force-deletes of the filesystem root, the home directory (`~`, `$HOME`, `${HOME}` and their `/*` forms), Windows and Git Bash / WSL drive roots, `/Users`, `/System`, and `--no-preserve-root`; `curl`/`wget` piped into a shell, `bash <(curl …)`, `sh -c "$(curl …)"`; PowerShell `iwr | iex`, `iex (irm …)`, `Invoke-Expression (Invoke-RestMethod …)`; `Format-Volume`, `Clear-Disk`; `dd`, `mkfs`, `wipefs` or `shred` on a block device; fork bombs; `chmod -R 777 /`; `find / -delete`; `mkfifo`, `mknod`, `ln`, `mklink` (also through `cmd /c`) or PowerShell `New-Item -ItemType SymbolicLink|HardLink|Junction` when the path it creates is one of the hook configuration files, or a link at `.guardian` or `~/.config/dev-guardian` — not when that path is only a link's source. Commands inside `do … done`, `then … fi`, `else`, `{ … }` and after `!` are assessed like any other.
- **Warned**: force-push, `git reset --hard`, `git clean -fd`, `chmod 777`, clearing shell history, `sudo`, any other recursive force-delete, `find ~ -delete`.

The deny message never says how to switch the guard off. That takes the user-level config or `GUARDIAN_HOOKS_BASH_BLOCK=0`, and an assistant's `Write` / `Edit` of either config file is itself denied.

## Install-time package vetting

When the command installs packages by name — `npm i|install|add`, `pnpm add`, `yarn add`, `bun add|i|install`, `pip install`, `uv add`, `uv pip install`, `poetry add`, `composer require`, `dotnet add package` — the hook runs the same checks as the `vet_packages` tool, under one **3 s** network budget for the whole command line:

| Finding | Hook answer |
| --- | --- |
| A version that would install is **malicious** (OSV `MAL-` advisory, or npm's `0.0.x-security` placeholder) | **deny**, in every command shape; the message says to ask the user to install it themselves |
| The name does **not exist** on the public registry | **deny** only when the whole command, comments stripped, is ONE plain install statement — a bare tool name (no `.venv/bin/pip`, `sudo`, `env`, `VAR=x`), no `&&`, `\|\|`, `;`, pipes, `&`, subshells, `$(…)`, backticks, variables or redirections, and only flags from a small per-tool allowlist that cannot change where a package resolves from — and nothing below explains the 404. Otherwise a warning: "not found on the public registry — if it is private or local, ignore this". |
| Published less than 72 h ago, npm install scripts, typosquat suspicion, an unpublished exact version | warning |
| Known vulnerabilities | warning, only for an exact version pin (for a range the installed version is unknown) |
| A check could not run (offline, timeout, HTTP error, rate limit, `GUARDIAN_OFFLINE=1`) | one line saying the package was **not** verified; the command runs |
| Every package clean, or nothing installed by name | silent, and no network request at all |

A missing-name deny carries its own escape hatch: re-run the install with an explicit `--registry` / `--index-url` / `--source` (that takes the command out of the plain shape), or set `GUARDIAN_PKG_VET=0`. A malicious-package deny has none.

What counts as "something explains the 404" — the hook reads files and environment only, never the network, for this:

- **npm, pnpm, yarn, bun**: `registry=` or `@scope:registry=` in the project `.npmrc`, the user npmrc (`NPM_CONFIG_USERCONFIG` or `~/.npmrc`), npm's global npmrc (`npm_config_globalconfig`, `npm_config_prefix`, `%APPDATA%\npm\etc\npmrc` or `<node prefix>/etc/npmrc`) and pnpm's global rc; yarn's `.yarnrc.yml` `npmRegistryServer` / `npmScopes` and classic `.yarnrc`; bun's `bunfig.toml` (project or `~/.bunfig.toml`); an npmjs auth token when the name is scoped (a private scoped package answers 404 anonymously); a workspace package (`package.json` `workspaces`, `pnpm-workspace.yaml`).
- **pip, uv, poetry**: `pip.conf` / `pip.ini` (user, venv, `PIP_CONFIG_FILE`, `/etc/pip.conf`, `/etc/xdg/pip/pip.conf`, `XDG_CONFIG_DIRS`, `%ProgramData%\pip\pip.ini`, macOS `~/Library/Application Support/pip`); `uv.toml` (`UV_CONFIG_FILE`, `~/.config/uv`, `%APPDATA%\uv`, `/etc/uv`, the project); `[[tool.uv.index]]`, `[[tool.poetry.source]]`, `[[tool.pdm.source]]` or a `[tool.uv]` index in `pyproject.toml`; uv workspace members and `[tool.uv.sources]`.
- **Composer**: a `repositories` entry in `composer.json` or the user's global `config.json`.
- **NuGet**: any `nuget.config` from the project up to the filesystem root, or the user-level one, with a source that is not nuget.org.
- **The hook's environment**, case-insensitively: `npm_config_*registry*`, `YARN_NPM_REGISTRY_SERVER`, `YARN_REGISTRY`, `BUN_CONFIG_REGISTRY`, `PIP_*INDEX*`, `UV_*INDEX*`, `NUGET_*`.
- **The command line**: any non-public `--registry`, `-i`, `--index-url`, `--source`.

A registry that *is* the public one (`registry.npmjs.org`, `pypi.org/simple`, `api.nuget.org`) is not custom. Paths, tarballs, URLs, git specs (`git@host:repo` included), `file:` / `workspace:` specs, requirement files and flag values are never looked up; a bare `npm install` vets nothing.

The network hosts involved are listed in [SECURITY.md](../SECURITY.md).

## Configuration

| Where | Who may write it | What it can do |
| --- | --- | --- |
| `.guardian/hooks.config.json` (project) | the user — an assistant's `Write` / `Edit` / `MultiEdit` is denied, but a shell command can still write it | only what makes the guard stricter or is advisory: `enabled: true`, `bash.block: true`, `bash.warn: true`, `secrets.block`, `secrets.warn`, `sessionStart`, `ignorePaths`. `"enabled": false`, `"bash": { "block": false }` and `"bash": { "warn": false }` here are **ignored**, and SessionStart says so; there is no project-level switch for package vetting. |
| `~/.config/dev-guardian/hooks.json` (user) | the user — an assistant's `Write` / `Edit` / `MultiEdit` is denied | every key, winning over the project file: `"enabled": false` turns every hook off, `"bash": { "block": false }` turns the shell block into a warning |
| `.guardian/hooks-allowlist.json` (project) | the user — an assistant's `Write` / `Edit` / `MultiEdit` is denied, but a shell command can still write it | substrings that silence a secret warning (and exempt a match from the opt-in secret block): a JSON array, or `{ "secrets": [...] }`. Advisory, like `secrets.warn`. |
| `GUARDIAN_HOOKS=off` | environment | disables every hook |
| `GUARDIAN_HOOKS_BASH_BLOCK=0` / `1` | environment | forces the shell block off or on, over both files |
| `GUARDIAN_PKG_VET=0` | environment | disables package vetting only |

`ignorePaths` defaults to `/test/fixtures/`, `eval-vuln-fixture`, `/.guardian/` and `__fixtures__`, matched against the path relative to the project. The plugin's own directory is always skipped. The user-level `ignorePaths`, when set, replaces the project's. A project's `ignorePaths` narrows the secret **warning** only: it never exempts a path from a `secrets.block: true` set in the user-level config, which honours the user's own `ignorePaths` or the defaults. (A block the project itself enabled may be narrowed by the same project's list.) The project's `.guardian/hooks-allowlist.json` still exempts a matching substring from the warning and from either block — it is advisory, so a user who relies on the block should review it.

**How the configuration files are read.** Each one — the project config, the allowlist and the user-level config — goes through two checks, and a file that fails either is not read, counts as absent (the protective defaults), and is named by SessionStart; a file that is not valid JSON is named too.

1. **Before anything is opened**, every path component below the project directory (for the two project files) or the home directory (for the user-level file) is examined with `lstat` and `readlink`, which never follow a link and never touch its target. If a link on the way — the file itself, `.guardian`, `.config`, `dev-guardian`, or any local link one of them leads to — points at a UNC or device path (`\\host\share`, `//host/share`, `\\?\…`, `\\.\…`), the file is refused. Opening such a link can wait on the network for minutes (≈136 s was measured on Windows for an unreachable host), far past the hook's 15 s.
2. **Then the file is opened** (a link is followed; on Linux and macOS with `O_NONBLOCK`, so a FIFO opens at once instead of waiting for a writer), and what was OPENED is checked with `fstat`: only a regular file of at most 64 KiB is read, and no more than 64 KiB + 1 bytes are read from it, so a file that grows after the check is refused too. A FIFO, a link to `/dev/zero`, a Windows link to a named pipe (which `stat`s as an empty regular file), a larger file or a file this account may not read is refused on its descriptor and closed unread; a directory is refused too (Windows will not open one at all). Because these checks apply to the open descriptor rather than to the path, swapping the path for a FIFO between two checks changes nothing. A leading UTF-8 byte-order mark is stripped.

A FIFO there used to hang the hook until Claude Code killed it at 15 s, after which the tool call ran unguarded. **Not covered:** the project and home directories themselves and their ancestors (the user's own layout), and a path the operating system redirects to the network without a link — a mapped drive letter, a DFS namespace, an NFS or SMB mount — which is opened like any local path. The install hook reads registry configuration (`.npmrc`, `package.json`, `pip.conf`, …) with the second check only, capped at 1 MiB.

**What the write guard does not cover.** It sees the `Write`, `Edit` and `MultiEdit` tools only. A shell command (`echo … > .guardian/hooks.config.json`) is not one of them — which is why a project file cannot loosen a protective hook at all: whatever an assistant writes there through the shell can only make the guard stricter or change advisory settings. The user-level file is outside the project but equally reachable by a shell write, and the hooks do not stop that; switching the guardrails off is meant to be the user's decision, made there or in the environment.

## The same detectors from a terminal

```text
node cli/dev-guardian.mjs check --file path/to/file      # secrets, exit 1 on a finding
node cli/dev-guardian.mjs check --bash "rm -rf /"         # ok / warn / block, exit 1 unless ok
node cli/dev-guardian.mjs check --file .env --min high --json
```

Exit code 2 is a usage error or an unreadable `--file`.
