# Other AI hosts

The engine is the MCP server, so any host that speaks MCP over stdio can use dev-guardian: Cursor, Windsurf, GitHub Copilot, Codex CLI, Gemini CLI, Cline and Claude Desktop. What those hosts do **not** get is the Claude Code plugin around it — the skills, the slash commands and the [guardrail hooks](hooks.md). They get the tools, the resources and a rules file that tells the model when to call which tool.

## 1. Clone once

The server is committed pre-built and bundled (`mcp/dist/server.js` has no runtime `node_modules`), so there is nothing to install or build — only Node.js ≥ 22.13 and git.

```text
git clone --depth 1 --branch v3.0.0 https://github.com/linofcp007/dev-guardian.git ~/tools/dev-guardian
```

The clone above pins 3.0.0; to follow a later release, use its `vX.Y.Z` tag. Do not pin `v2.0.0`: it has no `--update-mcp`, `--global` or `ci-init`, and its `mcp-config all --write` also writes the global Windsurf and Claude Desktop configs. Keep the clone somewhere stable, because every host config below points at it by absolute path.

## 2. Wire a host into a project

From the project you want to scan, run the CLI **by its absolute path** (it lives in the clone, not in your project):

```text
node ~/tools/dev-guardian/cli/dev-guardian.mjs mcp-config cursor            # print what it would write
node ~/tools/dev-guardian/cli/dev-guardian.mjs mcp-config cursor --write    # merge it into the project
node ~/tools/dev-guardian/cli/dev-guardian.mjs mcp-config all --write       # every host with a project-scoped config
node ~/tools/dev-guardian/cli/dev-guardian.mjs mcp-config all --write --global
```

The CLI needs no MCP connection. It fills in the absolute path of `mcp/dist/server.js`, merges the entry into the host's config (it never replaces other servers), and drops the host's rules file with every mention of the CLI rewritten to the clone's absolute `cli/dev-guardian.mjs`. Re-running it is safe.

| Host | MCP config (project / global) | Rules file |
| --- | --- | --- |
| Cursor | `.cursor/mcp.json` / `~/.cursor/mcp.json` | `.cursor/rules/dev-guardian.mdc` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` (global only) | `.windsurf/rules/dev-guardian.md` |
| GitHub Copilot | `.vscode/mcp.json` (project only; `servers` key, `type: "stdio"`) | `.github/copilot-instructions.md` |
| Codex CLI | `.codex/config.toml` / `~/.codex/config.toml` | `AGENTS.md` |
| Gemini CLI | `.gemini/settings.json` / `~/.gemini/settings.json` | `GEMINI.md` |
| Cline | manual — the CLI prints the snippet to paste into Cline's MCP settings | `.clinerules` |
| Claude Desktop | `claude_desktop_config.json` (global only; `%APPDATA%\Claude\`, `~/Library/Application Support/Claude/`, `~/.config/Claude/`) | none — paste `host-rules/AGENTS.md` into a Project's instructions |

| Flag | Meaning |
| --- | --- |
| `--write` | write or merge instead of printing |
| `--project <path>` | the project to configure (default: current directory) |
| `--scope project\|global`, `--global` | which config to write. `all --write` skips the two global-only hosts (Windsurf, Claude Desktop) unless `--global` is given, so it never touches a global config by surprise; naming either host directly writes its global config. |
| `--update-mcp` | refresh an entry or rules block that is already there but out of date (`--force` is a deprecated alias) |

Exit codes: 0 done, 1 missing or unknown host, 2 usage error.

### How rules files are merged

- `AGENTS.md`, `GEMINI.md`, `.github/copilot-instructions.md` and `.clinerules` are files you may already have. dev-guardian manages only a delimited block inside them (`<!-- dev-guardian:begin -->` … `<!-- dev-guardian:end -->`); everything outside it is never touched. A stale block is reported as `needs_update` until you pass `--update-mcp`. A file that mentions dev-guardian without the markers and is not byte-for-byte a template an earlier release installed is reported as `manual_merge_required` and left alone.
- `.cursor/rules/dev-guardian.mdc` and `.windsurf/rules/dev-guardian.md` belong to dev-guardian alone and are written whole, because both hosts only honour a rules file whose YAML frontmatter is its very first bytes.
- Codex's TOML entry is compared by content; `--update-mcp` replaces every `[mcp_servers.dev-guardian]` table and sub-table in the file, wherever they are.

## Manual configuration

If you would rather not let the CLI edit anything, paste one of these with the absolute path to your clone:

```jsonc
// Cursor, Windsurf, Gemini CLI, Claude Desktop — "mcpServers"
{ "mcpServers": { "dev-guardian": {
  "command": "node", "args": ["/abs/path/to/dev-guardian/mcp/dist/server.js"], "env": {}
} } }
```

```jsonc
// GitHub Copilot — .vscode/mcp.json uses "servers" and a type
{ "servers": { "dev-guardian": {
  "type": "stdio", "command": "node", "args": ["/abs/path/to/dev-guardian/mcp/dist/server.js"]
} } }
```

```toml
# Codex CLI — single quotes keep Windows backslashes literal
[mcp_servers.dev-guardian]
command = "node"
args = ['/abs/path/to/dev-guardian/mcp/dist/server.js']
enabled = true
```

The rules templates are in [`host-rules/`](../host-rules/); replace `{{DEV_GUARDIAN_CLI}}` in them with the absolute path of `cli/dev-guardian.mjs`.

## The server's working directory

Tools take a `project_path`; when it is omitted they use the server's working directory, and the resources always answer for it. Hosts start the server in different places, so pass `project_path` explicitly when in doubt.

For a project-scoped config, prefer the host's own workspace variable or `cwd` setting to a path that depends on where the host was launched. Claude Code in particular does **not** expand `${CLAUDE_PROJECT_DIR}` inside a project `.mcp.json` — the literal string reaches `node` and the server fails to start. It starts project servers in the project root, so a relative path works there; `${CLAUDE_PLUGIN_ROOT}` is expanded, but only in a plugin's own `plugin.json`. `audit_agent_config` flags an unexpanded `${VAR}` in a project `.mcp.json`.

## Auditing the MCP servers a project declares

`audit_agent_config` reads every host config above without running anything: the project's `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json` and a plugin's `.claude-plugin/plugin.json`, and with `include_user_config` the user-level ones — `~/.claude.json`, Claude Desktop's `claude_desktop_config.json`, `~/.cursor/mcp.json`, Windsurf's `~/.codeium/windsurf/mcp_config.json` and `~/.gemini/settings.json`, at the same paths `mcp-config --write` uses.

`audit_mcp_tools` goes one step further for the servers you name in `servers`: it starts each one as the host would, lists the tools, prompts, resources and templates it serves, and checks those definitions for tool poisoning, hidden Unicode and look-alike letters, instructions to read secrets or hide actions from the user, exfiltration (a URL, an address, an image, a parameter), and cross-server shadowing. Each tool is pinned (sha256 of its name, title, description, input and output schema and annotations), and so are each prompt, resource and template and the server's instructions, so a definition that changes under the same name — a "rug pull" — is reported on the next audit, even after the tool vanished for an audit in between. A name is an entry name, or `<source>::<name>` (as the response prints it) to pick one entry when several declare the same name with different commands. It **executes those servers' code**: only the names you list, with a minimal environment plus the entry's own `env`, never `tools/call`, remote servers (a URL entry; a network-path command; a URL in the command line or an `env` value, unless its host is exactly `localhost`, `127.x.x.x` or `[::1]`; `ssh`, `kubectl` and the like anywhere in the command line; `docker`/`podman`/`nerdctl` against another engine) only with `allow_remote: true`, and the process tree killed afterwards. A loopback URL may still be a tunnel (`ssh -L`, a local proxy) that the configuration does not show. A server can recognise the audit, so a clean result covers only what it chose to show this client — see [SECURITY.md](../SECURITY.md).

## This repository's own configs

A checkout of dev-guardian configures itself for every host (`.mcp.json`, `.cursor/`, `.vscode/mcp.json`, `.gemini/settings.json`, `.windsurf/rules/`, `.github/copilot-instructions.md`, root `AGENTS.md` and `GEMINI.md`), pointing at its own `mcp/dist/server.js`. The rules copies are generated from `mcp/src/hostsetup/rulesTemplate.ts` by `npm run build`; edit the template, not the copies.
