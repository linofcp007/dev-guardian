# The project's MCP servers — `audit_agent_config` and `audit_mcp_tools`

When the user asks whether the project's MCP servers (or the agent's configuration) are safe:

1. `audit_agent_config { project_path: "<project>" }` first. It reads the configurations (`.mcp.json`,
   `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json`, `.claude-plugin/plugin.json`,
   `hooks/hooks.json`; with
   `include_user_config: true` the user's too — Claude Code, Claude Desktop, Cursor, Windsurf, Gemini)
   **without running anything**, and says which servers are declared.
2. `audit_mcp_tools { project_path: "<project>", servers: ["<name>"] }` only for the servers the user asked to
   audit — the names are theirs; never pick them, nor pass the whole list without asking. **This tool runs
   third-party code**: it starts each named server's command with a minimal environment (plus the entry's own
   `env`), sends `initialize` and the tool / prompt / resource listings, **never calls `tools/call`**, and kills
   the process tree at the end. Remote servers only with `allow_remote: true`, which the user must ask for —
   remote is an entry with a URL, a command on a network path, a URL on the command line or in an `env` value
   (`mcp-remote` and other proxies, a database URL), `ssh` or `kubectl` anywhere on the command line, or
   `docker` / `podman` pointed at another engine. A URL whose host is exactly `localhost`, `127.x.x.x` or
   `[::1]` is local (`postgres://localhost/app` needs no `allow_remote`), but may be a tunnel (`ssh -L`, a local
   proxy) the configuration does not show. When several files declare the same name with different commands,
   the tool refuses and lists the qualified names (`.mcp.json::github`): ask the user which one, and pass that.
3. Read `coverage` and `servers[].status` before the findings: a `skipped` server (undeclared, ambiguous,
   remote without `allow_remote`, cancelled, out of budget), a `failed` one (did not start, no answer within
   `timeout_ms`) or a `partial` one (a listing cut by a limit) was not fully audited — that is not a clean
   result. Even a clean result covers only what the server chose to show this audit: it identifies itself as
   `dev-guardian-audit`, and a server could recognise it and show the host something else. Say so.
4. The findings name the tool and the field (description, `inputSchema`, …) holding the problem: instructions
   to the model, hidden Unicode, requests to read keys or configuration, to hide something from the user, to
   send data to a URL or in a parameter, instructions about other tools (shadowing).
   - `mcp-tool-definition-changed` (high) is a rug pull: the same tool with another definition (title,
     description, input or output schema, annotations) since the previous audit — reported once, and the new
     definition becomes the reference; a tool that disappears and comes back different counts too.
   - The server's `instructions` (which reach the system prompt) count as a tool
     (`mcp-server-instructions-changed`, high). Prompts, resources and templates are recorded too
     (`mcp-prompt-definition-changed` and the like, medium).
   - Two tools with one name are `mcp-tool-duplicate-name` (high): the client picks one ambiguously.
   - `mcp-tool-sensitive-file-access` at medium means the tool tells the model to read a credentials or
     configuration file: confirm with the user that this is the tool's purpose (an SSH or registry client may
     need it); at high it also says to send the file elsewhere or hide it — no tool needs that.
