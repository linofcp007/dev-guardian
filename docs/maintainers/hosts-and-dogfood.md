# AI hosts and the in-repo configs

> Maintainer notes, moved from `CLAUDE.md` (the index). Not loaded into sessions: read this file before you
> change its area.

## In-repo AI host configs (dogfooding)

This repo ships its own host configs so opening it in any AI host wires up the
dev-guardian MCP server out of the box: `.mcp.json` (Claude Code), `.cursor/`,
`.gemini/`, `.vscode/`, `.windsurf/`, `.github/copilot-instructions.md`, plus root
`AGENTS.md` / `GEMINI.md`. The MCP entries point at the committed
`mcp/dist/server.js` — a bare relative path in `.mcp.json` (Claude Code starts
project servers in the project root) and in `.gemini/settings.json` (with
`"cwd": "."`), `${workspaceFolder}/…` in `.cursor/mcp.json` and
`.vscode/mcp.json`. **Never use `${CLAUDE_PROJECT_DIR}` in `.mcp.json`**: Claude
Code does not expand it there, `node` receives the literal string, and the
server dies with `MODULE_NOT_FOUND` — only `${CLAUDE_PLUGIN_ROOT}` in
`plugin.json` is expanded. The rules copies (root `AGENTS.md` and `GEMINI.md`,
`.cursor/rules/dev-guardian.mdc`, `.windsurf/rules/dev-guardian.md`,
`.github/copilot-instructions.md`) and every `host-rules/*` template are generated
from `mcp/src/hostsetup/rulesTemplate.ts` by `npm run build`; edit the template,
never a copy. To install the same into *another* project, use the `mcp-config`
CLI (`node cli/dev-guardian.mjs mcp-config <host> --write`) — it fills in
absolute paths. See [`docs/hosts.md`](../../docs/hosts.md).

**Never put the CLI back in a top-level `bin/`.** Claude Desktop / claude.ai does not clone the repo:
it validates it on a remote Anthropic service that *rejects* any plugin shipping a top-level `bin/`
(those files land on PATH in the CLI but are invisible on the admin approval surface). The sync fails
with `status=failed_content` and the UI shows only "Marketplace sync failed. Check the repository
URL", which points nowhere near the cause. The local CLI (`/plugin marketplace add`) uses `git clone`
and does **not** apply this rule, so it passes even when Desktop refuses — it is not a valid pre-check.
Executable entry points belong in `hooks/`, `commands/` or `mcpServers`.

## The rules template

`RULES_BODY` is all a non-Claude host reads about dev-guardian, so it carries the safety rules first (a gap is
never "0 findings", `severity_min` filters the response only, `vet_packages` before an install, the
`create_fix_pr` dry run, `verify_live` and `audit_mcp_tools` need the user, never run `db adopt`), then one intent
line per area naming every tool, the LLM-scan recipe per host, and a short CI paragraph that points at
`docs/ci.md`. It stays at most 8 000 bytes (`hostRulesDrift.test.ts`): Codex reads 32 KiB of `AGENTS.md` in all,
dev-spec-driven's block and the user's own content included. Manuals (CI, the dashboard, a tool's internals)
belong in `docs/`, not here.

Cursor and Windsurf load it on demand: Cursor's frontmatter has a description, no globs and `alwaysApply: false`;
Windsurf's is `trigger: model_decision` with the same description (`RULES_DESCRIPTION`). An always-on rule cost
18.5 KB on every request, and Windsurf truncates a rule at 12 000 characters — the end of the file, where the
`db adopt` rule was, silently disappeared. The description names the moments a model must not miss (installing a
package, an AI skill or an MCP server).
