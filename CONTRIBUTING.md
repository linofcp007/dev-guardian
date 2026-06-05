# Contributing to dev-guardian

Thanks for helping. This is a Claude Code / Cowork plugin plus an MCP server;
see [CLAUDE.md](CLAUDE.md) for an orientation.

## Build & test

All work happens from `mcp/`:

```bash
cd mcp
npm ci               # reproducible install (native better-sqlite3)
npm run build        # tsc -> mcp/dist + copy-assets
npm test             # vitest run (full suite)
npm run typecheck    # tsc --noEmit
```

Markdown is linted with markdownlint (config: [.markdownlint.jsonc](.markdownlint.jsonc)):

```bash
npx markdownlint-cli2 "README.md" "CONTRIBUTING.md" "SECURITY.md" "skills/**/*.md" "commands/**/*.md"
```

## Non-negotiables

- **Commit the compiled `mcp/dist/`.** The repo *is* the distribution — Claude
  Code runs `mcp/dist/server.js` directly, no install-time build. Rebuild
  (`npm run build`) and stage `mcp/dist/` in the **same** commit as the `src/`
  change. CI fails if `dist/` drifts from a fresh build.
- **Tests stay green** (`npm test`) and **markdownlint stays clean** for
  `skills/`, `commands/`, `README.md` and the root docs.
- **The MCP tool surface is snapshotted.** Adding or removing a tool/resource
  updates `mcp/test/integration/toolSurface.test.ts` — an intentional change,
  reviewed as such (see the stability policy in the README).

## Commit style

Conventional Commits: `feat(scope): …`, `fix(scope): …`, `chore(release): …`,
`docs: …`, `test: …`. Breaking changes carry a `BREAKING CHANGE:` footer.

## Releases

1. Bump the version in [`.claude-plugin/plugin.json`](.claude-plugin/plugin.json),
   [`.claude-plugin/marketplace.json`](.claude-plugin/marketplace.json) and the
   root [`package.json`](package.json).
2. Update [CHANGELOG.md](CHANGELOG.md).
3. Tag `vX.Y.Z` and create a GitHub release.

### Publishing to npm (optional, maintainers)

The repo also publishes as the scoped package **`@dev-guardian/mcp-server`** —
bins `dev-guardian` (the `mcp-config` CLI) and `dev-guardian-mcp` (the server).
The root [`package.json`](package.json) `files` allowlist ships `bin/`,
`mcp/dist/` and the runtime assets only — never `src/`, `test/` or
`node_modules`. `prepublishOnly` rebuilds and tests first. The inner
`mcp/package.json` is `private`, so only the root package publishes.

```bash
npm pack --dry-run     # inspect the tarball, publishes nothing
npm login              # an account that owns the @dev-guardian scope
npm publish            # @dev-guardian/mcp-server, access: public
```

Consumers then get the CLI without cloning:

```bash
npm i -g @dev-guardian/mcp-server
dev-guardian mcp-config cursor --write
```

The Claude Code marketplace install (git) is independent of npm.

## Adding a scanner / tool

- Put pure parsing in `mcp/src/runners/scannerParsers/` with a unit test.
- Register the tool in `mcp/src/tools/` and import it in `mcp/src/server.ts`.
- Degrade gracefully when the scanner binary is absent — report it, never crash.
- Add an integration test; if it needs a real scanner, gate it like the e2e
  fixtures so the suite still passes without the binary.
