#!/usr/bin/env node
// The dev-guardian MCP server: started from the engine bundle (mcp/src/engine.ts), built by `npm run build`.
await (await import('./engine.js')).startServer();
