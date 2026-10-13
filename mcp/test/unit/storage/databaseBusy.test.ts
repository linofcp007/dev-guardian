/**
 * Review 8, finding 11: another process holding the shared database's write
 * lock froze the server for the whole busy timeout (5 s; `node:sqlite` is
 * synchronous) and then failed the tool call with a bare "database is locked",
 * no error code. The server's session waits less now, and a call whose wait
 * runs out answers `database_busy`, saying what to do.
 */
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { z } from 'zod';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GuardianDatabase, isDatabaseBusyError, SESSION_BUSY_TIMEOUT_MS, BUSY_TIMEOUT_MS } from '../../../src/storage/db.js';
import { attachAllTools, DATABASE_BUSY_MESSAGE, TOOLS, type ToolModule } from '../../../src/tools/index.js';
import { freshPlugin } from '../../helpers/historySeed.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

describe('a lock another connection holds', () => {
  it('the session waits less than startup, and the error it ends in is recognised as busy', () => {
    expect(SESSION_BUSY_TIMEOUT_MS).toBeLessThan(BUSY_TIMEOUT_MS);
    const path = join(makeTempDir('db-busy-'), 'g.db');
    const holder = new GuardianDatabase(path);
    const waiter = new GuardianDatabase(path);
    try {
      holder.exec('CREATE TABLE t (x INTEGER)');
      holder.exec('BEGIN IMMEDIATE');
      holder.exec('INSERT INTO t VALUES (1)');
      waiter.setBusyTimeout(100);
      let error: unknown;
      const started = Date.now();
      try {
        waiter.exec('INSERT INTO t VALUES (2)');
      } catch (e) {
        error = e;
      }
      expect(error).toBeDefined();
      expect(isDatabaseBusyError(error)).toBe(true);
      // The wait set is the wait taken — not the 5 s the connection opened with.
      expect(Date.now() - started).toBeLessThan(BUSY_TIMEOUT_MS);
    } finally {
      holder.exec('ROLLBACK');
      holder.close();
      waiter.close();
    }
  });

  it('only a lock is busy', () => {
    expect(isDatabaseBusyError(new Error('database is locked'))).toBe(true);
    expect(isDatabaseBusyError(Object.assign(new Error('x'), { errcode: 517 }))).toBe(true); // SQLITE_BUSY_SNAPSHOT
    expect(isDatabaseBusyError(new Error('no such table: t'))).toBe(false);
    expect(isDatabaseBusyError(Object.assign(new Error('x'), { errcode: 11 }))).toBe(false); // SQLITE_CORRUPT
  });
});

describe('tools/call when the database stays locked', () => {
  it('answers a coded, actionable database_busy error — not a bare protocol error', async () => {
    const busy: ToolModule = {
      name: 'test_busy_tool',
      description: 'throws what node:sqlite throws when the lock is not released',
      inputSchema: { project_path: z.string().optional() },
      handler: async () => {
        throw Object.assign(new Error('database is locked'), { errcode: 5 });
      },
    };
    TOOLS.push(busy);
    try {
      const server = new McpServer({ name: 'test', version: '0.0.0' });
      attachAllTools(server, freshPlugin().plugin);
      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      await server.connect(serverTransport);
      const client = new Client({ name: 'test-client', version: '0.0.0' });
      await client.connect(clientTransport);
      const r = (await client.callTool({ name: 'test_busy_tool', arguments: {} })) as {
        isError?: boolean;
        structuredContent?: { error?: { code?: string; message?: string } };
      };
      expect(r.isError).toBe(true);
      expect(r.structuredContent?.error?.code).toBe('database_busy');
      expect(r.structuredContent?.error?.message).toBe(DATABASE_BUSY_MESSAGE);
      expect(DATABASE_BUSY_MESSAGE).toMatch(/Retry the call in a few seconds/);
    } finally {
      TOOLS.splice(TOOLS.indexOf(busy), 1);
    }
  });
});
