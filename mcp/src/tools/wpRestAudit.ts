/**
 * `wp_rest_audit` — probe a live WordPress site's REST API for the
 * common "too-much-exposed" endpoints.
 *
 * Read-only HTTP GETs. Specifically checks:
 *   - GET /wp-json/wp/v2/users  (anonymous user enumeration — default ON)
 *   - GET /wp-json/wp/v2/comments
 *   - GET /wp-json/wp/v2/pages?status=draft  (drafts visible?)
 *   - GET /wp-json/  (route listing; flags plugins exposing internals)
 *   - GET /xmlrpc.php  (legacy attack surface)
 *
 * We never POST and never log in. Output is purely "exposed: yes/no" plus
 * the count of items returned.
 */

import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import type { ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

interface ProbeResult {
  endpoint: string;
  status: number;
  exposed: boolean;
  detail: string;
}

const inputSchema = {
  target_url: z
    .string()
    .url()
    .describe('Base URL of the WordPress site (e.g. https://example.com).'),
  timeout_ms: z.number().int().min(1000).max(60_000).optional(),
};

const tool: ToolModule = {
  name: 'wp_rest_audit',
  title: 'WordPress REST API exposure audit',
  description:
    'Probe (read-only HTTP GET) the live WP REST API for endpoints that commonly leak data: users ' +
    'enumeration, draft posts, comments, xmlrpc.php. No POSTs, no auth. Returns one row per ' +
    'endpoint with `exposed: yes/no`.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { target_url: string; timeout_ms?: number };
  const url = inp.target_url.replace(/\/$/, '');
  const timeoutMs = inp.timeout_ms ?? 15_000;

  const endpoints: Array<{ path: string; label: string; expectListing: boolean }> = [
    { path: '/wp-json/wp/v2/users', label: 'users (enumeration)', expectListing: true },
    { path: '/wp-json/wp/v2/comments', label: 'comments', expectListing: true },
    {
      path: '/wp-json/wp/v2/pages?status=draft',
      label: 'draft pages',
      expectListing: true,
    },
    { path: '/wp-json/', label: 'route discovery', expectListing: false },
    { path: '/xmlrpc.php', label: 'xmlrpc.php', expectListing: false },
  ];

  const results: ProbeResult[] = [];
  for (const ep of endpoints) {
    results.push(await probe(`${url}${ep.path}`, ep.label, ep.expectListing, timeoutMs));
  }

  const exposed = results.filter((r) => r.exposed);

  const scanId = randomUUID();
  ctx.storage.scans.insert({
    scan_id: scanId,
    scan_type: 'wp_rest_audit',
    project_path: url,
    tree_hash: '',
  });
  ctx.storage.scans.finalize({
    scan_id: scanId,
    status: 'completed',
    tools_run: [{ name: 'http-probe', status: 'ok' }],
    missing_tools: [],
    meta: { target_url: url, results, exposed_count: exposed.length },
  });

  return {
    ok: true,
    scan_id: scanId,
    target_url: url,
    results,
    exposed_count: exposed.length,
    hint:
      exposed.length > 0
        ? 'Block / restrict the exposed endpoints. Common fix: WP plugin "Disable REST API" or filter ' +
          'via `rest_endpoints` hook in functions.php.'
        : 'No exposed endpoints from this probe set.',
  };
}

async function probe(
  fullUrl: string,
  _label: string,
  expectListing: boolean,
  timeoutMs: number,
): Promise<ProbeResult> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(fullUrl, {
      method: 'GET',
      signal: controller.signal,
      headers: { 'User-Agent': 'dev-guardian/wp_rest_audit' },
    });
    let detail = '';
    let exposed = false;
    if (expectListing) {
      try {
        const text = await res.text();
        const parsed = JSON.parse(text);
        const count = Array.isArray(parsed) ? parsed.length : 0;
        exposed = res.status === 200 && count > 0;
        detail = `status=${res.status}, items=${count}`;
      } catch {
        exposed = res.status === 200;
        detail = `status=${res.status}, non-JSON body`;
      }
    } else {
      // For xmlrpc.php and /wp-json/ root: 200 OK means it's accessible
      exposed = res.status === 200 || res.status === 405; // 405 on xmlrpc.php = method not allowed but reachable
      detail = `status=${res.status}`;
    }
    return { endpoint: fullUrl, status: res.status, exposed, detail };
  } catch (e) {
    return {
      endpoint: fullUrl,
      status: 0,
      exposed: false,
      detail: `unreachable: ${(e as Error).message}`,
    };
  } finally {
    clearTimeout(timeout);
  }
}

