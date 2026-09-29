/**
 * Resource registry.
 *
 * Every resource serves compact JSON (no indentation — a resource is read
 * into a model's context, where whitespace is pure cost). Resources with
 * parameterized URIs (e.g. `guardian://scans/{scan_id}`, or a paged
 * `guardian://findings/open{?page,page_size}`) are registered via the SDK's
 * `ResourceTemplate`, matched by `paging.ts#QueryTolerantUriTemplate`;
 * static URIs use the simple string form.
 *
 * Every resource that reads history answers for the server's own project —
 * see `paging.ts#serverProjectPath`.
 */

import {
  McpServer,
  ResourceTemplate,
} from '@modelcontextprotocol/sdk/server/mcp.js';
import type { PluginContext } from '../context.js';
import { untrustedValue } from '../platform/untrustedText.js';
import { QueryTolerantUriTemplate } from './paging.js';

export type ResourceHandler = (
  uri: URL,
  params: Record<string, string | string[]>,
  ctx: PluginContext,
) => Promise<{ json: unknown }>;

export interface ResourceModule {
  name: string;
  /** Static URI like `guardian://scans/latest`, or a template string. */
  uri: string;
  description: string;
  /** When true, `uri` is interpreted as a URI template. */
  isTemplate?: boolean;
  /**
   * For a template: the concrete URI to list under `resources/list` — the
   * template read with no parameters (`guardian://findings/open` for
   * `guardian://findings/open{?page,page_size}`), so it stays discoverable.
   */
  listAs?: string;
  /** Comma-separated mime; defaults to application/json. */
  mimeType?: string;
  handler: ResourceHandler;
}

export const RESOURCES: ResourceModule[] = [];

export function registerResourceModule(resource: ResourceModule): void {
  if (RESOURCES.some((r) => r.name === resource.name)) {
    throw new Error(`Resource '${resource.name}' is already registered`);
  }
  RESOURCES.push(resource);
}

/**
 * A resource payload as the host receives it: every string in it — keys
 * included — passed through `untrustedValue` (`platform/untrustedText.ts`),
 * like every tool result, since a resource serves the same stored findings.
 */
export function resourceText(json: unknown): string {
  return JSON.stringify(untrustedValue(json));
}

export function attachAllResources(server: McpServer, ctx: PluginContext): void {
  for (const resource of RESOURCES) {
    const mimeType = resource.mimeType ?? 'application/json';
    if (resource.isTemplate) {
      const listAs = resource.listAs;
      const template = new ResourceTemplate(new QueryTolerantUriTemplate(resource.uri), {
        list:
          listAs === undefined
            ? undefined
            : () => ({ resources: [{ uri: listAs, name: resource.name, description: resource.description, mimeType }] }),
      });
      server.registerResource(
        resource.name,
        template,
        { description: resource.description, mimeType },
        async (uri, params) => {
          const { json } = await resource.handler(uri, params, ctx);
          return {
            contents: [{ uri: uri.href, mimeType, text: resourceText(json) }],
          };
        },
      );
    } else {
      server.registerResource(
        resource.name,
        resource.uri,
        { description: resource.description, mimeType },
        async (uri) => {
          const { json } = await resource.handler(uri, {}, ctx);
          return {
            contents: [{ uri: uri.href, mimeType, text: resourceText(json) }],
          };
        },
      );
    }
  }
}
