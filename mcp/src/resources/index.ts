/**
 * Resource registry.
 *
 * Every resource serves JSON. Resources with parameterized URIs (e.g.
 * `guardian://scans/{scan_id}`) are registered via the SDK's
 * `ResourceTemplate`; static URIs use the simple string form.
 */

import {
  McpServer,
  ResourceTemplate,
} from '@modelcontextprotocol/sdk/server/mcp.js';
import type { PluginContext } from '../context.js';

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

export function attachAllResources(server: McpServer, ctx: PluginContext): void {
  for (const resource of RESOURCES) {
    const mimeType = resource.mimeType ?? 'application/json';
    if (resource.isTemplate) {
      const template = new ResourceTemplate(resource.uri, { list: undefined });
      server.registerResource(
        resource.name,
        template,
        { description: resource.description, mimeType },
        async (uri, params) => {
          const normalizedParams = normalizeParams(params);
          const { json } = await resource.handler(uri, normalizedParams, ctx);
          return {
            contents: [
              { uri: uri.href, mimeType, text: JSON.stringify(json, null, 2) },
            ],
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
            contents: [
              { uri: uri.href, mimeType, text: JSON.stringify(json, null, 2) },
            ],
          };
        },
      );
    }
  }
}

function normalizeParams(
  params: Record<string, string | string[]>,
): Record<string, string | string[]> {
  // Surface a stable shape — templates that capture a single segment yield a
  // string, multi-capture yields an array. We pass both through verbatim
  // (handlers know which one they expect).
  return params;
}
