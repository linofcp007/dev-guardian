/**
 * The constraints the LLM-assisted scan ships under.
 *
 *   - NFR-1: the server holds no API key and calls no model provider — no
 *     provider SDK, no network module, no key read from the environment, in
 *     `src/llmscan/` or the three tools; and no new runtime dependency.
 *   - NFR-3: each new tool's description is at most 1500 characters.
 *   - NFR-4: the brief templates exist, versioned, and each records that it
 *     was written from this feature's spec (decision D-1 of the spike).
 *
 * T-34.
 */

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { TOOLS } from '../../../src/tools/index.js';

beforeAll(async () => {
  await import('../../../src/registerAll.js');
});

const MCP = resolve(fileURLToPath(new URL('../../../', import.meta.url)));
const REPO = resolve(MCP, '..');
const LLMSCAN = join(MCP, 'src', 'llmscan');
const TOOL_NAMES = ['llm_scan_start', 'llm_scan_task', 'llm_scan_submit'] as const;
const TOOL_FILES = ['llmScanStart.ts', 'llmScanTask.ts', 'llmScanSubmit.ts'].map((f) => join(MCP, 'src', 'tools', f));
const PROMPTS = join(REPO, 'configs', 'llm-scan', 'prompts', 'v1');
const PROVENANCE = '<!-- provenance: written from .specs/llm-scan (D-1) -->';

/** Package specifiers no file of the feature may import: model providers' SDKs and agent frameworks. */
const PROVIDER_SDKS: RegExp[] = [
  /^@anthropic-ai\//,
  /^anthropic$/,
  /^openai(\/|$)/,
  /^@openai\//,
  /^@google\/genai(\/|$)/,
  /^@google\/generative-ai(\/|$)/,
  /^@google-cloud\/vertexai(\/|$)/,
  /^ollama(\/|$)/,
  /^cohere-ai(\/|$)/,
  /^@mistralai\//,
  /^groq-sdk(\/|$)/,
  /^@aws-sdk\/client-bedrock/,
  /^ai$/,
  /^@ai-sdk\//,
  /^langchain(\/|$)/,
  /^@langchain\//,
  /^llamaindex(\/|$)/,
  /^replicate(\/|$)/,
  /^together-ai(\/|$)/,
];
/** Nothing in the feature talks to the network (constitution, principle 5). */
const NETWORK_MODULES: RegExp[] = [/^(node:)?(http|https|http2|net|tls|dgram)$/, /^undici(\/|$)/];

function tsFilesUnder(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) return tsFilesUnder(p);
    return p.endsWith('.ts') ? [p] : [];
  });
}

/** Comments removed (crudely: enough that a doc comment naming a provider is not an import). */
function code(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`])\/\/.*$/gm, '$1');
}

function specifiers(src: string): string[] {
  const out: string[] = [];
  for (const re of [/\bfrom\s+['"]([^'"]+)['"]/g, /\bimport\s*\(\s*['"]([^'"]+)['"]/g, /\brequire\s*\(\s*['"]([^'"]+)['"]/g, /^\s*import\s+['"]([^'"]+)['"]/gm]) {
    for (const m of src.matchAll(re)) if (m[1] !== undefined) out.push(m[1]);
  }
  return out;
}

describe('T-34 constraints (NFR-1, NFR-3, NFR-4)', () => {
  it('T-34 NFR-1: no provider SDK, no network module, no API key from the environment — in src/llmscan/ and the three tools', () => {
    for (const f of TOOL_FILES) expect(existsSync(f), `${f} exists`).toBe(true);
    const files = [...tsFilesUnder(LLMSCAN), ...TOOL_FILES.filter((f) => existsSync(f))];
    expect(files.length).toBeGreaterThanOrEqual(TOOL_FILES.length + 5);

    const problems: string[] = [];
    for (const file of files) {
      const src = code(readFileSync(file, 'utf8'));
      for (const spec of specifiers(src)) {
        if (PROVIDER_SDKS.some((re) => re.test(spec))) problems.push(`${file}: imports model-provider SDK '${spec}'`);
        if (NETWORK_MODULES.some((re) => re.test(spec))) problems.push(`${file}: imports network module '${spec}'`);
      }
      if (/\bfetch\s*\(/.test(src)) problems.push(`${file}: calls fetch()`);
      for (const m of src.matchAll(/process\.env(?:\.([A-Za-z_][A-Za-z0-9_]*)|\[\s*['"`]([^'"`]+)['"`]\s*\])/g)) {
        const name = m[1] ?? m[2] ?? '';
        if (/API_?KEY|TOKEN|SECRET/i.test(name)) problems.push(`${file}: reads ${name} from the environment`);
      }
      if (/process\.env\s*\[\s*[^'"`\s]/.test(src)) problems.push(`${file}: reads the environment by a computed name`);
      if (/\b[A-Z][A-Z0-9_]*_API_KEY\b/.test(src)) problems.push(`${file}: names an API key variable`);
    }
    expect(problems).toEqual([]);
  });

  it('T-34 NFR-1: no new runtime dependency', () => {
    const pkg = JSON.parse(readFileSync(join(MCP, 'package.json'), 'utf8')) as { dependencies?: Record<string, string> };
    expect(Object.keys(pkg.dependencies ?? {}).sort()).toEqual(['@modelcontextprotocol/sdk', 'execa', 'signal-exit', 'yaml', 'zod']);
  });

  it('T-34 NFR-3: the three tools are registered, each described in at most 1500 characters', () => {
    for (const name of TOOL_NAMES) {
      const tool = TOOLS.find((t) => t.name === name);
      expect(tool, `${name} is registered`).toBeDefined();
      expect(tool?.description.trim() ?? '', name).not.toBe('');
      expect(tool?.description.length ?? Number.POSITIVE_INFINITY, name).toBeLessThanOrEqual(1500);
    }
  });

  it.each(['verify.md', 'hunt-entrypoint.md', 'hunt-crosscut.md'])(
    'T-34 NFR-4: configs/llm-scan/prompts/v1/%s exists and opens with its provenance line',
    (name) => {
      const path = join(PROMPTS, name);
      expect(existsSync(path), path).toBe(true);
      const first = readFileSync(path, 'utf8').split(/\r?\n/)[0];
      expect(first).toBe(PROVENANCE);
    },
  );
});
