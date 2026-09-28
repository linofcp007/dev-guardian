/**
 * `check_toolchain` — surface installed / missing scanner state.
 *
 * Probes every catalogue entry directly: its binary and version command
 * (`installCatalog.ts` → `probe`), run through `runProcess` — argv, no shell,
 * so it works with no bash at all. For each tool it reports:
 *   - `installed` (bool) and `version` (parsed, or "")
 *   - `expected_version_floor` and `meets_version_floor`
 *   - `required_by` (which MCP tools need it)
 *   - `install_command` (string suggestion per current OS)
 *   - `compromised` (+ `advisory`) for a known-malicious release
 *   - `provided_by` when another entry satisfies it (dotnet-format ← SDK)
 *   - `probe_error` when the binary exists but could not report a version
 *
 * It used to run `scripts/scan/check-tools.sh`, which knew 11 of the 17
 * catalogue entries — nine were ALWAYS "not installed", including a .NET SDK
 * that was sitting right there — and whose raw output broke the JSON on a
 * real Windows host (see `runners/toolProbe.ts`).
 *
 * No installation happens here — that's `install_toolchain`'s job. This tool
 * is read-only.
 */

import type { PluginContext } from '../context.js';
import { detectOs } from '../platform/osDetect.js';
import { compareSemver, meetsFloor } from '../platform/semverCompare.js';
import {
  TOOL_CATALOG,
  knownCompromise,
  suggestedInstallCommandString,
} from '../runners/installCatalog.js';
import { runVersionProbe, type ProbeResult, type VersionProbe } from '../runners/toolProbe.js';
import type { ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

interface ToolStatus {
  name: string;
  installed: boolean;
  version: string;
  expected_version_floor: string;
  /**
   * `true` if installed version >= floor, `false` if below floor,
   * `null` when the version string couldn't be parsed (e.g. unusual output
   * from a custom build) — null is "best effort, assume usable".
   */
  meets_version_floor: boolean | null;
  required_by: string[];
  install_command: string | null;
  /** True when the installed version is a known-malicious release. */
  compromised: boolean;
  advisory?: { id: string; cve?: string; url: string; action: string };
  /** Another catalogue entry that provides this tool (dotnet-format ← dotnet-sdk). */
  provided_by?: string;
  /** Why a binary that exists could not report its version. */
  probe_error?: string;
}

/**
 * Not scanners, but what the scanners and scripts stand on. Reported for
 * information only, as the bash probe did; never counted in the summary.
 * Python is tried as `python3` first, then `python` — on Windows `python3`
 * is often the Microsoft Store stub, which exits 9009.
 */
const INFORMATIONAL: Array<{ name: string; probes: VersionProbe[] }> = [
  { name: 'node', probes: [{ command: 'node', args: ['--version'] }] },
  {
    name: 'python',
    probes: [
      { command: 'python3', args: ['--version'] },
      { command: 'python', args: ['--version'] },
    ],
  },
  { name: 'docker', probes: [{ command: 'docker', args: ['--version'] }] },
];

/** Probes run a few at a time: 20 interpreters starting at once is its own
 *  load test on a busy machine, and the slowest probe bounds the call. */
const PROBE_CONCURRENCY = 6;

const tool: ToolModule = {
  name: 'check_toolchain',
  title: 'Check toolchain status',
  description:
    'Probe every catalogued scanner directly (its binary and version command; no bash needed) and ' +
    'report per-scanner status: installed, version, expected version floor, known-compromised ' +
    'releases (with the advisory id), the MCP tools that depend on it, and the suggested install ' +
    'command for this OS.',
  inputSchema: {},
  handler: async (_input, ctx) => handler(ctx),
};

registerToolModule(tool);

async function handler(ctx: PluginContext): Promise<ToolResult<Record<string, unknown>>> {
  const os = detectOs();
  const cwd = ctx.scriptsDir;

  const catalogue = Object.values(TOOL_CATALOG);
  const probed = await mapLimited(catalogue, PROBE_CONCURRENCY, (meta) =>
    runVersionProbe(meta.probe, cwd),
  );
  const extras = await mapLimited(INFORMATIONAL, PROBE_CONCURRENCY, (x) => firstFound(x.probes, cwd));

  const byName = new Map<string, ProbeResult>();
  catalogue.forEach((meta, i) => {
    const r = probed[i];
    if (r !== undefined) byName.set(meta.name, r);
  });

  const tools: ToolStatus[] = [];
  for (const meta of catalogue) {
    let result = byName.get(meta.name) ?? { installed: false, version: '' };
    let providedBy: string | undefined;
    // `dotnet format` has shipped inside the SDK since .NET 6; the global
    // tool is only needed on older SDKs.
    if (meta.name === 'dotnet-format' && !result.installed) {
      const sdk = byName.get('dotnet-sdk');
      if (sdk?.installed && (compareSemver(sdk.version, '6.0.0') ?? -1) >= 0) {
        result = { installed: true, version: sdk.version };
        providedBy = 'dotnet-sdk';
      }
    }
    const compromise = result.installed ? knownCompromise(meta.name, result.version) : null;
    const status: ToolStatus = {
      name: meta.name,
      installed: result.installed,
      version: result.version,
      expected_version_floor: meta.version_floor,
      meets_version_floor: result.installed ? meetsFloor(result.version, meta.version_floor) : null,
      required_by: meta.required_by,
      install_command: suggestedInstallCommandString(meta.name, os),
      compromised: compromise !== null,
    };
    if (compromise) {
      status.advisory = {
        id: compromise.advisory,
        ...(compromise.cve ? { cve: compromise.cve } : {}),
        url: compromise.url,
        action: compromise.action,
      };
    }
    if (providedBy) status.provided_by = providedBy;
    if (result.error && !result.installed) status.probe_error = result.error;
    tools.push(status);
  }
  INFORMATIONAL.forEach((x, i) => {
    const r = extras[i] ?? { installed: false, version: '' };
    const status: ToolStatus = {
      name: x.name,
      installed: r.installed,
      version: r.version,
      expected_version_floor: '',
      meets_version_floor: null,
      required_by: [],
      install_command: null,
      compromised: false,
    };
    if (r.error && !r.installed) status.probe_error = r.error;
    tools.push(status);
  });

  // Sort: compromised first, then missing, then required, alphabetical.
  tools.sort((a, b) => {
    const aRequired = a.required_by.length > 0 ? 0 : 1;
    const bRequired = b.required_by.length > 0 ? 0 : 1;
    const aMissing = a.installed ? 1 : 0;
    const bMissing = b.installed ? 1 : 0;
    const aBad = a.compromised ? 0 : 1;
    const bBad = b.compromised ? 0 : 1;
    return (
      aBad - bBad ||
      aMissing - bMissing ||
      aRequired - bRequired ||
      a.name.localeCompare(b.name)
    );
  });

  const compromised = tools.filter((t) => t.compromised);
  const warnings = compromised.map(
    (t) =>
      `${t.name} ${t.version} is a known-compromised release (${t.advisory?.id ?? 'advisory'}): ` +
      `${t.advisory?.action ?? ''} ${t.advisory?.url ?? ''}`.trim(),
  );

  return {
    ok: true,
    os,
    tools,
    summary: {
      total_catalogued: catalogue.length,
      installed: tools.filter((t) => t.installed && TOOL_CATALOG[t.name]).length,
      missing: tools.filter((t) => !t.installed && TOOL_CATALOG[t.name]).length,
      below_floor: tools.filter((t) => t.meets_version_floor === false).length,
      compromised: compromised.length,
    },
    ...(warnings.length > 0 ? { warnings } : {}),
  };
}

/** The first probe that finds its tool; the last result when none does. */
async function firstFound(probes: VersionProbe[], cwd: string): Promise<ProbeResult> {
  let last: ProbeResult = { installed: false, version: '' };
  for (const probe of probes) {
    last = await runVersionProbe(probe, cwd);
    if (last.installed) return last;
  }
  return last;
}

/** `Promise.all(items.map(fn))`, at most `limit` at a time, order kept. */
async function mapLimited<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const out: R[] = new Array<R>(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const i = next++;
      const item = items[i];
      if (item === undefined) continue;
      out[i] = await fn(item);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}
