/**
 * `scan_dotnet_secrets` — scan .NET-specific config files for secrets and
 * connection strings that gitleaks does not catch.
 *
 * gitleaks knows generic patterns; the MS-specific ones (SQL Server
 * connection strings with `Integrated Security`, NuGet feed credentials
 * in `nuget.config`, etc.) are formatted with attributes that the generic
 * rules miss.
 *
 * Target files:
 *   - appsettings*.json
 *   - Web.config / App.config / *.config
 *   - nuget.config / NuGet.Config
 *   - launchSettings.json (developer secrets often live here)
 */

import { randomUUID } from 'node:crypto';
import { describeReadRefusal, listProjectDir, readProjectText } from '../platform/projectFs.js';
import { join, relative } from 'node:path';
import type { PluginContext } from '../context.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import {
  makeFinding,
  type ParserOutput,
} from '../runners/scannerParsers/index.js';
import { redactCredentialSnippets } from '../redaction/secretFindingRedaction.js';
import type { Finding, ToolResult, ToolRun } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';
import { computeCoverage } from './scanCoverage.js';

interface PatternRule {
  id: string;
  regex: RegExp;
  description: string;
  severity: 'critical' | 'high' | 'medium';
}

const PATTERNS: PatternRule[] = [
  {
    id: 'dotnet-sql-server-conn',
    description: 'SQL Server connection string with password',
    severity: 'critical',
    regex: /(Server|Data\s*Source)=[^;"']+;.*?(Password|Pwd)=[^;"']+/i,
  },
  {
    id: 'dotnet-trusted-conn',
    description: 'SQL Server connection string with Integrated Security and dev credentials',
    severity: 'medium',
    regex: /(Server|Data\s*Source)=[^;"']+;.*?Integrated\s*Security=(SSPI|true)/i,
  },
  {
    id: 'dotnet-postgres-conn',
    description: 'PostgreSQL connection string with password',
    severity: 'critical',
    regex: /Host=[^;"']+;.*?(Password|Pwd)=[^;"']+/i,
  },
  {
    id: 'dotnet-azure-storage-key',
    description: 'Azure Storage account key in connection string',
    severity: 'critical',
    regex: /AccountKey=[A-Za-z0-9+/=]{60,}/,
  },
  {
    id: 'dotnet-azure-servicebus',
    description: 'Azure Service Bus shared access key',
    severity: 'critical',
    regex: /SharedAccessKey=[A-Za-z0-9+/=]{40,}/,
  },
  {
    id: 'dotnet-aws-key-config',
    description: 'AWS access key in appsettings/config',
    severity: 'critical',
    regex: /AKIA[0-9A-Z]{16}/,
  },
  {
    id: 'dotnet-jwt-secret',
    description: 'JWT signing key in plain text',
    severity: 'high',
    // The key may be quoted itself: appsettings.json writes `"JwtSecret": "…"`,
    // with a quote between the key and the colon, which the pattern used to
    // refuse — every JSON signing key went unreported (review M4).
    regex: /(JwtSecret|JWT_SECRET|SigningKey)["']?\s*[:=]\s*["'][^"']{16,}["']/i,
  },
  {
    id: 'dotnet-nuget-feed-cred',
    description: 'NuGet feed credentials in nuget.config (plaintext clear password)',
    severity: 'critical',
    regex: /<add\s+key="ClearTextPassword"\s+value="[^"]+"/i,
  },
  {
    id: 'dotnet-appinsights-key',
    description: 'Application Insights instrumentation key',
    severity: 'medium',
    regex: /InstrumentationKey=[a-f0-9-]{36}/i,
  },
  {
    id: 'dotnet-sendgrid-key',
    description: 'SendGrid API key (SG. prefix)',
    severity: 'critical',
    regex: /SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{40,}/,
  },
];

const TARGET_FILES = [
  /^appsettings.*\.json$/i,
  /^Web\.config$/i,
  /^App\.config$/i,
  /^.*\.config$/i,
  /^nuget\.config$/i,
  /^NuGet\.Config$/i,
  /^launchSettings\.json$/i,
];

const SKIP_DIRS = new Set([
  'bin',
  'obj',
  'node_modules',
  '.git',
  '.guardian',
  'dist',
  'build',
  'packages',
  '.vs',
]);

const inputSchema = {
  project_path: ProjectPath,
};

const tool: ToolModule = {
  name: 'scan_dotnet_secrets',
  title: '.NET-specific secret scan',
  description:
    'Scan .NET config files (appsettings*.json, *.config, nuget.config, launchSettings.json) for ' +
    'MS-specific patterns that gitleaks generic rules miss: SQL Server conn strings, Azure ' +
    'Storage / Service Bus keys, NuGet feed plaintext credentials, JWT signing keys.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { project_path?: string };
  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    return {
      ok: false,
      error: { code: 'not_a_git_repo', message: (e as Error).message },
    };
  }

  const files = collectConfigFiles(projectPath, 6);
  const findings: Finding[] = [];
  /** Files found and not read: never counted as scanned, always named (review M4). */
  const notScanned: Array<{ file: string; reason: string }> = [];
  let scanned = 0;
  const rel = (file: string): string => relative(projectPath, file).replace(/\\/g, '/');

  for (const file of files) {
    // Read through `platform/projectFs.ts`: contained in the project, regular
    // files only, and at most 2 MB (massive files — likely not config but
    // build output drifting in — are not read at all).
    const read = readProjectText(projectPath, file, MAX_FILE_BYTES);
    if (read.status === 'absent') {
      notScanned.push({ file: rel(file), reason: 'could not be read (ENOENT)' });
      continue;
    }
    if (read.status === 'refused') {
      notScanned.push({
        file: rel(file),
        reason: read.reason === 'too-large' ? 'over 2 MB' : `not read: ${describeReadRefusal(read.reason)}`,
      });
      continue;
    }
    const content = read.text;
    scanned += 1;
    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i];
      if (line === undefined) continue;
      for (const rule of PATTERNS) {
        if (rule.regex.test(line)) {
          findings.push(
            makeFinding({
              tool: 'scan_dotnet_secrets',
              rule_id: rule.id,
              severity: rule.severity,
              category: 'security',
              subcategory: 'secret',
              title: rule.description,
              file_path: rel(file),
              line_start: i + 1,
              line_end: i + 1,
              snippet: line.length > 200 ? `${line.slice(0, 200)}…` : line,
              fix_available: false,
            }),
          );
        }
      }
    }
  }

  // Every finding here is `subcategory: 'secret'` by construction — the
  // whole matched line (connection string, key, password and all) is what
  // `snippet` held before this, straight into the response and the DB.
  // Redacted once, before either sees it.
  const redacted = redactCredentialSnippets(findings);

  const scanId = randomUUID();
  ctx.storage.scans.insert({
    scan_id: scanId,
    scan_type: 'dotnet_secrets',
    project_path: projectPath,
    tree_hash: '',
  });
  if (redacted.length > 0) {
    ctx.storage.findings.bulkInsert(redacted.map((f) => ({ ...f, scan_id: scanId })));
  }
  // Code-point order: the same on every machine, whatever its locale.
  notScanned.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
  const toolRun: ToolRun =
    notScanned.length === 0
      ? { name: 'scan_dotnet_secrets', status: 'ok' }
      : {
          name: 'scan_dotnet_secrets',
          status: scanned > 0 ? 'ok' : 'failed',
          reason: `${notScanned.length} file(s) not scanned: ${notScanned
            .slice(0, 5)
            .map((n) => `${n.file} (${n.reason})`)
            .join(', ')}${notScanned.length > 5 ? ` and ${notScanned.length - 5} more` : ''}`,
        };
  const tools_run = [toolRun];
  const missing_tools = notScanned.length > 0 ? ['scan_dotnet_secrets'] : [];
  ctx.storage.scans.finalize({
    scan_id: scanId,
    status: 'completed',
    tools_run,
    missing_tools,
    meta: { files_scanned: scanned, files_not_scanned: notScanned, findings_count: findings.length },
  });

  const parserOutput: ParserOutput = { findings: redacted, cves: [] };
  return {
    ok: true,
    scan_id: scanId,
    files_scanned: scanned,
    files_not_scanned: notScanned,
    coverage: computeCoverage(tools_run, missing_tools),
    tools_run,
    missing_tools,
    findings_count: findings.length,
    findings: parserOutput.findings,
  };
}

/** A config file larger than this is not read: named in `files_not_scanned`. */
const MAX_FILE_BYTES = 2_000_000;

function collectConfigFiles(root: string, maxDepth: number): string[] {
  const out: string[] = [];
  function walk(dir: string, depth: number): void {
    if (depth > maxDepth) return;
    // A directory link is never descended (`platform/projectFs.ts`); a linked
    // config file is kept, and its read judges where it leads.
    for (const { name, kind } of listProjectDir(root, dir)) {
      if (SKIP_DIRS.has(name)) continue;
      const abs = join(dir, name);
      if (kind === 'directory') {
        walk(abs, depth + 1);
      } else if ((kind === 'file' || kind === 'link') && TARGET_FILES.some((re) => re.test(name))) {
        out.push(abs);
      }
    }
  }
  walk(root, 0);
  return out;
}
