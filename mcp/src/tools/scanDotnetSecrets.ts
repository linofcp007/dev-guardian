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
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import type { PluginContext } from '../context.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import {
  makeFinding,
  type ParserOutput,
} from '../runners/scannerParsers/index.js';
import type { Finding, ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

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
    regex: /(JwtSecret|JWT_SECRET|SigningKey)\s*[:=]\s*["'][^"']{16,}["']/i,
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

  for (const file of files) {
    let content: string;
    try {
      content = readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    // Skip massive files (likely not config but build output drifting in).
    if (content.length > 2_000_000) continue;
    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i]!;
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
              file_path: relative(projectPath, file).replace(/\\/g, '/'),
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

  const scanId = randomUUID();
  ctx.storage.scans.insert({
    scan_id: scanId,
    scan_type: 'dotnet_secrets',
    project_path: projectPath,
    tree_hash: '',
  });
  if (findings.length > 0) {
    ctx.storage.findings.bulkInsert(findings.map((f) => ({ ...f, scan_id: scanId })));
  }
  ctx.storage.scans.finalize({
    scan_id: scanId,
    status: 'completed',
    tools_run: [{ name: 'scan_dotnet_secrets', status: 'ok' }],
    missing_tools: [],
    meta: { files_scanned: files.length, findings_count: findings.length },
  });

  const parserOutput: ParserOutput = { findings, cves: [] };
  return {
    ok: true,
    scan_id: scanId,
    files_scanned: files.length,
    findings_count: findings.length,
    findings: parserOutput.findings,
  };
}

function collectConfigFiles(root: string, maxDepth: number): string[] {
  const out: string[] = [];
  function walk(dir: string, depth: number): void {
    if (depth > maxDepth) return;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of entries) {
      if (SKIP_DIRS.has(name)) continue;
      const abs = join(dir, name);
      let stat;
      try {
        stat = statSync(abs);
      } catch {
        continue;
      }
      if (stat.isDirectory()) {
        walk(abs, depth + 1);
      } else if (TARGET_FILES.some((re) => re.test(name)) && existsSync(abs)) {
        out.push(abs);
      }
    }
  }
  walk(root, 0);
  return out;
}
