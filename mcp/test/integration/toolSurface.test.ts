/**
 * Stability snapshot of the public MCP surface.
 *
 * The exact set of tools and resources is part of dev-guardian's contract.
 * Adding or removing one is an intentional, reviewed change: update the lists
 * below AND the counts in the README. Accidental surface drift fails here.
 */

import { beforeAll, describe, expect, it } from 'vitest';

import { RESOURCES } from '../../src/resources/index.js';
import { TOOLS } from '../../src/tools/index.js';

beforeAll(async () => {
  await import('../../src/registerAll.js');
});

const EXPECTED_TOOLS = [
  'audit_agent_config',
  'audit_executive',
  'audit_mcp_tools',
  'bug_hunt',
  'bulk_audit_wordpress_sites',
  'check_toolchain',
  'compliance_check',
  'compliance_evidence',
  'create_fix_pr',
  'create_github_issues',
  'deps_audit',
  'deps_update_plan',
  'detect_stack',
  'diff_scans',
  'dotnet_describe_setup',
  'dotnet_efcore_audit',
  'dotnet_target_framework_check',
  'export_vex',
  'generate_sbom',
  'health_status',
  // sarif-import (test plan T-23).
  'import_sarif',
  'init_project',
  'install_toolchain',
  'license_compatibility',
  'llm_scan_start',
  'llm_scan_submit',
  'llm_scan_task',
  'map_attack_surface',
  'observability_setup',
  'perf_check',
  'precommit_install',
  'prioritize_findings',
  'quality_check',
  'register_custom_rules',
  'regression_alert',
  'report_export',
  'review_pr',
  'risk_score',
  'sbom_diff',
  'scan_containers',
  'scan_dast',
  'scan_deps',
  'scan_dotnet_secrets',
  'scan_iac',
  'scan_sast',
  'scan_secrets',
  'scan_skill',
  'scan_wordpress',
  'security_scan_full',
  'set_baseline',
  'suggest_fix',
  'suppress_finding',
  'triage_findings',
  'validate_finding',
  'vet_packages',
  'wp_audit',
  'wp_cron_audit',
  'wp_describe_setup',
  'wp_plugin_check',
  'wp_recommend_hardening',
  'wp_rest_audit',
  'wp_vuln_check',
  'wp_vuln_check_source',
];

const EXPECTED_RESOURCES = [
  'guardian-baseline',
  'guardian-compliance-status',
  'guardian-cves-active',
  'guardian-dotnet-efcore',
  'guardian-dotnet-target-frameworks',
  'guardian-findings-by-severity',
  'guardian-findings-critical',
  'guardian-findings-open',
  'guardian-sbom',
  'guardian-scans-by-id',
  'guardian-scans-history',
  'guardian-scans-latest',
  'guardian-stack',
  'guardian-surface-by-id',
  'guardian-surface-latest',
  'guardian-wp-audit-by-id',
  'guardian-wp-audit-latest',
  'guardian-wp-cron',
];

describe('MCP surface — stability snapshot', () => {
  it('T-23 exposes exactly the snapshotted tools (import_sarif included)', () => {
    expect(TOOLS.map((t) => t.name).sort()).toEqual(EXPECTED_TOOLS);
  });

  it('exposes exactly the snapshotted resources', () => {
    expect(RESOURCES.map((r) => r.name).sort()).toEqual(EXPECTED_RESOURCES);
  });

  it('T-23 matches the counts documented in the README (63 tools, 18 resources)', () => {
    expect(TOOLS).toHaveLength(63);
    expect(RESOURCES).toHaveLength(18);
  });
});
