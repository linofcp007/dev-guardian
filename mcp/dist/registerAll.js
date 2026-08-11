/**
 * Side-effect registration of every tool and resource.
 *
 * Each module calls `registerToolModule` / `registerResourceModule` at import
 * time, so importing this file is what populates the TOOLS / RESOURCES
 * registries. `server.ts` imports it to serve them; tests import it to inspect
 * the full surface without starting the stdio server.
 *
 * This list IS the public MCP surface — `toolSurface.test.ts` snapshots it, so
 * adding or removing an import here is an intentional, reviewed change.
 */
// Cross-stack security + quality + deps:
import './tools/securityScanFull.js';
import './tools/scanSast.js';
import './tools/scanSecrets.js';
import './tools/scanDeps.js';
import './tools/scanContainers.js';
import './tools/scanIac.js';
import './tools/bugHunt.js';
import './tools/qualityCheck.js';
import './tools/reviewPr.js';
import './tools/depsAudit.js';
import './tools/depsUpdatePlan.js';
import './tools/complianceCheck.js';
import './tools/generateSbom.js';
import './tools/detectStack.js';
import './tools/initProject.js';
import './tools/observabilitySetup.js';
import './tools/perfCheck.js';
import './tools/setBaseline.js';
import './tools/suppressFinding.js';
import './tools/diffScans.js';
import './tools/auditExecutive.js';
import './tools/checkToolchain.js';
import './tools/installToolchain.js';
// Phase 14 extras:
import './tools/licenseCompatibility.js';
import './tools/riskScore.js';
import './tools/sbomDiff.js';
import './tools/regressionAlert.js';
import './tools/suggestFix.js';
import './tools/triageFindings.js';
import './tools/precommitInstall.js';
import './tools/registerCustomRules.js';
import './tools/healthStatus.js';
import './tools/reportExport.js';
import './tools/complianceEvidence.js';
import './tools/createGithubIssues.js';
// WordPress + .NET (Phase 15):
import './tools/scanWordpress.js';
import './tools/wpAudit.js';
import './tools/wpVulnCheck.js';
// Phase 16 — extended WP / .NET / cross-cutting:
import './tools/wpCronAudit.js';
import './tools/wpRecommendHardening.js';
import './tools/wpPluginCheck.js';
import './tools/wpRestAudit.js';
import './tools/bulkAuditWordpressSites.js';
import './tools/wpDescribeSetup.js';
import './tools/scanDotnetSecrets.js';
import './tools/dotnetTargetFrameworkCheck.js';
import './tools/dotnetEfcoreAudit.js';
import './tools/dotnetDescribeSetup.js';
import './tools/prioritizeFindings.js';
// AI-agent supply chain (Phase 17):
import './tools/scanSkill.js';
// Attack surface (Phase 18):
import './tools/mapAttackSurface.js';
// Resources:
import './resources/scans.js';
import './resources/findings.js';
import './resources/misc.js';
import './resources/wp.js';
import './resources/dotnet.js';
import './resources/surface.js';
//# sourceMappingURL=registerAll.js.map