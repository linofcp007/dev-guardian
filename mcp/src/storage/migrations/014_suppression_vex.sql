-- 014_suppression_vex.sql
-- VEX: a suppression can state that the product is not affected by a
-- vulnerability, and a finding records which vulnerability ids are its own.
--
-- suppressions — `suppress_finding` with vex_status 'not_affected' records,
-- in OpenVEX's own vocabulary, why the product is not affected by the
-- vulnerability the suppressed finding is about — `export_vex` publishes it
-- as a `not_affected` statement.
--
--   vex_status           'not_affected', or NULL for an ordinary suppression
--   vex_justification    one of OpenVEX's five justification labels
--                        (component_not_present, vulnerable_code_not_present,
--                        vulnerable_code_not_in_execute_path,
--                        vulnerable_code_cannot_be_controlled_by_adversary,
--                        inline_mitigations_already_exist); required with a
--                        status, enforced by suppress_finding
--   vex_impact_statement optional free text
--
-- findings.vuln_aliases — a JSON array of the other ids the SCANNER gives
-- for the finding's vulnerability (Trivy VendorIDs, pip-audit's OSV aliases,
-- npm audit's GHSA and CVE ids, WPScan's further CVEs). With the rule id,
-- these are the only ids that tie a finding to a vulnerability
-- (`intel/vulnIds.ts`); an id its description merely mentions never does.
-- Not part of the fingerprint or the identity.
--
-- Additive and nullable. Every existing suppression reads NULL, i.e. a plain
-- "false positive" that states nothing in VEX terms — never not_affected.
-- Every existing finding reads no aliases: it is tied by its rule id alone
-- until the next scan records them. An older build sharing the file inserts
-- without these columns and gets the same NULLs.

ALTER TABLE suppressions ADD COLUMN vex_status TEXT;
ALTER TABLE suppressions ADD COLUMN vex_justification TEXT;
ALTER TABLE suppressions ADD COLUMN vex_impact_statement TEXT;

ALTER TABLE findings ADD COLUMN vuln_aliases TEXT;
