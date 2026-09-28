-- 014_suppression_vex.sql
-- A suppression can also be a VEX statement: `suppress_finding` with
-- vex_status 'not_affected' records, in OpenVEX's own vocabulary, why the
-- product is not affected by the CVE the suppressed finding names —
-- `export_vex` publishes it as a `not_affected` statement.
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
-- Additive and nullable: every existing suppression reads NULL, i.e. a plain
-- "false positive" that states nothing in VEX terms — never not_affected. An
-- older build sharing the file inserts without these columns and gets the
-- same NULLs.

ALTER TABLE suppressions ADD COLUMN vex_status TEXT;
ALTER TABLE suppressions ADD COLUMN vex_justification TEXT;
ALTER TABLE suppressions ADD COLUMN vex_impact_statement TEXT;
