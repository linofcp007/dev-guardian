-- 016_baseline_slot.sql
-- A baseline belongs to one project, one scan type — and, for an imported
-- SARIF log, one source tool.
--
-- Migration 008 scoped a baseline to (project, scan type). Every import is
-- one scan type (`sarif_import`), so one baseline per type would mix the
-- tools: a baseline set from CodeQL's import would be replaced by Snyk's.
-- `slot` names the open-set slot of the baseline's scan (`sarif_import:<tool>`,
-- history/scanRoles.ts#sarifSlot); NULL for every other scan type, which keep
-- exactly their per-(project, type) baseline.
--
-- Additive: an older build sharing the file never reads or writes the column,
-- and a row it inserts leaves it NULL.

ALTER TABLE baselines ADD COLUMN slot TEXT;
