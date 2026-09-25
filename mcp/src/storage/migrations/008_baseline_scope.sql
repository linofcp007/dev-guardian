-- 008_baseline_scope.sql
-- A baseline belongs to one project and one scan type.
--
-- `baselines` had neither, so "the active baseline" was the newest row in the
-- whole database: `guardian://baseline`, `diff_scans from:'baseline'` and
-- `regression_alert` all answered with another project's baseline whenever
-- that project had set one more recently, and compared a SAST scan against a
-- secrets baseline without noticing.
--
-- Both columns are copied from the baseline's scan. A row an older build
-- inserts later (it knows neither column) stays NULL here; readers fall back
-- to the scan's own project_path / scan_type for such a row
-- (BaselinesRepo, COALESCE over a join), so it is never invisible.
--
-- idx_scans_project_type serves every project- and type-scoped "latest scan"
-- query (ScansRepo.listCompletedOfTypes), which replaced searching a window of
-- the 50 newest scans in the whole database.

ALTER TABLE baselines ADD COLUMN project_path TEXT;
ALTER TABLE baselines ADD COLUMN scan_type TEXT;

UPDATE baselines
SET project_path = (SELECT s.project_path FROM scans s WHERE s.id = baselines.scan_id),
    scan_type    = (SELECT s.scan_type    FROM scans s WHERE s.id = baselines.scan_id)
WHERE project_path IS NULL OR scan_type IS NULL;

CREATE INDEX IF NOT EXISTS idx_baselines_project ON baselines(project_path, scan_type);
CREATE INDEX IF NOT EXISTS idx_scans_project_type ON scans(project_path, scan_type, started_at DESC);
