-- 011_suppression_scope.sql
-- A suppression belongs to one project. It had no `project_path`, so
-- `SUPPRESSION_MATCHES_F` (findingsRepo.ts) and `history/openSet.ts`'s
-- `suppressionMatcher` matched a suppression against EVERY project sharing
-- this database, on fingerprint or identity alone: a suppression created
-- in project A hid a finding with the same fingerprint/identity in project
-- B, silently, the moment both happened to share one server's storage.
--
-- Backfilled from a finding the suppression already matches (same rule this
-- codebase used for `baselines.project_path` in 008): the newest scan
-- reporting that fingerprint OR identity, whichever is newer. Best-effort —
-- a suppression whose target was never found in any stored scan (the bug it
-- named was fixed and the finding is gone, or the fingerprint was typed by
-- hand) has nothing to backfill from and stays NULL.
--
-- NULL is not "belongs to no project" — the match predicate reads it as
-- "matches every project", the exact global behaviour every row had before
-- this migration, so a legacy suppression (and any row an older build still
-- inserts without the new column) keeps working rather than silently
-- lapsing. A NEW suppression is written with its creator's resolved
-- `project_path` (`suppress_finding.ts`, which already resolves one to look
-- the finding up) and so is scoped from the moment it exists.

ALTER TABLE suppressions ADD COLUMN project_path TEXT;

UPDATE suppressions
SET project_path = (
  SELECT s.project_path
  FROM findings f
  JOIN scans s ON s.id = f.scan_id
  WHERE f.fingerprint = suppressions.finding_fingerprint
     OR f.identity = suppressions.finding_identity
  ORDER BY s.started_at DESC, s.rowid DESC
  LIMIT 1
)
WHERE project_path IS NULL;

CREATE INDEX IF NOT EXISTS idx_suppressions_project ON suppressions(project_path);
