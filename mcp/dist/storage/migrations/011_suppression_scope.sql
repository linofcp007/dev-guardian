-- 011_suppression_scope.sql
-- A suppression belongs to one project. It had no `project_path`, so
-- `SUPPRESSION_MATCHES_F` (findingsRepo.ts) and `history/openSet.ts`'s
-- `suppressionMatcher` matched a suppression against EVERY project sharing
-- this database, on fingerprint or identity alone: a suppression created
-- in project A hid a finding with the same fingerprint/identity in project
-- B, silently, the moment both happened to share one server's storage.
--
-- Backfilled from every COMPLETED, non-worktree scan that reports a finding
-- matching this suppression (same rule this codebase used for
-- `baselines.project_path` in 008), and only when they all agree on exactly
-- ONE project. Two things a first cut of this migration got wrong, both
-- reproduced live:
--
--   - It picked "the newest scan reporting the fingerprint", with no
--     `status = 'completed'` filter and no exclusion of `create_fix_pr`'s
--     disposable worktrees. Fingerprints are project-relative, and
--     `create_fix_pr` re-runs a scanner inside such a worktree
--     (`%guardian-fixpr-wt-%` — `findingsRepo.ts`'s own
--     `WORKTREE_PATH_EXCLUSION`, inlined here for the same reason it is
--     there: migrations are SQL only, no JS imports) to verify a fix. A
--     single `create_fix_pr` call on a project with a legacy suppression
--     produced a newer scan of the SAME fingerprint in a directory that no
--     longer exists by the time this migration runs — every such
--     suppression was backfilled to a deleted temp directory, and the
--     finding it named reappeared as open in the real project.
--   - "Newest" also silently resolved an AMBIGUOUS case — two genuinely
--     different real projects both reporting the fingerprint (a `git clone`
--     of the project, or coincidentally identical relative paths in an
--     unrelated one) — by picking whichever happened to scan last, which is
--     exactly the wrong-project attachment this migration exists to avoid,
--     just with a real project on both ends instead of a deleted one.
--
-- `COUNT(DISTINCT project_path)` over the candidates answers both at once:
-- multiple scans of the SAME project collapse to one candidate (no false
-- ambiguity), and a genuine second project makes the count 2, which resolves
-- to NULL rather than guessing. A suppression whose target is in no
-- candidate scan at all (fixed and gone, or hand-typed) also lands on
-- COUNT = 0 and stays NULL.
--
-- NULL is not "belongs to no project" — the match predicate reads it as
-- "matches every project", the exact global behaviour every row had before
-- this migration, so a legacy suppression (and any row an older build still
-- inserts without the new column) keeps working rather than silently
-- lapsing, whether NULL because nothing matched or because too much did. A
-- NEW suppression is written with its creator's resolved `project_path`
-- (`suppress_finding.ts`, which already resolves one to look the finding
-- up) and so is scoped from the moment it exists.

ALTER TABLE suppressions ADD COLUMN project_path TEXT;

UPDATE suppressions
SET project_path = (
  SELECT CASE WHEN COUNT(DISTINCT s.project_path) = 1 THEN MAX(s.project_path) ELSE NULL END
  FROM findings f
  JOIN scans s ON s.id = f.scan_id
  WHERE s.status = 'completed'
    AND s.project_path NOT LIKE '%guardian-fixpr-wt-%'
    AND (f.fingerprint = suppressions.finding_fingerprint
         OR f.identity = suppressions.finding_identity)
)
WHERE project_path IS NULL;

CREATE INDEX IF NOT EXISTS idx_suppressions_project ON suppressions(project_path);
