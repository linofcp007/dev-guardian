-- 003_finding_validations.sql
-- Verdicts produced by `validate_finding`.
--
-- Its own table, mirroring 002's reasoning: a verdict is a judgment ABOUT a
-- finding, not a finding. Putting it on `findings` would also mean a re-scan
-- that rewrites a findings row silently discards the judgment attached to it.
--
-- (project_path, fingerprint, provider) is the key: one verdict per provider
-- per finding, replaced when recomputed. tree_hash rides along so a reader can
-- tell a current verdict from one computed before the code moved.

CREATE TABLE IF NOT EXISTS finding_validations (
  project_path  TEXT NOT NULL,
  fingerprint   TEXT NOT NULL,
  provider      TEXT NOT NULL,
  verdict       TEXT NOT NULL,
  confidence    TEXT NOT NULL,
  evidence      TEXT NOT NULL,
  coverage_gaps TEXT NOT NULL,
  snapshot_id   INTEGER NOT NULL,
  tree_hash     TEXT NOT NULL,
  computed_at   TEXT NOT NULL,
  PRIMARY KEY (project_path, fingerprint, provider)
);

CREATE INDEX IF NOT EXISTS idx_validations_fingerprint
  ON finding_validations(fingerprint);
