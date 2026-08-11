-- 002_attack_surface.sql
-- Snapshots produced by `map_attack_surface`.
--
-- tree_hash is a column here rather than a row in `tree_cache` because
-- tree_cache declares FOREIGN KEY (scan_id) REFERENCES scans(id), and this
-- tool produces a snapshot, not a scan — reusing that table would mean
-- fabricating a scans row purely to satisfy the constraint.

CREATE TABLE IF NOT EXISTS surface_snapshots (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  project_path TEXT NOT NULL,
  captured_at  TEXT NOT NULL,
  tree_hash    TEXT NOT NULL,
  json         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_surface_captured_at
  ON surface_snapshots(captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_surface_tree_hash
  ON surface_snapshots(tree_hash);
