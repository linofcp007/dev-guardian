-- 015_stack_snapshot_project.sql
-- Every reader of stack_snapshots asks for ONE project's newest row
-- (`stackRepo.ts#getLatestForProject`: guardian://stack, bug_hunt,
-- audit_executive, init_project, map_attack_surface, observability_setup),
-- and the table had no index on project_path: each lookup scanned every
-- detect_stack row ever written, of every project, and sorted them. The
-- table is also kept to the newest few rows per project now
-- (`STACK_SNAPSHOTS_KEPT`), which prunes by the same key.
--
-- Additive: an older build sharing the file never reads the index.

CREATE INDEX IF NOT EXISTS idx_stack_project ON stack_snapshots(project_path, captured_at);
