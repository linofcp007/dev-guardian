-- 005_scan_cves.sql
-- Which CVEs each scan saw: one row per (scan, CVE, package, installed version).
--
-- Replaces reading `cves`, whose shape lost data in two ways (both reproduced):
--   * its key (cve_id, package_name, installed_version) never conflicts when
--     installed_version is NULL — NULLs are never equal in SQL — so every scan
--     of a package with no known version added one more duplicate row;
--   * it kept ONE global last_seen_scan_id per CVE, which the next scan of ANY
--     project (or a create_fix_pr verification worktree) overwrote, so
--     listActive(scanA) silently lost every CVE scanA shared with a later scan.
-- An unknown installed version is stored as '' so it takes part in the key.
--
-- `cves` itself stays, and is no longer written: dropping it would break an
-- older build that still shares this database file. Its rows are copied here
-- first. Each legacy row is evidence that BOTH its first- and its last-seen
-- scan saw that CVE, so both associations are carried over; last-seen first,
-- so where they collide the most recent severity/fix wins. Rows whose scan no
-- longer exists are skipped rather than violating the foreign key.

CREATE TABLE IF NOT EXISTS scan_cves (
  scan_id           TEXT NOT NULL,
  cve_id            TEXT NOT NULL,
  package_name      TEXT NOT NULL,
  installed_version TEXT NOT NULL DEFAULT '',
  fixed_version     TEXT,
  severity          TEXT NOT NULL,
  PRIMARY KEY (scan_id, cve_id, package_name, installed_version),
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- first/last-seen lookups search by CVE identity across a project's scans.
CREATE INDEX IF NOT EXISTS idx_scan_cves_identity
  ON scan_cves(cve_id, package_name, installed_version);

INSERT OR IGNORE INTO scan_cves
  (scan_id, cve_id, package_name, installed_version, fixed_version, severity)
SELECT last_seen_scan_id, cve_id, package_name, COALESCE(installed_version, ''),
       fixed_version, severity
FROM cves
WHERE last_seen_scan_id IN (SELECT id FROM scans);

INSERT OR IGNORE INTO scan_cves
  (scan_id, cve_id, package_name, installed_version, fixed_version, severity)
SELECT first_seen_scan_id, cve_id, package_name, COALESCE(installed_version, ''),
       fixed_version, severity
FROM cves
WHERE first_seen_scan_id IN (SELECT id FROM scans);

-- Retention (storage/maintenance.ts) deletes a scan together with every row
-- that points at it. These three referencing columns had no index, so each
-- deleted scan cost a full scan of `cves` (twice) and of `tree_cache`, once
-- for the explicit delete and again for SQLite's own foreign-key check.
-- Measured before: 21.5 s, under one write lock, to prune 2950 scans over
-- 60k legacy CVE rows.
CREATE INDEX IF NOT EXISTS idx_cves_first_seen_scan_id ON cves(first_seen_scan_id);
CREATE INDEX IF NOT EXISTS idx_cves_last_seen_scan_id  ON cves(last_seen_scan_id);
CREATE INDEX IF NOT EXISTS idx_tree_cache_scan_id      ON tree_cache(scan_id);
