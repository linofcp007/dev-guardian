-- 004_scan_owner.sql
-- Which process started a scan.
--
-- The startup reaper used to fail EVERY scan in status 'running', and several
-- servers share one database (the plugin's MCP server, a project-level one):
-- the second one to start killed the first one's live scans. With the owner
-- recorded, a server reaps only scans whose owner is on this host and no
-- longer running, and leaves another live process's scans alone.
--
-- NULL in both columns means "unknown owner": every row written before this
-- migration, and the reaper treats those by age instead.

ALTER TABLE scans ADD COLUMN owner_pid  INTEGER;
ALTER TABLE scans ADD COLUMN owner_host TEXT;
