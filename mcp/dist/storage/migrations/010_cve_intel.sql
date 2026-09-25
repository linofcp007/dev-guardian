-- 010_cve_intel.sql
-- A 24h-refresh cache of CISA KEV membership and FIRST EPSS score per CVE.
--
-- Keyed by cve_id ALONE, never by scan or project: KEV listing and EPSS
-- score are properties of the CVE itself, not of any one scan that happened
-- to see it, so one row answers for every project's open findings that
-- mention it. No FOREIGN KEY on scans(id) and no scan_id column at all —
-- same reasoning `storage/maintenance.ts`'s own header already gives for
-- `agent_config_hashes` and `surface_snapshots`: this is CURRENT STATE keyed
-- by the CVE, not scan history, so it must survive scan retention pruning a
-- project's old deps/security_full scans, and `deleteScans` needs no entry
-- for it.
--
-- `kev` is 0/1 rather than a second table: CISA's feed is small (~1-2k
-- entries as of 2026) and membership is a single boolean per CVE, not a
-- history worth its own rows. `epss_score`/`epss_percentile` are nullable
-- REAL — NULL means "asked FIRST, got no score for this CVE" (new/reserved
-- CVE ids are legitimately unscored), never "never asked": that distinction
-- lives in `fetched_at` being set at all. A row only exists here once at
-- least one fetch attempt for that CVE succeeded; a CVE whose every fetch
-- attempt failed has NO row, so a caller reading `getMany` back gets a
-- genuine cache miss for it rather than a fabricated all-null/all-false one
-- (`intel/enrich.ts` reports that as `status: 'unavailable'`, never as
-- `kev: false`).

CREATE TABLE IF NOT EXISTS cve_intel (
  cve_id           TEXT PRIMARY KEY,
  epss_score       REAL,
  epss_percentile  REAL,
  kev              INTEGER NOT NULL DEFAULT 0,
  kev_date_added   TEXT,
  fetched_at       TEXT NOT NULL
);
