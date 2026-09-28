-- 006_cache_key.sql
-- What a cached result was computed FROM.
--
-- Both caches were keyed by the tree hash alone (scans: plus the scan type),
-- so a call with other inputs, another project whose tree hashed the same,
-- another tool sharing the scan type, an edited rule pack or a new plugin
-- version was answered with a result that did not describe it. `cache_key`
-- is a hash of everything that shapes the run (see src/treeHash/cacheKey.ts);
-- a lookup matches it exactly.
--
-- NULL on every row written before this migration, and a NULL key never
-- matches: those rows stay in history and are never served from the cache,
-- because nothing records which inputs produced them.

ALTER TABLE scans ADD COLUMN cache_key TEXT;
CREATE INDEX IF NOT EXISTS idx_scans_cache_key ON scans(cache_key);

ALTER TABLE surface_snapshots ADD COLUMN cache_key TEXT;
CREATE INDEX IF NOT EXISTS idx_surface_cache_key ON surface_snapshots(cache_key);
