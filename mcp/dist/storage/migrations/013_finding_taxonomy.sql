-- 013_finding_taxonomy.sql
-- A finding's weakness taxonomy: its CWE ids and its OWASP Top 10:2025
-- categories, each a JSON array of strings (`["CWE-79","CWE-89"]`,
-- `["A05:2025"]`). See src/frameworks/taxonomy.ts.
--
-- Annotations, not identity: neither column is part of `fingerprint` or
-- `identity`, so a scanner that starts reporting a CWE never makes an
-- existing finding look new, and suppressions and baselines keep matching.
--
-- NULL on every row written before this migration, and nothing is
-- backfilled — the scanner output those rows came from is gone. NULL reads
-- as UNKNOWN (the field is absent on the Finding), never as "no category":
-- renderers count such a finding as unmapped and never file it under an
-- OWASP category or claim a category clean because of it.

ALTER TABLE findings ADD COLUMN cwe TEXT;
ALTER TABLE findings ADD COLUMN owasp TEXT;
