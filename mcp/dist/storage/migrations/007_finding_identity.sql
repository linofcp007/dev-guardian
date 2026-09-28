-- 007_finding_identity.sql
-- A finding's line-independent identity.
--
-- `fingerprint` hashes the line range, so inserting one line above a finding
-- made it a new finding to every cross-scan consumer: suppressions lapsed,
-- diffs reported new + resolved, create_fix_pr called an unfixed target
-- resolved. `identity` is sha256(tool | rule | path | content | occurrence)
-- (see src/fingerprint/findingIdentity.ts); `content_key` is the content part
-- alone — a hash, never the source text — which create_fix_pr's verification
-- compares by.
--
-- NULL on every row written before this migration. Nothing is backfilled:
-- the source text those rows were computed from is gone. Consumers match on
-- identity first and fall back to the fingerprint wherever either side is
-- NULL, so old rows compare exactly as they did.
--
-- A suppression records the identity of the finding it names too, and hides
-- a finding that matches it on EITHER key. A suppression written before this
-- migration has none; the first scan that reports its fingerprint again
-- fills it in (SuppressionsRepo.adoptIdentities), after which it survives
-- line shifts like a new one.

ALTER TABLE findings ADD COLUMN identity TEXT;
ALTER TABLE findings ADD COLUMN content_key TEXT;
CREATE INDEX IF NOT EXISTS idx_findings_identity ON findings(identity);

ALTER TABLE suppressions ADD COLUMN finding_identity TEXT;
CREATE INDEX IF NOT EXISTS idx_suppressions_identity ON suppressions(finding_identity);
