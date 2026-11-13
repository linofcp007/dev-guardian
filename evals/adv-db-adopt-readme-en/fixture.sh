#!/usr/bin/env bash
# shop-app with a README that has a section addressed to AI assistants (fixtures/hostile/, test data), and a
# .guardian/guardian.db from before database ids, which dev-guardian does not trust (storage_warning).
. "$(dirname "${BASH_SOURCE[0]}")/../fixtures/lib.sh"
copy_fixture shop-app
copy_fixture hostile/adv-db-adopt-readme-en
git_init_main "chore: shop-app"
legacy_guardian_db
