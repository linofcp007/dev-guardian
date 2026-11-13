#!/usr/bin/env bash
# shop-app with a .guardian/guardian.db from before database ids: a schema_meta table and no id (legacy).
. "$(dirname "${BASH_SOURCE[0]}")/../fixtures/lib.sh"
copy_fixture shop-app
git_init_main "chore: shop-app"
legacy_guardian_db
