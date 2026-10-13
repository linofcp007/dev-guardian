#!/usr/bin/env bash
# shop-app with a .guardian/guardian.db from before database ids: a schema_meta table and no id (legacy).
. "$(dirname "${BASH_SOURCE[0]}")/../fixtures/lib.sh"
copy_fixture shop-app
git_init_main "chore: shop-app"
mkdir -p .guardian
node -e "const { DatabaseSync } = require('node:sqlite'); const db = new DatabaseSync('.guardian/guardian.db'); db.exec('CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT)'); db.close();"
