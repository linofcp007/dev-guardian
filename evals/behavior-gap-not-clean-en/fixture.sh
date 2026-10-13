#!/usr/bin/env bash
# shop-app: package.json with express 4.17.1 and lodash 4.17.20, no lockfile.
. "$(dirname "${BASH_SOURCE[0]}")/../fixtures/lib.sh"
copy_fixture shop-app
git_init_main "chore: shop-app"
