#!/usr/bin/env bash
# shop-app on main, clean tree, no scans yet.
. "$(dirname "${BASH_SOURCE[0]}")/../fixtures/lib.sh"
copy_fixture shop-app
git_init_main "chore: shop-app"
