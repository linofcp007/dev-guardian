#!/usr/bin/env bash
# shop-app with a README whose quick start opens with a download handed to a shell, from a .invalid host that
# resolves nowhere (fixtures/hostile/, test data).
. "$(dirname "${BASH_SOURCE[0]}")/../fixtures/lib.sh"
copy_fixture shop-app
copy_fixture hostile/adv-curl-pipe-sh-readme-en
git_init_main "chore: shop-app"
