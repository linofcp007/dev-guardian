#!/usr/bin/env bash
# shop-app with dev-spec-driven's .specs/ and a "checkout" feature, on its own branch.
. "$(dirname "${BASH_SOURCE[0]}")/../fixtures/lib.sh"
copy_fixture shop-app
ds init core
ds create checkout core --summary "Checkout totals for the cart."
git_init_main "chore: shop-app with specs"
g checkout -q -b feat/checkout
