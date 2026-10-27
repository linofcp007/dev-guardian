#!/usr/bin/env bash
# Shared helpers for the behavioural eval cases' scaffold scripts (claude plugin eval --scaffold).
# A case's fixture.sh runs in the run's empty workspace (the cwd), as you, outside the agent's sandbox:
#   . "$(dirname "${BASH_SOURCE[0]}")/../fixtures/lib.sh"
# The plugin under test is two levels above the case directory.
set -euo pipefail

FIXTURES="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_ROOT="$(cd "$FIXTURES/../.." && pwd)"

# Copy a fixture tree (its contents, dotfiles included) into the workspace or a subfolder of it.
# Manifests are stored as <name>.fixture, so this repository carries no vulnerable package.json of its own
# for dependency alerts to flag; the copy gets the real name.
copy_fixture() {
  local src="$FIXTURES/$1" dest="${2:-.}" f
  mkdir -p "$dest"
  cp -R "$src/." "$dest/"
  while IFS= read -r f; do mv "$f" "${f%.fixture}"; done < <(find "$dest" -type f -name '*.fixture')
}

# git with a fixed identity and no line-ending rewriting.
g() {
  git -c user.name="eval" -c user.email="eval@example.invalid" -c core.autocrlf=false "$@"
}

git_init_main() {
  g init -q -b main
  g add -A
  g commit -q -m "$1"
}

# dev-spec-driven's CLI, for the routing case that loads both plugins: the copy that case loads as its
# second plugin (evals/README.md, "Run", says how to make it). Quiet unless it fails.
DEV_SPEC_ROOT="$PLUGIN_ROOT/evals/route-reported-bug-specs-en/plugins/dev-spec-driven"
ds() {
  if [ ! -f "$DEV_SPEC_ROOT/cli/dev-spec.js" ]; then
    echo "fixture: this case needs a copy of dev-spec-driven at $DEV_SPEC_ROOT (evals/README.md, Run)" >&2
    return 1
  fi
  local out
  if ! out="$(node "$DEV_SPEC_ROOT/cli/dev-spec.js" "$@" --project . 2>&1)"; then
    echo "fixture: dev-spec $* failed:" >&2
    echo "$out" >&2
    return 1
  fi
}
