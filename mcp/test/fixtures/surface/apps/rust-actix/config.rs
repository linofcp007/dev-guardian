// Fixture for guardian-import-rust's single (non-grouped) form
// (`use $MODULE::$SYMBOL;`), alongside the grouped brace form main.rs and
// rocket.rs use for their framework imports.
//
// This file is imported by nothing and declares no route, so the edge it
// contributes leaves it: it reaches src/settings.rs without being reachable
// itself. That keeps the crate-relative resolution exercised from a
// NON-route file too, so the pinned edge list would notice a resolver that
// only ever worked from a file the route rules also matched.
use crate::settings::Config;
use std::sync::Arc;

pub fn describe(config: &Config) -> Arc<str> {
    Arc::from(config.name.as_str())
}
