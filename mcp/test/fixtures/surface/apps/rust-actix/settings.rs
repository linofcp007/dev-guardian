// The only intra-project Rust module in this fixture that can resolve,
// imported by rust-actix/main.rs as `use self::settings::Config;`.
//
// `self::` anchors at the importing file's own directory, which is what makes
// it resolvable here. config.rs's `use crate::settings::Config;` deliberately
// stays UNresolvable: `crate::` anchors at the crate root (`src/` by Cargo
// convention) and this multi-app fixture tree has no top-level `src/`, so that
// import keeps exercising the unresolved-and-reported path.
//
// Adding, removing or renaming this file changes the pinned import-edge list
// in mcp/test/e2e/rulePackFixture.test.ts and the Rust reachability verdict in
// mcp/test/e2e/validateFindingFixture.test.ts.

pub struct Config {
    pub name: String,
}

impl Config {
    pub fn new() -> Self {
        Self { name: "actix-fixture".to_string() }
    }
}
