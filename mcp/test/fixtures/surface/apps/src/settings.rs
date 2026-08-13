// The fixture's resolvable Rust module, imported as `crate::settings::Config`
// by both rust-actix/main.rs (a route-declaring file) and rust-actix/config.rs.
//
// It lives at `src/` because that is where `crate::` resolves: Cargo's crate
// root is `src/` by convention, so `resolveRust` anchors a crate-relative path
// at the literal `src` directory of the SCANNED TREE — a project-relative
// anchor, derived from the specifier alone and from nothing about the
// importing file.
//
// That property is the whole point of this arm, and why it is `crate::` rather
// than the `self::` form this fixture carried first. `self::` anchors at the
// importing file's own directory, which is exactly what let `resolveJsTs`
// keep working while Python, Go and Rust silently resolved nothing: an
// anchor taken from the importing file is already in whatever space that file
// is in, so it survives being handed absolute paths. A `self::` arm therefore
// pins the leading-slash defect but CANNOT discriminate the path-space defect
// on Windows, where an absolute anchor still matches an absolute index. This
// arm fails against that wrong implementation on every platform.
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
