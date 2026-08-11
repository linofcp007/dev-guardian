//! KNOWN LIMITATION, pinned deliberately: Rocket's multi-argument route
//! attributes are NOT matched by `guardian-route-rust-actix`, so neither
//! function below appears in the E2E route set.
//!
//! Measured on Semgrep 1.164.0 and 1.86.0: `#[$METHOD($PATH, ...)] fn $F(...)
//! { ... }` reports zero matches for both forms, and so does the explicit
//! two-metavariable `#[$METHOD($PATH, $EXTRA)]`. Only a bare `#[$METHOD(...)]`
//! matches them, and that binds no $PATH at all — it would hand the extractor
//! a route whose path we never read.
//!
//! If a future Semgrep starts matching these, the E2E route set changes and the
//! limitation note in `configs/semgrep/routes.yml` needs deleting.

use rocket::{get, post};

#[post("/rocket/items", data = "<body>")]
async fn create(body: String) -> String {
    body
}

#[get("/rocket/ranked", rank = 2)]
async fn ranked() -> String {
    String::new()
}
