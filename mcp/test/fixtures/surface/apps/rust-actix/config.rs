// Fixture for guardian-import-rust's single (non-grouped) form
// (`use $MODULE::$SYMBOL;`), which main.rs and rocket.rs do not exercise —
// both only use the grouped brace form.
use crate::settings::Config;
use std::sync::Arc;

pub fn describe(config: &Config) -> Arc<str> {
    Arc::from(config.name.as_str())
}
