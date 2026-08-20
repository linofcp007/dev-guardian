use axum::{routing::get, routing::post, Router};
use rocket::{get as rget, routes};

// R10 axum — the dominant modern Rust web framework, macro-free
pub fn app() -> Router {
    Router::new()
        .route("/axum/health", get(health))
        .route("/axum/items", post(create))
        .nest("/axum/api", sub())
}

async fn health() {}
async fn create() {}
fn sub() -> Router { Router::new() }

// R11 rocket with data argument (documented gap)
#[rocket::post("/rocket/items", data = "<body>")]
fn rocket_create(body: String) -> &'static str { "ok" }

// R12 rocket plain
#[rocket::get("/rocket/health")]
fn rocket_health() -> &'static str { "ok" }
