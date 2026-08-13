use actix_web::{delete, get, patch, post, put, web, App, HttpResponse, HttpServer, Responder};

// The fixture's resolvable intra-project Rust import, and the dominant
// real-world shape. `crate::` anchors at the crate root (`src/` by Cargo
// convention) — a PROJECT-RELATIVE anchor derived from the specifier alone,
// which is what makes this arm discriminate a resolver fed absolute paths.
// See src/settings.rs.
use crate::settings::Config;

#[get("/rust/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().body(Config::new().name)
}

#[post("/rust/items")]
async fn create_item(item: web::Json<String>) -> impl Responder {
    HttpResponse::Created().json(item.into_inner())
}

#[put("/rust/items/{id}")]
async fn replace_item(path: web::Path<u32>) -> impl Responder {
    HttpResponse::Ok().json(path.into_inner())
}

#[patch("/rust/items/{id}/status")]
#[allow(clippy::unused_async)]
async fn patch_item(path: web::Path<u32>) -> impl Responder {
    HttpResponse::Ok().json(path.into_inner())
}

#[delete("/rust/items/{id}")]
async fn delete_item(path: web::Path<u32>) -> impl Responder {
    let _id = path.into_inner();
    HttpResponse::NoContent().finish()
}

// ADVERSARIAL. A foreign attribute precedes the route one, so the span of an
// unfocused rule would start at `#[allow(...)]` — and anchoring on the first
// argument list in it produced a route named `dead_code`. The rule focuses on
// $PATH, so Semgrep reports the path literal itself and `/rust/gated` is what
// comes back. `dead_code` must never appear.
#[allow(dead_code)]
#[get("/rust/gated")]
async fn gated() -> impl Responder {
    HttpResponse::Ok().finish()
}

// ADVERSARIAL. A commented-out old route above the live one — about as
// ordinary as source gets — plus apostrophes in the doc comment and a lifetime
// in the signature. Anchoring by name produced `/rust/legacy`; lexing strings
// lost the route. Focusing on $PATH answers neither question: Semgrep's own
// parser decides what the attribute is, and reports only the path.
#[allow(dead_code)]
/// Don't call this directly; it's the router's job.
// #[get("/rust/legacy")]
#[get("/rust/documented")]
async fn documented(name: &'static str) -> impl Responder {
    HttpResponse::Ok().body(name)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(health)
            .service(create_item)
            .service(replace_item)
            .service(patch_item)
            .service(delete_item)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
