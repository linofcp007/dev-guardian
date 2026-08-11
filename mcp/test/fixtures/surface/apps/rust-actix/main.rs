use actix_web::{delete, get, patch, post, put, web, App, HttpResponse, HttpServer, Responder};

#[get("/rust/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().body("ok".to_string())
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

// ADVERSARIAL. A foreign attribute precedes the route one, so Semgrep's span
// starts at `#[allow(...)]`. Reconstruction from a redacted span cannot tell
// which attribute is the route, so actix routes are refused outright and NONE
// of the routes in this file appear on a redacting Semgrep. What must never
// happen is a route named `dead_code`, which is what anchoring on the first
// argument list produced.
#[allow(dead_code)]
#[get("/rust/gated")]
async fn gated() -> impl Responder {
    HttpResponse::Ok().finish()
}

// ADVERSARIAL. A commented-out old route above the live one — about as
// ordinary as source gets — plus apostrophes in the doc comment and a lifetime
// in the signature. Anchoring by name produced `/rust/legacy`; lexing strings
// lost the route. Neither is acceptable, so the family is refused.
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
