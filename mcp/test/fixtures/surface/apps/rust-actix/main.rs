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

// A non-route attribute PRECEDING the route one. Semgrep's span for this match
// starts at `#[allow(...)]`, so recovery that anchors on the first argument
// list in the span reads `dead_code` as the path — and `dead_code` passes the
// literal test, so it is emitted as a RESOLVED route. The capture has to be
// anchored on `#[<verb>(` by name. Not registered below, hence the allow.
#[allow(dead_code)]
#[get("/rust/gated")]
async fn gated() -> impl Responder {
    HttpResponse::Ok().finish()
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
