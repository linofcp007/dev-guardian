use actix_web::{get, post, put, patch, delete, web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use crate::models::user::User;
use std::collections::HashMap as Map;
pub use crate::config::Settings;

// R01 control: async fn, no visibility modifier
#[get("/rust/health")]
async fn health() -> impl Responder { HttpResponse::Ok().finish() }

// R02 pub async fn — the common form in a routes module
#[post("/rust/items")]
pub async fn create_item() -> impl Responder { HttpResponse::Created().finish() }

// R03 fully-qualified attribute path
#[actix_web::get("/rust/qualified")]
async fn qualified() -> impl Responder { HttpResponse::Ok().finish() }

// R04 attribute with a guard argument (multi-arg)
#[get("/rust/guarded", wrap = "Auth")]
async fn guarded() -> impl Responder { HttpResponse::Ok().finish() }

// R05 non-macro registration — actix's other, equally common style
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/rust/manual").route(web::get().to(health)));
    cfg.route("/rust/routed", web::post().to(create_item));
}

// R06 put/patch/delete with generic fn signature
#[put("/rust/items/{id}")]
async fn replace(path: web::Path<String>) -> impl Responder { HttpResponse::Ok().finish() }

#[patch("/rust/items/{id}/status")]
async fn status(path: web::Path<String>) -> impl Responder { HttpResponse::Ok().finish() }

#[delete("/rust/items/{id}")]
async fn remove(path: web::Path<String>) -> impl Responder { HttpResponse::Ok().finish() }
