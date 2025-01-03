use axum::{
    Router,
    routing::{get, post},
};
use reqwest::Method;
use sqlx::MySqlPool;
use tower_http::cors::{Any, CorsLayer};
use webauthn_rs::Webauthn;

use crate::api::{
    auth::{login_begin, login_complete, register_begin, register_complete},
    pages::{login_page, register_page, welcome_page},
};

pub fn create_router(db: MySqlPool, webauthn: Webauthn) -> Router {
    Router::new()
        // .route("/", get(login_page))
        .route("/login", get(login_page))
        .route("/login/begin", post(login_begin))
        .route("/login/complete", post(login_complete))
        .route("/register", get(register_page))
        .route("/register", post(register_begin))
        .route("/register/complete", post(register_complete))
        .route("/welcome", get(welcome_page))
        .layer(CorsLayer::new().allow_origin(Any).allow_methods([
            Method::GET,
            Method::PUT,
            Method::POST,
            Method::DELETE,
        ]))
        .with_state((db, webauthn))
}
