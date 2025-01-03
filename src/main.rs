#![allow(dead_code, unused)]

use api::{
    auth::*,
    login_begin, login_complete,
    pages::{login_page, register_page, welcome_page},
    register_begin, register_complete,
    routes::create_router,
};

use askama::Template;
use config::{connect_db, tracing::set_up_tracing, web_authn::create_webauthn};
use reqwest::{Method, StatusCode, Url};
use serde::Serialize;
use sqlx::MySqlPool;
use std::net::SocketAddr;
use tokio::net::TcpListener;

use tower_http::cors::{Any, CorsLayer};
use webauthn_rs::{
    Webauthn, WebauthnBuilder,
    prelude::{CreationChallengeResponse, Passkey, PasskeyRegistration},
};

use axum::{
    Json, Router,
    extract::State,
    http::request::Builder,
    response::{Html, IntoResponse},
    routing::{get, post},
};
use serde_json::json;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api;
mod config;
mod models;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is not set");

    set_up_tracing();

    let db = connect_db(&db_url).await;
    tracing::info!("Connected to database");

    let app = create_router(db, create_webauthn());

    let host = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = TcpListener::bind(host)
        .await
        .expect("Failed to bind to port");

    println!("Listening on http://{}", listener.local_addr().unwrap());

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("Failed to serve");
}
