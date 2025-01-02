#![allow(dead_code, unused)]

use askama::Template;
use models::{
    model::{LoginTemplate, RegisterCompleteRequest, RegisterTemplate},
    CreateAccountRequest,
};
use reqwest::Url;
use sqlx::MySqlPool;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use webauthn_rs::{
    prelude::{CreationChallengeResponse, PasskeyRegistration},
    Webauthn, WebauthnBuilder,
};

use axum::{
    extract::State,
    http::request::Builder,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod models;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=info", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is not set");
    let db = sqlx::mysql::MySqlPool::connect(&db_url)
        .await
        .expect("Failed to connect to database");

    tracing::info!("Connected to database");
    let webauthn = create_webauthn();

    let app = Router::new()
        .route("/login", get(login_page))
        // .route("/login/begin", post(login_begin))
        // .route("/login", post(login_complete))
        .route("/register", get(register_page))
        .route("/register", post(register_begin))
        .route("/register/complete", post(register_complete))
        .with_state((db, webauthn));

    let host = SocketAddr::from(([127, 0, 0, 1], 3000));
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

async fn login_page() -> impl IntoResponse {
    Html(LoginTemplate {}.render().unwrap())
}

async fn register_page() -> impl IntoResponse {
    Html(RegisterTemplate {}.render().unwrap())
}

pub fn create_webauthn() -> Webauthn {
    let rp_id = "localhost".to_string();
    let rp_origin = Url::parse("http://localhost:3000").unwrap();
    let builder = WebauthnBuilder::new(&rp_id, &rp_origin).unwrap();
    builder.build().unwrap()
}

// async fn login_begin() -> impl IntoResponse {
//     todo!()
// }

// async fn login_complete() -> impl IntoResponse {
//     todo!()
// }

async fn register_begin(
    State((db, webauthn)): State<(MySqlPool, Webauthn)>,
    Json(req): Json<CreateAccountRequest>,
) -> Json<CreationChallengeResponse> {
    let user_id = uuid::Uuid::new_v4();

    // Generate the challenge using webauthn.rs
    let (challenge_res, passkey_reg) = webauthn
        .start_passkey_registration(user_id, &req.username, &req.display_name, None)
        .expect("Failed to start the registration");

    // Log the challenge response for debugging
    tracing::info!("Challenge response: {:?}", challenge_res);

    // Store user in the database
    sqlx::query!(
        "INSERT INTO users (id, username, email, display_name) VALUES (?, ?, ?, ?)",
        user_id.as_bytes().to_vec(),
        req.username,
        req.email,
        req.display_name,
    )
    .execute(&db)
    .await
    .expect("Failed to insert user");

    // Store registration state (passkey registration) in the database
    let reg_state_id = uuid::Uuid::new_v4();
    let serialized_reg =
        serde_json::to_vec(&passkey_reg).expect("Failed to serialize registration state");

    sqlx::query!(
        "INSERT INTO registration_state (id, user_id, passkey_registration) VALUES (?, ?, ?)",
        reg_state_id.as_bytes().to_vec(),
        user_id.as_bytes().to_vec(),
        serialized_reg,
    )
    .execute(&db)
    .await
    .expect("Failed to insert registration state");

    // Return the challenge response to the frontend
    Json(challenge_res)
}

async fn register_complete(
    State((db, webauthn)): State<(MySqlPool, Webauthn)>,
    Json(req): Json<RegisterCompleteRequest>,
) -> impl IntoResponse {
    // Retrieve the registration state from the database using the username
    let reg_state = sqlx::query!(
        "SELECT passkey_registration FROM registration_state
         INNER JOIN users ON users.id = registration_state.user_id
         WHERE users.username = ?",
        req.username
    )
    .fetch_one(&db)
    .await
    .expect("Failed to retrieve registration state");

    // Deserialize the passkey registration state
    let passkey_reg: PasskeyRegistration = serde_json::from_slice(&reg_state.passkey_registration)
        .expect("Failed to deserialize registration state");

    // Finish the registration process using the WebAuthn API
    let cred = webauthn
        .finish_passkey_registration(&req.credential, &passkey_reg)
        .expect("Failed to complete registration");

    // Log the completion for debugging
    tracing::info!("--------------------------------");
    tracing::info!("Registration completed");
    tracing::info!("Passkey: {:?}", cred);
    tracing::info!("--------------------------------");

    // Return a success response to the frontend
    Json(json!({ "status": "success" }))
}
