#![allow(dead_code, unused)]

use askama::Template;
use models::{
    model::{
        LoginCompleteRequest, LoginTemplate, RegisterCompleteRequest, RegisterTemplate,
        WelcomeTemplate,
    },
    CreateAccountRequest, LoginAccountRequest,
};
use reqwest::{StatusCode, Url};
use serde::Serialize;
use sqlx::MySqlPool;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use webauthn_rs::{
    prelude::{CreationChallengeResponse, Passkey, PasskeyRegistration},
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
        .route("/", get(login_page))
        .route("/login", get(login_page))
        .route("/login/begin", post(login_begin))
        .route("/login/complete", post(login_complete))
        .route("/register", get(register_page))
        .route("/register", post(register_begin))
        .route("/register/complete", post(register_complete))
        .route("/welcome", get(welcome_page))
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

async fn welcome_page() -> impl IntoResponse {
    Html(
        WelcomeTemplate {
            username: "".to_string(),
            email: "".to_string(),
            display_name: "".to_string(),
        }
        .render()
        .unwrap(),
    )
}
pub fn create_webauthn() -> Webauthn {
    let rp_id = "localhost".to_string();
    let rp_origin = Url::parse("http://localhost:3000").unwrap();
    let builder = WebauthnBuilder::new(&rp_id, &rp_origin).unwrap();
    builder.build().unwrap()
}

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
    // tracing::info!("Challenge response: {:?}", challenge_res);

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
        "SELECT registration_state.user_id, passkey_registration FROM registration_state
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

    // Serialize the credential to JSON first, then to bytes
    let serialized_cred = serde_json::to_vec(&cred).expect("Failed to serialize credential");

    // Store the passkey in the database
    let passkey_id = uuid::Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO passkeys (id, user_id, passkey) VALUES (?, ?, ?)",
        passkey_id.as_bytes().to_vec(),
        reg_state.user_id,
        serialized_cred.as_slice(), // Use as_slice() to get a &[u8]
    )
    .execute(&db)
    .await
    .expect("Failed to store passkey");

    // Return a success response to the frontend
    Json(json!({ "status": "success" })).into_response()
}

async fn login_begin(
    State((db, webauthn)): State<(MySqlPool, Webauthn)>,
    Json(req): Json<LoginAccountRequest>,
) -> impl IntoResponse {
    let user = sqlx::query!(
        "SELECT id, username FROM users WHERE username = ?",
        req.username
    )
    .fetch_one(&db)
    .await
    .map_err(|_| (StatusCode::NOT_FOUND, "User not found"))
    .expect("User not found");

    let user_id = uuid::Uuid::from_slice(&user.id)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid user ID"))
        .expect("Invalid user ID");

    let passkeys = sqlx::query!("SELECT passkey FROM passkeys WHERE user_id = ?", user.id)
        .fetch_all(&db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "No passkeys found"))
        .expect("No passkeys found");

    let passkey_list: Vec<Passkey> = passkeys
        .iter()
        .map(|row| serde_json::from_slice(&row.passkey).expect("Failed to deserialize passkey"))
        .collect();

    let (auth_challenge, auth_state) = webauthn
        .start_passkey_authentication(&passkey_list)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        .expect("Failed to start authentication");

    // Serialize the auth state to JSON before storing
    let serialized_state = serde_json::to_vec(&auth_state).expect("Failed to serialize auth state");

    let auth_state_id = uuid::Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO auth_state (id, user_id, auth_state) VALUES (?, ?, ?)",
        auth_state_id.as_bytes().to_vec(),
        user.id,
        serialized_state.as_slice(),
    )
    .execute(&db)
    .await
    .expect("Failed to store auth state");

    Json(auth_challenge)
}

async fn login_complete(
    State((db, webauthn)): State<(MySqlPool, Webauthn)>,
    Json(req): Json<LoginCompleteRequest>,
) -> impl IntoResponse {
    // Retrieve the auth state and user information from the database
    let auth_data = sqlx::query!(
        "SELECT auth_state.auth_state, auth_state.user_id FROM auth_state
         INNER JOIN users ON users.id = auth_state.user_id
         WHERE users.username = ?",
        req.username
    )
    .fetch_one(&db)
    .await
    .expect("Failed to retrieve auth state");

    // Deserialize the auth state
    let auth_state =
        serde_json::from_slice(&auth_data.auth_state).expect("Failed to deserialize auth state");

    // Verify the authentication with webauthn
    webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)
        .expect("Failed to complete authentication");

    // Generate a session token (you might want to use a proper JWT library)
    let token = uuid::Uuid::new_v4().to_string();

    // Clean up the auth state from the database
    sqlx::query!(
        "DELETE FROM auth_state WHERE user_id = ?",
        auth_data.user_id
    )
    .execute(&db)
    .await
    .expect("Failed to clean up auth state");

    // Get user data
    let user = sqlx::query!(
        "SELECT username, email, display_name FROM users WHERE id = ?",
        auth_data.user_id
    )
    .fetch_one(&db)
    .await
    .expect("Failed to fetch user data");

    // Instead of returning JSON, render the welcome template with user data
    Html(
        WelcomeTemplate {
            username: user.username,
            email: user.email,
            display_name: user.display_name,
        }
        .render()
        .unwrap(),
    )
    .into_response()
}
