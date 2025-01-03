use askama::Template;
use axum::{
    Json,
    extract::State,
    response::{Html, IntoResponse},
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::{StatusCode, header};
use serde_json::json;
use sqlx::MySqlPool;
use uuid::Uuid;
use webauthn_rs::{
    Webauthn,
    prelude::{CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration},
};

use crate::models::{
    auth::{LoginCompleteRequest, RegisterCompleteRequest},
    templates::{LoginTemplate, WelcomeTemplate},
    user::{CreateAccountRequest, LoginAccountRequest},
};
pub async fn register_begin(
    State((db, webauthn)): State<(MySqlPool, Webauthn)>,
    Json(req): Json<CreateAccountRequest>,
) -> impl IntoResponse {
    let user_id = uuid::Uuid::new_v4();

    // Check if user already exists
    let existing_user = sqlx::query!(
        "SELECT username FROM users WHERE username = ?",
        req.username
    )
    .fetch_optional(&db)
    .await
    .expect("Failed to check existing user");

    if existing_user.is_some() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Username already exists"
            })),
        )
            .into_response();
    }

    // Generate the challenge
    let (challenge_res, passkey_reg) = match webauthn.start_passkey_registration(
        user_id,
        &req.username,
        &req.display_name,
        None,
    ) {
        Ok(result) => result,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": format!("Failed to start registration: {}", e)
                })),
            )
                .into_response();
        }
    };

    // Store user in the database
    if let Err(e) = sqlx::query!(
        "INSERT INTO users (id, username, email, display_name) VALUES (?, ?, ?, ?)",
        user_id.as_bytes().to_vec(),
        req.username,
        req.email,
        req.display_name,
    )
    .execute(&db)
    .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": format!("Failed to insert user: {}", e)
            })),
        )
            .into_response();
    }

    // Store registration state
    let reg_state_id = uuid::Uuid::new_v4();
    let serialized_reg =
        serde_json::to_vec(&passkey_reg).expect("Failed to serialize registration state");

    if let Err(e) = sqlx::query!(
        "INSERT INTO registration_state (id, user_id, passkey_registration) VALUES (?, ?, ?)",
        reg_state_id.as_bytes().to_vec(),
        user_id.as_bytes().to_vec(),
        serialized_reg,
    )
    .execute(&db)
    .await
    {
        // Clean up the user if registration state fails
        let _ = sqlx::query!(
            "DELETE FROM users WHERE id = ?",
            user_id.as_bytes().to_vec()
        )
        .execute(&db)
        .await;

        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": format!("Failed to store registration state: {}", e)
            })),
        )
            .into_response();
    }

    // Return the challenge
    Json(challenge_res).into_response()
}

pub async fn register_complete(
    State((db, webauthn)): State<(MySqlPool, Webauthn)>,
    Json(req): Json<RegisterCompleteRequest>,
) -> impl IntoResponse {
    // Retrieve the registration state
    let reg_state = match sqlx::query!(
        "SELECT registration_state.user_id, passkey_registration FROM registration_state
         INNER JOIN users ON users.id = registration_state.user_id
         WHERE users.username = ?",
        req.username
    )
    .fetch_one(&db)
    .await
    {
        Ok(state) => state,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!("Registration state not found: {}", e)
                })),
            )
                .into_response();
        }
    };

    // Deserialize the passkey registration state
    let passkey_reg: PasskeyRegistration =
        match serde_json::from_slice(&reg_state.passkey_registration) {
            Ok(reg) => reg,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": format!("Failed to deserialize registration state: {}", e)
                    })),
                )
                    .into_response();
            }
        };

    // Finish the registration process
    let cred = match webauthn.finish_passkey_registration(&req.credential, &passkey_reg) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!("Failed to complete registration: {}", e)
                })),
            )
                .into_response();
        }
    };

    // Store the passkey
    let passkey_id = uuid::Uuid::new_v4();
    let serialized_cred = serde_json::to_vec(&cred).expect("Failed to serialize credential");

    if let Err(e) = sqlx::query!(
        "INSERT INTO passkeys (id, user_id, passkey) VALUES (?, ?, ?)",
        passkey_id.as_bytes().to_vec(),
        reg_state.user_id,
        serialized_cred.as_slice(),
    )
    .execute(&db)
    .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": format!("Failed to store passkey: {}", e)
            })),
        )
            .into_response();
    }

    // Clean up registration state
    let _ = sqlx::query!(
        "DELETE FROM registration_state WHERE user_id = ?",
        reg_state.user_id
    )
    .execute(&db)
    .await;

    Json(json!({ "status": "success" })).into_response()
}
pub async fn login_begin(
    State((db, webauthn)): State<(MySqlPool, Webauthn)>,
    Json(req): Json<LoginAccountRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Validate username
    let username = req.username.trim();
    if username.is_empty() {
        return Err(AppError::BadRequest("Username is required".to_string()));
    }

    // Get user and passkeys
    let user = sqlx::query!(
        "SELECT id, username FROM users WHERE username = ?",
        username
    )
    .fetch_one(&db)
    .await
    .map_err(|_| AppError::NotFound("User not found".to_string()))?;

    let user_id = Uuid::from_slice(&user.id)
        .map_err(|_| AppError::Internal("Invalid user ID format".to_string()))?;

    let passkeys = sqlx::query!("SELECT passkey FROM passkeys WHERE user_id = ?", user.id)
        .fetch_all(&db)
        .await
        .map_err(|_| AppError::NotFound("No passkeys found".to_string()))?;

    let passkey_list: Vec<Passkey> = passkeys
        .iter()
        .filter_map(|row| serde_json::from_slice(&row.passkey).ok())
        .collect();

    if passkey_list.is_empty() {
        return Err(AppError::BadRequest(
            "No valid passkeys found for user".to_string(),
        ));
    }

    // Start authentication
    let (auth_challenge, auth_state) = webauthn
        .start_passkey_authentication(&passkey_list)
        .map_err(|e| AppError::Internal(format!("Failed to start authentication: {}", e)))?;

    // Clean up any existing auth state
    let _ = sqlx::query!("DELETE FROM auth_state WHERE user_id = ?", user.id)
        .execute(&db)
        .await;

    // Store new auth state
    let auth_state_id = Uuid::new_v4();
    let serialized_state = serde_json::to_vec(&auth_state)
        .map_err(|_| AppError::Internal("Failed to serialize auth state".to_string()))?;

    sqlx::query!(
        "INSERT INTO auth_state (id, user_id, auth_state, created_at) VALUES (?, ?, ?, NOW())",
        auth_state_id.as_bytes().to_vec(),
        user.id,
        serialized_state.as_slice(),
    )
    .execute(&db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to store auth state: {}", e)))?;

    Ok(Json(auth_challenge))
}

pub async fn login_complete(
    State((db, webauthn)): State<(MySqlPool, Webauthn)>,
    Json(req): Json<LoginCompleteRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Get auth state and user data
    let auth_data = sqlx::query!(
        r#"
        SELECT
            auth_state.auth_state,
            auth_state.user_id,
            users.username,
            users.email,
            users.display_name
        FROM auth_state
        INNER JOIN users ON users.id = auth_state.user_id
        WHERE users.username = ?
        AND auth_state.created_at > DATE_SUB(NOW(), INTERVAL 5 MINUTE)
        "#,
        req.username
    )
    .fetch_one(&db)
    .await
    .map_err(|_| AppError::BadRequest("Invalid or expired authentication state".to_string()))?;

    // Deserialize auth state
    let auth_state: PasskeyAuthentication = serde_json::from_slice(&auth_data.auth_state)
        .map_err(|_| AppError::Internal("Failed to deserialize auth state".to_string()))?;

    // Verify the authentication
    let _auth_result = webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)
        .map_err(|e| AppError::BadRequest(format!("Authentication failed: {}", e)))?;

    // Clean up the auth state
    let _ = sqlx::query!(
        "DELETE FROM auth_state WHERE user_id = ?",
        auth_data.user_id
    )
    .execute(&db)
    .await;

    // Return user data
    let user_data = json!({
        "username": auth_data.username,
        "email": auth_data.email,
        "display_name": auth_data.display_name,
    });

    let user_data_string = serde_json::to_string(&user_data)
        .map_err(|_| AppError::Internal("Failed to serialize user data".to_string()))?;
    let user_data_encoded = STANDARD.encode(user_data_string);

    Ok(Json(json!({
        "redirect_url": format!("/welcome?user_data={}", user_data_encoded)
    })))
}

#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    NotFound(String),
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            AppError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
