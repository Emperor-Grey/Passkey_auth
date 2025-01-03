use askama::Template;
use axum::{
    extract::State,
    response::{Html, IntoResponse},
    Json,
};
use reqwest::StatusCode;
use serde_json::json;
use sqlx::MySqlPool;
use webauthn_rs::{
    prelude::{CreationChallengeResponse, Passkey, PasskeyRegistration},
    Webauthn,
};

use crate::models::{
    auth::{LoginCompleteRequest, RegisterCompleteRequest},
    templates::WelcomeTemplate,
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

pub async fn login_complete(
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

    Json(json!({
        "username": user.username,
        "email": user.email,
        "display_name": user.display_name
    }))
    .into_response()

    // // Instead of returning JSON, render the welcome template with user data
    // Html(
    //     WelcomeTemplate {
    //         username: user.username,
    //         email: user.email,
    //         display_name: user.display_name,
    //     }
    //     .render()
    //     .unwrap(),
    // )
    // .into_response()
}
