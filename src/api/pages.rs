use askama::Template;
use axum::extract::Query;
use axum::response::{Html, IntoResponse};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::StatusCode;
use serde::Deserialize;

use crate::models::templates::{LoginTemplate, RegisterTemplate, WelcomeTemplate};

pub async fn login_page() -> impl IntoResponse {
    Html(LoginTemplate {}.render().unwrap())
}

pub async fn register_page() -> impl IntoResponse {
    Html(RegisterTemplate {}.render().unwrap())
}

#[derive(Deserialize)]
pub struct WelcomeParams {
    user_data: String,
}

pub async fn welcome_page(Query(params): Query<WelcomeParams>) -> impl IntoResponse {
    let decoded = match STANDARD.decode(params.user_data) {
        Ok(d) => d,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid user data").into_response(),
    };

    let user_data: serde_json::Value = match serde_json::from_slice(&decoded) {
        Ok(d) => d,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid user data format").into_response(),
    };

    Html(
        WelcomeTemplate {
            username: user_data["username"].as_str().unwrap_or("").to_string(),
            email: user_data["email"].as_str().unwrap_or("").to_string(),
            display_name: user_data["display_name"].as_str().unwrap_or("").to_string(),
        }
        .render()
        .unwrap(),
    )
    .into_response()
}
