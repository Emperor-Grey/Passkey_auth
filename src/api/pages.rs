use askama::Template;
use axum::response::{Html, IntoResponse};

use crate::models::templates::{LoginTemplate, RegisterTemplate, WelcomeTemplate};

pub async fn login_page() -> impl IntoResponse {
    Html(LoginTemplate {}.render().unwrap())
}

pub async fn register_page() -> impl IntoResponse {
    Html(RegisterTemplate {}.render().unwrap())
}

pub async fn welcome_page() -> impl IntoResponse {
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
