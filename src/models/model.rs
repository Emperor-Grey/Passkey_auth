use askama_axum::Template;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateAccountRequest {
    pub username: String,
    pub email: String,
    pub display_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginAccountRequest {
    pub username: String,
}

/* ********* */
/* Templates */
/* ********* */

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate;

#[derive(Template)]
#[template(path = "register.html")]
pub struct RegisterTemplate;

#[derive(Template)]
#[template(path = "welcome.html")]
pub struct WelcomeTemplate {
    pub username: String,
    pub email: String,
    pub display_name: String,
}

#[derive(Serialize)]
pub struct UserInfo {
    pub username: String,
    pub email: String,
    pub display_name: String,
}

// /* ***************** */
// /* Passkey's Related */
// /* ***************** */
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterCompleteRequest {
    pub username: String,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Deserialize)]
pub struct LoginCompleteRequest {
    pub username: String,
    pub credential: PublicKeyCredential,
}
