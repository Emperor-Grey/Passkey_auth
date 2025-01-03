use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

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
