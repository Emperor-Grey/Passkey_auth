use serde::{Deserialize, Serialize};

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

#[derive(Serialize)]
pub struct UserInfo {
    pub username: String,
    pub email: String,
    pub display_name: String,
}
