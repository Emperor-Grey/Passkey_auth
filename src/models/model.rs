use askama_axum::Template;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

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

/* ***************** */
/* Passkey's Related */
/* ***************** */

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterPublicKey {
    pub id: String,
    pub raw_id: String,
    pub response: AuthenticatorAttestationResponse,
    pub r#type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatorAttestationResponse {
    pub client_data_json: String,
    pub attestation_object: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterCompleteRequest {
    pub username: String,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginCredential {
    pub id: String,
    pub raw_id: String,
    pub response: AuthenticatorAssertionResponse,
    pub r#type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatorAssertionResponse {
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginCompleteRequest {
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    pub origin: String,
}

#[derive(Debug)]
pub struct StoredCredential {
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub signature_counter: u32,
}

// /* ****************** */
// /* Challenge response */
// /* ****************** */
// #[derive(Debug, Serialize, Deserialize)]
// pub struct ChallengeRes {
//     pub public_key: PublicKeyCredentialCreationOptions,
// }

// #[derive(Debug, Serialize, Deserialize)]
// pub struct PublicKeyCredentialCreationOptions {
//     pub rp: RelyingParty,
//     pub user: User,
//     pub challenge: String,
//     pub pub_key_cred_params: Vec<PubKeyCredParam>,
//     pub timeout: u32,
//     pub authenticator_selection: AuthenticatorSelection,
//     pub attestation: String,
//     pub extensions: Extensions,
// }

// #[derive(Debug, Serialize, Deserialize)]
// pub struct RelyingParty {
//     pub name: String,
//     pub id: String,
// }

// #[derive(Debug, Serialize, Deserialize)]
// pub struct User {
//     pub id: String,
//     pub name: String,
//     #[serde(rename = "displayName")]
//     pub display_name: String,
// }

// #[derive(Debug, Serialize, Deserialize)]
// pub struct PubKeyCredParam {
//     #[serde(rename = "type")]
//     pub type_: String,
//     pub alg: i32,
// }

// #[derive(Debug, Serialize, Deserialize)]
// pub struct AuthenticatorSelection {
//     #[serde(rename = "residentKey")]
//     pub resident_key: String,
//     #[serde(rename = "requireResidentKey")]
//     pub require_resident_key: bool,
//     #[serde(rename = "userVerification")]
//     pub user_verification: String,
// }

// #[derive(Debug, Serialize, Deserialize)]
// pub struct Extensions {
//     #[serde(rename = "credentialProtectionPolicy")]
//     pub credential_protection_policy: String,
//     #[serde(rename = "enforceCredentialProtectionPolicy")]
//     pub enforce_credential_protection_policy: bool,
//     pub uvm: bool,
//     #[serde(rename = "credProps")]
//     pub cred_props: bool,
// }
