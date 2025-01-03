use reqwest::Url;
use webauthn_rs::{Webauthn, WebauthnBuilder};

pub fn create_webauthn() -> Webauthn {
    let rp_id = "passkey-auth-nzbh.onrender.com".to_string();
    let rp_origin = Url::parse("https://passkey-auth-nzbh.onrender.com").unwrap();
    let builder = WebauthnBuilder::new(&rp_id, &rp_origin).unwrap();
    builder.build().unwrap()
}
