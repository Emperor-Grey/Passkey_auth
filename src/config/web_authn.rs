use reqwest::Url;
use std::env;
use webauthn_rs::{Webauthn, WebauthnBuilder};

pub fn create_webauthn() -> Webauthn {
    let rp_id = env::var("RP_ID").expect("RP_ID is not set");
    let rp_origin = Url::parse(&env::var("RP_ORIGIN").expect("RP_ORIGIN is not set")).unwrap();
    let builder = WebauthnBuilder::new(&rp_id, &rp_origin).unwrap();
    builder.build().unwrap()
}
