use askama_axum::Template;

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
