use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub role: String,
    pub email: String,
}
