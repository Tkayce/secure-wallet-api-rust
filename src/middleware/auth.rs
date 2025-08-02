use axum::{
    http::{Request, StatusCode},
    body::Body,
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::models::auth::AuthPayload;

#[derive(Debug, Serialize, Deserialize, Clone)]
 pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub role: String,     
    pub email: String,  
}

pub async fn auth_middleware(
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok());

    if let Some(token) = auth_header.and_then(|h| h.strip_prefix("Bearer ")) {
        let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

        let decoded = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::default(),
        );

        match decoded {
            Ok(token_data) => {
                // 👇 Inject user ID into request extensions
                let user_id = token_data.claims.sub;

                // Parse string UUID into real Uuid
                if let Ok(uuid) = Uuid::parse_str(&user_id) {
                   let payload = AuthPayload { 
                    user_id: uuid, 
                    email: token_data.claims.email.clone(),
                    role: token_data.claims.role.clone(),
                   }; 
                   req.extensions_mut().insert(payload);        
                   return Ok(next.run(req).await);
                } else {
                    return Err(StatusCode::UNAUTHORIZED);
                }
            }
            Err(_) => return Err(StatusCode::UNAUTHORIZED),
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}