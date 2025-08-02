use axum::{
    extract::{State},
    http::StatusCode,
    routing::post,
    Json, Router
};
use bcrypt::{hash, DEFAULT_COST};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;
use bcrypt::verify;
use chrono::{Utc, Duration};
use jsonwebtoken::{encode, EncodingKey, Header};
use crate::utils::auth_token::Claims;
use crate::models::user::{RegisterUser, LoginUser, User, UserProfileDto};
use axum::routing::{get, put};
// use crate::services::wallet_service::{get_or_create_wallet, deposit_to_wallet, withdraw_from_wallet};
// use crate::models::user::{Wallet, DepositRequest, WithdrawRequest};
use crate::middleware::auth::auth_middleware;
use crate::controllers::wallet_controller::set_pin;
use crate::controllers::wallet_controller::update_pin;
use crate::controllers::wallet_controller::withdraw;
use crate::controllers::wallet_controller::deposit;
use crate::controllers::wallet_controller::get_balance;
use crate::controllers::wallet_controller::get_wallet_id;
use crate::controllers::wallet_controller::transfer_handler;
 use crate::models::auth::AuthPayload;
use axum::Extension;


pub fn auth_routes() -> Router<PgPool> {
    let public_routes = Router::new()
        .route("/register", post(register))
        .route("/login", post(login));

    let protected_routes = Router::new()
        .route("/profile", get(get_profile))
        .route("/balance", get(get_balance))
        .route("/wallet-id", get(get_wallet_id))
        .route("/deposit", post(deposit))
        .route("/transfer", post(transfer_handler))
        .route("/withdraw", post(withdraw))
        .route("/set-pin", post(set_pin))
        .route("/update-pin", put(update_pin))
        .layer(axum::middleware::from_fn(auth_middleware));

    public_routes.merge(protected_routes)
}

pub async fn get_profile(
    State(pool): State<PgPool>,
    Extension(user): Extension<AuthPayload>,
) -> Result<Json<UserProfileDto>, StatusCode> {
    let user_id = user.user_id;
    let user = sqlx::query_as!(
        User,
        "SELECT id, email, password_hash, role, created_at FROM users WHERE id = $1",
        user_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(Json(UserProfileDto {
        id: user.id,
        email: user.email,
        role: user.role,
    }))
}

async fn register(
    State(pool): State<PgPool>,
    Json(payload): Json<RegisterUser>,
) -> (StatusCode, Json<serde_json::Value>) {
    // 1. Hash the password
    let hashed_password = match hash(&payload.password, DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "status": "error",
                    "message": "Failed to hash password"
                })),
            )
        }
    };

    // 2. Save the user to the database
    let user_id = Uuid::new_v4();
    let result = sqlx::query!(
        r#"
        INSERT INTO users (id, email, password_hash)
        VALUES ($1, $2, $3)
        RETURNING id
        "#,
        user_id,
        payload.email,
        hashed_password
    )
    .fetch_one(&pool)
    .await;

    match result {
        Ok(_) => (
            StatusCode::CREATED,
            Json(json!({
                "status": "success",
                "message": "User registered successfully"
            })),
        ),
        Err(e) => {
            eprintln!("DB error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "status": "error",
                    "message": "Failed to register user"
                })),
            )
        }
    }
}

async fn login(
    State(pool): State<PgPool>,
    Json(payload): Json<LoginUser>,
) -> Json<serde_json::Value> {
    let user = sqlx::query_as_unchecked!(
        User,
        r#"
        SELECT id, email, password_hash, role, created_at
        FROM users
        WHERE email = $1
        "#,
        payload.email
    )
    .fetch_optional(&pool)
    .await
    .unwrap();

     if let Some(user) = user {
        let is_valid = verify(&payload.password, &user.password_hash).unwrap();

        if is_valid {
            let expiration = Utc::now()
                .checked_add_signed(Duration::hours(24))
                .unwrap()
                .timestamp();

            let claims = Claims {
                sub: user.id.to_string(),
                exp: expiration as usize,
                role: user.role,
                email: user.email.clone(),
            };

            let secret = std::env::var("JWT_SECRET").unwrap_or("secret".to_string());

            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(secret.as_ref()),
            )
            .unwrap();

            return Json(json!({
                "status": "success",
                "message": "Login successful",
                "token": token
            }));
        }
    }

    Json(json!({
        "status": "error",
        "message": "Invalid email or password"
    }))
}

// async fn get_balance(
//     State(pool): State<PgPool>,
//     Extension(user): Extension<AuthPayload>
// ) -> Result<Json<Wallet>, (axum::http::StatusCode, String)> {
//     match get_or_create_wallet(&pool, &user.user_id).await {
//     Ok(wallet) => Ok(Json(wallet)),
//     Err(e) => {
//         eprintln!("Error while getting or creating wallet: {:?}", e); 
//         Err((axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to get wallet".into()))
//     }
//  }
// }

// pub async fn withdraw(
//     State(pool): State<PgPool>,
//     Extension(user): Extension<AuthPayload>,
//     Json(payload): Json<WithdrawRequest>,
// ) -> Result<Json<Wallet>, (axum::http::StatusCode, String)> {
//     match withdraw_from_wallet(&pool, &user.user_id, payload.amount).await {
//         Ok(wallet) => Ok(Json(wallet)),
//         Err(e) => {
//             if e.to_string().contains("Insufficient balance") {
//                 Err((axum::http::StatusCode::BAD_REQUEST, e.to_string()))
//             } else {
//                 Err((axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
//             }
//         }
//     }
// }

// pub async fn deposit(
//     State(pool): State<PgPool>,
//     Extension(user): Extension<AuthPayload>,
//     Json(payload): Json<DepositRequest>,
// ) -> Result<Json<Wallet>, (axum::http::StatusCode, String)> {
//     match deposit_to_wallet(&pool, &user.user_id, payload.amount).await {
//         Ok(wallet) => Ok(Json(wallet)),
//         Err(e) => Err((axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
//     }
// }

// pub async fn set_pin(
//     State(pool): State<PgPool>,
//     Extension(user): Extension<AuthPayload>,
//     Json(payload): Json<SetPinRequest>
// ) -> Result<StatusCode, (StatusCode, String)> {
//     if payload.pin.len() != 4 || !payload.pin.chars().all(char::is_numeric) {
//         return Err((StatusCode::BAD_REQUEST, "PIN must be exactly 4 digits.".into()));
//     }

//     // Optional: Hash the PIN before saving for better security

//     let result = sqlx::query("UPDATE wallets SET withdrawal_pin = $1 WHERE user_id = $2")
//         .bind(&payload.pin)
//         .bind(user.user_id)
//         .execute(pool)
//         .await;

//     match result {
//         Ok(_) => Ok(StatusCode::OK),
//         Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
//     }
// }

