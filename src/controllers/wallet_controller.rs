use axum::{
    extract::{State},
    http::StatusCode,
    Json,  response::IntoResponse
};
use serde::Deserialize;
use serde::Serialize;
use crate::{
    middleware::auth::Claims,
    models::user::Wallet,
    services::wallet_service,
};
use sqlx::PgPool;
use uuid::Uuid;
use crate::services::wallet_service::{get_or_create_wallet};
use crate::models::auth::AuthPayload;
use serde_json::json;
use axum::Extension;
use axum_macros::debug_handler;
use argon2::{Argon2, PasswordHasher, PasswordVerifier, PasswordHash};
use argon2::password_hash::{SaltString, rand_core::OsRng};




#[derive(Deserialize)]
pub struct WalletActionDto {
    pub amount: f64,
    pub pin: String,
}

#[derive(Deserialize)]
pub struct DepositDto {
    pub amount: f64,
}
#[derive(Serialize)]
pub struct WalletSummaryDto {
    pub wallet_id: Uuid,
    pub balance: f64,
}

#[derive(Deserialize)]
pub struct SetPinRequest {
    pub pin: String, // Must be 4 digits, validated
}

#[derive(Deserialize)]
pub struct UpdatePinRequest {
    pub old_pin: String,
    pub new_pin: String,
}

#[derive(Deserialize)]
pub struct TransferDto {
    pub recipient_wallet_id: Uuid,
    pub amount: f64,
    pub pin: String,
}


// ✅ GET /api/wallet - Get or create wallet
pub async fn get_wallet(
    State(pool): State<PgPool>,
    claims: Claims,
) -> Result<Json<Wallet>, StatusCode> {
    let user_id = claims.sub.clone();
    let user_uuid = match Uuid::parse_str(&user_id) {
    Ok(uuid) => uuid,
    Err(_) => {
      return Err(StatusCode::BAD_REQUEST);
    }
};

    match wallet_service::get_or_create_wallet(&pool, &user_uuid).await {
    Ok(wallet) => Ok(Json(wallet)),
    Err(e) => {
        eprintln!("Wallet service failed: {:?}", e);  // Add this line
        Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

}

#[debug_handler]
pub async fn get_balance(
    State(pool): State<PgPool>,
    Extension(user): Extension<AuthPayload>
) -> Result<Json<Wallet>, (axum::http::StatusCode, String)> {
    match get_or_create_wallet(&pool, &user.user_id).await {
    Ok(wallet) => Ok(Json(wallet)),
    Err(e) => {
        eprintln!("Error while getting or creating wallet: {:?}", e); 
        Err((axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to get wallet".into()))
    }
 }
}

#[debug_handler]
pub async fn get_wallet_id(
    State(pool): State<PgPool>,
    Extension(user): Extension<AuthPayload>,
) -> Result<Json<WalletSummaryDto>, StatusCode> {
    let wallet_id = user.user_id;

    let wallet = sqlx::query!(
        "SELECT balance FROM wallets WHERE user_id = $1",
        wallet_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(Json(WalletSummaryDto {
        wallet_id,
        balance: wallet.balance.unwrap_or(0.0),
    }))
}

// ✅ POST /api/wallet/deposit
#[debug_handler]
pub async fn deposit(
    State(pool): State<PgPool>,
    Extension(user): Extension<AuthPayload>,
    Json(payload): Json<DepositDto>,
) -> Result<Json<Wallet>, StatusCode> {
    let user_uuid = user.user_id;

    match wallet_service::deposit_to_wallet(&pool, &user_uuid, payload.amount).await {
        Ok(wallet) => Ok(Json(wallet)),
        Err(err) => {
            eprintln!("Deposit error: {:?}", err); 
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ✅ POST /api/wallet/transfer
pub async fn transfer_handler(
    State(pool): State<PgPool>,
    Extension(user): Extension<AuthPayload>,
    Json(payload): Json<TransferDto>,
) -> Result<Json<Wallet>, StatusCode> {
    if payload.amount <= 0.0 {
        return Err(StatusCode::BAD_REQUEST);
    }

    match wallet_service::transfer_funds(
        &pool,
        &user.user_id,
        &payload.recipient_wallet_id,
        payload.amount,
        &payload.pin,
    )
    .await
    {
        Ok((updated_sender, _)) => Ok(Json(updated_sender)),
        Err(_) => Err(StatusCode::UNAUTHORIZED),
    }
}

// ✅ POST /api/wallet/withdraw 
#[debug_handler]
pub async fn withdraw(
    State(pool): State<PgPool>,
    Extension(user): Extension<AuthPayload>,
    Json(payload): Json<WalletActionDto>,
) -> Result<Json<Wallet>, StatusCode> {
    let user_uuid = user.user_id;

    match wallet_service::withdraw_from_wallet(&pool, &user_uuid, payload.amount, &payload.pin).await {
        Ok(wallet) => Ok(Json(wallet)),
        Err(err) => {
            if err.to_string().contains("incorrect pin") {
                Err(StatusCode::UNAUTHORIZED)
            } else if err.to_string().contains("pin locked") {
                Err(StatusCode::FORBIDDEN)
            } else if err.to_string().contains("insufficient funds") {
                Err(StatusCode::BAD_REQUEST)
            } else {
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
}


// ✅ POST /api/wallet/set_pin
pub async fn set_pin(
    State(pool): State<PgPool>,
    Extension(user): Extension<AuthPayload>,
    Json(payload): Json<SetPinRequest>
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if payload.pin.len() != 4 || !payload.pin.chars().all(char::is_numeric) {
        return Err((StatusCode::BAD_REQUEST, "PIN must be exactly 4 digits.".into()));
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hashed_pin = argon2
        .hash_password(payload.pin.as_bytes(), &salt)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Hashing failed: {}", e)))?
        .to_string();

    let result = sqlx::query("UPDATE wallets SET withdrawal_pin = $1 WHERE user_id = $2")
        .bind(&hashed_pin)
        .bind(user.user_id)
        .execute(&pool)
        .await;

    match result {
        Ok(_) => Ok(Json(json!({ "message": "Withdrawal PIN created successfully" }))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

// ✅ POST /api/wallet/update_pin
pub async fn update_pin(
    State(pool): State<PgPool>,
    Extension(user): Extension<AuthPayload>,
    Json(payload): Json<UpdatePinRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if payload.new_pin.len() != 4 || !payload.new_pin.chars().all(char::is_numeric) {
        return Err((StatusCode::BAD_REQUEST, "New PIN must be 4 digits.".into()));
    }

    let row = sqlx::query!(
        "SELECT withdrawal_pin FROM wallets WHERE user_id = $1",
        user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let Some(record) = row else {
        return Err((StatusCode::NOT_FOUND, "Wallet not found.".into()));
    };

    let Some(stored_pin) = &record.withdrawal_pin else {
        return Err((StatusCode::BAD_REQUEST, "No stored PIN.".into()));
    };

    let pin_is_valid = if let Ok(parsed_hash) = PasswordHash::new(stored_pin) {
        // Stored PIN is hashed, verify using Argon2
        Argon2::default()
            .verify_password(payload.old_pin.as_bytes(), &parsed_hash)
            .is_ok()
    } else {
        // Stored PIN is plain, compare directly
        stored_pin == &payload.old_pin
    };

    if !pin_is_valid {
        return Err((StatusCode::UNAUTHORIZED, "Incorrect PIN.".into()));
    }

    // Now hash the new PIN
    let salt = SaltString::generate(&mut OsRng);
    let hashed_new_pin = Argon2::default()
        .hash_password(payload.new_pin.as_bytes(), &salt)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .to_string();

    sqlx::query!(
        "UPDATE wallets SET withdrawal_pin = $1 WHERE user_id = $2",
        hashed_new_pin,
        user.user_id
    )
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "message": "Withdrawal PIN updated successfully"
    })))
}
