use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use chrono::NaiveDateTime;

#[derive(Serialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub password_hash: String,
    pub created_at: Option<NaiveDateTime>, 
}

#[derive(Deserialize)]
pub struct RegisterUser {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginUser {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct UserProfileDto {
    pub id: Uuid,
    pub email: String,
    pub role: String,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Wallet {
    pub id: Uuid,
    pub user_id: Uuid,
    pub balance: f64,
    pub withdrawal_pin: Option<String>,
    pub pin_attempts: i32,
    pub pin_locked_until: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct DepositRequest {
    pub amount: f64,
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct WithdrawRequest {
    pub amount: f64,
    pub pin: String,
}
