use crate::models::user::Wallet;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use sqlx::{PgPool, Error};
use uuid::Uuid;
use anyhow::{Result};

pub async fn get_or_create_wallet(pool: &PgPool, user_id: &Uuid) -> Result<Wallet, Error> {
    // Try to find existing wallet
    if let Some(wallet) = sqlx::query_as::<_, Wallet>(
        "SELECT id, user_id, balance, created_at, updated_at FROM wallets WHERE user_id = $1"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await? {
        return Ok(wallet);
    }

    // If not found, create new wallet
    let wallet_id = Uuid::new_v4();
    let wallet = sqlx::query_as::<_, Wallet>(
        r#"
        INSERT INTO wallets (id, user_id, balance)
        VALUES ($1, $2, 0.0)
        RETURNING id, user_id, balance, created_at, updated_at
        "#
    )
    .bind(wallet_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(wallet)
}

pub async fn deposit_to_wallet(pool: &PgPool, user_id: &Uuid, amount: f64) -> Result<Wallet, Error> {
    let wallet = sqlx::query_as::<_, Wallet>(
        "UPDATE wallets SET balance = balance + $1, updated_at = now() WHERE user_id = $2 RETURNING *"
    )
    .bind(amount)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(wallet)
}

pub async fn withdraw_from_wallet(
    pool: &PgPool,
    user_id: &Uuid,
    amount: f64,
    pin: &str,
) -> Result<Wallet> {
    let mut wallet = sqlx::query_as::<_, Wallet>(
        "SELECT * FROM wallets WHERE user_id = $1"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // Check if PIN is locked
    if let Some(lock_time) = wallet.pin_locked_until {
        if lock_time > chrono::Utc::now() {
            return Err(anyhow::anyhow!("pin locked"));
        }
    }

    // Verify hashed pin
    let stored_pin = wallet.withdrawal_pin.as_deref().unwrap_or("");
    let parsed_hash = PasswordHash::new(stored_pin)
        .map_err(|_| anyhow::anyhow!("stored hash invalid"))?;

    let pin_valid = Argon2::default()
        .verify_password(pin.as_bytes(), &parsed_hash)
        .is_ok();

    if !pin_valid {
        wallet.pin_attempts += 1;

        if wallet.pin_attempts >= 5 {
            sqlx::query("UPDATE wallets SET pin_attempts = $1, pin_locked_until = now() + interval '1 hour' WHERE user_id = $2")
                .bind(wallet.pin_attempts)
                .bind(user_id)
                .execute(pool)
                .await?;
        } else {
            sqlx::query("UPDATE wallets SET pin_attempts = $1 WHERE user_id = $2")
                .bind(wallet.pin_attempts)
                .bind(user_id)
                .execute(pool)
                .await?;
        }

        return Err(anyhow::anyhow!("incorrect pin"));
    }

    // Reset attempts on success
    sqlx::query("UPDATE wallets SET pin_attempts = 0, pin_locked_until = NULL WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;

    // Check balance
    if wallet.balance < amount {
        return Err(anyhow::anyhow!("insufficient funds"));
    }

    // Withdraw
    let updated_wallet = sqlx::query_as::<_, Wallet>(
        "UPDATE wallets SET balance = balance - $1, updated_at = now() WHERE user_id = $2 RETURNING *"
    )
    .bind(amount)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(updated_wallet)
}

pub async fn transfer_funds(
    pool: &PgPool,
    sender_id: &Uuid,
    recipient_wallet_id: &Uuid,
    amount: f64,
    pin: &str,
) -> Result<(Wallet, Wallet), sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Get sender wallet
    let sender_wallet = sqlx::query_as::<_, Wallet>(
        "SELECT * FROM wallets WHERE user_id = $1 FOR UPDATE"
    )
    .bind(sender_id)
    .fetch_one(&mut *tx)
    .await?;

    // Check if balance is sufficient
    if sender_wallet.balance < amount {
        return Err(sqlx::Error::RowNotFound); // Replace with custom error if needed
    }

    // Verify PIN
    let hashed_pin = sender_wallet
    .withdrawal_pin
    .as_ref()
    .ok_or_else(|| sqlx::Error::RowNotFound)?; // or use a custom error

    let parsed_hash = PasswordHash::new(hashed_pin)
    .map_err(|_| sqlx::Error::RowNotFound)?; // hash parse error

    Argon2::default()
    .verify_password(pin.as_bytes(), &parsed_hash)
    .map_err(|_| sqlx::Error::RowNotFound)?; // invalid pin


    // Deduct from sender
    let updated_sender = sqlx::query_as::<_, Wallet>(
        "UPDATE wallets SET balance = balance - $1, updated_at = now() WHERE user_id = $2 RETURNING *"
    )
    .bind(amount)
    .bind(sender_id)
    .fetch_one(&mut *tx)
    .await?;

    // Credit to recipient
    let updated_recipient = sqlx::query_as::<_, Wallet>(
        "UPDATE wallets SET balance = balance + $1, updated_at = now() WHERE user_id = $2 RETURNING *"
    )
    .bind(amount)
    .bind(recipient_wallet_id)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok((updated_sender, updated_recipient))
}