use axum::{Router, routing::get, extract::State, response::IntoResponse};
use dotenvy::dotenv;
use std::{env, time::Duration};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tracing_subscriber;
use anyhow::Result;
use crate::middleware::auth::auth_middleware;
use axum::middleware::from_fn;
mod models;
mod routes;
mod utils;
mod middleware;
pub mod controllers;
pub mod services;



#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    tracing_subscriber::fmt::init();

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in .env");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&database_url)
        .await?;

    println!("✅ Connected to Postgres!");

    let protected_routes = Router::new()
    .route("/profile", get(get_profile))
    .layer(from_fn(auth_middleware))
    .with_state(pool.clone()); 

    let app = Router::new()
        .route("/", get(health_check))
        .nest("/auth", routes::auth_routes())
        .nest("/api", protected_routes)
        .with_state(pool); 

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await?;
    println!("🚀 Server listening on {}", listener.local_addr()?);
    
    axum::serve(listener, app).await?;
    Ok(())
}

// This route will test DB connection by running a simple SELECT 1 query
async fn health_check(State(pool): State<PgPool>) -> impl IntoResponse {
    match sqlx::query("SELECT 1")
        .fetch_one(&pool)
        .await
    {
        Ok(_) => "✅ API & DB connection healthy".into_response(),
        Err(e) => {
            eprintln!("❌ DB health check failed: {}", e);
            "❌ API up, DB error".into_response()
        }
    }
}

async fn get_profile(State(_pool): State<PgPool>) -> impl IntoResponse {
    // Optional: use pool to fetch user info
    "🔐 Welcome to your profile!".into_response()
}  