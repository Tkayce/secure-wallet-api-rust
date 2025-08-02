pub mod auth;

use axum::Router;
use sqlx::PgPool;

pub fn auth_routes() -> Router<PgPool> {
    Router::new().nest("/", auth::auth_routes())
}
