use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthPayload {
    pub user_id: Uuid,
    pub email: String,
    pub role: String,
}
