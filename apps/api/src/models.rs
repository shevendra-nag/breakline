use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, FromRow, Serialize)]
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow, Serialize)]
pub struct Project {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub description: String,
    pub repository_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, FromRow, Serialize)]
pub struct Environment {
    pub id: Uuid,
    pub project_id: Uuid,
    pub name: String,
    pub slug: String,
    pub is_production: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow, Serialize)]
pub struct Deployment {
    pub id: Uuid,
    pub project_id: Uuid,
    pub environment_id: Uuid,
    pub project_name: String,
    pub environment_name: String,
    pub version: String,
    pub commit_sha: Option<String>,
    pub branch: Option<String>,
    pub triggered_by: String,
    pub description: String,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow, Serialize)]
pub struct Activity {
    pub id: i64,
    pub action: String,
    pub entity_type: String,
    pub entity_id: Option<Uuid>,
    pub detail: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow, Serialize)]
pub struct TrendDay {
    pub day: String,
    pub total: i64,
    pub succeeded: i64,
    pub failed: i64,
}
