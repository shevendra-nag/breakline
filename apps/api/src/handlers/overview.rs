use axum::{extract::State, http::HeaderMap, Json};
use serde::Serialize;

use crate::{auth, error::ApiError, handlers::deployments::Pagination, models::{Activity, Deployment, TrendDay}, AppState};

#[derive(Serialize)]
pub struct Metrics {
    pub projects: i64,
    pub environments: i64,
    pub deployments: i64,
    pub running: i64,
    pub succeeded: i64,
    pub failed: i64,
}

#[derive(Serialize)]
pub struct Overview {
    pub metrics: Metrics,
    pub trend: Vec<TrendDay>,
    pub recent_deployments: Vec<Deployment>,
    pub activities: Vec<Activity>,
}

pub async fn get(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Overview>, ApiError> {
    auth::current_user(&state, &headers).await?;
    let projects: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM projects").fetch_one(&state.pool).await?;
    let environments: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM environments").fetch_one(&state.pool).await?;
    let deployments: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deployments").fetch_one(&state.pool).await?;
    let running: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deployments WHERE status='running'").fetch_one(&state.pool).await?;
    let succeeded: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deployments WHERE status='succeeded'").fetch_one(&state.pool).await?;
    let failed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deployments WHERE status='failed'").fetch_one(&state.pool).await?;
    let trend = sqlx::query_as::<_, TrendDay>(r#"
        SELECT TO_CHAR(days.day,'YYYY-MM-DD') AS day,
               COUNT(d.id) AS total,
               COUNT(d.id) FILTER (WHERE d.status='succeeded') AS succeeded,
               COUNT(d.id) FILTER (WHERE d.status='failed') AS failed
        FROM GENERATE_SERIES((CURRENT_DATE - INTERVAL '6 days')::date, CURRENT_DATE, INTERVAL '1 day') AS days(day)
        LEFT JOIN deployments d ON d.created_at::date = days.day::date
        GROUP BY days.day ORDER BY days.day
    "#).fetch_all(&state.pool).await?;
    let recent_query = format!("{} ORDER BY d.created_at DESC LIMIT $1 OFFSET $2", super::deployments::SELECT_DEPLOYMENTS);
    let (limit, offset) = Pagination { limit: Some(6), offset: Some(0) }.values();
    let recent_deployments = sqlx::query_as::<_, Deployment>(&recent_query)
        .bind(limit).bind(offset).fetch_all(&state.pool).await?;
    let activities = sqlx::query_as::<_, Activity>("SELECT id,action,entity_type,entity_id,detail,created_at FROM activities ORDER BY created_at DESC LIMIT 8")
        .fetch_all(&state.pool).await?;
    Ok(Json(Overview {
        metrics: Metrics { projects, environments, deployments, running, succeeded, failed },
        trend, recent_deployments, activities,
    }))
}
