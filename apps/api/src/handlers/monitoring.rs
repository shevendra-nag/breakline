use axum::{extract::{Path, Query, State}, http::{HeaderMap, StatusCode}, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use crate::{audit,auth, error::ApiError, monitor_url::validate_url, validation::check_text, AppState};

#[derive(Serialize, FromRow)]
pub struct Monitor {
    pub id: Uuid,
    pub project_id: Uuid,
    pub environment_id: Uuid,
    pub environment_name: String,
    pub project_name: String,
    pub name: String,
    pub url: String,
    pub method: String,
    pub expected_status: i32,
    pub interval_seconds: i32,
    pub timeout_seconds: i32,
    pub enabled: bool,
    pub last_status: String,
    pub last_http_status: Option<i32>,
    pub last_latency_ms: Option<i32>,
    pub last_checked_at: Option<DateTime<Utc>>,
    pub consecutive_failures: i32,
    pub created_at: DateTime<Utc>,
    pub checks_24h: i64,
    pub uptime_24h: Option<f64>,
}

const MONITOR_QUERY: &str = r#"
SELECT m.id,m.project_id,m.environment_id,e.name AS environment_name,p.name AS project_name,
       m.name,m.url,m.method,m.expected_status,m.interval_seconds,m.timeout_seconds,m.enabled,
       m.last_status,m.last_http_status,m.last_latency_ms,m.last_checked_at,m.consecutive_failures,m.created_at,
       (SELECT COUNT(*) FROM monitor_checks c WHERE c.monitor_id=m.id AND c.checked_at > NOW()-INTERVAL '24 hours') AS checks_24h,
       (SELECT (100.0*COUNT(*) FILTER (WHERE c.status='up') / NULLIF(COUNT(*),0))::FLOAT8
          FROM monitor_checks c WHERE c.monitor_id=m.id AND c.checked_at > NOW()-INTERVAL '24 hours') AS uptime_24h
FROM monitors m JOIN projects p ON p.id=m.project_id JOIN environments e ON e.id=m.environment_id
"#;

#[derive(Deserialize)]
pub struct MonitorFilter { pub project_id: Option<Uuid> }
#[derive(Deserialize)]
pub struct CreateMonitor {
    pub project_id: Uuid,
    pub environment_id: Uuid,
    pub name: String,
    pub url: String,
    pub method: Option<String>,
    pub expected_status: Option<i32>,
    pub interval_seconds: Option<i32>,
    pub timeout_seconds: Option<i32>,
}
#[derive(Deserialize)]
pub struct UpdateMonitor {
    pub name: Option<String>,
    pub url: Option<String>,
    pub enabled: Option<bool>,
    pub method: Option<String>,
    pub expected_status: Option<i32>,
    pub interval_seconds: Option<i32>,
    pub timeout_seconds: Option<i32>,
}

fn validate_method(value: &str) -> Result<String, ApiError> {
    if matches!(value, "GET" | "HEAD") { Ok(value.to_owned()) }
    else { Err(ApiError::bad_request("Monitor method must be GET or HEAD")) }
}
fn validate_status(value: i32) -> Result<i32, ApiError> {
    if (100..=599).contains(&value) { Ok(value) }
    else { Err(ApiError::bad_request("Expected status must be between 100 and 599")) }
}
fn validate_interval(value: i32) -> Result<i32, ApiError> {
    if (60..=3600).contains(&value) { Ok(value) }
    else { Err(ApiError::bad_request("Interval must be between 60 and 3600 seconds")) }
}
fn validate_timeout(value: i32) -> Result<i32, ApiError> {
    if (2..=20).contains(&value) { Ok(value) }
    else { Err(ApiError::bad_request("Timeout must be between 2 and 20 seconds")) }
}

async fn one(state: &AppState, id: Uuid) -> Result<Monitor, ApiError> {
    let query = format!("{MONITOR_QUERY} WHERE m.id=$1");
    sqlx::query_as::<_, Monitor>(&query).bind(id).fetch_optional(&state.pool).await?.ok_or_else(ApiError::not_found)
}

pub async fn list(State(state): State<AppState>, headers: HeaderMap, Query(filter): Query<MonitorFilter>) -> Result<Json<Vec<Monitor>>, ApiError> {
    auth::current_user(&state, &headers).await?;
    let query = format!("{MONITOR_QUERY} WHERE ($1::uuid IS NULL OR m.project_id=$1) ORDER BY m.created_at DESC LIMIT 500");
    let rows = sqlx::query_as::<_, Monitor>(&query).bind(filter.project_id).fetch_all(&state.pool).await?;
    Ok(Json(rows))
}

pub async fn create(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<CreateMonitor>) -> Result<(StatusCode, Json<Monitor>), ApiError> {
    auth::require_client_header(&headers)?;
    let user = auth::current_user(&state, &headers).await?;
    auth::require_role(&user, &["owner", "admin", "operator"])?;
    let name = check_text(&input.name, 2, 100, "Monitor name must be 2–100 characters")?;
    let url = validate_url(&input.url)?;
    let method = validate_method(input.method.as_deref().unwrap_or("GET"))?;
    let expected = validate_status(input.expected_status.unwrap_or(200))?;
    let interval = validate_interval(input.interval_seconds.unwrap_or(60))?;
    let timeout = validate_timeout(input.timeout_seconds.unwrap_or(10))?;
    let environment: Option<Uuid> = sqlx::query_scalar("SELECT id FROM environments WHERE id=$1 AND project_id=$2")
        .bind(input.environment_id).bind(input.project_id).fetch_optional(&state.pool).await?;
    if environment.is_none() { return Err(ApiError::bad_request("Environment must belong to the selected project")); }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO monitors(id,project_id,environment_id,name,url,method,expected_status,interval_seconds,timeout_seconds) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(id).bind(input.project_id).bind(input.environment_id).bind(name).bind(url).bind(method)
        .bind(expected).bind(interval).bind(timeout).execute(&state.pool).await?;
    audit::write(&state.pool,Some(user.id),"monitor.created","monitor",Some(id),Some(input.project_id),"Monitor created").await?;
    state.publish("monitor.created", Some(input.project_id));
    Ok((StatusCode::CREATED, Json(one(&state, id).await?)))
}

pub async fn update(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<Uuid>, Json(input): Json<UpdateMonitor>) -> Result<Json<Monitor>, ApiError> {
    auth::require_client_header(&headers)?;
    let user = auth::current_user(&state, &headers).await?;
    auth::require_role(&user, &["owner", "admin", "operator"])?;
    let name = input.name.as_deref().map(|n| check_text(n, 2, 100, "Monitor name must be 2–100 characters")).transpose()?;
    let url = input.url.as_deref().map(validate_url).transpose()?;
    let method = input.method.as_deref().map(validate_method).transpose()?;
    let expected = input.expected_status.map(validate_status).transpose()?;
    let interval = input.interval_seconds.map(validate_interval).transpose()?;
    let timeout = input.timeout_seconds.map(validate_timeout).transpose()?;
    let result = sqlx::query("UPDATE monitors SET name=COALESCE($2,name),url=COALESCE($3,url),method=COALESCE($4,method),expected_status=COALESCE($5,expected_status),interval_seconds=COALESCE($6,interval_seconds),timeout_seconds=COALESCE($7,timeout_seconds),enabled=COALESCE($8,enabled),next_check_at=CASE WHEN $8::boolean IS TRUE OR $3::text IS NOT NULL THEN NOW() ELSE next_check_at END,updated_at=NOW() WHERE id=$1")
        .bind(id).bind(name).bind(url).bind(method).bind(expected).bind(interval).bind(timeout).bind(input.enabled)
        .execute(&state.pool).await?;
    if result.rows_affected() == 0 { return Err(ApiError::not_found()); }
    let monitor = one(&state, id).await?;
    audit::write(&state.pool,Some(user.id),"monitor.updated","monitor",Some(id),Some(monitor.project_id),"Monitor updated").await?;
    state.publish("monitor.updated", Some(monitor.project_id));
    Ok(Json(monitor))
}

pub async fn remove(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<StatusCode, ApiError> {
    auth::require_client_header(&headers)?;
    let user = auth::current_user(&state, &headers).await?;
    auth::require_role(&user, &["owner", "admin"])?;
    let row: Option<Uuid> = sqlx::query_scalar("DELETE FROM monitors WHERE id=$1 RETURNING project_id")
        .bind(id).fetch_optional(&state.pool).await?;
    let project_id = row.ok_or_else(ApiError::not_found)?;
    audit::write(&state.pool,Some(user.id),"monitor.deleted","monitor",Some(id),Some(project_id),"Monitor deleted").await?;
    state.publish("monitor.deleted", Some(project_id));
    Ok(StatusCode::NO_CONTENT)
}

pub async fn run_now(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<StatusCode, ApiError> {
    auth::require_client_header(&headers)?;
    let user = auth::current_user(&state, &headers).await?;
    auth::require_role(&user, &["owner", "admin", "operator"])?;
    let project: Option<Uuid> = sqlx::query_scalar("UPDATE monitors SET next_check_at=NOW() WHERE id=$1 AND enabled=TRUE RETURNING project_id")
        .bind(id).fetch_optional(&state.pool).await?;
    let project = project.ok_or_else(|| ApiError::bad_request("Monitor is disabled or does not exist"))?;
    audit::write(&state.pool,Some(user.id),"monitor.check_requested","monitor",Some(id),Some(project),"Manual health check queued").await?;
    state.publish("monitor.queued", Some(project));
    Ok(StatusCode::ACCEPTED)
}

#[derive(Serialize, FromRow)]
pub struct MonitorCheck {
    pub id: i64,
    pub status: String,
    pub http_status: Option<i32>,
    pub latency_ms: Option<i32>,
    pub error_message: Option<String>,
    pub checked_at: DateTime<Utc>,
}
#[derive(Deserialize)]
pub struct CheckFilter { pub limit: Option<i64> }
pub async fn checks(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<Uuid>, Query(filter): Query<CheckFilter>) -> Result<Json<Vec<MonitorCheck>>, ApiError> {
    auth::current_user(&state, &headers).await?;
    let _ = one(&state, id).await?;
    let rows = sqlx::query_as::<_, MonitorCheck>("SELECT id,status,http_status,latency_ms,error_message,checked_at FROM monitor_checks WHERE monitor_id=$1 ORDER BY checked_at DESC LIMIT $2")
        .bind(id).bind(filter.limit.unwrap_or(60).clamp(1, 200)).fetch_all(&state.pool).await?;
    Ok(Json(rows))
}

#[derive(Serialize, FromRow)]
pub struct MonitorSummary {
    pub total: i64,
    pub active: i64,
    pub up: i64,
    pub down: i64,
    pub unknown: i64,
    pub checks_24h: i64,
    pub uptime_24h: Option<f64>,
    pub avg_latency_ms: Option<f64>,
}
pub async fn summary(State(state): State<AppState>, headers: HeaderMap, Query(filter): Query<MonitorFilter>) -> Result<Json<MonitorSummary>, ApiError> {
    auth::current_user(&state, &headers).await?;
    let counts: (i64, i64, i64, i64, i64) = sqlx::query_as("SELECT COUNT(*)::bigint,COUNT(*) FILTER (WHERE enabled)::bigint,COUNT(*) FILTER (WHERE last_status='up' AND enabled)::bigint,COUNT(*) FILTER (WHERE last_status='down' AND enabled)::bigint,COUNT(*) FILTER (WHERE last_status='unknown' OR NOT enabled)::bigint FROM monitors WHERE ($1::uuid IS NULL OR project_id=$1)")
        .bind(filter.project_id).fetch_one(&state.pool).await?;
    let checks: (i64, Option<f64>, Option<f64>) = sqlx::query_as("SELECT COUNT(*)::bigint,(100.0*COUNT(*) FILTER (WHERE c.status='up') / NULLIF(COUNT(*),0))::float8,AVG(c.latency_ms)::float8 FROM monitor_checks c JOIN monitors m ON m.id=c.monitor_id WHERE c.checked_at>NOW()-INTERVAL '24 hours' AND ($1::uuid IS NULL OR m.project_id=$1)")
        .bind(filter.project_id).fetch_one(&state.pool).await?;
    Ok(Json(MonitorSummary { total: counts.0, active: counts.1, up: counts.2, down: counts.3, unknown: counts.4, checks_24h: checks.0, uptime_24h: checks.1, avg_latency_ms: checks.2 }))
}
