use axum::{extract::{Path, State}, http::{HeaderMap, StatusCode}, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, Row};
use uuid::Uuid;
use crate::{audit,auth, incident_engine, error::ApiError, handlers::deployments::SELECT_DEPLOYMENTS, models::Deployment, validation::{check_text, valid_transition}, AppState};

fn hash_token(value: &str) -> String { format!("{:x}", Sha256::digest(value.as_bytes())) }
fn make_token() -> String { format!("bl_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()) }

#[derive(Serialize, FromRow)]
pub struct TokenMetadata {
    pub id: Uuid,
    pub project_id: Uuid,
    pub label: String,
    pub token_prefix: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}
#[derive(Serialize)]
pub struct IssuedToken { pub token: String, pub credential: TokenMetadata }
#[derive(Deserialize)]
pub struct NewToken { pub label: String }

pub async fn list_tokens(State(state): State<AppState>, headers: HeaderMap, Path(project_id): Path<Uuid>) -> Result<Json<Vec<TokenMetadata>>, ApiError> {
    let actor = auth::current_user(&state, &headers).await?;
    auth::require_role(&actor, &["owner", "admin"])?;
    let rows = sqlx::query_as::<_, TokenMetadata>("SELECT id,project_id,label,token_prefix,created_at,last_used_at,revoked_at FROM ingest_tokens WHERE project_id=$1 ORDER BY created_at DESC")
        .bind(project_id).fetch_all(&state.pool).await?;
    Ok(Json(rows))
}

pub async fn new_token(State(state): State<AppState>, headers: HeaderMap, Path(project_id): Path<Uuid>, Json(input): Json<NewToken>) -> Result<(StatusCode, Json<IssuedToken>), ApiError> {
    auth::require_client_header(&headers)?;
    let actor = auth::current_user(&state, &headers).await?;
    auth::require_role(&actor, &["owner", "admin"])?;
    let label = check_text(&input.label, 2, 80, "Token label must be 2–80 characters")?;
    let token = make_token();
    let id = Uuid::new_v4();
    let credential = sqlx::query_as::<_, TokenMetadata>("INSERT INTO ingest_tokens(id,project_id,label,token_prefix,token_hash,created_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,project_id,label,token_prefix,created_at,last_used_at,revoked_at")
        .bind(id).bind(project_id).bind(label).bind(&token[..15]).bind(hash_token(&token)).bind(actor.id)
        .fetch_one(&state.pool).await?;
    audit::write(&state.pool,Some(actor.id),"ingest.token_created","ingest_token",Some(id),Some(project_id),"Project-scoped ingestion token issued").await?;
    Ok((StatusCode::CREATED, Json(IssuedToken { token, credential })))
}

pub async fn revoke_token(State(state): State<AppState>, headers: HeaderMap, Path((project_id, token_id)): Path<(Uuid, Uuid)>) -> Result<StatusCode, ApiError> {
    auth::require_client_header(&headers)?;
    let actor = auth::current_user(&state, &headers).await?;
    auth::require_role(&actor, &["owner", "admin"])?;
    let affected = sqlx::query("UPDATE ingest_tokens SET revoked_at=NOW() WHERE id=$1 AND project_id=$2 AND revoked_at IS NULL")
        .bind(token_id).bind(project_id).execute(&state.pool).await?;
    if affected.rows_affected() == 0 { return Err(ApiError::not_found()); }
    audit::write(&state.pool,Some(actor.id),"ingest.token_revoked","ingest_token",Some(token_id),Some(project_id),"Ingestion token revoked").await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn authenticate_ingest(state: &AppState, headers: &HeaderMap) -> Result<Uuid, ApiError> {
    let raw = headers.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ")).ok_or_else(ApiError::unauthorized)?;
    if raw.len() != 67 || !raw.starts_with("bl_") || !raw[3..].bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::unauthorized());
    }
    let project_id: Option<Uuid> = sqlx::query_scalar("UPDATE ingest_tokens SET last_used_at=NOW() WHERE token_hash=$1 AND revoked_at IS NULL RETURNING project_id")
        .bind(hash_token(raw)).fetch_optional(&state.pool).await?;
    project_id.ok_or_else(ApiError::unauthorized)
}

#[derive(Deserialize)]
pub struct DeploymentEvent {
    pub delivery_id: String,
    pub external_id: String,
    pub environment: String,
    pub version: String,
    pub status: String,
    pub commit_sha: Option<String>,
    pub branch: Option<String>,
    pub description: Option<String>,
}
#[derive(Serialize)]
pub struct EventReceipt { pub deployment: Deployment, pub changed: bool }

pub async fn deployment_event(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<DeploymentEvent>) -> Result<Json<EventReceipt>, ApiError> {
    let project_id = authenticate_ingest(&state, &headers).await?;
    let delivery_id = check_text(&input.delivery_id, 1, 160, "Delivery ID must be 1–160 characters")?;
    let external_id = check_text(&input.external_id, 1, 160, "External ID must be 1–160 characters")?;
    let env_slug = check_text(&input.environment, 1, 70, "Environment slug is invalid")?;
    let version = check_text(&input.version, 1, 100, "Version must be 1–100 characters")?;
    let status = input.status.as_str();
    if !matches!(status, "pending" | "running" | "succeeded" | "failed" | "cancelled") {
        return Err(ApiError::bad_request("Invalid deployment status"));
    }
    let commit = input.commit_sha.as_deref().map(|v| check_text(v, 1, 64, "Commit SHA is too long")).transpose()?;
    let branch = input.branch.as_deref().map(|v| check_text(v, 1, 150, "Branch is too long")).transpose()?;
    let description = check_text(input.description.as_deref().unwrap_or(""), 0, 500, "Release notes are too long")?;
    let mut tx = state.pool.begin().await?;
    // Serialize event processing for a project across workers/instances.
    sqlx::query("SELECT id FROM projects WHERE id=$1 FOR UPDATE").bind(project_id).fetch_one(&mut *tx).await?;
    let prior: Option<Uuid> = sqlx::query_scalar("SELECT deployment_id FROM ingestion_events WHERE project_id=$1 AND delivery_id=$2")
        .bind(project_id).bind(&delivery_id).fetch_optional(&mut *tx).await?;
    if let Some(id) = prior {
        let deployment = sqlx::query_as::<_, Deployment>(&format!("{SELECT_DEPLOYMENTS} WHERE d.id=$1"))
            .bind(id).fetch_one(&mut *tx).await?;
        return Ok(Json(EventReceipt { deployment, changed: false }));
    }
    let env: Option<Uuid> = sqlx::query_scalar("SELECT id FROM environments WHERE project_id=$1 AND slug=$2")
        .bind(project_id).bind(env_slug).fetch_optional(&mut *tx).await?;
    let env = env.ok_or_else(|| ApiError::bad_request("Environment does not exist in this project"))?;
    let existing = sqlx::query("SELECT id,status,environment_id,version FROM deployments WHERE project_id=$1 AND external_id=$2 FOR UPDATE")
        .bind(project_id).bind(&external_id).fetch_optional(&mut *tx).await?;
    let (id, changed) = if let Some(row) = existing {
        let id: Uuid = row.try_get("id")?;
        let current: String = row.try_get("status")?;
        let prev_env: Uuid = row.try_get("environment_id")?;
        let prev_version: String = row.try_get("version")?;
        if prev_env != env || prev_version != version { return Err(ApiError::conflict("External deployment ID is already used for another release")); }
        if current == status { (id, false) }
        else {
            if !valid_transition(&current, status) { return Err(ApiError::conflict("Deployment is already terminal or transition is invalid")); }
            sqlx::query("UPDATE deployments SET status=$2,finished_at=CASE WHEN $2 IN ('succeeded','failed','cancelled') THEN NOW() ELSE NULL END WHERE id=$1")
                .bind(id).bind(status).execute(&mut *tx).await?;
            (id, true)
        }
    } else {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO deployments(id,project_id,environment_id,version,commit_sha,branch,description,triggered_by,status,external_id,source,finished_at) VALUES($1,$2,$3,$4,$5,$6,$7,'Pipeline',$8,$9,'pipeline',CASE WHEN $8 IN ('succeeded','failed','cancelled') THEN NOW() ELSE NULL END)")
            .bind(id).bind(project_id).bind(env).bind(&version).bind(commit).bind(branch).bind(description).bind(status).bind(&external_id)
            .execute(&mut *tx).await?;
        (id, true)
    };
    sqlx::query("INSERT INTO ingestion_events(project_id,delivery_id,deployment_id,status) VALUES($1,$2,$3,$4)")
        .bind(project_id).bind(delivery_id).bind(id).bind(status).execute(&mut *tx).await?;
    if changed {
        sqlx::query("INSERT INTO activities(action,entity_type,entity_id,detail) VALUES ('deployment.ingested','deployment',$1,$2)")
            .bind(id).bind(format!("Pipeline event: {status}")).execute(&mut *tx).await?;
    }
    let incident_changed=if changed && status=="failed" {
        incident_engine::deployment_failed(&mut tx,&state,id,project_id,env,&version).await?
    } else {false};
    let deployment = sqlx::query_as::<_, Deployment>(&format!("{SELECT_DEPLOYMENTS} WHERE d.id=$1"))
        .bind(id).fetch_one(&mut *tx).await?;
    if changed {audit::in_tx(&mut tx,None,"deployment.ingested","deployment",Some(id),Some(project_id),
        &format!("Pipeline reported deployment status {}",status)).await?;}
    tx.commit().await?;
    if changed { state.publish("deployment.ingested", Some(project_id)); }
    if incident_changed {state.publish("incident.changed",Some(project_id));}
    Ok(Json(EventReceipt { deployment, changed }))
}

#[derive(Deserialize)]
pub struct ApiSample { pub route: String, pub method: String, pub status_code: i32, pub latency_ms: i32 }
#[derive(Deserialize)]
pub struct ApiBatch { pub environment: String, pub samples: Vec<ApiSample> }
#[derive(Serialize)]
pub struct Accepted { pub accepted: usize }

fn validate_sample(s: &ApiSample) -> Result<(), ApiError> {
    if s.route.len() > 160 || !s.route.starts_with('/') || s.route.contains('?') || s.route.contains('#') || s.route.chars().any(char::is_control) {
        return Err(ApiError::bad_request("Route must be a normalized path of 160 characters or less"));
    }
    if !matches!(s.method.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS") {
        return Err(ApiError::bad_request("Invalid HTTP method"));
    }
    if !(100..=599).contains(&s.status_code) || !(0..=600000).contains(&s.latency_ms) {
        return Err(ApiError::bad_request("Invalid status code or request latency"));
    }
    Ok(())
}

pub async fn metrics(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<ApiBatch>) -> Result<(StatusCode, Json<Accepted>), ApiError> {
    let project_id = authenticate_ingest(&state, &headers).await?;
    if input.samples.is_empty() || input.samples.len() > 100 { return Err(ApiError::bad_request("Send 1–100 samples per batch")); }
    for sample in &input.samples { validate_sample(sample)?; }
    let env: Option<Uuid> = sqlx::query_scalar("SELECT id FROM environments WHERE project_id=$1 AND slug=$2")
        .bind(project_id).bind(&input.environment).fetch_optional(&state.pool).await?;
    let env = env.ok_or_else(|| ApiError::bad_request("Environment does not exist in this project"))?;
    let mut tx = state.pool.begin().await?;
    for sample in &input.samples {
        sqlx::query("INSERT INTO api_samples(project_id,environment_id,route,method,status_code,latency_ms) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(project_id).bind(env).bind(&sample.route).bind(&sample.method).bind(sample.status_code).bind(sample.latency_ms)
            .execute(&mut *tx).await?;
    }
    tx.commit().await?;
    state.publish("metrics.ingested", Some(project_id));
    Ok((StatusCode::ACCEPTED, Json(Accepted { accepted: input.samples.len() })))
}

#[derive(Deserialize)]
pub struct PerformanceFilter { pub project_id: Option<Uuid>, pub hours: Option<i32> }
#[derive(Serialize, FromRow)]
pub struct RequestMetrics {
    pub requests: i64,
    pub errors: i64,
    pub avg_latency_ms: Option<f64>,
    pub p95_latency_ms: Option<f64>,
}
#[derive(Serialize, FromRow)]
pub struct HourPoint {
    pub bucket: DateTime<Utc>,
    pub requests: i64,
    pub errors: i64,
    pub avg_latency_ms: Option<f64>,
}
#[derive(Serialize, FromRow)]
pub struct RoutePoint {
    pub route: String,
    pub method: String,
    pub requests: i64,
    pub errors: i64,
    pub avg_latency_ms: Option<f64>,
}
#[derive(Serialize)]
pub struct Performance { pub hours: i32, pub metrics: RequestMetrics, pub trend: Vec<HourPoint>, pub routes: Vec<RoutePoint> }

pub async fn performance(State(state): State<AppState>, headers: HeaderMap, Query(filter): Query<PerformanceFilter>) -> Result<Json<Performance>, ApiError> {
    auth::current_user(&state, &headers).await?;
    let hours = filter.hours.unwrap_or(24).clamp(1, 168);
    let metrics = sqlx::query_as::<_, RequestMetrics>("SELECT COUNT(*)::bigint AS requests,COUNT(*) FILTER (WHERE status_code>=500)::bigint AS errors,AVG(latency_ms)::float8 AS avg_latency_ms,PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms)::float8 AS p95_latency_ms FROM api_samples WHERE ($1::uuid IS NULL OR project_id=$1) AND observed_at>NOW()-($2::int*INTERVAL '1 hour')")
        .bind(filter.project_id).bind(hours).fetch_one(&state.pool).await?;
    let trend = sqlx::query_as::<_, HourPoint>("SELECT DATE_TRUNC('hour',observed_at) AS bucket,COUNT(*)::bigint AS requests,COUNT(*) FILTER (WHERE status_code>=500)::bigint AS errors,AVG(latency_ms)::float8 AS avg_latency_ms FROM api_samples WHERE ($1::uuid IS NULL OR project_id=$1) AND observed_at>NOW()-($2::int*INTERVAL '1 hour') GROUP BY 1 ORDER BY 1")
        .bind(filter.project_id).bind(hours).fetch_all(&state.pool).await?;
    let routes = sqlx::query_as::<_, RoutePoint>("SELECT route,method,COUNT(*)::bigint AS requests,COUNT(*) FILTER (WHERE status_code>=500)::bigint AS errors,AVG(latency_ms)::float8 AS avg_latency_ms FROM api_samples WHERE ($1::uuid IS NULL OR project_id=$1) AND observed_at>NOW()-($2::int*INTERVAL '1 hour') GROUP BY route,method ORDER BY requests DESC LIMIT 12")
        .bind(filter.project_id).bind(hours).fetch_all(&state.pool).await?;
    Ok(Json(Performance { hours, metrics, trend, routes }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metric_validation() {
        let good = ApiSample { route: "/api/users/:id".into(), method: "GET".into(), status_code: 200, latency_ms: 120 };
        assert!(validate_sample(&good).is_ok());
        let bad = ApiSample { route: "http://internal/?token=s".into(), method: "GET".into(), status_code: 200, latency_ms: 10 };
        assert!(validate_sample(&bad).is_err());
    }
    #[test]
    fn token_generation() {
        assert_eq!(make_token().len(), 67);
        assert_ne!(make_token(), make_token());
    }
}
