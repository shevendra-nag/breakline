use axum::{extract::{Path, Query, State}, http::{HeaderMap, StatusCode}, Json};
use serde::Deserialize;
use uuid::Uuid;

use crate::{audit,auth, incident_engine, error::ApiError, models::Deployment, validation::{check_text, valid_transition}, AppState};

pub(crate) const SELECT_DEPLOYMENTS: &str = "SELECT d.id,d.project_id,d.environment_id,p.name AS project_name,e.name AS environment_name,d.version,d.commit_sha,d.branch,d.triggered_by,d.description,d.status,d.started_at,d.finished_at,d.created_at FROM deployments d JOIN projects p ON p.id=d.project_id JOIN environments e ON e.id=d.environment_id";

#[derive(Deserialize)]
pub struct Pagination { pub limit: Option<i64>, pub offset: Option<i64> }
impl Pagination {
    pub fn values(&self) -> (i64, i64) { (self.limit.unwrap_or(30).clamp(1, 100), self.offset.unwrap_or(0).clamp(0, 100_000)) }
}

#[derive(Deserialize)]
pub struct CreateDeployment {
    pub environment_id: Uuid,
    pub version: String,
    pub commit_sha: Option<String>,
    pub branch: Option<String>,
    pub description: Option<String>,
}
#[derive(Deserialize)]
pub struct SetStatus { pub status: String }

pub async fn list_all(State(state): State<AppState>, headers: HeaderMap, Query(pagination): Query<Pagination>) -> Result<Json<Vec<Deployment>>, ApiError> {
    auth::current_user(&state, &headers).await?;
    let (limit, offset) = pagination.values();
    let query = format!("{SELECT_DEPLOYMENTS} ORDER BY d.created_at DESC LIMIT $1 OFFSET $2");
    let result = sqlx::query_as::<_, Deployment>(&query).bind(limit).bind(offset).fetch_all(&state.pool).await?;
    Ok(Json(result))
}

pub async fn list_for_project(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<Uuid>, Query(pagination): Query<Pagination>) -> Result<Json<Vec<Deployment>>, ApiError> {
    auth::current_user(&state, &headers).await?;
    let (limit, offset) = pagination.values();
    let exists: Option<Uuid> = sqlx::query_scalar("SELECT id FROM projects WHERE id=$1").bind(id).fetch_optional(&state.pool).await?;
    if exists.is_none() { return Err(ApiError::not_found()); }
    let query = format!("{SELECT_DEPLOYMENTS} WHERE d.project_id=$1 ORDER BY d.created_at DESC LIMIT $2 OFFSET $3");
    let result = sqlx::query_as::<_, Deployment>(&query).bind(id).bind(limit).bind(offset).fetch_all(&state.pool).await?;
    Ok(Json(result))
}

pub async fn create(State(state): State<AppState>, headers: HeaderMap, Path(project_id): Path<Uuid>, Json(input): Json<CreateDeployment>) -> Result<(StatusCode, Json<Deployment>), ApiError> {
    auth::require_client_header(&headers)?;
    let actor = auth::current_user(&state, &headers).await?;
    auth::require_role(&actor, &["owner", "admin", "operator"])?;
    let version = check_text(&input.version, 1, 100, "Version must be 1–100 characters")?;
    let commit = input.commit_sha.as_ref().map(|v| check_text(v, 1, 64, "Commit SHA is too long")).transpose()?;
    let branch = input.branch.as_ref().map(|v| check_text(v, 1, 150, "Branch is too long")).transpose()?;
    let description = check_text(input.description.as_deref().unwrap_or(""), 0, 500, "Description exceeds 500 characters")?;
    let valid_env: Option<Uuid> = sqlx::query_scalar("SELECT id FROM environments WHERE id=$1 AND project_id=$2")
        .bind(input.environment_id).bind(project_id).fetch_optional(&state.pool).await?;
    if valid_env.is_none() { return Err(ApiError::bad_request("Select an environment for this project")); }
    let id = Uuid::new_v4();
    let mut tx = state.pool.begin().await?;
    sqlx::query("INSERT INTO deployments(id,project_id,environment_id,version,commit_sha,branch,description,triggered_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(id).bind(project_id).bind(input.environment_id).bind(version).bind(commit).bind(branch).bind(description).bind(&actor.name)
        .execute(&mut *tx).await?;
    sqlx::query("INSERT INTO activities(actor_id,action,entity_type,entity_id,detail) VALUES($1,'deployment.created','deployment',$2,$3)")
        .bind(actor.id).bind(id).bind("Started a new deployment").execute(&mut *tx).await?;
    let query = format!("{SELECT_DEPLOYMENTS} WHERE d.id=$1");
    let result = sqlx::query_as::<_, Deployment>(&query).bind(id).fetch_one(&mut *tx).await?;
    audit::in_tx(&mut tx,Some(actor.id),"deployment.created","deployment",Some(id),Some(project_id),"Deployment started").await?;
    tx.commit().await?;
    state.publish("deployment.created", Some(project_id));
    Ok((StatusCode::CREATED, Json(result)))
}

pub async fn change_status(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<Uuid>, Json(input): Json<SetStatus>) -> Result<Json<Deployment>, ApiError> {
    auth::require_client_header(&headers)?;
    let actor = auth::current_user(&state, &headers).await?;
    auth::require_role(&actor, &["owner", "admin", "operator"])?;
    let mut tx = state.pool.begin().await?;
    let current: Option<(String,Uuid,Uuid,String)> = sqlx::query_as("SELECT status,project_id,environment_id,version FROM deployments WHERE id=$1 FOR UPDATE")
        .bind(id).fetch_optional(&mut *tx).await?;
    let (current,project_id,environment_id,version) = current.ok_or_else(ApiError::not_found)?;
    if !valid_transition(&current, &input.status) { return Err(ApiError::bad_request("This status transition is not allowed")); }
    sqlx::query("UPDATE deployments SET status=$2,finished_at=CASE WHEN $2 IN ('succeeded','failed','cancelled') THEN NOW() ELSE NULL END WHERE id=$1")
        .bind(id).bind(&input.status).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO activities(actor_id,action,entity_type,entity_id,detail) VALUES($1,'deployment.status_changed','deployment',$2,$3)")
        .bind(actor.id).bind(id).bind(format!("Deployment marked {}", input.status)).execute(&mut *tx).await?;
    let incident_changed=if input.status=="failed" {
        incident_engine::deployment_failed(&mut tx,&state,id,project_id,environment_id,&version).await?
    } else {false};
    let query = format!("{SELECT_DEPLOYMENTS} WHERE d.id=$1");
    let result = sqlx::query_as::<_, Deployment>(&query).bind(id).fetch_one(&mut *tx).await?;
    audit::in_tx(&mut tx,Some(actor.id),"deployment.status_changed","deployment",Some(id),Some(project_id),
        &format!("Deployment moved to {}",input.status)).await?;
    tx.commit().await?;
    state.publish("deployment.updated", Some(result.project_id));
    if incident_changed {state.publish("incident.changed",Some(project_id));}
    Ok(Json(result))
}
