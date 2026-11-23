use axum::{extract::{Path, State}, http::{HeaderMap, StatusCode}, Json};
use serde::Deserialize;
use uuid::Uuid;

use crate::{audit,auth, error::ApiError, models::{Environment, Project}, validation::{check_text, slugify}, AppState};

#[derive(Deserialize)]
pub struct CreateProject { pub name: String, pub description: Option<String>, pub repository_url: Option<String> }
#[derive(Deserialize)]
pub struct UpdateProject { pub name: Option<String>, pub description: Option<String>, pub repository_url: Option<String> }
#[derive(Deserialize)]
pub struct CreateEnvironment { pub name: String, pub is_production: Option<bool> }

fn repository_url(value: Option<&str>) -> Result<Option<String>, ApiError> {
    match value.map(str::trim).filter(|v| !v.is_empty()) {
        Some(url) if url.len() <= 512 && (url.starts_with("https://") || url.starts_with("http://")) => Ok(Some(url.to_owned())),
        Some(_) => Err(ApiError::bad_request("Repository URL must begin with https:// or http://")),
        None => Ok(None),
    }
}

pub async fn list(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Vec<Project>>, ApiError> {
    auth::current_user(&state, &headers).await?;
    let projects = sqlx::query_as::<_, Project>("SELECT id,name,slug,description,repository_url,created_at,updated_at FROM projects ORDER BY updated_at DESC")
        .fetch_all(&state.pool).await?;
    Ok(Json(projects))
}

pub async fn get(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Project>, ApiError> {
    auth::current_user(&state, &headers).await?;
    let project = sqlx::query_as::<_, Project>("SELECT id,name,slug,description,repository_url,created_at,updated_at FROM projects WHERE id=$1")
        .bind(id).fetch_optional(&state.pool).await?.ok_or_else(ApiError::not_found)?;
    Ok(Json(project))
}

pub async fn create(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<CreateProject>) -> Result<(StatusCode, Json<Project>), ApiError> {
    auth::require_client_header(&headers)?;
    let actor = auth::current_user(&state, &headers).await?;
    auth::require_role(&actor, &["owner", "admin", "operator"])?;
    let name = check_text(&input.name, 2, 100, "Project name must be 2–100 characters")?;
    let slug = slugify(&name, 80);
    if slug.len() < 2 { return Err(ApiError::bad_request("Project name must contain at least two Latin letters or digits")); }
    let description = check_text(input.description.as_deref().unwrap_or(""), 0, 500, "Description exceeds 500 characters")?;
    let repo = repository_url(input.repository_url.as_deref())?;
    let id = Uuid::new_v4();
    let mut tx = state.pool.begin().await?;
    let project = sqlx::query_as::<_, Project>("INSERT INTO projects(id,name,slug,description,repository_url,created_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,name,slug,description,repository_url,created_at,updated_at")
        .bind(id).bind(name).bind(slug).bind(description).bind(repo).bind(actor.id)
        .fetch_one(&mut *tx).await?;
    for (label, key, production) in [("Production", "production", true), ("Staging", "staging", false)] {
        sqlx::query("INSERT INTO environments(id,project_id,name,slug,is_production) VALUES ($1,$2,$3,$4,$5)")
            .bind(Uuid::new_v4()).bind(id).bind(label).bind(key).bind(production)
            .execute(&mut *tx).await?;
    }
    sqlx::query("INSERT INTO activities(actor_id, action, entity_type,entity_id,detail) VALUES ($1,'project.created','project',$2,$3)")
        .bind(actor.id).bind(id).bind(format!("Created project {}", project.name)).execute(&mut *tx).await?;
    audit::in_tx(&mut tx,Some(actor.id),"project.created","project",Some(id),Some(id),"Project created").await?;
    tx.commit().await?;
    state.publish("project.created", Some(id));
    Ok((StatusCode::CREATED, Json(project)))
}

pub async fn update(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<Uuid>, Json(input): Json<UpdateProject>) -> Result<Json<Project>, ApiError> {
    auth::require_client_header(&headers)?;
    let actor = auth::current_user(&state, &headers).await?;
    auth::require_role(&actor, &["owner", "admin", "operator"])?;
    let name = input.name.as_ref().map(|n| check_text(n, 2, 100, "Project name must be 2–100 characters")).transpose()?;
    let description = input.description.as_ref().map(|d| check_text(d, 0, 500, "Description exceeds 500 characters")).transpose()?;
    let repo = input.repository_url.as_deref().map(|r| repository_url(Some(r))).transpose()?;
    let mut tx=state.pool.begin().await?;
    let project = sqlx::query_as::<_, Project>("UPDATE projects SET name=COALESCE($2,name),description=COALESCE($3,description),repository_url=CASE WHEN $4::boolean THEN $5 ELSE repository_url END,updated_at=NOW() WHERE id=$1 RETURNING id,name,slug,description,repository_url,created_at,updated_at")
        .bind(id).bind(name).bind(description).bind(input.repository_url.is_some()).bind(repo.flatten())
        .fetch_optional(&mut *tx).await?.ok_or_else(ApiError::not_found)?;
    audit::in_tx(&mut tx,Some(actor.id),"project.updated","project",Some(id),Some(id),"Project settings updated").await?;
    tx.commit().await?;
    state.publish("project.updated",Some(id));
    Ok(Json(project))
}

pub async fn remove(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<StatusCode, ApiError> {
    auth::require_client_header(&headers)?;
    let actor = auth::current_user(&state, &headers).await?;
    auth::require_role(&actor, &["owner", "admin"])?;
    let mut tx=state.pool.begin().await?;
    let project:Option<String>=sqlx::query_scalar("DELETE FROM projects WHERE id=$1 RETURNING name")
        .bind(id).fetch_optional(&mut *tx).await?;
    let name=project.ok_or_else(ApiError::not_found)?;
    audit::in_tx(&mut tx,Some(actor.id),"project.deleted","project",Some(id),Some(id),&format!("Deleted project {}",name)).await?;
    tx.commit().await?;
    state.publish("project.deleted",Some(id));
    Ok(StatusCode::NO_CONTENT)
}

pub async fn environments(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Vec<Environment>>, ApiError> {
    auth::current_user(&state, &headers).await?;
    let project: Option<Uuid> = sqlx::query_scalar("SELECT id FROM projects WHERE id=$1").bind(id).fetch_optional(&state.pool).await?;
    if project.is_none() { return Err(ApiError::not_found()); }
    let result = sqlx::query_as::<_, Environment>("SELECT id,project_id,name,slug,is_production,created_at FROM environments WHERE project_id=$1 ORDER BY is_production DESC, name ASC")
        .bind(id).fetch_all(&state.pool).await?;
    Ok(Json(result))
}

pub async fn create_environment(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<Uuid>, Json(input): Json<CreateEnvironment>) -> Result<(StatusCode, Json<Environment>), ApiError> {
    auth::require_client_header(&headers)?;
    let actor = auth::current_user(&state, &headers).await?;
    auth::require_role(&actor, &["owner", "admin", "operator"])?;
    let name = check_text(&input.name, 2, 70, "Environment name must be 2–70 characters")?;
    let slug = slugify(&name, 70);
    if slug.len() < 2 { return Err(ApiError::bad_request("Environment name must include letters or digits")); }
    let project: Option<Uuid> = sqlx::query_scalar("SELECT id FROM projects WHERE id=$1").bind(id).fetch_optional(&state.pool).await?;
    if project.is_none() { return Err(ApiError::not_found()); }
    let mut tx=state.pool.begin().await?;
    let result = sqlx::query_as::<_, Environment>("INSERT INTO environments(id,project_id,name,slug,is_production) VALUES ($1,$2,$3,$4,$5) RETURNING id,project_id,name,slug,is_production,created_at")
        .bind(Uuid::new_v4()).bind(id).bind(name).bind(slug).bind(input.is_production.unwrap_or(false))
        .fetch_one(&mut *tx).await?;
    audit::in_tx(&mut tx,Some(actor.id),"environment.created","environment",Some(result.id),Some(id),"Environment created").await?;
    tx.commit().await?;
    state.publish("environment.created",Some(id));
    Ok((StatusCode::CREATED, Json(result)))
}
