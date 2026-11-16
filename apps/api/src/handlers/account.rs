use axum::{extract::State, http::{HeaderMap, StatusCode}, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use sha2::{Digest,Sha256};
use uuid::Uuid;

use crate::{audit, auth, error::ApiError, models::User, validation::check_text, AppState};

#[derive(Deserialize)]
pub struct SetupInput { pub name: String, pub email: String, pub password: String, pub setup_token: String }
#[derive(Deserialize)]
pub struct LoginInput { pub email: String, pub password: String }
#[derive(Deserialize)]
pub struct CreateUserInput { pub name: String, pub email: String, pub password: String, pub role: String }
#[derive(Serialize)]
pub struct SetupStatus { pub needs_setup: bool }

pub async fn setup_status(State(state): State<AppState>) -> Result<Json<SetupStatus>, ApiError> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users").fetch_one(&state.pool).await?;
    Ok(Json(SetupStatus { needs_setup: count == 0 }))
}

pub async fn setup(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<SetupInput>) -> Result<impl IntoResponse, ApiError> {
    auth::require_client_header(&headers)?;
    auth::verify_bootstrap_token(&state, &input.setup_token)?;
    let name = check_text(&input.name, 2, 80, "Name must be 2–80 characters")?;
    let email = auth::validate_email(&input.email)?;
    auth::validate_password(&input.password)?;
    let password_hash = auth::hash_password(&input.password)?;
    let mut tx = state.pool.begin().await?;
    // Serializes concurrent first-admin creation requests, including multiple instances.
    sqlx::query("SELECT pg_advisory_xact_lock(764281905)").fetch_one(&mut *tx).await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users").fetch_one(&mut *tx).await?;
    if count != 0 { return Err(ApiError::conflict("Workspace has already been initialized")); }
    let id = Uuid::new_v4();
    let user = sqlx::query_as::<_, User>("INSERT INTO users (id,name,email,password_hash,role) VALUES ($1,$2,$3,$4,'owner') RETURNING id,name,email,role,created_at")
        .bind(id).bind(name).bind(email).bind(password_hash)
        .fetch_one(&mut *tx).await?;
    audit::in_tx(&mut tx,Some(id),"workspace.initialized","user",Some(id),None,"Initial workspace owner created").await?;
    tx.commit().await?;
    let cookie = auth::open_session(&state, id).await?;
    Ok((StatusCode::CREATED, cookie, Json(user)))
}

pub async fn login(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<LoginInput>) -> Result<impl IntoResponse, ApiError> {
    auth::require_client_header(&headers)?;
    let email = auth::validate_email(&input.email)?;
    // A database-backed limit survives restarts and works across API instances.
    // Hash the normalized identifier to avoid storing repeated login targets.
    let bucket = format!("{:x}",Sha256::digest(email.as_bytes()));
    let attempts:i32=sqlx::query_scalar(r#"INSERT INTO login_rate_limits(identifier_hash,attempts)
        VALUES($1,1) ON CONFLICT(identifier_hash) DO UPDATE SET
        attempts=CASE WHEN login_rate_limits.window_started_at < NOW()-INTERVAL '15 minutes'
            THEN 1 ELSE login_rate_limits.attempts+1 END,
        window_started_at=CASE WHEN login_rate_limits.window_started_at < NOW()-INTERVAL '15 minutes'
            THEN NOW() ELSE login_rate_limits.window_started_at END
        RETURNING attempts"#).bind(&bucket).fetch_one(&state.pool).await?;
    if attempts>8 {return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS,"rate_limited","Too many sign-in attempts. Try again in 15 minutes"));}
    let row = sqlx::query("SELECT id, name, email, role, created_at, password_hash FROM users WHERE email=$1")
        .bind(&email).fetch_optional(&state.pool).await?;
    // Unknown accounts take a password-hashing step too, reducing timing-based
    // email enumeration. A provider-level rate limit is also recommended.
    let verified=match &row {
        Some(row) => {
            let stored:String=row.try_get("password_hash")?;
            auth::verify_password(&stored,&input.password)
        }
        None => { let _=auth::hash_password("breakline-constant-fallback-password");false }
    };
    if !verified {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED,"invalid_credentials","Invalid email or password"));
    }
    let row = row.expect("verified accounts exist");
    sqlx::query("DELETE FROM login_rate_limits WHERE identifier_hash=$1")
        .bind(&bucket).execute(&state.pool).await?;
    let user = User {
        id: row.try_get("id")?, name: row.try_get("name")?, email: row.try_get("email")?,
        role: row.try_get("role")?, created_at: row.try_get("created_at")?,
    };
    let cookie = auth::open_session(&state, user.id).await?;
    audit::write(&state.pool,Some(user.id),"auth.login","user",Some(user.id),None,"User signed in").await?;
    Ok((cookie, Json(user)))
}

pub async fn me(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<User>, ApiError> {
    Ok(Json(auth::current_user(&state, &headers).await?))
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Result<impl IntoResponse, ApiError> {
    auth::require_client_header(&headers)?;
    if let Ok(user)=auth::current_user(&state,&headers).await {
        audit::write(&state.pool,Some(user.id),"auth.logout","user",Some(user.id),None,"User signed out").await?;
    }
    auth::revoke_session(&state.pool, &headers).await?;
    Ok((auth::clear_session_cookie(&state), StatusCode::NO_CONTENT))
}

pub async fn list_users(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Vec<User>>, ApiError> {
    let actor = auth::current_user(&state, &headers).await?;
    auth::require_role(&actor, &["owner", "admin"])?;
    let users = sqlx::query_as::<_, User>("SELECT id,name,email,role,created_at FROM users ORDER BY created_at ASC")
        .fetch_all(&state.pool).await?;
    Ok(Json(users))
}

pub async fn create_user(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<CreateUserInput>) -> Result<impl IntoResponse, ApiError> {
    auth::require_client_header(&headers)?;
    let actor = auth::current_user(&state, &headers).await?;
    auth::require_role(&actor, &["owner", "admin"])?;
    let allowed = match actor.role.as_str() {
        "owner" => ["admin", "operator", "viewer"].contains(&input.role.as_str()),
        _ => ["operator", "viewer"].contains(&input.role.as_str()),
    };
    if !allowed { return Err(ApiError::forbidden()); }
    let name = check_text(&input.name, 2, 80, "Name must be 2–80 characters")?;
    let email = auth::validate_email(&input.email)?;
    auth::validate_password(&input.password)?;
    let hash = auth::hash_password(&input.password)?;
    let id = Uuid::new_v4();
    let user = sqlx::query_as::<_, User>("INSERT INTO users (id,name,email,password_hash,role) VALUES ($1,$2,$3,$4,$5) RETURNING id,name,email,role,created_at")
        .bind(id).bind(name).bind(email).bind(hash).bind(input.role)
        .fetch_one(&state.pool).await?;
    audit::write(&state.pool,Some(actor.id),"team.member_created","user",Some(id),None,"Team account created").await?;
    Ok((StatusCode::CREATED, Json(user)))
}
