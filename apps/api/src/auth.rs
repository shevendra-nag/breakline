use argon2::{password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString}, Argon2};
use axum::{http::{header, HeaderMap, HeaderValue}, response::AppendHeaders};
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{error::ApiError, models::User, AppState};

const COOKIE_NAME: &str = "breakline_session";

pub fn require_client_header(headers: &HeaderMap) -> Result<(), ApiError> {
    if headers.get("x-breakline-client").and_then(|h| h.to_str().ok()) == Some("web") {
        Ok(())
    } else {
        Err(ApiError::forbidden())
    }
}

pub fn verify_bootstrap_token(state: &AppState, token: &str) -> Result<(), ApiError> {
    let hash = Sha256::digest(token.as_bytes());
    if hash.as_slice().ct_eq(state.bootstrap_token_hash.as_slice()).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(ApiError::forbidden())
    }
}

pub fn hash_password(input: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default().hash_password(input.as_bytes(), &salt)
        .map(|value| value.to_string())
        .map_err(|_| ApiError::bad_request("Unable to process password"))
}

pub fn verify_password(hash: &str, input: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default().verify_password(input.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

fn session_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn token_hash(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

pub async fn open_session(state: &AppState, user_id: Uuid) -> Result<AppendHeaders<[(header::HeaderName, HeaderValue); 1]>, ApiError> {
    let token = session_token();
    sqlx::query("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1,$2,$3)")
        .bind(token_hash(&token))
        .bind(user_id)
        .bind(Utc::now() + Duration::days(state.session_days))
        .execute(&state.pool).await?;
    let mut cookie = format!("{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}", state.session_days * 86_400);
    if state.cookie_secure { cookie.push_str("; Secure"); }
    let value = HeaderValue::from_str(&cookie).map_err(|_| ApiError::bad_request("Invalid cookie"))?;
    Ok(AppendHeaders([(header::SET_COOKIE, value)]))
}

pub fn clear_session_cookie(state: &AppState) -> AppendHeaders<[(header::HeaderName, HeaderValue); 1]> {
    let mut cookie = format!("{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    if state.cookie_secure { cookie.push_str("; Secure"); }
    AppendHeaders([(header::SET_COOKIE, HeaderValue::from_str(&cookie).expect("cookie is ASCII"))])
}

fn extract_token(headers: &HeaderMap) -> Option<String> {
    headers.get(header::COOKIE)?.to_str().ok()?.split(';').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        (name == COOKIE_NAME && value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| value.to_owned())
    })
}

pub async fn current_user(state: &AppState, headers: &HeaderMap) -> Result<User, ApiError> {
    let token = extract_token(headers).ok_or_else(ApiError::unauthorized)?;
    let query = "SELECT u.id, u.name, u.email, u.role, u.created_at FROM users u JOIN sessions s ON s.user_id = u.id WHERE s.token_hash = $1 AND s.expires_at > NOW()";
    sqlx::query_as::<_, User>(query)
        .bind(token_hash(&token))
        .fetch_optional(&state.pool).await?
        .ok_or_else(ApiError::unauthorized)
}

pub async fn revoke_session(pool: &PgPool, headers: &HeaderMap) -> Result<(), ApiError> {
    if let Some(token) = extract_token(headers) {
        sqlx::query("DELETE FROM sessions WHERE token_hash=$1")
            .bind(token_hash(&token)).execute(pool).await?;
    }
    Ok(())
}

pub fn require_role(user: &User, allowed: &[&str]) -> Result<(), ApiError> {
    if allowed.contains(&user.role.as_str()) { Ok(()) } else { Err(ApiError::forbidden()) }
}

pub fn validate_email(email: &str) -> Result<String, ApiError> {
    let value = email.trim().to_ascii_lowercase();
    if value.len() > 254 || value.len() < 5 || value.contains(' ') || value.matches('@').count() != 1
        || value.starts_with('@') || !value.split('@').last().unwrap_or("").contains('.') {
        return Err(ApiError::bad_request("Enter a valid email address"));
    }
    Ok(value)
}

pub fn validate_password(password: &str) -> Result<(), ApiError> {
    if password.chars().count() < 12 || password.len() > 256 {
        return Err(ApiError::bad_request("Password must contain 12–256 characters"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn passwords_are_hashed_and_verified() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(!hash.contains("correct horse"));
        assert!(verify_password(&hash, "correct horse battery staple"));
        assert!(!verify_password(&hash, "wrong password"));
    }
    #[test]
    fn tokens_are_unpredictable() {
        let first = session_token();
        let second = session_token();
        assert_ne!(first, second);
        assert_eq!(first.len(), 64);
    }
}
