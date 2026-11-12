mod alerting;
mod audit;
mod auth;
mod incident_engine;
mod error;
mod handlers;
mod models;
mod monitor_url;
mod validation;
mod worker;

use anyhow::{anyhow, Context, Result};
use axum::{extract::State, http::{StatusCode,Method,header}, middleware::{self,Next}, response::Response, routing::{get, post}, Json, Router};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use std::{env, net::SocketAddr, time::Duration};
use tokio::{net::TcpListener, sync::broadcast};
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};

#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::PgPool,
    pub bootstrap_token_hash: [u8; 32],
    pub cookie_secure: bool,
    pub session_days: i64,
    pub events: broadcast::Sender<String>,
    pub alerts: alerting::AlertConfig,
    pub allowed_origin: Option<String>,
}

impl AppState {
    pub fn publish(&self, kind: &str, project_id: Option<uuid::Uuid>) {
        let data = json!({"type": kind, "project_id": project_id, "at": chrono::Utc::now()});
        let _ = self.events.send(data.to_string());
    }
}

fn routes(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/health", get(|| async { (StatusCode::OK, Json(json!({"status":"ok","service":"breakline-api"}))) }))
        .route("/api/v1/health/ready", get(readiness))
        .route("/api/v1/auth/status", get(handlers::account::setup_status))
        .route("/api/v1/auth/setup", post(handlers::account::setup))
        .route("/api/v1/auth/login", post(handlers::account::login))
        .route("/api/v1/auth/me", get(handlers::account::me))
        .route("/api/v1/auth/logout", post(handlers::account::logout))
        .route("/api/v1/users", get(handlers::account::list_users).post(handlers::account::create_user))
        .route("/api/v1/overview", get(handlers::overview::get))
        .route("/api/v1/analytics", get(handlers::analytics::get))
        .route("/api/v1/audit", get(handlers::governance::audit_log))
        .route("/api/v1/alerts/silences", get(handlers::governance::silences).post(handlers::governance::create_silence))
        .route("/api/v1/alerts/silences/{id}/revoke", post(handlers::governance::revoke_silence))
        .route("/api/v1/alerts/deliveries/{id}/retry", post(handlers::governance::retry_delivery))
        .route("/api/v1/projects", get(handlers::projects::list).post(handlers::projects::create))
        .route("/api/v1/projects/{id}", get(handlers::projects::get).patch(handlers::projects::update).delete(handlers::projects::remove))
        .route("/api/v1/projects/{id}/environments", get(handlers::projects::environments).post(handlers::projects::create_environment))
        .route("/api/v1/projects/{id}/deployments", get(handlers::deployments::list_for_project).post(handlers::deployments::create))
        .route("/api/v1/deployments", get(handlers::deployments::list_all))
        .route("/api/v1/deployments/{id}/status", axum::routing::patch(handlers::deployments::change_status))
        .route("/api/v1/monitors", get(handlers::monitoring::list).post(handlers::monitoring::create))
        .route("/api/v1/monitors/summary", get(handlers::monitoring::summary))
        .route("/api/v1/monitors/{id}", axum::routing::patch(handlers::monitoring::update).delete(handlers::monitoring::remove))
        .route("/api/v1/monitors/{id}/checks", get(handlers::monitoring::checks))
        .route("/api/v1/monitors/{id}/run", post(handlers::monitoring::run_now))
        .route("/api/v1/performance", get(handlers::ingest::performance))
        .route("/api/v1/projects/{id}/ingest-tokens", get(handlers::ingest::list_tokens).post(handlers::ingest::new_token))
        .route("/api/v1/projects/{id}/ingest-tokens/{token_id}", axum::routing::delete(handlers::ingest::revoke_token))
        .route("/api/v1/ingest/deployments", post(handlers::ingest::deployment_event))
        .route("/api/v1/ingest/metrics", post(handlers::ingest::metrics))
        .route("/api/v1/incidents", get(handlers::incidents::list))
        .route("/api/v1/incidents/summary", get(handlers::incidents::summary))
        .route("/api/v1/incidents/{id}", get(handlers::incidents::get))
        .route("/api/v1/incidents/{id}/acknowledge", post(handlers::incidents::acknowledge))
        .route("/api/v1/incidents/{id}/resolve", post(handlers::incidents::resolve))
        .route("/api/v1/incidents/{id}/comments", post(handlers::incidents::comment))
        .route("/api/v1/projects/{id}/incident-rules", get(handlers::incidents::rules).put(handlers::incidents::update_rules))
        .route("/api/v1/alerts/channels", get(handlers::incidents::channels))
        .route("/api/v1/alerts/deliveries", get(handlers::incidents::deliveries))
        .route("/api/v1/events", get(handlers::stream::subscribe))
        .layer(RequestBodyLimitLayer::new(64 * 1024))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn_with_state(state.clone(), check_origin))
        .with_state(state)
}

async fn readiness(State(state):State<AppState>)->(StatusCode,Json<serde_json::Value>){
    match sqlx::query_scalar::<_,i32>("SELECT 1").fetch_one(&state.pool).await {
        Ok(_) => (StatusCode::OK,Json(json!({"status":"ready"}))),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE,Json(json!({"status":"unavailable"}))),
    }
}

async fn check_origin(State(state):State<AppState>,request:axum::extract::Request,next:Next)->Result<Response,StatusCode>{
    let method=request.method();
    if method!=Method::GET && method!=Method::HEAD && method!=Method::OPTIONS {
        if let Some(origin)=request.headers().get(header::ORIGIN) {
            let origin=origin.to_str().map_err(|_|StatusCode::FORBIDDEN)?;
            if let Some(ref allowed)=state.allowed_origin {
                if origin!=allowed {return Err(StatusCode::FORBIDDEN);}
            } else if origin=="null" {return Err(StatusCode::FORBIDDEN);}
        }
    }
    let mut response=next.run(request).await;
    response.headers_mut().insert(header::CACHE_CONTROL,axum::http::HeaderValue::from_static("no-store"));
    Ok(response)
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "breakline_api=info,tower_http=info".into()))
        .init();
    let database_url = env::var("DATABASE_URL").context("DATABASE_URL is required")?;
    let bootstrap = env::var("BOOTSTRAP_TOKEN").context("BOOTSTRAP_TOKEN must be set to a randomly generated secret")?;
    if bootstrap.len() < 32 { return Err(anyhow!("BOOTSTRAP_TOKEN must contain at least 32 characters")); }
    let digest = Sha256::digest(bootstrap.as_bytes());
    let mut bootstrap_token_hash = [0u8; 32];
    bootstrap_token_hash.copy_from_slice(&digest);
    let pool = PgPoolOptions::new().max_connections(12).acquire_timeout(Duration::from_secs(15)).connect(&database_url)
        .await.context("connecting to PostgreSQL")?;
    sqlx::migrate!("./migrations").run(&pool).await.context("running migrations")?;
    sqlx::query("DELETE FROM sessions WHERE expires_at < NOW()").execute(&pool).await?;
    let (events, _) = broadcast::channel(512);
    let state = AppState {
        pool, events, bootstrap_token_hash,
        alerts: alerting::AlertConfig::from_env(),
        cookie_secure: env::var("COOKIE_SECURE").map(|x| x == "true").unwrap_or(false),
        session_days: 7,
        allowed_origin: env::var("PUBLIC_ORIGIN").ok().filter(|s|!s.is_empty()),
    };
    if state.cookie_secure && state.allowed_origin.as_deref().map(|s|!s.starts_with("https://")).unwrap_or(true) {
        return Err(anyhow!("COOKIE_SECURE=true requires PUBLIC_ORIGIN=https://your-domain"));
    }
    worker::spawn(state.clone());
    let host = env::var("API_HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port: u16 = env::var("API_PORT").unwrap_or_else(|_| "8080".into()).parse().context("invalid API_PORT")?;
    let address: SocketAddr = format!("{host}:{port}").parse().context("invalid bind address")?;
    let listener = TcpListener::bind(address).await?;
    tracing::info!(%address, "Breakline API listening");
    axum::serve(listener, routes(state)).with_graceful_shutdown(shutdown_signal()).await?;
    Ok(())
}

async fn shutdown_signal() { let _ = tokio::signal::ctrl_c().await; }
