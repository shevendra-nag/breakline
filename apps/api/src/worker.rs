//! Database-leased monitoring scheduler. Claiming due checks atomically allows
//! multiple API instances without probing the same monitor at the same time.
use sqlx::FromRow;
use std::time::Duration;
use tokio::{task::JoinSet, time::MissedTickBehavior};
use uuid::Uuid;
use crate::{alerting,incident_engine,monitor_url, AppState};

#[derive(FromRow)]
struct DueMonitor {
    id: Uuid,
    project_id: Uuid,
    environment_id: Uuid,
    is_production: bool,
    name: String,
    url: String,
    method: String,
    expected_status: i32,
    interval_seconds: i32,
    timeout_seconds: i32,
}

async fn take_due(state: &AppState) -> Result<Vec<DueMonitor>, sqlx::Error> {
    sqlx::query_as::<_, DueMonitor>(r#"
WITH due AS (
    SELECT id FROM monitors
    WHERE enabled AND next_check_at <= NOW() AND (claimed_until IS NULL OR claimed_until < NOW())
    ORDER BY next_check_at LIMIT 12 FOR UPDATE SKIP LOCKED
)
UPDATE monitors m SET claimed_until=NOW()+INTERVAL '90 seconds'
FROM due, environments e WHERE m.id=due.id AND e.id=m.environment_id
RETURNING m.id,m.project_id,m.environment_id,e.is_production,m.name,m.url,m.method,m.expected_status,m.interval_seconds,m.timeout_seconds
"#).fetch_all(&state.pool).await
}

async fn execute(state: AppState, monitor: DueMonitor) {
    let result = monitor_url::probe(&monitor.url, &monitor.method, monitor.expected_status, monitor.timeout_seconds).await;
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(error) => { tracing::warn!(%error, "monitor result transaction failed"); return; }
    };
    // A disabled or deleted monitor must not receive a stale result. If the monitor
    // was edited after this check was claimed, the result is discarded.
    let is_current: Option<(Uuid, String, i32)> = match sqlx::query_as(
        "SELECT id,last_status,consecutive_failures FROM monitors WHERE id=$1 AND enabled AND url=$2 AND method=$3 AND expected_status=$4 AND claimed_until>NOW() FOR UPDATE")
        .bind(monitor.id).bind(&monitor.url).bind(&monitor.method).bind(monitor.expected_status)
        .fetch_optional(&mut *tx).await {
            Ok(value) => value,
            Err(error) => { tracing::warn!(%error, "monitor result validation failed"); return; }
        };
    let Some((_, previous_status, previous_failures)) = is_current else { return; };
    let query = sqlx::query("INSERT INTO monitor_checks(monitor_id,status,http_status,latency_ms,error_message) VALUES ($1,$2,$3,$4,$5)")
        .bind(monitor.id).bind(result.status).bind(result.http_status).bind(result.latency_ms).bind(result.error_message)
        .execute(&mut *tx).await;
    if let Err(error) = query { tracing::warn!(%error, "failed to store probe"); return; }
    let query = sqlx::query("UPDATE monitors SET last_status=$2,last_http_status=$3,last_latency_ms=$4,last_checked_at=NOW(),consecutive_failures=CASE WHEN $2='up' THEN 0 ELSE consecutive_failures+1 END,next_check_at=NOW()+($5::int*INTERVAL '1 second'),claimed_until=NULL,updated_at=NOW() WHERE id=$1")
        .bind(monitor.id).bind(result.status).bind(result.http_status).bind(result.latency_ms).bind(monitor.interval_seconds)
        .execute(&mut *tx).await;
    if let Err(error) = query { tracing::warn!(%error, "failed to update monitor"); return; }
    if previous_status != result.status {
        let action = if result.status == "up" { "monitor.recovered" } else { "monitor.degraded" };
        let detail = format!("{}: {}", monitor.name, if result.status == "up" { "healthy" } else { "unreachable or unexpected response" });
        if let Err(error) = sqlx::query("INSERT INTO activities(action,entity_type,entity_id,detail) VALUES($1,'monitor',$2,$3)")
            .bind(action).bind(monitor.id).bind(detail).execute(&mut *tx).await {
            tracing::warn!(%error, "failed to write monitor activity"); return;
        }
    }
    let failures = if result.status == "up" { 0 } else { previous_failures.saturating_add(1) };
    let incident_changed = match incident_engine::monitor_result(&mut tx,&state,monitor.id,
        monitor.project_id,monitor.environment_id,&monitor.name,monitor.is_production,result.status,failures).await {
        Ok(changed)=>changed,Err(error)=>{tracing::warn!(%error,"incident detection failed");return;}
    };
    if let Err(error) = tx.commit().await { tracing::warn!(%error, "probe transaction commit failed"); return; }
    state.publish("monitor.checked", Some(monitor.project_id));
    if incident_changed { state.publish("incident.changed",Some(monitor.project_id)); }
}

pub fn spawn(state: AppState) {
    // Independent delivery and regression scanner workers; monitor probes must
    // not be delayed by third-party notification services.
    let background = state.clone();
    tokio::spawn(async move {
        let mut tick=tokio::time::interval(Duration::from_secs(15));
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut last_metrics=std::time::Instant::now()-Duration::from_secs(60);
        loop {
            tick.tick().await;
            if let Err(e)=alerting::dispatch_pending(&background).await {tracing::warn!(%e,"alert queue failure");}
            if last_metrics.elapsed()>=Duration::from_secs(60) {
                last_metrics=std::time::Instant::now();
                if let Err(e)=incident_engine::scan_metrics(&background).await {tracing::warn!(%e,"API incident scanner failure");}
            }
        }
    });
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut last_cleanup = std::time::Instant::now();
        loop {
            interval.tick().await;
            match take_due(&state).await {
                Ok(monitors) => {
                    let mut jobs = JoinSet::new();
                    for monitor in monitors {
                        let state = state.clone();
                        jobs.spawn(execute(state, monitor));
                    }
                    while let Some(outcome) = jobs.join_next().await {
                        if let Err(error) = outcome { tracing::warn!(%error, "probe worker task failed"); }
                    }
                },
                Err(error) => tracing::warn!(%error, "monitor scheduler query failed"),
            }
            if last_cleanup.elapsed() >= Duration::from_secs(3600) {
                last_cleanup = std::time::Instant::now();
                for query in [
                    "DELETE FROM monitor_checks WHERE checked_at < NOW() - INTERVAL '30 days'",
                    "DELETE FROM api_samples WHERE observed_at < NOW() - INTERVAL '30 days'",
                    "DELETE FROM ingestion_events WHERE received_at < NOW() - INTERVAL '90 days'",
                    "DELETE FROM sessions WHERE expires_at < NOW()",
                    "DELETE FROM login_rate_limits WHERE window_started_at < NOW() - INTERVAL '24 hours'",
                ] {
                    if let Err(error) = sqlx::query(query).execute(&state.pool).await {
                        tracing::warn!(%error, "retention cleanup failed");
                    }
                }
            }
        }
    });
}
