//! Incident state transitions share a database transaction with the event that
//! triggered them. Partial unique indexes suppress duplicate active incidents
//! even when multiple API workers receive the same signal concurrently.
use sqlx::{Postgres, Transaction};
use uuid::Uuid;
use crate::{audit,AppState};

/// Returns new incident id when a fingerprint is not already active.
async fn open(
    tx: &mut Transaction<'_, Postgres>, state: &AppState,
    project_id: Uuid, environment_id: Uuid, monitor_id: Option<Uuid>,
    trigger_deployment_id: Option<Uuid>, fingerprint: &str, source: &str,
    severity: &str, title: &str, summary: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    let suspected: Option<Uuid> = if source == "deployment" { None } else {
        sqlx::query_scalar(r#"SELECT id FROM deployments
            WHERE project_id=$1 AND environment_id=$2 AND status='succeeded'
              AND finished_at BETWEEN NOW()-INTERVAL '2 hours' AND NOW()
            ORDER BY finished_at DESC LIMIT 1"#)
            .bind(project_id).bind(environment_id).fetch_optional(&mut **tx).await?
    };
    let id = Uuid::new_v4();
    let created: Option<Uuid> = sqlx::query_scalar(r#"
        INSERT INTO incidents(id,project_id,environment_id,monitor_id,trigger_deployment_id,
          suspected_deployment_id,fingerprint,source,severity,title,summary)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        ON CONFLICT (project_id,fingerprint) WHERE status IN ('open','acknowledged') DO NOTHING
        RETURNING id"#)
        .bind(id).bind(project_id).bind(environment_id).bind(monitor_id).bind(trigger_deployment_id)
        .bind(suspected).bind(fingerprint).bind(source).bind(severity).bind(title).bind(summary)
        .fetch_optional(&mut **tx).await?;
    if let Some(id) = created {
        record_event(tx, state, id, None, "opened", summary).await?;
        audit::in_tx(tx,None,"incident.detected","incident",Some(id),Some(project_id),title).await?;
        sqlx::query("INSERT INTO activities(action,entity_type,entity_id,detail) VALUES('incident.opened','incident',$1,$2)")
            .bind(id).bind(title).execute(&mut **tx).await?;
    }
    Ok(created)
}

/// Append a timeline event and enqueue notifications in the same transaction.
/// A channel is queued only if its operator-provided environment configuration
/// is complete AND that project has enabled the channel.
pub async fn record_event(
    tx: &mut Transaction<'_, Postgres>, state: &AppState, id: Uuid,
    actor: Option<Uuid>, kind: &str, message: &str,
) -> Result<i64, sqlx::Error> {
    let event_id: i64 = sqlx::query_scalar("INSERT INTO incident_events(incident_id,actor_id,kind,message) VALUES($1,$2,$3,$4) RETURNING id")
        .bind(id).bind(actor).bind(kind).bind(message).fetch_one(&mut **tx).await?;
    if kind == "opened" || kind == "resolved" {
        for (channel, available) in [
            ("email", state.alerts.email_ready()),
            ("discord", state.alerts.discord_url.is_some()),
            ("webhook", state.alerts.webhook_ready()),
        ] {
            if !available { continue; }
            let flag = match channel {
                "email" => "notify_email", "discord" => "notify_discord", _ => "notify_webhook",
            };
            // Fixed column choice: no user input is ever interpolated here.
            let query = format!(r#"INSERT INTO alert_deliveries(incident_event_id,channel)
                SELECT $1,$2 FROM incidents i LEFT JOIN incident_rules r ON r.project_id=i.project_id
                WHERE i.id=$3 AND COALESCE(r.{flag}, TRUE)
                ON CONFLICT (incident_event_id,channel) DO NOTHING"#);
            sqlx::query(&query).bind(event_id).bind(channel).bind(id).execute(&mut **tx).await?;
        }
    }
    Ok(event_id)
}

fn should_open_monitor(enabled:bool, failures:i32, threshold:i32)->bool {
    enabled && failures==threshold
}

pub async fn monitor_result(
    tx: &mut Transaction<'_, Postgres>, state: &AppState, monitor_id: Uuid,
    project_id: Uuid, environment_id: Uuid, monitor_name: &str,
    is_production: bool, status: &str, failures: i32,
) -> Result<bool, sqlx::Error> {
    if status == "up" {
        let rows: Vec<Uuid> = sqlx::query_scalar(r#"UPDATE incidents SET status='resolved',resolved_at=NOW(),updated_at=NOW()
            WHERE monitor_id=$1 AND status IN ('open','acknowledged') RETURNING id"#)
            .bind(monitor_id).fetch_all(&mut **tx).await?;
        for id in &rows {
            record_event(tx,state,*id,None,"resolved","Monitor recovered and the outage closed automatically").await?;
            audit::in_tx(tx,None,"incident.auto_resolved","incident",Some(*id),Some(project_id),"Monitor recovered").await?;
        }
        return Ok(!rows.is_empty());
    }
    let threshold: (bool, i32) = sqlx::query_as(r#"SELECT COALESCE(r.monitor_enabled,TRUE),COALESCE(r.failure_threshold,3)
        FROM projects p LEFT JOIN incident_rules r ON r.project_id=p.id WHERE p.id=$1"#)
        .bind(project_id).fetch_one(&mut **tx).await?;
    // Only the threshold-crossing check can open an incident; resolving an active
    // incident by hand will not immediately create a duplicate on the next probe.
    if !should_open_monitor(threshold.0,failures,threshold.1) { return Ok(false); }
    let severity = if is_production { "high" } else { "medium" };
    let id = open(tx,state,project_id,environment_id,Some(monitor_id),None,
        &format!("monitor:{monitor_id}"),"monitor",severity,
        &format!("{} is unavailable",monitor_name),
        &format!("{} consecutive checks failed for {}",failures,monitor_name)).await?;
    Ok(id.is_some())
}

pub async fn deployment_failed(
    tx: &mut Transaction<'_, Postgres>, state: &AppState,
    id: Uuid, project_id: Uuid, environment_id: Uuid, version: &str,
) -> Result<bool, sqlx::Error> {
    let enabled: bool = sqlx::query_scalar(r#"SELECT COALESCE(r.deployment_enabled,TRUE)
        FROM projects p LEFT JOIN incident_rules r ON r.project_id=p.id WHERE p.id=$1"#)
        .bind(project_id).fetch_one(&mut **tx).await?;
    if !enabled { return Ok(false); }
    let is_production: bool = sqlx::query_scalar("SELECT is_production FROM environments WHERE id=$1")
        .bind(environment_id).fetch_one(&mut **tx).await?;
    let id = open(tx,state,project_id,environment_id,None,Some(id),
        &format!("deployment:{id}"),"deployment",if is_production { "high" } else { "medium" },
        &format!("Release {} failed", version),
        &format!("Deployment {} did not complete successfully",version)).await?;
    Ok(id.is_some())
}

pub async fn scan_metrics(state: &AppState) -> Result<usize, sqlx::Error> {
    // Scan project-environment pairs with enough traffic. Conditions are checked
    // inside the locked transaction before opening a single fingerprint per env.
    let pairs: Vec<(Uuid, Uuid)> = sqlx::query_as("SELECT DISTINCT project_id,environment_id FROM api_samples WHERE observed_at>NOW()-INTERVAL '5 minutes' LIMIT 250")
        .fetch_all(&state.pool).await?;
    let mut created = 0;
    for (project_id, env_id) in pairs {
        let mut tx = state.pool.begin().await?;
        let (enabled, threshold, minimum): (bool, i32, i32) = sqlx::query_as(r#"SELECT
            COALESCE(r.metrics_enabled,TRUE),COALESCE(r.api_error_threshold,15),COALESCE(r.minimum_samples,30)
            FROM projects p LEFT JOIN incident_rules r ON r.project_id=p.id WHERE p.id=$1"#)
            .bind(project_id).fetch_one(&mut *tx).await?;
        if !enabled { continue; }
        let (requests, failures): (i64, i64) = sqlx::query_as(r#"SELECT COUNT(*)::bigint,
            COUNT(*) FILTER (WHERE status_code>=500)::bigint
            FROM api_samples WHERE project_id=$1 AND environment_id=$2 AND observed_at>NOW()-INTERVAL '5 minutes'"#)
            .bind(project_id).bind(env_id).fetch_one(&mut *tx).await?;
        let mut changed=false;
        if requests >= i64::from(minimum) && failures * 100 >= requests * i64::from(threshold) {
            let production: bool = sqlx::query_scalar("SELECT is_production FROM environments WHERE id=$1")
                .bind(env_id).fetch_one(&mut *tx).await?;
            let percentage = failures as f64 / requests as f64 * 100.;
            // Allow the operator a recovery window after a manually resolved
            // error-rate incident. The active-fingerprint unique index handles
            // duplicate open incidents across instances.
            let recent: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM incidents WHERE project_id=$1 AND fingerprint=$2 AND detected_at>NOW()-INTERVAL '15 minutes')")
                .bind(project_id).bind(format!("metrics:{env_id}"))
                .fetch_one(&mut *tx).await?;
            if recent {tx.commit().await?;continue;}
            let incident = open(&mut tx,state,project_id,env_id,None,None,
                &format!("metrics:{env_id}"),"metrics",
                if production { "high" } else { "medium" },"Elevated API error rate",
                &format!("HTTP 5xx responses reached {:.1}% across {} requests in 5 minutes",percentage,requests)).await?;
            if incident.is_some() { created += 1; changed=true; }
        }
        tx.commit().await?;
        if changed { state.publish("incident.changed",Some(project_id)); }
    }
    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn monitor_only_opens_when_threshold_is_crossed() {
        assert!(!should_open_monitor(true,1,3));
        assert!(!should_open_monitor(true,2,3));
        assert!(should_open_monitor(true,3,3));
        assert!(!should_open_monitor(true,4,3));
        assert!(!should_open_monitor(false,3,3));
    }
}
