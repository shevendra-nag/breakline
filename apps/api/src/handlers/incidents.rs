use axum::{extract::{Path,Query,State},http::{HeaderMap,StatusCode},Json};
use chrono::{DateTime,Utc};
use serde::{Deserialize,Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use crate::{audit,auth,error::ApiError,incident_engine,validation::check_text,AppState};

#[derive(Debug,Serialize,FromRow)]
pub struct Incident {
    pub id: Uuid,
    pub project_id: Uuid,
    pub project_name: String,
    pub environment_id: Uuid,
    pub environment_name: String,
    pub monitor_id: Option<Uuid>,
    pub trigger_deployment_id: Option<Uuid>,
    pub suspected_deployment_id: Option<Uuid>,
    pub suspected_version: Option<String>,
    pub fingerprint: String,
    pub source: String,
    pub status: String,
    pub severity: String,
    pub title: String,
    pub summary: String,
    pub detected_at: DateTime<Utc>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}
const INCIDENT_SELECT: &str = r#"SELECT i.id,i.project_id,p.name AS project_name,i.environment_id,
    env.name AS environment_name,i.monitor_id,i.trigger_deployment_id,
    i.suspected_deployment_id,d.version AS suspected_version,i.fingerprint,i.source,
    i.status,i.severity,i.title,i.summary,i.detected_at,i.acknowledged_at,i.resolved_at,i.updated_at
    FROM incidents i JOIN projects p ON p.id=i.project_id
    JOIN environments env ON env.id=i.environment_id
    LEFT JOIN deployments d ON d.id=i.suspected_deployment_id"#;

#[derive(Deserialize)]
pub struct Filter { pub project_id: Option<Uuid>, pub status: Option<String>, pub limit: Option<i64>, pub offset: Option<i64> }
pub async fn list(State(state):State<AppState>,headers:HeaderMap,Query(f):Query<Filter>) -> Result<Json<Vec<Incident>>,ApiError> {
    auth::current_user(&state,&headers).await?;
    if f.status.as_deref().is_some_and(|s| !matches!(s,"open"|"acknowledged"|"resolved"|"active"|"all")) {
        return Err(ApiError::bad_request("Unknown incident filter"));
    }
    let status=f.status.as_deref().unwrap_or("active");
    let query=format!("{INCIDENT_SELECT} WHERE ($1::uuid IS NULL OR i.project_id=$1) AND ($2='all' OR ($2='active' AND i.status!='resolved') OR i.status=$2) ORDER BY i.detected_at DESC LIMIT $3 OFFSET $4");
    Ok(Json(sqlx::query_as::<_,Incident>(&query)
        .bind(f.project_id).bind(status).bind(f.limit.unwrap_or(60).clamp(1,100)).bind(f.offset.unwrap_or(0).clamp(0,100_000))
        .fetch_all(&state.pool).await?))
}

#[derive(Serialize,FromRow)]
pub struct IncidentSummary {
    pub open: i64,
    pub acknowledged: i64,
    pub resolved_7d: i64,
    pub critical_active: i64,
    pub high_active: i64,
    pub avg_resolution_minutes_7d: Option<f64>,
}
pub async fn summary(State(state):State<AppState>,headers:HeaderMap,Query(f):Query<Filter>) -> Result<Json<IncidentSummary>,ApiError> {
    auth::current_user(&state,&headers).await?;
    let row=sqlx::query_as::<_,IncidentSummary>(r#"SELECT
        COUNT(*) FILTER (WHERE status='open')::bigint AS open,
        COUNT(*) FILTER (WHERE status='acknowledged')::bigint AS acknowledged,
        COUNT(*) FILTER (WHERE status='resolved' AND resolved_at>NOW()-INTERVAL '7 days')::bigint AS resolved_7d,
        COUNT(*) FILTER (WHERE status!='resolved' AND severity='critical')::bigint AS critical_active,
        COUNT(*) FILTER (WHERE status!='resolved' AND severity='high')::bigint AS high_active,
        (AVG(EXTRACT(EPOCH FROM (resolved_at-detected_at))/60) FILTER (WHERE status='resolved' AND resolved_at>NOW()-INTERVAL '7 days'))::float8 AS avg_resolution_minutes_7d
        FROM incidents WHERE ($1::uuid IS NULL OR project_id=$1)"#)
        .bind(f.project_id).fetch_one(&state.pool).await?;
    Ok(Json(row))
}

#[derive(Serialize,FromRow)]
pub struct TimelineEvent {
    pub id: i64,
    pub kind: String,
    pub message: String,
    pub author: Option<String>,
    pub created_at: DateTime<Utc>,
}
#[derive(Serialize,FromRow)]
pub struct ReleaseCandidate { pub id: Uuid, pub version: String, pub finished_at: DateTime<Utc> }
#[derive(Serialize,FromRow,Default)]
pub struct PerfWindow {
    pub requests: i64,
    pub errors: i64,
    pub avg_ms: Option<f64>,
    pub p95_ms: Option<f64>,
}
#[derive(Serialize)]
pub struct RegressionEvidence {
    pub candidate: Option<ReleaseCandidate>,
    pub before: PerfWindow,
    pub after: PerfWindow,
    pub assessment: &'static str,
    pub note: &'static str,
}
#[derive(Serialize)]
pub struct IncidentDetail { pub incident: Incident, pub timeline: Vec<TimelineEvent>, pub regression: RegressionEvidence }

async fn one(state:&AppState,id:Uuid)->Result<Incident,ApiError>{
    let query=format!("{INCIDENT_SELECT} WHERE i.id=$1");
    sqlx::query_as::<_,Incident>(&query).bind(id).fetch_optional(&state.pool).await?.ok_or_else(ApiError::not_found)
}
async fn sample_window(state:&AppState,incident:&Incident,from:DateTime<Utc>,to:DateTime<Utc>)->Result<PerfWindow,ApiError>{
    Ok(sqlx::query_as::<_,PerfWindow>(r#"SELECT COUNT(*)::bigint AS requests,
        COUNT(*) FILTER (WHERE status_code>=500)::bigint AS errors,
        AVG(latency_ms)::float8 AS avg_ms,
        PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95_ms
        FROM api_samples WHERE project_id=$1 AND environment_id=$2 AND observed_at >= $3 AND observed_at < $4"#)
        .bind(incident.project_id).bind(incident.environment_id).bind(from).bind(to)
        .fetch_one(&state.pool).await?)
}
async fn evidence(state:&AppState,incident:&Incident)->Result<RegressionEvidence,ApiError>{
    let mut result=RegressionEvidence { candidate:None,before:PerfWindow::default(),after:PerfWindow::default(),
        assessment:"no_candidate",note:"A recent successful deployment is only a correlation candidate, never proof of causation." };
    if let Some(id)=incident.suspected_deployment_id {
        let candidate=sqlx::query_as::<_,ReleaseCandidate>("SELECT id,version,finished_at FROM deployments WHERE id=$1 AND status='succeeded' AND finished_at IS NOT NULL")
            .bind(id).fetch_optional(&state.pool).await?;
        if let Some(candidate)=candidate {
            let start=candidate.finished_at;
            result.before=sample_window(state,incident,start-chrono::Duration::minutes(15),start).await?;
            // Cap the comparison to 15 minutes after the deployment; use only
            // observed data. Never claim statistically reliable signals below 20 samples.
            result.after=sample_window(state,incident,start,start+chrono::Duration::minutes(15)).await?;
            result.assessment=assess(&result.before,&result.after);
            result.candidate=Some(candidate);
        }
    }
    Ok(result)
}
fn assess(before:&PerfWindow,after:&PerfWindow)->&'static str {
    if before.requests<20 || after.requests<20 {return "insufficient_data";}
    let previous_errors=before.errors as f64/before.requests as f64;
    let current_errors=after.errors as f64/after.requests as f64;
    let latency=match (before.p95_ms,after.p95_ms) {Some(b),Some(a) if b>0.0 => a>=b*1.5,None=>false,_=>false};
    if current_errors-previous_errors>=0.05 || latency {"elevated"} else {"no_clear_regression"}
}

pub async fn get(State(state):State<AppState>,headers:HeaderMap,Path(id):Path<Uuid>)->Result<Json<IncidentDetail>,ApiError>{
    auth::current_user(&state,&headers).await?;
    let incident=one(&state,id).await?;
    let timeline=sqlx::query_as::<_,TimelineEvent>(r#"SELECT e.id,e.kind,e.message,u.name AS author,e.created_at
       FROM incident_events e LEFT JOIN users u ON e.actor_id=u.id WHERE e.incident_id=$1 ORDER BY e.created_at ASC,e.id ASC LIMIT 500"#)
        .bind(id).fetch_all(&state.pool).await?;
    let regression=evidence(&state,&incident).await?;
    Ok(Json(IncidentDetail {incident,timeline,regression}))
}

pub async fn acknowledge(State(state):State<AppState>,headers:HeaderMap,Path(id):Path<Uuid>)->Result<Json<Incident>,ApiError>{
    auth::require_client_header(&headers)?;
    let actor=auth::current_user(&state,&headers).await?;
    auth::require_role(&actor,&["owner","admin","operator"])?;
    let mut tx=state.pool.begin().await?;
    let updated: Option<Uuid>=sqlx::query_scalar("UPDATE incidents SET status='acknowledged',acknowledged_at=NOW(),acknowledged_by=$2,updated_at=NOW() WHERE id=$1 AND status='open' RETURNING id")
        .bind(id).bind(actor.id).fetch_optional(&mut *tx).await?;
    if updated.is_none(){
        return Err(if sqlx::query_scalar::<_,Uuid>("SELECT id FROM incidents WHERE id=$1").bind(id).fetch_optional(&mut *tx).await?.is_some(){ApiError::conflict("Incident has already been acknowledged or resolved")}else{ApiError::not_found()});
    }
    incident_engine::record_event(&mut tx,&state,id,Some(actor.id),"acknowledged","Incident acknowledged; investigation underway").await?;
    let project:Uuid=sqlx::query_scalar("SELECT project_id FROM incidents WHERE id=$1").bind(id).fetch_one(&mut *tx).await?;
    audit::in_tx(&mut tx,Some(actor.id),"incident.acknowledged","incident",Some(id),Some(project),"Incident acknowledged").await?;
    tx.commit().await?;
    let incident=one(&state,id).await?;
    state.publish("incident.changed",Some(incident.project_id));
    Ok(Json(incident))
}

pub async fn resolve(State(state):State<AppState>,headers:HeaderMap,Path(id):Path<Uuid>)->Result<Json<Incident>,ApiError>{
    auth::require_client_header(&headers)?;
    let actor=auth::current_user(&state,&headers).await?;
    auth::require_role(&actor,&["owner","admin","operator"])?;
    let mut tx=state.pool.begin().await?;
    let updated: Option<Uuid>=sqlx::query_scalar("UPDATE incidents SET status='resolved',resolved_at=NOW(),resolved_by=$2,updated_at=NOW() WHERE id=$1 AND status IN ('open','acknowledged') RETURNING id")
        .bind(id).bind(actor.id).fetch_optional(&mut *tx).await?;
    if updated.is_none(){
        return Err(if sqlx::query_scalar::<_,Uuid>("SELECT id FROM incidents WHERE id=$1").bind(id).fetch_optional(&mut *tx).await?.is_some(){ApiError::conflict("Incident has already been resolved")}else{ApiError::not_found()});
    }
    incident_engine::record_event(&mut tx,&state,id,Some(actor.id),"resolved","Incident manually resolved").await?;
    let project:Uuid=sqlx::query_scalar("SELECT project_id FROM incidents WHERE id=$1").bind(id).fetch_one(&mut *tx).await?;
    audit::in_tx(&mut tx,Some(actor.id),"incident.resolved","incident",Some(id),Some(project),"Incident manually resolved").await?;
    tx.commit().await?;
    let incident=one(&state,id).await?;
    state.publish("incident.changed",Some(incident.project_id));
    Ok(Json(incident))
}

#[derive(Deserialize)]
pub struct NewComment {pub message:String}
pub async fn comment(State(state):State<AppState>,headers:HeaderMap,Path(id):Path<Uuid>,Json(input):Json<NewComment>)->Result<(StatusCode,Json<TimelineEvent>),ApiError>{
    auth::require_client_header(&headers)?;
    let actor=auth::current_user(&state,&headers).await?;
    auth::require_role(&actor,&["owner","admin","operator"])?;
    let message=check_text(&input.message,2,1000,"Comment must be 2–1000 characters")?;
    let mut tx=state.pool.begin().await?;
    // Serializes comments with deletion and validates the incident exists.
    let project:Option<Uuid>=sqlx::query_scalar("SELECT project_id FROM incidents WHERE id=$1 FOR UPDATE")
        .bind(id).fetch_optional(&mut *tx).await?;
    let project=project.ok_or_else(ApiError::not_found)?;
    let event_id=incident_engine::record_event(&mut tx,&state,id,Some(actor.id),"comment",&message).await?;
    audit::in_tx(&mut tx,Some(actor.id),"incident.note_added","incident",Some(id),Some(project),"Investigation note added").await?;
    tx.commit().await?;
    let event=sqlx::query_as::<_,TimelineEvent>("SELECT e.id,e.kind,e.message,u.name AS author,e.created_at FROM incident_events e LEFT JOIN users u ON e.actor_id=u.id WHERE e.id=$1")
        .bind(event_id).fetch_one(&state.pool).await?;
    state.publish("incident.comment",Some(project));
    Ok((StatusCode::CREATED,Json(event)))
}

#[derive(Serialize,FromRow)]
pub struct IncidentRule {
    pub project_id:Uuid,pub monitor_enabled:bool,pub deployment_enabled:bool,pub metrics_enabled:bool,
    pub failure_threshold:i32,pub api_error_threshold:i32,pub minimum_samples:i32,
    pub notify_email:bool,pub notify_discord:bool,pub notify_webhook:bool,
}
const RULES_QUERY:&str=r#"SELECT p.id AS project_id,
    COALESCE(r.monitor_enabled,TRUE) AS monitor_enabled,
    COALESCE(r.deployment_enabled,TRUE) AS deployment_enabled,
    COALESCE(r.metrics_enabled,TRUE) AS metrics_enabled,
    COALESCE(r.failure_threshold,3) AS failure_threshold,
    COALESCE(r.api_error_threshold,15) AS api_error_threshold,
    COALESCE(r.minimum_samples,30) AS minimum_samples,
    COALESCE(r.notify_email,TRUE) AS notify_email,
    COALESCE(r.notify_discord,TRUE) AS notify_discord,
    COALESCE(r.notify_webhook,TRUE) AS notify_webhook
    FROM projects p LEFT JOIN incident_rules r ON r.project_id=p.id WHERE p.id=$1"#;
async fn get_rules(state:&AppState,id:Uuid)->Result<IncidentRule,ApiError>{
    sqlx::query_as::<_,IncidentRule>(RULES_QUERY).bind(id).fetch_optional(&state.pool).await?.ok_or_else(ApiError::not_found)
}
pub async fn rules(State(state):State<AppState>,headers:HeaderMap,Path(id):Path<Uuid>)->Result<Json<IncidentRule>,ApiError>{
    auth::current_user(&state,&headers).await?;
    Ok(Json(get_rules(&state,id).await?))
}
#[derive(Deserialize)]
pub struct SetRules {
    monitor_enabled:bool,deployment_enabled:bool,metrics_enabled:bool,
    failure_threshold:i32,api_error_threshold:i32,minimum_samples:i32,
    notify_email:bool,notify_discord:bool,notify_webhook:bool,
}
pub async fn update_rules(State(state):State<AppState>,headers:HeaderMap,Path(id):Path<Uuid>,Json(input):Json<SetRules>)->Result<Json<IncidentRule>,ApiError>{
    auth::require_client_header(&headers)?;
    let actor=auth::current_user(&state,&headers).await?;
    auth::require_role(&actor,&["owner","admin"])?;
    if !(2..=10).contains(&input.failure_threshold) || !(5..=80).contains(&input.api_error_threshold)
        || !(20..=1000).contains(&input.minimum_samples) {
        return Err(ApiError::bad_request("Incident thresholds are out of range"));
    }
    let _=get_rules(&state,id).await?;
    sqlx::query(r#"INSERT INTO incident_rules(project_id,monitor_enabled,deployment_enabled,metrics_enabled,
        failure_threshold,api_error_threshold,minimum_samples,notify_email,notify_discord,notify_webhook)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        ON CONFLICT(project_id) DO UPDATE SET monitor_enabled=$2,deployment_enabled=$3,metrics_enabled=$4,
          failure_threshold=$5,api_error_threshold=$6,minimum_samples=$7,notify_email=$8,
          notify_discord=$9,notify_webhook=$10,updated_at=NOW()"#)
        .bind(id).bind(input.monitor_enabled).bind(input.deployment_enabled).bind(input.metrics_enabled)
        .bind(input.failure_threshold).bind(input.api_error_threshold).bind(input.minimum_samples)
        .bind(input.notify_email).bind(input.notify_discord).bind(input.notify_webhook)
        .execute(&state.pool).await?;
    audit::write(&state.pool,Some(actor.id),"incident.rules_updated","project",Some(id),Some(id),"Detection and alert rules changed").await?;
    state.publish("incident.rules_updated",Some(id));
    Ok(Json(get_rules(&state,id).await?))
}

#[derive(Serialize)]
pub struct AlertChannelStatus {pub email:bool,pub discord:bool,pub webhook:bool}
pub async fn channels(State(state):State<AppState>,headers:HeaderMap)->Result<Json<AlertChannelStatus>,ApiError>{
    let actor=auth::current_user(&state,&headers).await?;
    auth::require_role(&actor,&["owner","admin"])?;
    Ok(Json(AlertChannelStatus{email:state.alerts.email_ready(),discord:state.alerts.discord_url.is_some(),webhook:state.alerts.webhook_ready()}))
}
#[derive(Serialize,FromRow)]
pub struct DeliveryStatus {
    pub id:i64,pub incident_event_id:i64,pub channel:String,pub status:String,
    pub attempts:i32,pub last_http_status:Option<i32>,pub last_error:Option<String>,
    pub delivered_at:Option<DateTime<Utc>>,pub created_at:DateTime<Utc>,
}
pub async fn deliveries(State(state):State<AppState>,headers:HeaderMap,Query(f):Query<Filter>)->Result<Json<Vec<DeliveryStatus>>,ApiError>{
    let actor=auth::current_user(&state,&headers).await?;
    auth::require_role(&actor,&["owner","admin"])?;
    let result=sqlx::query_as::<_,DeliveryStatus>(r#"SELECT d.id,d.incident_event_id,d.channel,d.status,d.attempts,d.last_http_status,d.last_error,d.delivered_at,d.created_at
        FROM alert_deliveries d JOIN incident_events e ON e.id=d.incident_event_id JOIN incidents i ON i.id=e.incident_id
        WHERE ($1::uuid IS NULL OR i.project_id=$1) ORDER BY d.created_at DESC,d.id DESC LIMIT 100"#)
        .bind(f.project_id).fetch_all(&state.pool).await?;
    Ok(Json(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn correlation_requires_adequate_samples() {
        let empty=PerfWindow::default();
        assert_eq!(assess(&empty,&empty),"insufficient_data");
        let before=PerfWindow {requests:30,errors:0,avg_ms:Some(50.),p95_ms:Some(100.)};
        let after=PerfWindow {requests:30,errors:6,avg_ms:Some(200.),p95_ms:Some(300.)};
        assert_eq!(assess(&before,&after),"elevated");
        assert_eq!(assess(&before,&before),"no_clear_regression");
    }
}
