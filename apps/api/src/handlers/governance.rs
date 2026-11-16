//! Administrative audit, scheduled alert silences and deliberate replay of
//! failed/suppressed notifications. Every mutation requires an admin session.
use axum::{extract::{Path,Query,State},http::{HeaderMap,StatusCode},Json};
use chrono::{DateTime,Utc};
use serde::{Deserialize,Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use crate::{audit,auth,error::ApiError,validation::check_text,AppState};

#[derive(Deserialize)]
pub struct AuditFilter {pub project_id:Option<Uuid>,pub action:Option<String>,pub limit:Option<i64>,pub before_id:Option<i64>}
#[derive(Serialize,FromRow)]
pub struct AuditEntry {
    pub id:i64,pub actor_name:Option<String>,pub action:String,pub resource_type:String,
    pub resource_id:Option<Uuid>,pub project_id:Option<Uuid>,pub detail:String,pub created_at:DateTime<Utc>,
}

pub async fn audit_log(State(state):State<AppState>,headers:HeaderMap,Query(filter):Query<AuditFilter>)->Result<Json<Vec<AuditEntry>>,ApiError>{
    let actor=auth::current_user(&state,&headers).await?;
    auth::require_role(&actor,&["owner","admin"])?;
    if let Some(a)=&filter.action {
        if a.len()>80 || !a.chars().all(|c|c.is_ascii_alphanumeric() || c=='.' || c=='_') {
            return Err(ApiError::bad_request("Invalid audit action filter"));
        }
    }
    let rows=sqlx::query_as::<_,AuditEntry>(r#"SELECT a.id,u.name AS actor_name,a.action,a.resource_type,
        a.resource_id,a.project_id,a.detail,a.created_at
      FROM audit_log a LEFT JOIN users u ON u.id=a.actor_id
      WHERE ($1::uuid IS NULL OR a.project_id=$1)
        AND ($2::text IS NULL OR a.action=$2)
        AND ($3::bigint IS NULL OR a.id<$3)
      ORDER BY a.id DESC LIMIT $4"#)
        .bind(filter.project_id).bind(filter.action).bind(filter.before_id)
        .bind(filter.limit.unwrap_or(50).clamp(1,100))
        .fetch_all(&state.pool).await?;
    Ok(Json(rows))
}

#[derive(Serialize,FromRow)]
pub struct Silence {
    pub id:Uuid,pub project_id:Uuid,pub project_name:String,pub channel:String,
    pub reason:String,pub created_by_name:Option<String>,
    pub created_at:DateTime<Utc>,pub ends_at:DateTime<Utc>,pub revoked_at:Option<DateTime<Utc>>,pub active:bool,
}
#[derive(Deserialize)]
pub struct SilenceFilter {pub project_id:Option<Uuid>,pub active_only:Option<bool>}
#[derive(Deserialize)]
pub struct NewSilence {pub project_id:Uuid,pub channel:String,pub hours:i32,pub reason:String}

async fn one(state:&AppState,id:Uuid)->Result<Silence,ApiError>{
    sqlx::query_as::<_,Silence>(r#"SELECT s.id,s.project_id,p.name AS project_name,s.channel,s.reason,
       u.name AS created_by_name,s.created_at,s.ends_at,s.revoked_at,
       (s.revoked_at IS NULL AND s.ends_at>NOW()) AS active
       FROM alert_silences s JOIN projects p ON p.id=s.project_id
       LEFT JOIN users u ON u.id=s.created_by WHERE s.id=$1"#)
        .bind(id).fetch_optional(&state.pool).await?.ok_or_else(ApiError::not_found)
}
pub async fn silences(State(state):State<AppState>,headers:HeaderMap,Query(f):Query<SilenceFilter>)->Result<Json<Vec<Silence>>,ApiError>{
    let actor=auth::current_user(&state,&headers).await?;
    auth::require_role(&actor,&["owner","admin"])?;
    let rows=sqlx::query_as::<_,Silence>(r#"SELECT s.id,s.project_id,p.name AS project_name,s.channel,s.reason,
       u.name AS created_by_name,s.created_at,s.ends_at,s.revoked_at,
       (s.revoked_at IS NULL AND s.ends_at>NOW()) AS active
       FROM alert_silences s JOIN projects p ON p.id=s.project_id
       LEFT JOIN users u ON u.id=s.created_by
       WHERE ($1::uuid IS NULL OR s.project_id=$1)
       AND (NOT $2::bool OR (s.revoked_at IS NULL AND s.ends_at>NOW()))
       ORDER BY s.created_at DESC LIMIT 100"#)
        .bind(f.project_id).bind(f.active_only.unwrap_or(false)).fetch_all(&state.pool).await?;
    Ok(Json(rows))
}
pub async fn create_silence(State(state):State<AppState>,headers:HeaderMap,Json(input):Json<NewSilence>)->Result<(StatusCode,Json<Silence>),ApiError>{
    auth::require_client_header(&headers)?;
    let actor=auth::current_user(&state,&headers).await?;
    auth::require_role(&actor,&["owner","admin"])?;
    if !matches!(input.channel.as_str(),"all"|"email"|"discord"|"webhook") {
        return Err(ApiError::bad_request("Invalid alert channel"));
    }
    if !(1..=168).contains(&input.hours) {return Err(ApiError::bad_request("Silence duration must be 1–168 hours"));}
    let reason=check_text(&input.reason,5,250,"Reason must be 5–250 characters")?;
    let mut tx=state.pool.begin().await?;
    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1)")
        .bind(input.project_id).fetch_one(&mut *tx).await?;
    if !exists {return Err(ApiError::not_found());}
    let id=Uuid::new_v4();
    sqlx::query("INSERT INTO alert_silences(id,project_id,channel,reason,created_by,ends_at) VALUES($1,$2,$3,$4,$5,NOW()+($6::int*INTERVAL '1 hour'))")
        .bind(id).bind(input.project_id).bind(&input.channel).bind(reason).bind(actor.id).bind(input.hours)
        .execute(&mut *tx).await?;
    audit::in_tx(&mut tx,Some(actor.id),"alerts.silenced","alert_silence",Some(id),Some(input.project_id),
        &format!("Silenced {} alerts for {} hours",input.channel,input.hours)).await?;
    tx.commit().await?;
    state.publish("alerts.silenced",Some(input.project_id));
    Ok((StatusCode::CREATED,Json(one(&state,id).await?)))
}
pub async fn revoke_silence(State(state):State<AppState>,headers:HeaderMap,Path(id):Path<Uuid>)->Result<Json<Silence>,ApiError>{
    auth::require_client_header(&headers)?;
    let actor=auth::current_user(&state,&headers).await?;
    auth::require_role(&actor,&["owner","admin"])?;
    let mut tx=state.pool.begin().await?;
    let project:Option<Uuid>=sqlx::query_scalar("UPDATE alert_silences SET revoked_at=NOW() WHERE id=$1 AND revoked_at IS NULL AND ends_at>NOW() RETURNING project_id")
        .bind(id).fetch_optional(&mut *tx).await?;
    let project=match project {
        Some(project)=>project,
        None=>{
            let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM alert_silences WHERE id=$1)")
                .bind(id).fetch_one(&mut *tx).await?;
            return Err(if exists {ApiError::conflict("Silence is no longer active")} else {ApiError::not_found()});
        }
    };
    audit::in_tx(&mut tx,Some(actor.id),"alerts.silence_revoked","alert_silence",Some(id),Some(project),"Alert silence ended early").await?;
    tx.commit().await?;
    state.publish("alerts.silence_revoked",Some(project));
    Ok(Json(one(&state,id).await?))
}

pub async fn retry_delivery(State(state):State<AppState>,headers:HeaderMap,Path(id):Path<i64>)->Result<StatusCode,ApiError>{
    auth::require_client_header(&headers)?;
    let actor=auth::current_user(&state,&headers).await?;
    auth::require_role(&actor,&["owner","admin"])?;
    let mut tx=state.pool.begin().await?;
    let record:Option<(Uuid,String,String)>=sqlx::query_as(r#"SELECT i.project_id,d.channel,d.status
        FROM alert_deliveries d JOIN incident_events e ON e.id=d.incident_event_id
        JOIN incidents i ON i.id=e.incident_id WHERE d.id=$1 FOR UPDATE OF d"#)
        .bind(id).fetch_optional(&mut *tx).await?;
    let (project,channel,status)=record.ok_or_else(ApiError::not_found)?;
    if status!="failed" && status!="suppressed" {return Err(ApiError::conflict("Only failed or suppressed deliveries can be retried"));}
    let silenced:bool=sqlx::query_scalar(r#"SELECT EXISTS(SELECT 1 FROM alert_silences
        WHERE project_id=$1 AND channel IN ('all',$2) AND revoked_at IS NULL AND ends_at>NOW())"#)
        .bind(project).bind(&channel).fetch_one(&mut *tx).await?;
    if silenced {return Err(ApiError::conflict("Alerts are currently silenced for this project"));}
    sqlx::query("UPDATE alert_deliveries SET status='pending',attempts=0,next_attempt_at=NOW(),leased_until=NULL,last_error=NULL,last_http_status=NULL,delivered_at=NULL WHERE id=$1")
        .bind(id).execute(&mut *tx).await?;
    audit::in_tx(&mut tx,Some(actor.id),"alerts.delivery_retried","alert_delivery",None,Some(project),
        &format!("Scheduled alert delivery #{} for retry",id)).await?;
    tx.commit().await?;
    state.publish("alerts.delivery_retried",Some(project));
    Ok(StatusCode::ACCEPTED)
}

#[cfg(test)]
mod tests{#[test]fn duration_bounds(){assert!((1..=168).contains(&24));assert!(!(1..=168).contains(&169));}}
