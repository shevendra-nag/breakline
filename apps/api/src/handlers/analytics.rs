//! Incident and release statistics computed from stored data; no fake data.
use axum::{extract::{Query,State},http::HeaderMap,Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize,Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use crate::{auth,error::ApiError,AppState};

#[derive(Deserialize)]
pub struct Filter { pub project_id:Option<Uuid>, pub days:Option<i64> }
#[derive(Serialize)]
pub struct Scorecard {
    pub incidents:i64, pub resolved:i64, pub active:i64,
    pub mean_acknowledgement_minutes:Option<f64>,
    pub mean_resolution_minutes:Option<f64>,
    pub deployments:i64, pub successful_deployments:i64,
    pub uptime_percent:Option<f64>, pub checked_samples:i64,
    pub alert_delivered:i64, pub alert_failed:i64,
}
#[derive(Serialize,FromRow)]
pub struct Point { pub day:String, pub opened:i64, pub resolved:i64, pub deployments:i64, pub failed_deployments:i64 }
#[derive(Serialize,FromRow)]
pub struct ProjectImpact {pub id:Uuid,pub name:String,pub incidents:i64,pub critical:i64,pub avg_resolution_minutes:Option<f64>}
#[derive(Serialize)]
pub struct Analytics {pub days:i64,pub project_id:Option<Uuid>,pub from:DateTime<Utc>,pub scorecard:Scorecard,pub daily:Vec<Point>,pub impacted_projects:Vec<ProjectImpact>}

fn window_days(input:Option<i64>)->Result<i64,ApiError>{
    let days=input.unwrap_or(30);
    if [7,30,90].contains(&days){Ok(days)} else {Err(ApiError::bad_request("Analytics period must be 7, 30 or 90 days"))}
}

pub async fn get(State(state):State<AppState>,headers:HeaderMap,Query(filter):Query<Filter>)->Result<Json<Analytics>,ApiError>{
    auth::current_user(&state,&headers).await?;
    let days=window_days(filter.days)?;
    if let Some(project_id)=filter.project_id {
        let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1)").bind(project_id).fetch_one(&state.pool).await?;
        if !exists {return Err(ApiError::not_found());}
    }
    let first_day=Utc::now().date_naive()-chrono::Duration::days(days-1);
    let from=DateTime::<Utc>::from_naive_utc_and_offset(first_day.and_hms_opt(0,0,0).expect("valid midnight"),Utc);
    // Resolution and acknowledgement durations use their own timestamps;
    // ongoing incidents do not bias mean resolution time.
    let incident:(i64,i64,i64,Option<f64>,Option<f64>)=sqlx::query_as(r#"SELECT COUNT(*)::bigint,
      COUNT(*) FILTER(WHERE resolved_at IS NOT NULL)::bigint,
      COUNT(*) FILTER(WHERE status<>'resolved')::bigint,
      AVG(EXTRACT(EPOCH FROM (acknowledged_at-detected_at))/60.0)::float8,
      AVG(EXTRACT(EPOCH FROM (resolved_at-detected_at))/60.0)::float8
      FROM incidents WHERE detected_at >= $1 AND ($2::uuid IS NULL OR project_id=$2)"#)
        .bind(from).bind(filter.project_id).fetch_one(&state.pool).await?;
    let deployments:(i64,i64)=sqlx::query_as(r#"SELECT COUNT(*)::bigint,
      COUNT(*) FILTER(WHERE status='succeeded')::bigint FROM deployments
      WHERE created_at >= $1 AND ($2::uuid IS NULL OR project_id=$2)"#)
        .bind(from).bind(filter.project_id).fetch_one(&state.pool).await?;
    let checks:(i64,Option<f64>)=sqlx::query_as(r#"SELECT COUNT(*)::bigint,
      (100.0*COUNT(*) FILTER(WHERE c.status='up')/NULLIF(COUNT(*),0))::float8
      FROM monitor_checks c JOIN monitors m ON m.id=c.monitor_id
      WHERE c.checked_at >= $1 AND ($2::uuid IS NULL OR m.project_id=$2)"#)
        .bind(from).bind(filter.project_id).fetch_one(&state.pool).await?;
    let alerts:(i64,i64)=sqlx::query_as(r#"SELECT COUNT(*) FILTER(WHERE d.status='delivered')::bigint,
      COUNT(*) FILTER(WHERE d.status='failed')::bigint
      FROM alert_deliveries d JOIN incident_events e ON e.id=d.incident_event_id
      JOIN incidents i ON i.id=e.incident_id WHERE d.created_at >= $1 AND ($2::uuid IS NULL OR i.project_id=$2)"#)
        .bind(from).bind(filter.project_id).fetch_one(&state.pool).await?;
    let daily=sqlx::query_as::<_,Point>(r#"SELECT TO_CHAR(day::date,'YYYY-MM-DD') AS day,
       (SELECT COUNT(*)::bigint FROM incidents i WHERE i.detected_at::date=day::date AND ($2::uuid IS NULL OR i.project_id=$2)) AS opened,
       (SELECT COUNT(*)::bigint FROM incidents i WHERE i.resolved_at::date=day::date AND ($2::uuid IS NULL OR i.project_id=$2)) AS resolved,
       (SELECT COUNT(*)::bigint FROM deployments d WHERE d.created_at::date=day::date AND ($2::uuid IS NULL OR d.project_id=$2)) AS deployments,
       (SELECT COUNT(*)::bigint FROM deployments d WHERE d.created_at::date=day::date AND d.status='failed' AND ($2::uuid IS NULL OR d.project_id=$2)) AS failed_deployments
       FROM GENERATE_SERIES((CURRENT_DATE-$1::int+1)::date,CURRENT_DATE,INTERVAL '1 day') AS series(day) ORDER BY day"#)
        .bind(days as i32).bind(filter.project_id).fetch_all(&state.pool).await?;
    let impacted_projects=sqlx::query_as::<_,ProjectImpact>(r#"SELECT p.id,p.name,
      COUNT(i.id)::bigint AS incidents,
      COUNT(i.id) FILTER(WHERE i.severity='critical')::bigint AS critical,
      AVG(EXTRACT(EPOCH FROM (i.resolved_at-i.detected_at))/60.0)::float8 AS avg_resolution_minutes
      FROM projects p JOIN incidents i ON i.project_id=p.id AND i.detected_at >= $1
      WHERE ($2::uuid IS NULL OR p.id=$2) GROUP BY p.id,p.name
      ORDER BY incidents DESC,p.name LIMIT 8"#)
        .bind(from).bind(filter.project_id).fetch_all(&state.pool).await?;
    Ok(Json(Analytics{days,project_id:filter.project_id,from,
        scorecard:Scorecard{incidents:incident.0,resolved:incident.1,active:incident.2,
            mean_acknowledgement_minutes:incident.3,mean_resolution_minutes:incident.4,
            deployments:deployments.0,successful_deployments:deployments.1,
            uptime_percent:checks.1,checked_samples:checks.0,
            alert_delivered:alerts.0,alert_failed:alerts.1},
        daily,impacted_projects}))
}

#[cfg(test)]
mod tests{use super::*;#[test]fn period_is_bounded(){assert_eq!(window_days(None).unwrap(),30);for d in [7,30,90]{assert!(window_days(Some(d)).is_ok())}assert!(window_days(Some(365)).is_err());}}
