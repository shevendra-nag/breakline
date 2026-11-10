//! Durable, opt-in outbound alert delivery. Destinations are configured ONLY
//! through server environment variables; neither browser requests nor incident
//! content can control the URL. DNS results are validated and pinned on send.
use std::{env,net::{IpAddr,SocketAddr},time::Duration};
use hmac::{Hmac,Mac};
use reqwest::{Client, Url};
use serde_json::{json,Value};
use sha2::Sha256;
use sqlx::FromRow;
use uuid::Uuid;
use crate::{auth,monitor_url,AppState};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone,Default)]
pub struct AlertConfig {
    pub webhook_url: Option<String>,
    pub webhook_secret: Option<String>,
    pub discord_url: Option<String>,
    pub resend_key: Option<String>,
    pub email_from: Option<String>,
    pub email_to: Option<String>,
}
impl AlertConfig {
    pub fn from_env() -> Self {
        let webhook_url = env::var("BREAKLINE_ALERT_WEBHOOK_URL").ok().filter(|v| !v.is_empty())
            .and_then(|value| safe_url(&value));
        let webhook_secret = env::var("BREAKLINE_ALERT_SIGNING_SECRET").ok().filter(|v| v.len()>=32);
        let discord_url = env::var("BREAKLINE_DISCORD_WEBHOOK_URL").ok().filter(|v| {
            (v.starts_with("https://discord.com/api/webhooks/") || v.starts_with("https://discordapp.com/api/webhooks/"))
                && v.len()>"https://discord.com/api/webhooks/".len()+10
        }).and_then(|value| safe_url(&value));
        let resend_key = env::var("RESEND_API_KEY").ok().filter(|v| !v.is_empty());
        let email_from = env::var("RESEND_FROM_EMAIL").ok().and_then(|v| auth::validate_email(&v).ok());
        let email_to = env::var("BREAKLINE_ALERT_EMAIL_TO").ok().and_then(|v| auth::validate_email(&v).ok());
        Self { webhook_url, webhook_secret, discord_url, resend_key, email_from, email_to }
    }
    pub fn webhook_ready(&self) -> bool { self.webhook_url.is_some() && self.webhook_secret.is_some() }
    pub fn email_ready(&self) -> bool { self.resend_key.is_some() && self.email_from.is_some() && self.email_to.is_some() }
}
fn safe_url(value: &str) -> Option<String> { monitor_url::validate_url(value).ok() }

#[derive(FromRow)]
struct AlertJob {
    channel: String,
    event_id: i64,
    kind: String,
    message: String,
    incident_id: Uuid,
    project_id: Uuid,
    title: String,
    severity: String,
    source: String,
    project_name: String,
    environment_name: String,
}

/// Returns the exact ASCII hex digest of the JSON body (not a normalized or
/// reserialized copy). The receiver can validate X-Breakline-Signature.
fn sign(body: &[u8], secret: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts arbitrary key lengths");
    mac.update(body);
    mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// HTTPS, no proxy, no redirects, global public DNS only, pinned socket set.
/// This prevents server-side alert delivery from reaching metadata/internal IPs.
async fn http_client(url: &str) -> Result<Client,&'static str> {
    let parsed = Url::parse(url).map_err(|_| "invalid configured destination")?;
    let host = parsed.host_str().ok_or("missing destination host")?;
    let literal = host.trim_matches(|c| c=='[' || c==']');
    let addresses: Vec<SocketAddr> = if let Ok(ip) = literal.parse::<IpAddr>() {
        vec![SocketAddr::new(ip,443)]
    } else {
        tokio::net::lookup_host((host,443)).await.map_err(|_| "destination DNS failed")?.collect()
    };
    if addresses.is_empty() || addresses.iter().any(|a| !monitor_url::public_ip(a.ip())) {
        return Err("destination DNS resolved to an unsafe IP");
    }
    Client::builder().https_only(true).no_proxy().redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(host,&addresses).timeout(Duration::from_secs(8))
        .user_agent("BreaklineAlerts/1.0")
        .build().map_err(|_| "failed to initialize HTTPS client")
}

/// Error messages deliberately contain no response body, token, destination or
/// recipient to avoid logging sensitive provider credentials.
async fn send(job: &AlertJob, cfg: &AlertConfig) -> Result<(),(Option<i32>, &'static str)> {
    let body_text = format!("{}: {} [{} / {}]\n{}\nIncident ID: {}",job.kind.to_uppercase(),job.title,job.project_name,job.environment_name,job.message,job.incident_id);
    let (destination,body): (&str,Value) = match job.channel.as_str() {
        "discord" => (cfg.discord_url.as_deref().ok_or((None,"Discord not configured"))?, json!({"content":body_text.chars().take(1800).collect::<String>()})),
        "webhook" => (cfg.webhook_url.as_deref().ok_or((None,"Webhook not configured"))?, json!({
            "id":job.event_id,"event":format!("incident.{}",job.kind),"incident_id":job.incident_id,
            "project":job.project_name,"environment":job.environment_name,
            "severity":job.severity,"source":job.source,"title":job.title,"message":job.message,
        })),
        "email" => ("https://api.resend.com/emails",json!({
            "from":cfg.email_from.as_deref().ok_or((None,"Email not configured"))?,
            "to":[cfg.email_to.as_deref().ok_or((None,"Email not configured"))?],
            "subject":format!("[Breakline] {} · {}",job.kind,job.title),
            "text":body_text,
        })),
        _ => return Err((None,"Unknown delivery channel")),
    };
    let client = http_client(destination).await.map_err(|e| (None,e))?;
    let bytes = serde_json::to_vec(&body).map_err(|_|(None,"Serialization error"))?;
    let mut request = client.post(destination).header("Content-Type","application/json");
    if job.channel == "webhook" {
        let secret = cfg.webhook_secret.as_deref().ok_or((None,"Webhook signing key not configured"))?;
        request = request.header("X-Breakline-Signature",format!("sha256={}",sign(&bytes,secret)));
    }
    if job.channel == "email" {
        request = request.bearer_auth(cfg.resend_key.as_deref().ok_or((None,"Email not configured"))?);
    }
    let response = request.body(bytes).send().await.map_err(|_| (None,"HTTPS request failed"))?;
    if response.status().is_success() { Ok(()) }
    else { Err((Some(i32::from(response.status().as_u16())),"Provider returned non-success HTTP status")) }
}

async fn send_one(state: AppState, id: i64) {
    let job: Result<Option<AlertJob>,sqlx::Error> = sqlx::query_as(r#"SELECT d.channel,e.id AS event_id,e.kind,e.message,
        i.id AS incident_id,i.project_id,i.title,i.severity,i.source,p.name AS project_name,
        env.name AS environment_name FROM alert_deliveries d
        JOIN incident_events e ON e.id=d.incident_event_id
        JOIN incidents i ON i.id=e.incident_id
        JOIN projects p ON p.id=i.project_id
        JOIN environments env ON env.id=i.environment_id WHERE d.id=$1"#)
        .bind(id).fetch_optional(&state.pool).await;
    let job = match job { Ok(Some(v))=>v,Ok(None)=>return,Err(e)=>{tracing::warn!(%e,"failed to load alert delivery");return;} };
    // Silence is checked at dispatch time, rather than event creation time.
    // Jobs that are silenced are marked as such and require explicit admin retry.
    let silenced:Result<bool,sqlx::Error>=sqlx::query_scalar(r#"SELECT EXISTS(
        SELECT 1 FROM alert_silences WHERE project_id=$1 AND channel IN ('all',$2)
          AND revoked_at IS NULL AND ends_at>NOW())"#)
        .bind(job.project_id).bind(&job.channel).fetch_one(&state.pool).await;
    match silenced {
        Ok(true) => {
            if let Err(error)=sqlx::query("UPDATE alert_deliveries SET status='suppressed',leased_until=NULL,last_error='Suppressed by an active alert silence' WHERE id=$1 AND status='leased'")
                .bind(id).execute(&state.pool).await {
                tracing::warn!(%error,"failed to suppress an alert delivery");
            }
            return;
        }
        Err(error) => {tracing::warn!(%error,"could not read alert silence rules");return;}
        Ok(false) => {}
    }
    let response = send(&job,&state.alerts).await;
    let (ok,code,error) = match response { Ok(())=>(true,None,None),Err((code,message))=>(false,code,Some(message)) };
    let result = sqlx::query(r#"UPDATE alert_deliveries SET attempts=attempts+1,
        status=CASE WHEN $2 THEN 'delivered' WHEN attempts+1>=5 THEN 'failed' ELSE 'pending' END,
        delivered_at=CASE WHEN $2 THEN NOW() ELSE delivered_at END,
        next_attempt_at=NOW()+(CASE WHEN attempts=0 THEN 60 WHEN attempts=1 THEN 300 WHEN attempts=2 THEN 900 ELSE 3600 END * INTERVAL '1 second'),
        leased_until=NULL,last_http_status=$3,last_error=$4 WHERE id=$1 AND status='leased'"#)
        .bind(id).bind(ok).bind(code).bind(error).execute(&state.pool).await;
    if let Err(e) = result { tracing::warn!(%e,"failed to update alert delivery"); }
}

pub async fn dispatch_pending(state: &AppState) -> Result<(),sqlx::Error> {
    let ids: Vec<i64> = sqlx::query_scalar(r#"WITH due AS (
        SELECT id FROM alert_deliveries WHERE attempts < 5 AND next_attempt_at<=NOW()
          AND (status='pending' OR (status='leased' AND leased_until<NOW()))
        ORDER BY next_attempt_at,id LIMIT 12 FOR UPDATE SKIP LOCKED
    ) UPDATE alert_deliveries d SET status='leased',leased_until=NOW()+INTERVAL '90 seconds'
        FROM due WHERE d.id=due.id RETURNING d.id"#).fetch_all(&state.pool).await?;
    let mut tasks = tokio::task::JoinSet::new();
    for id in ids { let state = state.clone(); tasks.spawn(send_one(state,id)); }
    while let Some(result) = tasks.join_next().await { if let Err(e)=result {tracing::warn!(%e,"alert task failed");} }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signs_exact_payload() {
        let secret = "test-secret";
        let first=sign(br#"{"event":"incident.opened"}"#,secret);
        let same=sign(br#"{"event":"incident.opened"}"#,secret);
        let different=sign(br#"{"event":"incident.resolved"}"#,secret);
        assert_eq!(first,same);
        assert_eq!(first.len(),64);
        assert_ne!(first,different);
    }
    #[test]
    fn destination_urls_reject_private_targets_and_queries() {
        assert!(safe_url("https://127.0.0.1/hook").is_none());
        assert!(safe_url("http://example.com/hook").is_none());
        assert!(safe_url("https://example.com/hook?token=hidden").is_none());
        assert!(safe_url("https://example.com/hook").is_some());
    }
}
