//! Integration smoke test. Runs automatically in CI with TEST_DATABASE_URL.
//! Skips locally unless a disposable PostgreSQL database is configured.
use std::{process::{Child, Command, Stdio}, time::Duration};
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};

struct ProcessGuard(Child);
impl Drop for ProcessGuard {
    fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
}

#[tokio::test]
async fn api_monitoring_and_ingestion_smoke() {
    let Ok(db) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("skipped: TEST_DATABASE_URL is not configured");
        return;
    };
    let sock = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();
    drop(sock);
    let child = Command::new(env!("CARGO_BIN_EXE_breakline-api"))
        .env("DATABASE_URL", db)
        .env("BOOTSTRAP_TOKEN", "test-bootstrap-token-12345678901234567890")
        .env("API_HOST", "127.0.0.1")
        .env("API_PORT", port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn().expect("spawn API");
    let _server = ProcessGuard(child);
    let base = format!("http://127.0.0.1:{port}/api/v1");
    let client = Client::new();
    let mut ready = false;
    for _ in 0..60 {
        if let Ok(response) = client.get(format!("{base}/health")).send().await {
            if response.status().is_success() { ready = true; break; }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(ready, "API startup timed out");
    let unauthorized = client.get(format!("{base}/monitors")).send().await.unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let response = client.post(format!("{base}/auth/setup"))
        .header("X-Breakline-Client", "web")
        .json(&json!({"name":"Test Owner","email":"test-owner@example.com","password":"correct horse battery staple","setup_token":"test-bootstrap-token-12345678901234567890"}))
        .send().await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let cookie = response.headers().get(reqwest::header::SET_COOKIE).unwrap().to_str().unwrap()
        .split(';').next().unwrap().to_string();
    let created = client.post(format!("{base}/projects"))
        .header("Cookie", &cookie).header("X-Breakline-Client", "web")
        .json(&json!({"name":"Monitoring test app","description":"CI integration app","repository_url":""}))
        .send().await.unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let project: Value = created.json().await.unwrap();
    let project_id = project["id"].as_str().unwrap();
    let environments: Vec<Value> = client.get(format!("{base}/projects/{project_id}/environments"))
        .header("Cookie", &cookie).send().await.unwrap().json().await.unwrap();
    let production = environments.iter().find(|e| e["slug"] == "production").unwrap()["id"].as_str().unwrap();

    // Step 4: audit and analytics require a signed-in user; admin-only controls.
    let metrics: Value = client.get(format!("{base}/analytics?project_id={project_id}&days=30"))
        .header("Cookie", &cookie).send().await.unwrap().json().await.unwrap();
    assert_eq!(metrics["days"], 30);
    assert_eq!(metrics["scorecard"]["deployments"], 0);
    assert_eq!(metrics["daily"].as_array().unwrap().len(), 30);
    let invalid_period = client.get(format!("{base}/analytics?days=365"))
        .header("Cookie", &cookie).send().await.unwrap();
    assert_eq!(invalid_period.status(), StatusCode::BAD_REQUEST);
    let audit: Vec<Value> = client.get(format!("{base}/audit"))
        .header("Cookie", &cookie).send().await.unwrap().json().await.unwrap();
    assert!(!audit.is_empty());
    let silenced = client.post(format!("{base}/alerts/silences"))
        .header("Cookie", &cookie).header("X-Breakline-Client", "web")
        .json(&json!({"project_id":project_id,"channel":"all","hours":2,"reason":"CI testing maintenance"}))
        .send().await.unwrap();
    assert_eq!(silenced.status(), StatusCode::CREATED);
    let silence: Value = silenced.json().await.unwrap();
    assert_eq!(silence["active"], true);
    let active: Vec<Value> = client.get(format!("{base}/alerts/silences?project_id={project_id}&active_only=true"))
        .header("Cookie", &cookie).send().await.unwrap().json().await.unwrap();
    assert_eq!(active.len(), 1);
    let ended = client.post(format!("{base}/alerts/silences/{}/revoke", silence["id"].as_str().unwrap()))
        .header("Cookie", &cookie).header("X-Breakline-Client", "web")
        .send().await.unwrap();
    assert_eq!(ended.status(), StatusCode::OK);
    let invalid_retry = client.post(format!("{base}/alerts/deliveries/99999999/retry"))
        .header("Cookie", &cookie).header("X-Breakline-Client", "web")
        .send().await.unwrap();
    assert_eq!(invalid_retry.status(), StatusCode::NOT_FOUND);
    let invalid = client.post(format!("{base}/monitors"))
        .header("Cookie", &cookie).header("X-Breakline-Client", "web")
        .json(&json!({"project_id":project_id,"environment_id":production,"name":"Blocked local","url":"https://127.0.0.1/health"}))
        .send().await.unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST, "private address should be blocked at creation");
    let created = client.post(format!("{base}/monitors"))
        .header("Cookie", &cookie).header("X-Breakline-Client", "web")
        .json(&json!({"project_id":project_id,"environment_id":production,"name":"Public health","url":"https://example.com/health","interval_seconds":300}))
        .send().await.unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let monitor: Value = created.json().await.unwrap();
    assert_eq!(monitor["last_status"], "unknown");
    let list: Vec<Value> = client.get(format!("{base}/monitors?project_id={project_id}"))
        .header("Cookie", &cookie).send().await.unwrap().json().await.unwrap();
    assert_eq!(list.len(), 1);

    let response = client.post(format!("{base}/projects/{project_id}/ingest-tokens"))
        .header("Cookie", &cookie).header("X-Breakline-Client", "web")
        .json(&json!({"label":"CI token"})).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let secret: Value = response.json().await.unwrap();
    let bearer = secret["token"].as_str().unwrap();
    let deployment = json!({"delivery_id":"ci-evt-1","external_id":"ci-run-1","environment":"production","version":"v1.0.0","status":"running"});
    let posted = client.post(format!("{base}/ingest/deployments")).bearer_auth(bearer)
        .json(&deployment).send().await.unwrap();
    assert_eq!(posted.status(), StatusCode::OK);
    let receipt: Value = posted.json().await.unwrap();
    assert_eq!(receipt["changed"], true);
    let duplicate: Value = client.post(format!("{base}/ingest/deployments")).bearer_auth(bearer)
        .json(&deployment).send().await.unwrap().json().await.unwrap();
    assert_eq!(duplicate["changed"], false);

    let metrics = client.post(format!("{base}/ingest/metrics")).bearer_auth(bearer)
        .json(&json!({"environment":"production","samples":[{"route":"/api/orders","method":"GET","status_code":200,"latency_ms":42},{"route":"/api/orders","method":"GET","status_code":503,"latency_ms":220}]}))
        .send().await.unwrap();
    assert_eq!(metrics.status(), StatusCode::ACCEPTED);
    let perf: Value = client.get(format!("{base}/performance?project_id={project_id}"))
        .header("Cookie", &cookie).send().await.unwrap().json().await.unwrap();
    assert_eq!(perf["metrics"]["requests"], 2);
    assert_eq!(perf["metrics"]["errors"], 1);

    let revoked = client.delete(format!("{base}/projects/{project_id}/ingest-tokens/{}", secret["credential"]["id"].as_str().unwrap()))
        .header("Cookie", &cookie).header("X-Breakline-Client", "web")
        .send().await.unwrap();
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
    let denied = client.post(format!("{base}/ingest/deployments")).bearer_auth(bearer)
        .json(&json!({"delivery_id":"ci-evt-2","external_id":"ci-run-1","environment":"production","version":"v1.0.0","status":"succeeded"}))
        .send().await.unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    // Incident rules remain scoped to this project and permit admin-only updates.
    let rules: Value=client.get(format!("{base}/projects/{project_id}/incident-rules"))
        .header("Cookie",&cookie).send().await.unwrap().json().await.unwrap();
    assert_eq!(rules["failure_threshold"],3);
    let update=client.put(format!("{base}/projects/{project_id}/incident-rules"))
        .header("Cookie",&cookie).header("X-Breakline-Client","web")
        .json(&json!({
            "monitor_enabled":true,"deployment_enabled":true,"metrics_enabled":true,
            "failure_threshold":2,"api_error_threshold":15,"minimum_samples":30,
            "notify_email":false,"notify_discord":false,"notify_webhook":false
        })).send().await.unwrap();
    assert_eq!(update.status(),StatusCode::OK);
    let out_of_range=client.put(format!("{base}/projects/{project_id}/incident-rules"))
        .header("Cookie",&cookie).header("X-Breakline-Client","web")
        .json(&json!({
            "monitor_enabled":true,"deployment_enabled":true,"metrics_enabled":true,
            "failure_threshold":1,"api_error_threshold":15,"minimum_samples":30,
            "notify_email":true,"notify_discord":true,"notify_webhook":true
        })).send().await.unwrap();
    assert_eq!(out_of_range.status(),StatusCode::BAD_REQUEST);

    let created=client.post(format!("{base}/projects/{project_id}/deployments"))
        .header("Cookie",&cookie).header("X-Breakline-Client","web")
        .json(&json!({"environment_id":production,"version":"v1.9.1","description":"Release under test"}))
        .send().await.unwrap();
    assert_eq!(created.status(),StatusCode::CREATED);
    let release: Value=created.json().await.unwrap();
    let release_id=release["id"].as_str().unwrap();
    let failed=client.patch(format!("{base}/deployments/{release_id}/status"))
        .header("Cookie",&cookie).header("X-Breakline-Client","web")
        .json(&json!({"status":"failed"})).send().await.unwrap();
    assert_eq!(failed.status(),StatusCode::OK);

    let incident_list:Vec<Value>=client.get(format!("{base}/incidents?project_id={project_id}&status=active"))
        .header("Cookie",&cookie).send().await.unwrap().json().await.unwrap();
    assert_eq!(incident_list.len(),1);
    assert_eq!(incident_list[0]["source"],"deployment");
    assert_eq!(incident_list[0]["status"],"open");
    let incident_id=incident_list[0]["id"].as_str().unwrap();
    let detail:Value=client.get(format!("{base}/incidents/{incident_id}"))
        .header("Cookie",&cookie).send().await.unwrap().json().await.unwrap();
    assert_eq!(detail["timeline"].as_array().unwrap().len(),1);
    assert_eq!(detail["regression"]["assessment"],"no_candidate");

    let viewer=client.post(format!("{base}/users"))
        .header("Cookie",&cookie).header("X-Breakline-Client","web")
        .json(&json!({"name":"Read Only","email":"viewer-incident@example.com",
            "password":"another long secure password","role":"viewer"})).send().await.unwrap();
    assert_eq!(viewer.status(),StatusCode::CREATED);
    let logged=client.post(format!("{base}/auth/login"))
        .header("X-Breakline-Client","web")
        .json(&json!({"email":"viewer-incident@example.com","password":"another long secure password"}))
        .send().await.unwrap();
    assert_eq!(logged.status(),StatusCode::OK);
    let viewer_cookie=logged.headers().get(reqwest::header::SET_COOKIE).unwrap().to_str().unwrap()
        .split(';').next().unwrap().to_string();
    let forbidden=client.post(format!("{base}/incidents/{incident_id}/acknowledge"))
        .header("Cookie",&viewer_cookie).header("X-Breakline-Client","web")
        .send().await.unwrap();
    assert_eq!(forbidden.status(),StatusCode::FORBIDDEN);
    let read=client.get(format!("{base}/incidents/{incident_id}"))
        .header("Cookie",&viewer_cookie).send().await.unwrap();
    assert_eq!(read.status(),StatusCode::OK);

    // Viewers may read analytics but never view audit logs or change alert policy.
    let viewer_analytics=client.get(format!("{base}/analytics?days=7"))
        .header("Cookie",&viewer_cookie).send().await.unwrap();
    assert_eq!(viewer_analytics.status(),StatusCode::OK);
    let viewer_audit=client.get(format!("{base}/audit"))
        .header("Cookie",&viewer_cookie).send().await.unwrap();
    assert_eq!(viewer_audit.status(),StatusCode::FORBIDDEN);
    let viewer_silence=client.post(format!("{base}/alerts/silences"))
        .header("Cookie",&viewer_cookie).header("X-Breakline-Client","web")
        .json(&json!({"project_id":project_id,"channel":"all","hours":2,"reason":"Should not be allowed"}))
        .send().await.unwrap();
    assert_eq!(viewer_silence.status(),StatusCode::FORBIDDEN);
    let acknowledge=client.post(format!("{base}/incidents/{incident_id}/acknowledge"))
        .header("Cookie",&cookie).header("X-Breakline-Client","web")
        .send().await.unwrap();
    assert_eq!(acknowledge.status(),StatusCode::OK);
    let duplicate_ack=client.post(format!("{base}/incidents/{incident_id}/acknowledge"))
        .header("Cookie",&cookie).header("X-Breakline-Client","web")
        .send().await.unwrap();
    assert_eq!(duplicate_ack.status(),StatusCode::CONFLICT);
    let commented=client.post(format!("{base}/incidents/{incident_id}/comments"))
        .header("Cookie",&cookie).header("X-Breakline-Client","web")
        .json(&json!({"message":"Release failed, rolling back deployment"})).send().await.unwrap();
    assert_eq!(commented.status(),StatusCode::CREATED);
    let resolved=client.post(format!("{base}/incidents/{incident_id}/resolve"))
        .header("Cookie",&cookie).header("X-Breakline-Client","web")
        .send().await.unwrap();
    assert_eq!(resolved.status(),StatusCode::OK);
    let again=client.post(format!("{base}/incidents/{incident_id}/resolve"))
        .header("Cookie",&cookie).header("X-Breakline-Client","web")
        .send().await.unwrap();
    assert_eq!(again.status(),StatusCode::CONFLICT);
    let history:Value=client.get(format!("{base}/incidents/{incident_id}"))
        .header("Cookie",&cookie).send().await.unwrap().json().await.unwrap();
    assert_eq!(history["timeline"].as_array().unwrap().len(),4);
    let active:Vec<Value>=client.get(format!("{base}/incidents?project_id={project_id}&status=active"))
        .header("Cookie",&cookie).send().await.unwrap().json().await.unwrap();
    assert!(active.is_empty());
    let stats:Value=client.get(format!("{base}/incidents/summary?project_id={project_id}"))
        .header("Cookie",&cookie).send().await.unwrap().json().await.unwrap();
    assert_eq!(stats["resolved_7d"],1);
    let channels:Value=client.get(format!("{base}/alerts/channels"))
        .header("Cookie",&cookie).send().await.unwrap().json().await.unwrap();
    assert_eq!(channels["email"],false);

}
