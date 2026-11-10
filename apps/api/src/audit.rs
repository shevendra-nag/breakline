//! Append-only administrative audit entries. Never log credentials, request
//! bodies, bearer tokens or provider responses; write only bounded summaries.
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

pub async fn in_tx(
    tx: &mut Transaction<'_, Postgres>, actor: Option<Uuid>, action: &str,
    resource_type: &str, resource_id: Option<Uuid>, project_id: Option<Uuid>, detail: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO audit_log(actor_id,action,resource_type,resource_id,project_id,detail) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(actor).bind(action).bind(resource_type).bind(resource_id).bind(project_id)
        .bind(detail.chars().take(350).collect::<String>())
        .execute(&mut **tx).await?;
    Ok(())
}

pub async fn write(
    pool: &PgPool, actor: Option<Uuid>, action: &str,
    resource_type: &str, resource_id: Option<Uuid>, project_id: Option<Uuid>, detail: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO audit_log(actor_id,action,resource_type,resource_id,project_id,detail) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(actor).bind(action).bind(resource_type).bind(resource_id).bind(project_id)
        .bind(detail.chars().take(350).collect::<String>())
        .execute(pool).await?;
    Ok(())
}
