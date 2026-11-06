# Breakline deployment guide

This runbook is for one-instance deployments using the included PostgreSQL + Rust API + Nginx web stack. The default Compose configuration is **localhost-only**, not a public HTTPS deployment.

## 1. Requirements

- Linux host or a managed Docker-compatible environment with Docker Compose v2.
- Public DNS record for a hostname you control, and a trusted TLS reverse proxy (Caddy, Nginx, Traefik, etc.) for internet-facing usage.
- Database backups and access to the original PostgreSQL volume before every upgrade.
- Outbound HTTPS if monitoring public services or sending alerts.

Generate two independent random secrets:

```bash
openssl rand -hex 32
openssl rand -hex 32
```

Copy `.env.example` to `.env` (never commit it). Set `POSTGRES_PASSWORD`, `BOOTSTRAP_TOKEN` and `DATABASE_URL` consistently:

```dotenv
POSTGRES_DB=breakline
POSTGRES_USER=breakline
POSTGRES_PASSWORD=replace-with-your-random-password
DATABASE_URL=postgres://breakline:replace-with-your-random-password@db:5432/breakline
BOOTSTRAP_TOKEN=replace-with-your-different-random-token
COOKIE_SECURE=false
PUBLIC_ORIGIN=
WEB_PORT=3000
```

The values above are **examples**, not working credentials. Use your generated values; percent-encode reserved characters in database URL credentials. `POSTGRES_PASSWORD` and `BOOTSTRAP_TOKEN` must be different. The first owner uses `BOOTSTRAP_TOKEN` only once, during setup.

## 2. Start locally

```bash
docker compose up -d --build
docker compose ps
docker compose logs --tail=100 api
curl -fsS http://127.0.0.1:3000/api/v1/health/ready
```

Open `http://127.0.0.1:3000` and create the owner. The readiness endpoint returns `200` only when PostgreSQL responds. The liveness endpoint `/api/v1/health` does not check the database.

**Never** expose port 8080 or database port 5432 directly to the public internet. The API is only accessible through the included web proxy by default. If a host firewall exists, explicitly close database access from the public network.

## 3. Public HTTPS deployment

Terminate TLS at a host-level reverse proxy. For example, a simple Caddyfile on the host can be:

```caddyfile
breakline.example.com {
    encode gzip
    reverse_proxy 127.0.0.1:3000
}
```

The domain is illustrative; replace it with your own hostname and point the DNS record at your server. Run Caddy (or another trusted TLS reverse proxy) independently and verify the actual HTTPS certificate is valid.

Set both of these values in `.env`:

```dotenv
COOKIE_SECURE=true
PUBLIC_ORIGIN=https://breakline.example.com
```

`PUBLIC_ORIGIN` must be the **exact** browser origin, including `https://` and any nonstandard port, with no trailing slash or path. When `COOKIE_SECURE=true`, the API refuses to start without an HTTPS `PUBLIC_ORIGIN`. Requests from a browser with a different `Origin` are rejected. Recreate the API container after editing the environment:

```bash
docker compose up -d --force-recreate api
```

Verify login, logout, monitor scheduling, server-sent events and the new Analytics/Governance pages over HTTPS. Configure HSTS at your TLS-terminating proxy only after confirming that HTTPS works correctly and you intend to enforce it for the domain.

## 4. Upgrade from Breakline Step 3

The final release adds a fourth **additive** SQL migration. It preserves previous accounts, projects, releases, incidents, monitor checks, ingestion tokens and alert deliveries. It also imports the previous activity feed into the new `audit_log` table. Do not delete or replace your PostgreSQL volume.

1. Take a consistent database backup, test that it can be restored, and store it outside the host.
2. Extract the new source over the previous tracked code files, keeping the original `.env` and persistent PostgreSQL volume.
3. Add the new `PUBLIC_ORIGIN` variable to `.env`. If using `COOKIE_SECURE=true`, set it to your HTTPS browser origin before starting.
4. Run `docker compose up -d --build`.
5. Check `docker compose logs --tail=150 api` for migration errors.
6. Verify `/api/v1/health/ready`, the dashboard, project data, and historical incidents.
7. In the owner account, check Analytics, Governance → Audit trail and Governance → Alert controls.

SQLx runs migrations during API startup. If a migration fails, investigate the error; **do not** mark migrations complete manually or wipe the volume.

## 5. PostgreSQL backup and restore

For a consistent logical backup from the Compose database (run in the repository root):

```bash
docker compose exec -T db pg_dump -U breakline -d breakline -Fc > breakline-backup.dump
```

Use a timestamped file name in actual operations. Do not place backups inside the Git repository. A database dump contains account hashes and potentially sensitive incident/monitoring data; encrypt it at rest and restrict access.

For restoration to an isolated, empty `breakline` database, use `pg_restore` inside the target PostgreSQL container. **Do not** restore directly over a live production database without first isolating the application and confirming the target database, schema ownership and credentials. Example with your dump piped to the container:

```bash
cat breakline-backup.dump | docker compose exec -T db pg_restore -U breakline -d breakline --clean --if-exists --no-owner
```

Restoration is destructive. Test it on a separate environment and verify account access and record counts before planning production recovery.

## 6. Routine verification

```bash
# Container status
docker compose ps
# API and worker errors
docker compose logs --tail=100 api
# Database-backed readiness
curl -fsS http://127.0.0.1:3000/api/v1/health/ready
# No volume deletion
docker compose down
```

For security: rotate or revoke exposed ingestion tokens, use database backups, keep Docker and the host updated, protect `.env`, and verify provider delivery using actual credentials. Manual `retry` works only for failed or suppressed alert deliveries. Active silences prevent retries until revoked or expired.

## 7. Known limits

- Real-time SSE broadcasts are per-process. Run one API instance for consistent instant refresh; clients also poll periodically.
- Login attempts are limited per normalized email with a 15-minute window; network-edge controls are still recommended for abuse protection.
- Application service-health monitoring supports **public HTTPS only**; it does not reach internal networks or private IPs.
- Alert muting is project-scoped. Notifications suppressed during maintenance are never replayed automatically.
- This project provides operational foundations, not a guarantee of complete security or uptime. Run Rust builds, integration tests, the frontend build, a vulnerability assessment and a deployment smoke test before internet-facing use.
