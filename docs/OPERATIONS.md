# Operational runbook

## Incident response

1. Find the incident under **Incidents**, inspect its source and severity, and acknowledge ownership.
2. Compare health checks, recent release events and the incident timeline. A release correlation is a clue, **not proof** of root cause.
3. Add concise notes about observations, mitigations and confirmed fixes.
4. Restore the affected service or roll back the release through your normal deployment system. Breakline records status; it does **not** execute rollbacks.
5. Resolve the incident after verifying recovery. Monitor-origin incidents automatically resolve on a successful check; other incident classes require manual resolution.
6. Review the **Analytics** page over 7, 30 or 90 days for incident volume, time to acknowledge/resolve and release success.

## Planned maintenance and silences

Owners/admins open **Governance → Alert controls**, select a project and channel, set 1–168 hours, and record a maintenance reason. Silences apply only to notification delivery, **not** incident detection or monitoring. A due notification is marked `suppressed` instead of sent. When the silence expires or is ended, earlier suppressed notifications remain suppressed until an administrator explicitly retries them. You can inspect delivered, pending, failed and suppressed outcomes under Alert controls.

## Audit history

**Governance → Audit trail** shows administrative changes with actor, action, resource, summary and timestamp. Owners/admins can filter by project and page older records. The final migration imports earlier entries from the existing activities feed; those older entries may lack a project association. Audit logs do **not** include passwords, bearer tokens or provider secrets. Audit history is retained until an operator explicitly removes it from PostgreSQL. Maintain an access and data retention policy for your organization.

## Data semantics

- Mean time to acknowledge/resolve is calculated from incidents **detected within the selected window** and with recorded acknowledgement/resolution timestamps. It is not an SLA score.
- Uptime is the percent of **stored probe outcomes** marked `up`, not time-weighted service availability.
- Release success rate includes all deployments recorded during the selected period, including running/pending; if you want terminal-only rates, use a separate report or refine the metric.
- Alert delivery success includes jobs currently in final delivered/failed states, not suppressed or pending jobs.
- Analytics days are calendar days in UTC. Historic data beyond the 30-day metric/check retention may be incomplete by design.

## Rollback and restoring data

Back up and test restore the PostgreSQL data before each upgrade. For a broken application release, roll the tracked application code back to a known commit. For database/schema problems, do not delete migrations or drop volumes; follow [DEPLOYMENT.md](DEPLOYMENT.md) and restore a verified backup into an isolated database before switching production traffic.
