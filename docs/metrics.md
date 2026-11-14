# Metrics (OpenTelemetry)

[keycloak-mcp-server](../README.md) › documentation

What the server measures and exports over OTLP, and what each metric answers.

Off until asked for; then exported over OTLP to a collector (Prometheus, Grafana, Datadog ... behind it):

```shell
QUARKUS_OTEL_SDK_DISABLED=false
QUARKUS_OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317
# QUARKUS_OTEL_METRIC_EXPORT_INTERVAL=60s   QUARKUS_OTEL_TRACES_ENABLED=false (metrics only)
```

Quarkus reports HTTP server metrics per route (MCP endpoint, BFF, admin API), JVM metrics and a trace per request.
The server adds its own:

| metric | type | attributes | what it answers |
|---|---|---|---|
| `kc_mcp.tool.call.duration` | histogram, s (count = calls) | `tool`, `level`, `outcome` (`ok` or the error code), `via`, `system`, `realm` (opt-in) | is it used, is it working, what fails how |
| `kc_mcp.policy.refusals` | counter | `reason` (`forbidden`, `privilege_escalation`, `realm_not_allowed`, `read_only_mode`, `entry_mismatch`, ...), `tool`, `level`, `system` | misconfigured roles, or someone probing |
| `kc_mcp.confirmation.decisions` | counter | `confirmer` (`ciba`, `built-in`, an extension's id, `none`), `outcome`, `tool` | who confirms destructive tools, how often they are declined |
| `kc_mcp.ciba.requests` | counter | `system` | approvals asked for |
| `kc_mcp.ciba.decisions`, `kc_mcp.ciba.decision.duration` | counter, histogram s | `outcome` (`approved`, `declined`, `expired`, `timeout`, `rejected`), `system` | how fast people answer; `rejected` = the approval's ID token was invalid or named someone else: alert on it |
| `kc_mcp.ciba.pending` | gauge | | approvals waiting for a device |
| `kc_mcp.discovery.searches` | counter | `result` (`hit`, `miss`, `stopped` by the repeated-miss brake), `mode`, `category` | how well models find tools |
| `kc_mcp.discovery.hits` | histogram | `mode` | tools per search |
| `kc_mcp.discovery.marked` | counter | `reason` (`forbidden`, `unsupported`) | hits shown with `allowed=false` |
| `kc_mcp.discovery.unknown_tools` | counter | `suggested` (`yes`/`no`: did-you-mean had candidates) | models guessing tool names |
| `kc_mcp.keycloak.request.duration` | histogram, s | `system`, `method`, `resource` (`users`, `groups`, `clients`, `realm`, ... never an id), `status_class` | Admin REST API latency and errors per system |
| `kc_mcp.keycloak.token.duration` | histogram, s | `system`, `grant` (`client_credentials`, `password`, `token-exchange`, `ciba`), `status_class` | token acquisition and delegation exchanges |
| `kc_mcp.keycloak.token.scope_fallbacks` | counter | `system` | servers that refused `kc-admin-api` |
| `kc_mcp.mcp.connections` | gauge | `client` (name from `initialize`, 20 distinct values, then `other`) | open MCP sessions |
| `kc_mcp.audit.trail.degraded` | gauge (0/1) | | the audit trail cannot be written: alert on it |
| `kc_mcp.audit.trail.failures` | counter | `result` (`failed`: the delivery threw, `skipped`: left out while failing), `listener` (`db`, an extension's id) | how many events the trail misses |
| `kc_mcp.ui.sessions`, `kc_mcp.ui.backchannel_logouts` | gauge, counter (`result`: `ended`, `invalid`) | | management UI |

The Keycloak metrics come from a JAX-RS client filter on every RESTEasy client the server builds for a system (admin
client, `private_key_jwt` token manager, token exchange), since Quarkus does not instrument clients made outside CDI;
a request that gets no response at all is not measured there and shows up as `keycloak_unreachable` in the tool
calls. The CIBA client's requests to its provider are covered by `kc_mcp.ciba.*`.

No user, subject, argument or client-supplied value becomes an attribute; who did what is the audit log's. Values
are cut to short tokens, so an extension's odd error code cannot create unbounded series.
`kc-mcp.metrics.include-realm=true` adds the realm to the tool calls (one series per realm: think before turning
it on for a server with thousands). The tool and refusal metrics come from the audit hook (`AuditListener` id
`metrics`, `kc-mcp.spi.audit-listener.metrics.enabled=false` switches it off), so they count exactly what the audit log records.
