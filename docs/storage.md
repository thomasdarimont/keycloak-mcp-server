# Database storage

[keycloak-mcp-server](../README.md) › documentation

The optional `storage` module (`keycloak-mcp-server-storage`, a dependency of the backend) keeps what the server would
otherwise hold in files or memory in a database: systems, keys and secrets, audit events, UI sessions and pending
approvals. With it, several instances share one state. Without a JDBC URL it stays dormant.

## What is stored

| store | SPI id | table | holds |
|---|---|---|---|
| systems | `db` (`KeycloakSystemRepository`) | `kc_mcp_system` | Keycloak systems registered at runtime |
| keys and secrets | `db` (`KeyVault`) | `kc_mcp_signing_key`, `kc_mcp_secret` | per-system signing keys, client secrets |
| audit | `db` (`AuditListener`) | `kc_mcp_audit_event` | one row per call, denials and reads included |
| UI sessions | `db` (`UserSessionStore`) | `kc_mcp_user_session` | the management UI's sessions, tokens encrypted, expired rows purged hourly |
| pending approvals | `db` (`PendingApprovalStore`) | `kc_mcp_pending_approval` | CIBA requests waiting for a device ([CIBA confirmation](ciba-confirmation.md)) |

Hibernate ORM with Panache; Liquibase creates and migrates the schema at startup (`db/kc-mcp/changelog.xml` includes
one file per schema version, `0.1.0-changelog.xml` first). Timestamps are `bigint` epoch milliseconds, as in Keycloak.

## Turning it on

A `quarkus.datasource.jdbc.url` switches the storage on (`kc-mcp.storage.enabled` forces it on or off). Then
`kc-mcp.dynamic-systems=true` exposes the stored systems, the database vault replaces the file vault, and audit rows
start. Each store has its own switch: `kc-mcp.spi.system-repository.db.enabled`, `kc-mcp.spi.key-vault.db.enabled`,
`kc-mcp.spi.audit-listener.db.enabled`.

```shell
QUARKUS_DATASOURCE_JDBC_URL=jdbc:h2:file:./data/kc-mcp KC_MCP_DYNAMIC_SYSTEMS=true \
KC_MCP_STORAGE_SECRET_KEY=$(openssl rand -base64 32) java -jar modules/backend/target/quarkus-app/quarkus-run.jar start
```

- **The database kind is fixed at build time.** The distribution comes built for H2 (`jdbc:h2:file:...`, a single
  instance). For PostgreSQL (`jdbc:postgresql://host:5432/kcmcp` with `quarkus.datasource.username` and `password`), stop
  the server and run `bin/kcmcp.sh build --db=postgresql` once, in the unpacked distribution or while building an image;
  it needs neither Maven nor network access, and `--db=h2` goes back. From source: `./mvnw package -Ppostgresql`. Both
  drivers ship, but the dialect does not switch at runtime: a JDBC URL for the other database stops the start and names
  this command.
- **Share a database server with Keycloak, never its schema.** The tables are prefixed `kc_mcp_`.

## Encryption and key rotation

`kc-mcp.storage.secret-key` encrypts private keys, client secrets and passwords with AES-256-GCM. It is the base64 of
32 bytes, or a passphrase that Argon2id turns into one. Unset, the values are stored in plain text and the startup log
warns; the `shared` profile refuses to start without it. Stored values read `enc:v2:<key id>:<nonce>:<ciphertext>`;
the key id, 8 hex digits of the key's SHA-256, names the key they were written with.

Rotating the key:

1. Put the new key into `secret-key` and the old one into `previous-secret-keys` (comma separated; they only decrypt).
2. Roll that out to every instance.
3. Let the startup pass rewrite the rows, or call `POST /admin/storage/rekey`. Both are idempotent, and plain and
   `enc:v1` values from older builds get encrypted as well.
4. Check that `GET /admin/storage` shows only the current key id in use.
5. Drop the old key from `previous-secret-keys`.

Rows written under a key that is configured nowhere are reported as `remaining` and never touched.

Audit pseudonyms are HMACs under `secret-key`, so a rotation changes them. `kc-mcp.spi.audit-scrubber.pii.pseudonym-key`
gives the scrubber a key of its own that rotates independently.

## Systems in the database

`kc_mcp_system` has a UUID primary key and holds `alias` (the system name: the `system` argument,
`/mcp/systems/<alias>`), `name` (a display label) and `description`; all three can change. `enabled=false` keeps a
system but stops serving it. Only service clients are stored: there are no username and password columns, and the
repository refuses the password grant.

Reads are served from a snapshot, reloaded when older than `kc-mcp.spi.system-repository.db.cache-seconds` (10; a local write
reloads at once). A tool call costs no query, and event-loop threads get the snapshot as is. While the database cannot be read,
the last snapshot stays in use ([When the database is away](#when-the-database-is-away)).

## Audit retention and personal data

- **Traces.** With tracing on (`quarkus.otel.sdk.disabled=false`), an event records the OpenTelemetry `trace_id` and
  `span_id` of the span the server runs each tool call in (`kc_mcp.tool <name>`), so the call is found in the tracing or logging system and, the other
  way round, a trace in the audit trail (`GET /admin/audit?traceId=`). Without tracing both stay empty.
- **Reading.** `GET /admin/audit` filters and pages the rows ([admin API](systems.md)), and the management UI's
  *Audit* page shows them to operators and viewers. In a split deployment only the admin instance reads them.
- **Retention.** `kc-mcp.spi.audit-listener.db.retention-days` deletes older events at startup and then hourly, one statement on
  the `occurred_at` index. Unset keeps everything, like Keycloak's event store without expiration.
- **Personal data.** The `pii` audit scrubber decides what of it reaches the rows (`kc-mcp.spi.audit-scrubber.pii.mode`):
  `keep` (default); `pseudonymize`, which turns the caller name and the values of the `args` arguments
  (`username,email,firstName,lastName,search,userId,user,attributes`, plus `id` on user tools) into a keyed hash under
  `secret-key` and drops the message; or `drop`. `targets` names the listeners it applies to: `db` (default),
  `console`, or `*`.

## Several instances on one database

This is how `examples/dynamic-systems/` runs. It needs the PostgreSQL build (the H2 file database is single-process)
and the same `kc-mcp.storage.secret-key` on every instance.

| change on one instance | visible on the others |
|---|---|
| a system registered, changed or removed | within `cache-seconds` |
| a secret stored | on their next tool call |
| a signing key rotated | on their next token request; every JWKS publishes the current key plus keys retired within `kc-mcp.spi.key-vault.db.retired-key-grace-seconds` (3600), so Keycloak accepts a lagging instance; after that the retired key's private key is deleted (with the next rotation, else by the hourly purge), its row stays as history |
| an audit retention purge | runs on every instance; deletes are idempotent |

Two instances creating a first signing key at the same time both succeed: both keys are published, the newest signs.

**Instances with different roles.** The same database also lets the roles split, with `kc-mcp.instance-role`:

- `mcp` for the instances behind the public ingress: the MCP endpoint only, the admin API and the UI off;
- `admin` for one instance on the internal network: the admin API (and the management UI when enabled), its MCP
  endpoint and entries answer a plain 404, so the admin API is never reachable from where the MCP clients are.

The role sets the defaults of `kc-mcp.mcp.enabled`, `kc-mcp.admin.enabled` and `kc-mcp.ui.enabled`; one of them set
against it stops the start. In profile `shared`, an `admin` instance needs no caller authentication, since it has no
callers. Systems registered there, their keys and secrets reach the MCP instances within `cache-seconds`, as in the
table above.

The two sides can also use two database users, so that the MCP instances cannot change what the admin side
configured: they read systems, realms, secrets and keys, append audit rows and keep the CIBA approvals, nothing more.
The admin instance owns the schema and runs the migrations; the MCP instances run with
`quarkus.liquibase.migrate-at-start=false`, and the audit retention runs on the admin instance. The grants and a
working setup: [`examples/split-deployment/`](../examples/split-deployment/).

**MCP sessions and several instances.** The streamable HTTP transport keeps a session (the `Mcp-Session-Id` the
`initialize` answer hands out) in the memory of the instance that opened it: the MCP server extension's
`ConnectionManager` is a map, deliberately without a store behind it (the upstream request for one, quarkiverse issue
510, was closed in favour of the protocol's stateless mode). The session holds little: the protocol version, the client's
capabilities (whether it supports elicitation, which the confirmation of destructive tools relies on), an open SSE stream
and, in the `progressive` tool exposure only, the tools the last `search_tools` surfaced. Everything a request needs is
taken from the request itself (the caller from the token, system and realm from the entry) or from the database
(systems, keys, secrets, pending approvals, UI logins, the audit trail), so losing a session loses nothing the user did.

- **Clients speaking MCP 2026-07-28 or later** run stateless: no session, a transient connection per request with the
  client's capabilities in the request's `_meta`. Any instance serves any request; nothing to configure. The
  confirmation of a destructive tool travels with the client too (an `input_required` result, then the same call
  again with the answer), so it can finish on another instance.
- **Older clients** (2025-11-25 and before, most clients in the field) hold a session, and their requests must reach
  the instance that opened it: a request anywhere else answers 404, the client re-initializes there (the MCP
  specification requires that of it), and under round-robin routing the next request lands elsewhere again, so without
  affinity such a client re-initializes most of the time and no SSE stream survives. The affinity has to map a request
  back to the initializing instance: a load-balancer cookie set on the `initialize` response works only with clients
  that keep cookies, which MCP clients mostly do not; client address affinity works for clients that keep their
  address; hashing the `Mcp-Session-Id` does not, since the id is minted by whichever instance served `initialize` and
  says nothing about where it lives. Test the affinity with the clients you have before relying on it. On a failover
  the session is gone whatever the affinity: in-flight requests fail, the client re-initializes on the next instance and
  carries on; nothing the user did is lost.
- **`quarkus.mcp.server.http.streamable.auto-init=true`** makes every instance accept any request from an older client
  by opening a session on the spot, honouring capabilities the client puts into `_meta` and assuming none otherwise. The
  extension documents it as a stop-gap until every client speaks the stateless protocol; without the capabilities the
  server cannot tell whether a client supports elicitation, so on a shared server prefer sticky routing and leave it off.

## When the database is away

A restart for maintenance, a failover, a network cut: what an instance does until the database answers again,
measured with [`examples/split-deployment/db-outage.sh`](../examples/split-deployment/).

| | while the database is away |
|---|---|
| systems | the last snapshot is served. Callers do not wait: one background reload retries after 1 s, doubling up to `cache-seconds`, and the first that succeeds ends it. One WARN when it starts, one INFO when it recovers. Before the first load ever succeeded, the instance knows no systems |
| tool calls with `forward` | keep working: the caller brings the token, the instance needs no credentials of its own |
| service account and `exchange` calls | keep working with the tokens the instance holds; a new token request fails once they expire, as the signing key and stored secrets are read from the database on each request |
| audit | the console line is written, the row is not; the listener is left out until a probe every 2 s reaches the database, so calls do not wait for it. Changes are refused with `kc-mcp.audit-on-failure=refuse-changes` (default in `shared`) ([the audit gap](#the-audit-gap)) |
| admin API, management UI, UI logins, CIBA approvals, JWKS | fail; Keycloak keeps the JWKS it fetched until its keys cache expires |

**Latency.** Every database access on a caller's thread costs about a second while the connection cannot be made
(the pool tries to create a connection and fails), and the attempts of concurrent threads queue up. The systems
reload and the audit insert stay off the callers' threads while failing, so only the first call after the database
goes away pays it.

**After the restart.** Connections in the pool are dead. Each fails exactly one operation (`terminating connection due
to administrator command`) and is discarded, so the first few database accesses after the restart may fail once.

### The audit gap

The row is written after the tool has run, so a failing insert cannot stop the call it records: the change is made in
Keycloak by then. What the server can do is refuse the next ones: with `kc-mcp.audit-on-failure=refuse-changes`
(default in profile `shared`) write and destructive tools answer `audit_unavailable` from the first failed insert
until the probe reaches the database again, and reads keep running. So on each instance only the changes already running when
the first insert fails go without a row; their log lines, like that of every call during the outage, is still written. Ship the logs to
keep that record. `kc_mcp.audit.trail.degraded` and `kc_mcp.audit.trail.failures` show the outage
([Metrics](metrics.md)).

## From code

`DatabaseKeycloakSystemRepository` (`save`, `rename`, `setEnabled`, `delete`), `DatabaseKeyVault` (`createSigningKey`
retires the previous row, `putSecret`) and `DatabaseAuditListener` (`recent`, `byCaller`, `search` with an `AuditQuery`) are injectable.
