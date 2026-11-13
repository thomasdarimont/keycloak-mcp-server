# Split deployment: an admin instance and MCP instances, two database users

The same server in two instance roles on one PostgreSQL database
([Several instances](../../docs/storage.md#several-instances-on-one-database)):

| service | port | `kc-mcp.instance-role` | serves | database user |
|---|---|---|---|---|
| `admin` | 127.0.0.1:8094 | `admin` | admin API (and the management UI, when enabled); `/mcp` answers 404 | `kcmcp_admin`: owns the schema, runs the migrations, purges old audit rows |
| `mcp` | 8095 | `mcp` | the MCP endpoint for people (forward delegation); `/admin` answers 404 | `kcmcp_mcp`: reads systems, realms, secrets, keys; appends audit rows; keeps CIBA approvals |

Keycloak runs on :8093 (`admin`/`admin`), PostgreSQL on :5491. In a real deployment `mcp` sits behind the public
ingress and `admin` on the internal network only. The MCP clients, and the models behind them, never reach the admin
API. Even a compromised MCP instance cannot change what the admin side configured: its database user may not.

```shell
../../mvnw -f ../../pom.xml package -DskipTests -Ppostgresql    # PostgreSQL build
docker compose up -d --build && ./demo.sh                        # idempotent
docker compose down -v                                           # drops the databases
```

Iterating on the server without an image build: `docker-compose.dev.yml` mounts `target/quarkus-app`
(`docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d`, then `restart admin mcp` after the next package).

The example reuses the `acme-dev` realm, the `keycloak-mcp-server` client and `mcp-call.py` of
[dynamic-systems](../dynamic-systems/).

## What `demo.sh` shows

1. `acme` is registered on the admin instance, and its key pair is generated there. Keycloak fetches the JWKS from
   the admin instance (`http://admin:8081/auth/keys/<id>/jwks.json`, `signingKey.jwksPath` of the registration). The MCP instance signs with the same key,
   which it reads from the database.
2. The MCP instance knows `acme` only through the database, within `cache-seconds` (10). alice and sam call tools with
   their own tokens; sam's write is `forbidden` by Keycloak.
3. What each side cannot do:

   | attempt | answer |
   |---|---|
   | `GET`/`PUT /admin/systems` on the MCP instance, with the admin token | 404 |
   | the MCP endpoint on the admin instance | 404 |
   | the admin API with alice's MCP token (audience `keycloak-mcp-server`) | 401 |
   | the admin API with a master admin's token without the admin audience | 401 |
   | `kcmcp_mcp`: change a system, add a secret, replace a key | permission denied |
   | `kcmcp_mcp`: read or delete audit rows, read UI sessions | permission denied |

## The pieces

- **Instance roles.** `KC_MCP_INSTANCE_ROLE=admin` turns the MCP endpoint off and the admin API on;
  `KC_MCP_INSTANCE_ROLE=mcp` turns the admin API and the UI off. Setting `kc-mcp.admin.enabled=true` on an `mcp`
  instance (or `kc-mcp.mcp.enabled=true` on an `admin` one) stops the start instead of quietly winning. Both run
  in profile `shared`. The `admin` instance needs no caller authentication there, because it has no MCP callers.
- **Two audiences.** The admin API accepts tokens with the audience `keycloak-mcp-admin-api`
  (`clients/keycloak-mcp-admin.json`), the MCP endpoint only `keycloak-mcp-server`. A token issued for one never opens
  the other, even on a server that runs both.
- **Two database users** (`init/postgres-init.sql`). The database and the schema belong to `kcmcp_admin`; nobody
  else may create objects. The MCP instance runs with `QUARKUS_LIQUIBASE_MIGRATE_AT_START=false`, because its user
  may not create tables.
- **The grants** (`init/grants.sql`) come from the one-shot `grants` service, once the admin instance has migrated
  the schema; the MCP instance waits for it. After an upgrade that adds tables, start the admin instance, then
  `docker compose run --rm grants`, then the MCP instances. A table not listed there has no grants, so a new feature
  fails closed on the MCP side until someone decides what that side may do with it.

  | table | `kcmcp_mcp` |
  |---|---|
  | `kc_mcp_system`, `kc_mcp_realm`, `kc_mcp_secret`, `kc_mcp_signing_key` | `SELECT` |
  | `kc_mcp_audit_event` | `INSERT` |
  | `kc_mcp_pending_approval` | `SELECT`, `INSERT`, `UPDATE`, `DELETE` (CIBA confirmations) |
  | `kc_mcp_user_session`, Liquibase's tables | none |

- **What has to happen on the admin side**, because the MCP side cannot write it:
  - signing keys: register with `"signingKey": "generate"`, and rotate with `POST /admin/systems/<alias>/signing-key`.
    An MCP instance that meets a `private_key_jwt` system without a key would have to create one, which its
    database user may not: the key has to exist before the MCP side uses the system.
  - the audit retention (`KC_MCP_SPI_AUDIT_LISTENER_DB_RETENTION_DAYS`): set it on the admin instance only.
- **The management UI** would run on the admin instance as well (`KC_MCP_UI_ENABLED=true`, with HTTPS and its client).
  Its session rows are the admin user's alone. See [management-ui](../management-ui/).

## Inspect

```shell
docker compose exec postgres psql -U kcmcp_admin kcmcp -c '\dp kc_mcp_*'    # the grants
docker compose exec postgres psql -U kcmcp_mcp kcmcp -c 'select alias from kc_mcp_system'
```
