# Dynamic systems, stored in PostgreSQL

The MCP server starts with no Keycloak configured. `demo.sh` registers one through the admin API and exercises it.

- `mcp` (:8091): admin API, calls run as the registered system's service account
- `mcp-users` (:8092): OIDC login with consent, calls run with a delegated token: Keycloak exchanges the user's token for
  one that names the user as `sub` and the system's client as `act` (`KC_MCP_MCP_DELEGATION=exchange`)
- Both share one PostgreSQL database (:5490); Keycloak on :8090 (`admin`/`admin`)
- A second Keycloak on :8089 (`admin`/`admin`) with four realms of its own and nothing of the MCP server in it:
  the one to [adopt realms](#5-a-second-keycloak-adopting-realms) from

```
../../mvnw -f ../../pom.xml package -DskipTests -Ppostgresql    # PostgreSQL build
docker compose up -d --build
./demo.sh                                                         # idempotent
docker compose down -v                                            # drops databases, system and key
```

Iterating on the server: `docker-compose.dev.yml` mounts `target/quarkus-app` into a plain JDK image, no image build.
IntelliJ: the `dynamic-systems: *` run configurations in `.run/` cover build + up, the dev stack, restart, demo, down.

```
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
../../mvnw -f ../../pom.xml package -DskipTests -Ppostgresql && docker compose -f docker-compose.yml -f docker-compose.dev.yml restart mcp mcp-users
```

## Steps

### 1. Register the system

```shell
curl -s -X PUT localhost:8091/api/admin/systems/acme \
  -H 'Authorization: Bearer demo-admin-token' \
  -H 'Content-Type: application/json' \
  -d '{
    "displayName": "ACME Corp.",
    "description": "ACME's Keycloak, administered through the MCP server",
    "url": "http://keycloak:8080",
    "issuer": "http://localhost:8090/realms/acme-dev",
    "authRealm": "acme-dev",
    "clientId": "keycloak-mcp-server",
    "clientAuth": "private_key_jwt",
    "defaultRealm": "acme-dev",
    "allowedRealms": ["acme-dev"],
    "version": "26.8.2",
    "signingKey": "generate"
  }' | jq .
```

- Stored in `kc_mcp_system`; key pair generated in `kc_mcp_signing_key`, encrypted with `KC_MCP_STORAGE_SECRET_KEY`
- `signingKey`: `generate` (new pair), `existing` (already in the vault), absent (existing, else generate)
- Response: no secrets; `signingKey.kid`, `signingKey.jwksPath`, `signingKey.jwksUrl`, `entries`
- JWKS URL for Keycloak inside compose: `http://mcp:8081` + `signingKey.jwksPath` (`/auth/keys/<id>/jwks.json`, the
  system's id: a later `acme` gets another)
- `url` must match `KC_MCP_ALLOWED_HOSTS`
- `authRealm`: the realm of the system's client, here `acme-dev` itself. In delegation mode `exchange` the client must
  live in the realm the users log in at, because Keycloak exchanges a token only in the realm that issued it. One
  client serves both servers: `mcp` uses its service account, `mcp-users` uses it as the actor of the delegated tokens
- `GET /api/admin/systems` lists, `POST /api/admin/systems/acme/signing-key` rotates, `DELETE /api/admin/systems/acme` removes
- `client_secret` systems reference a vault secret (`"clientSecret": "vault:acme/client-secret"`, stored with
  `PUT /api/admin/secrets/acme/client-secret`); see [Several Keycloak systems](../../docs/systems.md)

Bearer: the static `KC_MCP_ADMIN_TOKEN`, or an access token of a master realm admin:

```shell
TOKEN=$(curl -s http://localhost:8090/realms/master/protocol/openid-connect/token \
  -d 'grant_type=password&client_id=keycloak-mcp-admin&username=admin&password=admin' | jq -r .access_token)
curl -s localhost:8091/api/admin/systems \
  -H "Authorization: Bearer $TOKEN" | jq .
```

- `KC_MCP_ADMIN_OAUTH_ISSUER`: the realm; `KC_MCP_ADMIN_OAUTH_AUDIENCE=keycloak-mcp-server`; role `realm:admin`
- `keycloak-mcp-admin` (step 2b) is a public client with that audience mapper
- `admin-cli` tokens are refused: lightweight in Keycloak 26, no roles, no audience

### 2. Realm `acme-dev`

`realms/acme-dev.json`: Admin Permissions enabled, groups with realm-management roles, and the public PKCE client
`mcp-consumer`: consent required, optional scope `delegation:client`, audience `keycloak-mcp-server`, full scope off
without any role in its scope and without `kc-admin-api`. Its tokens open the MCP server and nothing else.

| user | password | group | realm-management roles | outcome |
|---|---|---|---|---|
| `alice` | `alice-demo` | `/mcp-admins` | `realm-admin` | everything |
| `sam` | `sam-demo` | `/mcp-support` | `view-users`, `view-events`, `query-users`, `query-groups` | reads; writes `forbidden`, `search_tools` marks them `allowed: false` |
| `dave` | `dave-demo` | `/mcp-developers` | `manage-clients`, `view-clients`, `query-clients`, `view-realm`, `view-users` | client work; user changes `forbidden` |
| `bob` | `bob-demo` | `/staff` | none, disabled | acted upon |

### 3. Client in the realm `acme-dev`

- `clients/keycloak-mcp-server.json`: confidential, service account, authenticator `client-jwt`, `use.jwks.url=true`,
  default scope `kc-admin-api` (Keycloak 26.8.2+ Admin API audience check), `standard.token.exchange.enabled=true`
- `kcadm` fills in the JWKS URL, grants the service account `realm-management` `realm-admin`, adds the role to the
  client's scope (full scope stays off)
- The service account's role is what `mcp` (:8091) acts with. The role scope does two jobs: it lets the role into the
  service account's tokens, and it caps the delegated tokens of `mcp-users` (:8092), where a user's roles count as far
  as they lie within it. With `realm-admin` in the scope a user keeps all of their own roles and gains none
- `init/grant-delegation.sh` (run inside the Keycloak container) grants the client the Admin Permissions `delegate`
  permission on the realm's users. A realm import cannot carry it. Without it Keycloak drops the delegation scope
  silently and every tool answers `delegation_failed`
- Keycloak needs `--features=token-exchange-delegation,parameterized-scopes` (preview in 26.8, set in
  `docker-compose.yml`)
- Keycloak fetches the public key on the first token request
- 3b: `clients/keycloak-mcp-admin.json` in the master realm, the public client for step 1's access token

### 4. Calls

Service account, no login:

```
./mcp-call.py http://localhost:8091/mcp/systems/acme/acme-dev whoami
./mcp-call.py http://localhost:8091/mcp/systems/acme/acme-dev keycloak_user_search '{"search": "alice"}'
```

Users: login at the entry's realm with the consent page ("Allow keycloak-mcp-server to act on your behalf?"). The
server exchanges the user's token for a delegated one and sends that to the Admin API, never the user's own token.
Keycloak enforces the user's roles, the audit names the person. `mcp-call.py --login` walks the browser flow (login
form, consent page, code with PKCE), because a client that requires consent refuses the password grant:

```
./mcp-call.py http://localhost:8092/mcp/systems/acme/acme-dev whoami                          # 401 + WWW-Authenticate … resource_metadata
curl -s localhost:8092/.well-known/oauth-protected-resource/mcp/systems/acme/acme-dev | jq .  # realm acme-dev, scope delegation:client:keycloak-mcp-server
./mcp-call.py --login alice:alice-demo http://localhost:8092/mcp/systems/acme/acme-dev whoami # delegation: {mode: exchange, consented: true, actor: keycloak-mcp-server}
./mcp-call.py --login alice:alice-demo --scope openid http://localhost:8092/mcp/systems/acme/acme-dev whoami   # delegation_failed: no consent
./mcp-call.py --login sam:sam-demo     http://localhost:8092/mcp/systems/acme/acme-dev keycloak_user_set_enabled '{"id": "bob", "enabled": true}'   # forbidden
./mcp-call.py --login dave:dave-demo   http://localhost:8092/mcp/systems/acme/acme-dev keycloak_client_list '{}'
./mcp-call.py --login dave:dave-demo   http://localhost:8092/mcp/systems/acme/acme-dev keycloak_user_delete '{"id": "bob", "username": "bob"}'      # forbidden
```

LLM clients (LM Studio, Claude): `mcp.json` (service account), `mcp-oauth.json` (login at `acme-dev` via `mcp-consumer`;
the client reads the delegation scope from the entry's protected resource metadata and Keycloak shows the consent page).

The [management UI](../../docs/management-ui.md) of the first server: <http://localhost:8091/ui/>, sign in as
`admin` / `admin` of the master realm. The one-shot job `keycloak-init` creates the public client `keycloak-mcp-ui`
there when the stack starts, so the UI works before `demo.sh` has run; it is empty then. After `demo.sh`, *Systems*
shows `acme` and `globex` and lets you add or change systems, *Audit* lists the tool calls of both servers.
It runs in dev mode without HTTPS, for one person's machine only.

### 5. A second Keycloak: adopting realms

`keycloak-globex` (:8089) is another company's Keycloak. It starts with the realms `globex-staff`,
`globex-customers`, `globex-partners` and `globex-legacy` (disabled), imported from `realms-globex/`, and has no
client for the MCP server. Step 5 of `demo.sh` goes the way an administrator would:

```shell
A='Authorization: Bearer demo-admin-token'
# a: register it; the client will live in master, no realm is named yet
curl -s -X PUT localhost:8091/api/admin/systems/globex -H "$A" -H 'Content-Type: application/json' -d '{
    "displayName": "Globex Corp.", "url": "http://keycloak-globex:8080",
    "issuer": "http://localhost:8089/realms/master", "authRealm": "master",
    "clientId": "keycloak-mcp-server", "clientAuth": "private_key_jwt", "version": "26.8.2",
    "signingKey": "generate"}' | jq .
# b: the client for that Keycloak, as JSON and as a kcadm script; run the script there
curl -s -H "$A" 'localhost:8091/api/admin/systems/globex/client-setup?roles=admin&credential=public-key' \
  | jq -r .script | ./adopt-setup.sh
# c: the realms its service account sees
curl -s -H "$A" localhost:8091/api/admin/systems/globex/keycloak-realms | jq -c '.realms[] | {name, displayName, adopted}'
# d: adopt two; they become the system's allowlist
curl -s -X POST localhost:8091/api/admin/systems/globex/adoption -H "$A" -H 'Content-Type: application/json' \
  -d '{"realms": ["globex-staff", "globex-customers"], "restrict": true}' | jq .
# e: an adopted realm answers at its own entry
./mcp-call.py http://localhost:8091/mcp/systems/globex/globex-staff keycloak_user_search '{"search": "*"}'
```

- The server creates nothing in Keycloak. `client-setup` answers the client and a script; `adopt-setup.sh` runs
  that script with the `kcadm.sh` of the Keycloak container, logged in as `admin`
- `credential=public-key` copies the server's public key into the client. The JWKS URL the server names for itself
  is `http://localhost:8091/...`, which a Keycloak in a container cannot fetch; with `jwks-url` the script's URL
  would need `http://mcp:8081` instead
- `roles=admin` gives the service account the master `admin` role: it sees every realm, later ones too.
  `roles=read` or `manage` with `realms=globex-staff,globex-customers` gives only those realms' roles, and the others
  do not even show up in step c
- `restrict: true` is needed because a system without an allowlist reaches every realm: adopting a selection narrows
  it to that selection (409 `would_restrict` without it)
- `globex-partners` then answers `realm_not_allowed`

**In the management UI.** <http://localhost:8091/ui/> (`admin` / `admin`), system `globex`, tab *Adopt*: the two
realms left over, `globex-partners` and the disabled `globex-legacy`, are there to adopt, and the adopted ones to
unadopt. To do all of it in the UI, run `./demo.sh --skip-adopt` (steps 1 to 4 still register `acme`), then:

1. *Systems* → *New*: URL `http://keycloak-globex:8080`, issuer `http://localhost:8089/realms/master`, auth realm
   `master`, client authentication *Signed JWT*, client id `keycloak-mcp-server`. The URL is how the server reaches
   Keycloak, inside the compose network.
2. Tab *Adopt* → *1. Client in Keycloak*: key credential *public key*, copy the script, then
   `pbpaste | ./adopt-setup.sh`.
3. *2. Realms in Keycloak* → *Load*, then *3. Adopt* a selection, or every realm including later ones.

Worth trying: *Load* before the script ran (`token_refused`); rename a realm in Globex' admin console
(<http://localhost:8089/admin>) and reload (*renamed from*); delete one (*not listed*).
`docker compose down` throws Globex' Keycloak away with the client in it; the system and its key stay in
PostgreSQL, so the next `./demo.sh` creates the client again with the same key. More:
[Adopting a Keycloak's realms](../../docs/systems.md#adopting-a-keycloaks-realms).

## What it shows

- Admin API + database storage: `KC_MCP_STATIC_SYSTEMS=false`, `KC_MCP_DYNAMIC_SYSTEMS=true`, `KC_MCP_ADMIN_ENABLED=true`
- Per-system JWKS: no shared secret; Keycloak fetches the public key
- Two servers, one database: a system registered on `mcp` is known to `mcp-users`; both write audit rows
- One client, two uses: service account on `mcp`, actor of delegated tokens on `mcp-users`, both signing with the
  system's key from the database. Keycloak's `TOKEN_EXCHANGE` events name the actor, its admin events the user
- PII scrubbing on `mcp-users`: console lines pseudonymized (`targets: console`), database rows complete
- Role-based outcomes: same tools, three users, three results
- Audit retention: `KC_MCP_SPI_AUDIT_LISTENER_DB_RETENTION_DAYS=30` on `mcp`
- Adoption: a Keycloak that knows nothing of the server becomes a system, its client comes from a generated script,
  and its realms are taken over one by one, through the admin API or the management UI

Inspect: `psql -h localhost -p 5490 -U kcmcp kcmcp` (tables `kc_mcp_system`, `kc_mcp_signing_key`, `kc_mcp_secret`,
`kc_mcp_audit_event`).
