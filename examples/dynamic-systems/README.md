# Dynamic systems, stored in PostgreSQL

The MCP server starts with no Keycloak configured. `demo.sh` registers one through the admin API and exercises it.

Each party has a host name of its own and serves HTTPS, with one certificate from mkcert:

| address | what |
|---|---|
| <https://mcp-admin.localhost:8091> | `mcp`: admin API and management UI, calls run as the registered system's service account |
| <https://mcp.localhost:8092> | `mcp-users`: OIDC login with consent, calls run with a delegated token: Keycloak exchanges the user's token for one that names the user as `sub` and the system's client as `act` (`KC_MCP_MCP_DELEGATION=exchange`) |
| <https://acme.localhost:8090> | the first Keycloak (`admin`/`admin`): realm `master` signs people in to the admin API and the UI, realm `acme-dev` is the one `demo.sh` creates |
| <https://globex.localhost:8089> | a second Keycloak (`admin`/`admin`) with four realms of its own and nothing of the MCP server in it: the one to [adopt realms](#5-a-second-keycloak-adopting-realms) from |

Both servers share one PostgreSQL database (:5490).

```
../../etc/mkcert.sh acme.localhost globex.localhost mcp-admin.localhost mcp.localhost   # once: the certificate
../../mvnw -f ../../pom.xml package -DskipTests -Ppostgresql    # PostgreSQL build
docker compose up -d --build
./demo.sh                                                         # idempotent
docker compose down -v                                            # drops databases, system and key
```

- **Why names of their own.** Both Keycloaks have a realm `master`. Under one host name their login cookies would
  overwrite each other, since cookies do not tell ports apart: signing in at one would sign you out of the other.
  Browsers and the operating system resolve `*.localhost` to this machine without an entry in `/etc/hosts`.
- **Why HTTPS.** MCP clients such as Claude Code send credentials over plain HTTP only to `localhost` itself.
- **The certificate.** `etc/mkcert.sh` installs mkcert's CA in the local trust stores and writes `.certs/localhost.pem`
  with the names given, next to `localhost`; the containers mount `.certs/`. Browsers, `curl` and Claude Code
  trust it from there. `mcp-call.py` and `demo.sh` ask `mkcert -CAROOT` for the CA, because Python does not read
  the system's store everywhere. On Linux the containers' users have to be able to read the key:
  `chmod 644 ../../.certs/localhost-key.pem`.
- **One address per party.** Inside the compose network each service listens on the same port and carries its
  name as a network alias, so `https://globex.localhost:8089` means the same Keycloak in the browser and for the MCP
  servers. A system's `url` is therefore also its issuer, and Keycloak fetches the server's keys from the JWKS URL
  the admin API names. The containers trust mkcert's CA (`.certs/rootCA.pem`). A deployment where the server reaches
  Keycloak at an internal address and needs a separate `issuer` is what
  [split-deployment](../split-deployment/) shows.

Iterating on the server: `docker-compose.dev.yml` mounts `target/quarkus-app` into a plain JDK image, no image build.
IntelliJ: the `dynamic-systems: *` run configurations in `.run/` cover build + up, the dev stack, restart, demo, down.

```
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
../../mvnw -f ../../pom.xml package -DskipTests -Ppostgresql && docker compose -f docker-compose.yml -f docker-compose.dev.yml restart mcp mcp-users
```

## Steps

### 1. Register the system

```shell
curl -s -X PUT https://mcp-admin.localhost:8091/api/admin/systems/acme \
  -H 'Authorization: Bearer demo-admin-token' \
  -H 'Content-Type: application/json' \
  -d '{
    "displayName": "ACME Corp.",
    "description": "ACME's Keycloak, administered through the MCP server",
    "url": "https://acme.localhost:8090",
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
- JWKS URL for Keycloak: `signingKey.jwksUrl`, `https://mcp.localhost:8092/auth/keys/<id>/jwks.json` (the system's
  id: a later `acme` gets another). It names `mcp-users`, not the admin server that answered:
  `KC_MCP_ADMIN_JWKS_HOSTNAME` says where the keys are fetched from. Every server on the database serves them; the
  one people use is the one a Keycloak can be expected to reach, and it leaves the admin server internal
- `url` must match `KC_MCP_ALLOWED_HOSTS`
- `authRealm`: the realm of the system's client, here `acme-dev` itself. In delegation mode `exchange` the client must
  live in the realm the users log in at, because Keycloak exchanges a token only in the realm that issued it. One
  client serves both servers: `mcp` uses its service account, `mcp-users` uses it as the actor of the delegated tokens
- `GET /api/admin/systems` lists, `POST /api/admin/systems/acme/signing-key` rotates, `DELETE /api/admin/systems/acme` removes
- `client_secret` systems reference a vault secret (`"clientSecret": "vault:acme/client-secret"`, stored with
  `PUT /api/admin/secrets/acme/client-secret`); see [Several Keycloak systems](../../docs/systems.md)

Bearer: the static `KC_MCP_ADMIN_TOKEN`, or an access token of a master realm admin:

```shell
TOKEN=$(curl -s https://acme.localhost:8090/realms/master/protocol/openid-connect/token \
  -d 'grant_type=password&client_id=keycloak-mcp-admin&username=admin&password=admin' | jq -r .access_token)
curl -s https://mcp-admin.localhost:8091/api/admin/systems \
  -H "Authorization: Bearer $TOKEN" | jq .
```

- `KC_MCP_ADMIN_OAUTH_ISSUER`: the realm; `KC_MCP_ADMIN_OAUTH_AUDIENCE=keycloak-mcp-server`; role `realm:admin`
- `keycloak-mcp-admin` (step 2b) is a public client with that audience mapper
- `admin-cli` tokens are refused: lightweight in Keycloak 26, no roles, no audience

### 2. Realm `acme-dev`

`realms/acme-dev.json`: Admin Permissions enabled, groups with realm-management roles, and the public PKCE client
`mcp-consumer`: consent required, optional scope `delegation:client`, audience `keycloak-mcp-server`, full scope off
without any role in its scope and without `kc-admin-api`. Its tokens open the MCP server and nothing else.

Its consent page asks one thing, *Allow keycloak-mcp-server to act on your behalf?*, preceded by *Offline Access* for
a client that asks for it (Claude Code does). The client has no `roles`, `profile` or `email` scope, each of which
would add a line: the server reads the caller's roles from the delegated token, and the user name comes from a
mapper of the client (`preferred_username`), which a consent page does not list.

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
- The service account's role is what `mcp` (`mcp-admin.localhost`) acts with. The role scope does two jobs: it lets the role into the
  service account's tokens, and it caps the delegated tokens of `mcp-users` (`mcp.localhost`), where a user's roles count as far
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
./mcp-call.py https://mcp-admin.localhost:8091/mcp/systems/acme/acme-dev whoami
./mcp-call.py https://mcp-admin.localhost:8091/mcp/systems/acme/acme-dev keycloak_user_search '{"search": "alice"}'
```

Users: login at the entry's realm with the consent page ("Allow keycloak-mcp-server to act on your behalf?"). The
server exchanges the user's token for a delegated one and sends that to the Admin API, never the user's own token.
Keycloak enforces the user's roles, the audit names the person. `mcp-call.py --login` walks the browser flow (login
form, consent page, code with PKCE), because a client that requires consent refuses the password grant:

```
./mcp-call.py https://mcp.localhost:8092/mcp/systems/acme/acme-dev whoami                          # 401 + WWW-Authenticate … resource_metadata
curl -s https://mcp.localhost:8092/.well-known/oauth-protected-resource/mcp/systems/acme/acme-dev | jq .  # realm acme-dev, scope delegation:client:keycloak-mcp-server
./mcp-call.py --login alice:alice-demo https://mcp.localhost:8092/mcp/systems/acme/acme-dev whoami # delegation: {mode: exchange, consented: true, actor: keycloak-mcp-server}
./mcp-call.py --login alice:alice-demo --scope openid https://mcp.localhost:8092/mcp/systems/acme/acme-dev whoami   # delegation_failed: no consent
./mcp-call.py --login sam:sam-demo     https://mcp.localhost:8092/mcp/systems/acme/acme-dev keycloak_user_set_enabled '{"id": "bob", "enabled": true}'   # forbidden
./mcp-call.py --login dave:dave-demo   https://mcp.localhost:8092/mcp/systems/acme/acme-dev keycloak_client_list '{}'
./mcp-call.py --login dave:dave-demo   https://mcp.localhost:8092/mcp/systems/acme/acme-dev keycloak_user_delete '{"id": "bob", "username": "bob"}'      # forbidden
```

LLM clients (LM Studio, Claude): `mcp.json` (service account), `mcp-oauth.json` (login at `acme-dev` via `mcp-consumer`;
the client reads the delegation scope from the entry's protected resource metadata and Keycloak shows the consent page).
Claude Code, after `./demo.sh` has created the realm and registered `acme`:

```shell
claude mcp add --transport http --client-id mcp-consumer --callback-port 33418 keycloak-acme-dev \
  https://mcp.localhost:8092/mcp/systems/acme/acme-dev
```

The address is the entry, not `https://mcp.localhost:8092/mcp`: this server knows its systems from the database only, so
callers log in at the realm of one of them, and the bare `/mcp` answers `entry_required`.

The [management UI](../../docs/management-ui.md) of the first server: <https://mcp-admin.localhost:8091/ui/>, sign in as
`admin` / `admin` of the master realm. The one-shot job `keycloak-init` creates the public client `keycloak-mcp-ui`
there when the stack starts, so the UI works before `demo.sh` has run; it is empty then. After `demo.sh`, *Systems*
shows `acme` and `globex` and lets you add or change systems, *Audit* lists the tool calls of both servers.
It is served over HTTPS like the rest, so its session cookie is `Secure` and the server runs without dev mode.

### 5. A second Keycloak: adopting realms

`keycloak-globex` (<https://globex.localhost:8089>) is another company's Keycloak. It starts with the realms
`globex-staff`, `globex-customers`, `globex-partners` and `globex-legacy` (disabled), imported from
`realms-globex/`, and has no client for the MCP server. Step 5 of `demo.sh` goes the way an administrator would:

```shell
A='Authorization: Bearer demo-admin-token'
# a: register it; the client will live in master, no realm is named yet
curl -s -X PUT https://mcp-admin.localhost:8091/api/admin/systems/globex -H "$A" -H 'Content-Type: application/json' -d '{
    "displayName": "Globex Corp.", "url": "https://globex.localhost:8089", "authRealm": "master",
    "clientId": "keycloak-mcp-server", "clientAuth": "private_key_jwt", "version": "26.8.2",
    "signingKey": "generate"}' | jq .
# b: the client for that Keycloak, as JSON and as a kcadm script; run the script there
curl -s -H "$A" 'https://mcp-admin.localhost:8091/api/admin/systems/globex/client-setup?roles=admin' \
  | jq -r .script | ./adopt-setup.sh
# c: the realms its service account sees
curl -s -H "$A" https://mcp-admin.localhost:8091/api/admin/systems/globex/keycloak-realms | jq -c '.realms[] | {name, displayName, adopted}'
# d: adopt two; they become the system's allowlist
curl -s -X POST https://mcp-admin.localhost:8091/api/admin/systems/globex/adoption -H "$A" -H 'Content-Type: application/json' \
  -d '{"realms": ["globex-staff", "globex-customers"], "restrict": true}' | jq .
# e: an adopted realm answers at its own entry
./mcp-call.py https://mcp-admin.localhost:8091/mcp/systems/globex/globex-staff keycloak_user_search '{"search": "*"}'
```

- The server creates nothing in Keycloak. `client-setup` answers the client and a script; `adopt-setup.sh` runs
  that script with the `kcadm.sh` of the Keycloak container, logged in as `admin`
- The client names the server's JWKS URL, and Globex' Keycloak fetches the key from there. For a Keycloak that
  cannot reach the server, `credential=public-key` copies the public key into the client instead
- `roles=admin` gives the service account the master `admin` role: it sees every realm, later ones too.
  `roles=read` or `manage` with `realms=globex-staff,globex-customers` gives only those realms' roles, and the others
  do not even show up in step c
- `restrict: true` is needed because a system without an allowlist reaches every realm: adopting a selection narrows
  it to that selection (409 `would_restrict` without it)
- `globex-partners` then answers `realm_not_allowed`

**In the management UI.** <https://mcp-admin.localhost:8091/ui/> (`admin` / `admin`), system `globex`, tab *Adopt*: the two
realms left over, `globex-partners` and the disabled `globex-legacy`, are there to adopt, and the adopted ones to
unadopt. To do all of it in the UI, run `./demo.sh --skip-adopt` (steps 1 to 4 still register `acme`), then:

1. *Systems* → *New*: URL `https://globex.localhost:8089`, auth realm `master`, client authentication
   *Signed JWT*, client id `keycloak-mcp-server`. No issuer: it is the URL.
2. Tab *Adopt* → *1. Client in Keycloak*: copy the script, then `pbpaste | ./adopt-setup.sh`.
3. *2. Realms in Keycloak* → *Load*, then *3. Adopt* a selection, or every realm including later ones.

**Globex' own people, with their own roles.** The steps above use the service account (`mcp-admin.localhost`). On `mcp.localhost`
a user of Globex logs in at the master realm of Globex' Keycloak instead, and every call runs with a delegated token
that carries that user's roles:

```shell
./globex-login.sh
claude mcp add --transport http --client-id mcp-consumer --callback-port 33418 keycloak-globex \
  https://mcp.localhost:8092/mcp/systems/globex
./mcp-call.py --login globex-support:globex-support-demo https://mcp.localhost:8092/mcp/systems/globex whoami
```

- `globex-login.sh` creates in Globex' master realm what a login with delegation needs: the public client
  `mcp-consumer` (PKCE, consent, the scope `delegation:client`, audience `keycloak-mcp-server`), Admin Permissions with
  the grant that lets `keycloak-mcp-server` act for users, *Standard Token Exchange* on that client, and the user
  `globex-support` / `globex-support-demo`.
- `globex-support` holds roles of the master realm's clients `globex-staff-realm` and `globex-customers-realm`
  (users, clients, events; the master realm has no `realm-admin` for another realm, the single roles are it). So the
  user manages those two realms and no other, whatever the system has adopted; a realm that is not adopted answers
  `realm_not_allowed` first.
- What such a user can do today: read in both realms and manage clients. Writes on users (enable, password,
  roles, groups, credentials) answer `caller_foreign_realm`: the no-escalation and self-protection
  [checks](../../docs/security.md#built-in-policies-group-scope-no-escalation-self-protection) compare caller and
  target within one realm, and only a master `admin` passes them from outside.
- The address is the system's entry: its auth realm, `master`, is where the login happens. The realm is an
  argument of each call (`"realm": "globex-staff"`).

Worth trying: *Load* before the script ran (`token_refused`); rename a realm in Globex' admin console
(<https://globex.localhost:8089/admin>) and reload (*renamed from*); delete one (*not listed*).
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
