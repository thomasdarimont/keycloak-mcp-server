# Demo: tenants as systems, one MCP entry per tenant or realm

Two tenants on one Keycloak. Tenant A owns the realms `realm-a-1` (employees) and `realm-a-2` (customers),
tenant B owns `realm-b-1`. An onboarding job (`init/onboard-tenants.sh`, what a SaaS control plane would run)
gives each tenant a confidential client `keycloak-mcp-server-<tenant>` in the master realm, authenticating with
*Signed JWT* and the JWKS URL `http://mcp:8081/auth/keys/<tenant>/jwks.json`, and grants its service account
the admin roles of the tenant's realms (master's `<realm>-realm` client roles). `gen-keys.sh` provisions one
private key per tenant (`keys/<tenant>.pem`, what operations or the control plane would do), the MCP server learns
the tenants from `systems.json` and reads the keys from its read-only file vault, and Keycloak fetches the public
key from the MCP server when the first token is requested. No secret is configured anywhere.

In a real SaaS each tenant is its own Keycloak and the client is simply `keycloak-mcp-server` in that server's
master realm; here the two share one Keycloak, hence the tenant suffix.

```
./gen-keys.sh                      # keys/tenant-a.pem, keys/tenant-b.pem (needs openssl)
docker compose up --build          # Keycloak on :8090 (admin/admin), MCP server on :8091
```

Then, from this directory:

```
curl -s localhost:8091/auth/keys/tenant-a/jwks.json | jq .          # the key Keycloak fetches for tenant A
./mcp-call.py http://localhost:8091/mcp/systems/tenant-a whoami            # entry bound to tenant A, realm-a-1 by default
./mcp-call.py http://localhost:8091/mcp/systems/tenant-a keycloak_user_search '{"search": "alice"}'
./mcp-call.py http://localhost:8091/mcp/systems/tenant-a keycloak_user_search '{"realm": "realm-a-2", "search": "anna"}'
./mcp-call.py http://localhost:8091/mcp/systems/tenant-a/realm-a-2 keycloak_user_search '{"search": "anna"}'
./mcp-call.py http://localhost:8091/mcp/systems/tenant-a/realm-a-2 keycloak_user_search '{"realm": "realm-a-1"}'
                                                                     # -> entry_mismatch: bound to realm-a-2
./mcp-call.py http://localhost:8091/mcp/systems/tenant-b/realm-b-1 keycloak_user_search '{"search": "carol"}'
./mcp-call.py http://localhost:8091/mcp/systems/tenant-b keycloak_user_search '{"realm": "realm-a-1"}'
                                                                     # -> realm_not_allowed: not tenant B's realm
./mcp-call.py http://localhost:8091/mcp keycloak_user_search '{"system": "tenant-a", "realm": "realm-a-1", "search": "bob"}'
                                                                     # the root takes an explicit system
```

`mcp.json` configures an LLM client (LM Studio, Claude) with one logical MCP server per tenant or realm.

What the demo shows:

- **`KC_MCP_STATIC_SYSTEMS=false` + `KC_MCP_DYNAMIC_SYSTEMS=true` + `KC_MCP_SYSTEMS_FILE`**: systems come from
  the mounted `systems.json` only, re-read when it changes. Add a tenant to the file (and run the onboarding
  for it) and its entry works on the next call, without a restart.
- **Per-tenant keys, provisioned**: the file vault is read-only; `keys/` is mounted at `KC_MCP_KEYS_DIR` and
  `docker compose logs mcp` shows `[tenant-a] private_key_jwt key loaded from ...`. A tenant only ever registers a
  public key; creating and rotating keys inside the server is the job of a database-backed `KeyVault`.
- **`version` in `systems.json`**: the user-login server acts with delegated tokens of the realms' users and
  does not read the server info; the configured version keeps the version checks on (`whoami` shows `server.version`).
  Edit the file while the stack runs: it is re-read on the next call.
- **`issuer` in `systems.json`**: the MCP server reaches Keycloak at the internal `http://keycloak:8080`, but
  Keycloak's issuer is its public hostname `http://localhost:8090/realms/master`, and that is the audience a
  client assertion must carry. Without it Keycloak answers "Invalid token audience".
- **Entries**: `/mcp/systems/tenant-a` pins the system, `/mcp/systems/tenant-a/realm-a-2` pins system and realm; a
  disagreeing `system` or `realm` argument is refused with `entry_mismatch`, a realm the tenant does not own with
  `realm_not_allowed`.
- **`KC_MCP_ALLOWED_HOSTS=keycloak:8080`**: a system in `systems.json` pointing elsewhere is refused and logged.

The [management UI](../../docs/management-ui.md) of the first server: <http://localhost:8091/ui/>, sign in as
`admin` / `admin` of the master realm (the onboarding job creates the public client `keycloak-mcp-ui` there).
*Systems* lists the tenants with their realms, *Audit* the tool calls. It runs in dev mode without HTTPS, for one
person's machine only, with an H2 file in the container for its sessions and the audit trail. The tenants' keys
still come from `keys/`: `KC_MCP_SPI_KEY_VAULT_DB_ENABLED=false` keeps the database vault out, which would otherwise
replace the file vault.

## User login per realm (`mcp-users`, port 8092)

The second server requires an OAuth login at its MCP endpoint (`KC_MCP_MCP_OAUTH_ENABLED=true`) and makes
every Admin API call with a delegated token (`KC_MCP_DELEGATION=exchange`): Keycloak issues it for the user and
the tenant's client together (token exchange delegation, preview in Keycloak 26.8; `sub` is the user, `act` is
`keycloak-mcp-server-<tenant>`). The user's own token opens the MCP server only and never reaches the Admin API.
Keycloak enforces the user's roles, and both audits name the human.

A realm entry logs its users in at that realm: `/mcp/systems/tenant-a/realm-a-1` verifies tokens of `realm-a-1`,
`/mcp/systems/tenant-b/realm-b-1` those of `realm-b-1`. Keycloak accepts a token only at the realm that issued
it, so the exchange happens in that realm too, not in the system's auth realm `master`. The system stays the
tenant with its one client id and one key; what each realm that users log in at needs is:

- **The tenant's client, once more**: `keycloak-mcp-server-<tenant>` exists in each of the tenant's realms
  (`realms/*.json`) with the same client id and the same JWKS URL as in master, so the server logs in there with
  the same key (the client assertion names that realm's issuer as audience). It has *Standard Token Exchange*
  enabled and a service account without any admin role. Its role scope (`clientScopeMappings`) lists the
  `realm-management` roles a delegated token may carry at most.
- **`mcp-consumer`**: the public PKCE client MCP clients log the user in with requires consent, offers the
  optional scope `delegation:client` and puts `keycloak-mcp-server` (what the server accepts,
  `KC_MCP_MCP_OAUTH_AUDIENCE`) and the tenant's client into the token's audience. It has no `kc-admin-api`
  scope and no role scope.
- **Admin Permissions**: the realm has them enabled, and the onboarding job grants the tenant's client the
  permission *Users / delegate* (`init/grant-delegation.sh`, called by `init/onboard-tenants.sh`). A realm import
  cannot carry that grant. Without it Keycloak drops the delegation scope silently.
- **Keycloak features**: `token-exchange-delegation,parameterized-scopes` (see `docker-compose.yml`).

The entry's protected resource metadata tells an MCP client which scope to ask for: `openid` and
`delegation:client:keycloak-mcp-server-<tenant>`. At the login Keycloak asks the user whether that client may act
on their behalf. `./mcp-call.py --login user:password` does what the MCP client's browser does: it reads the
metadata, walks the login form and the consent page and sends the access token as a Bearer token. A password grant
is not possible, because a client that requires consent refuses it.

The tenant's client in master keeps its admin roles for the first server (`mcp`), and Keycloak fetches the public
keys from that server, so `mcp-users` needs it running. The system entry `/mcp/systems/tenant-a` and the root
`/mcp` verify tokens of the master realm; this example has no login client there, so users log in at the realm
entries only.

| user | realm | roles via group | what happens |
|---|---|---|---|
| `alice / alice-demo` | `realm-a-1` | `/mcp-admins` → `realm-admin` | everything works |
| `sam / sam-demo` | `realm-a-1` | `/mcp-support` → `view-users`, `view-events` | reads work, writes come back `forbidden`, `search_tools` marks them `allowed: false` |
| `bob / bob-demo` | `realm-a-1` | none (and disabled) | cannot log in |
| `anna / anna-demo` | `realm-a-2` | `/mcp-admins` | tenant A's customer realm |
| `carol / carol-demo` | `realm-b-1` | `/mcp-admins` | tenant B |

```
./mcp-call.py http://localhost:8092/mcp/systems/tenant-a/realm-a-1 whoami          # 401 + WWW-Authenticate … resource_metadata
curl -s localhost:8092/.well-known/oauth-protected-resource/mcp/systems/tenant-a/realm-a-1 | jq .
                                             # names realm-a-1 and the scope delegation:client:keycloak-mcp-server-tenant-a
./mcp-call.py --login alice:alice-demo http://localhost:8092/mcp/systems/tenant-a/realm-a-1 whoami
                                             # delegation: mode exchange, consented, actor keycloak-mcp-server-tenant-a
./mcp-call.py --login alice:alice-demo http://localhost:8092/mcp/systems/tenant-a/realm-a-1 keycloak_user_search '{"search": "sam"}'
./mcp-call.py --login sam:sam-demo http://localhost:8092/mcp/systems/tenant-a/realm-a-1 keycloak_user_set_enabled '{"id": "bob", "enabled": true}'
                                                                               # -> forbidden: sam lacks manage-users
./mcp-call.py --login anna:anna-demo http://localhost:8092/mcp/systems/tenant-a/realm-a-2 keycloak_user_search '{"search": "anna"}'
./mcp-call.py --login carol:carol-demo http://localhost:8092/mcp/systems/tenant-b/realm-b-1 keycloak_user_search '{"search": "dave"}'
./mcp-call.py --login alice:alice-demo@realm-a-1 http://localhost:8092/mcp/systems/tenant-b/realm-b-1 whoami
                                                                               # -> 401: a realm-a-1 token is no good for tenant B
./mcp-call.py --login alice:alice-demo --scope openid http://localhost:8092/mcp/systems/tenant-a/realm-a-1 keycloak_user_search '{"search": "sam"}'
                                                                               # -> delegation_failed: no consent, no may_act claim
```

The realms record the events `TOKEN_EXCHANGE` and `TOKEN_EXCHANGE_ERROR`: the admin console of `realm-a-1`
(Events, user events) shows one exchange per call, with the user, the client `keycloak-mcp-server-tenant-a` and
the actor.

`mcp-oauth.json` configures LM Studio with the three realm entries and `"auth": {"CLIENT_ID": "mcp-consumer"}`;
LM Studio opens the browser at the right realm for each entry and asks for the scope the entry's metadata names.
To switch users, remove the server in LM Studio and add it again, or log out in the Keycloak account console.

```
docker compose down -v             # drops the onboarded clients; the provisioned keys stay in keys/
```
