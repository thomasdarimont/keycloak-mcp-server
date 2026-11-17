# Delegated authentication: the MCP server as an agent acting on the user's behalf

The MCP server holds no admin credentials and acts *for* the signed-in user, with Keycloak's own delegation
(RFC 8693 `may_act` / `act`, Keycloak 26.8 **token exchange delegation**, preview). The user logs in through the
browser, consents to the client `keycloak-mcp` acting on their behalf, and every Admin API call runs with a delegated
token Keycloak issues for that pair:

```
MCP client ──(OAuth 2.1 / PKCE, scope "openid delegation:client:keycloak-mcp")──▶ Keycloak
   │  T_user: aud ∋ keycloak-mcp, may_act = {sub: <service account of keycloak-mcp>, client_id: keycloak-mcp}
   ▼
keycloak-mcp (the MCP server; confidential client, service account, Standard Token Exchange on, no admin role)
   │ 1. verifies T_user as a resource server (OIDC tenant)
   │ 2. T_sa  = client_credentials(keycloak-mcp)                          its own token, the actor
   │ 3. T_del = token-exchange(subject_token=T_user, actor_token=T_sa)   cached per T_user until either expires
   │      sub = the user, act = {client_id: keycloak-mcp}, roles = the user's ∩ keycloak-mcp's role scope
   │ 4. role checks, policies, confirmation (judged on T_del)
   ▼
Admin REST API with T_del → Keycloak enforces the user's realm-management roles; admin events name the user
```

What that buys over passing the user's own token through to the Admin API, which the MCP authorization
specification forbids and this server no longer does:

| | token passed through | exchange |
|---|---|---|
| Keycloak sees | the user | the user **and** the agent (`act`, `TOKEN_EXCHANGE` event with actor) |
| the user's token | goes to the Admin API as is, and opens it without the server too | stays with the MCP server and opens nothing else; a transient delegated token (no refresh, no session) goes out |
| narrowing | none: the user's full roles | the actor client's role scope caps every delegated token, whoever the user is |
| consent | none | explicit, every login session (Keycloak never stores it) |
| can be revoked | with the user's session | per client (Admin Permissions) or per client policy (`may-act` executor) |

## Start

```shell
cd examples/delegated-auth
docker compose up -d        # Keycloak 26.8.2 on http://localhost:8096 (admin / admin); the init job grants the permission
docker compose logs keycloak-init
```

Then run the MCP server on the host as the actor client:

```shell
cd ../..
set -a; source examples/delegated-auth/env/delegation.env; set +a
./mvnw quarkus:dev -pl modules/backend -am     # MCP endpoint: http://localhost:8097/mcp
```

or packaged, inside compose (`./mvnw package -DskipTests` first):

```shell
docker compose --profile mcp up -d --build && docker compose logs -f mcp
```

The startup log says `delegation=exchange: actor client 'keycloak-mcp' logs in; admin calls run with the delegated
tokens Keycloak exchanges for the callers`. Inside compose the server reaches Keycloak as `keycloak:8080` and its
protected resource metadata names that address as the authorization server, which a browser on the host cannot
open: `demo.sh` and `mcp-call.py` work either way (they log in at `localhost:8096` themselves), browser-based MCP
clients want the server on the host. IntelliJ: `.run/` has `quarkus:dev (delegation)` and the stack
(regenerate with `examples/gen-run-configs.sh`). `docker compose down -v` resets the realm.

## What is in the stack

| thing | details |
|---|---|
| Keycloak | 26.8.2 with `--features=token-exchange-delegation,parameterized-scopes`; realm `demo` with *Admin Permissions* (FGAP V2) on, login and admin events on |
| `mcp-consumer` | public PKCE client MCP clients log the user in with. **Consent required** (Keycloak insists for delegation scopes). Redirect URIs: LM Studio's `http://127.0.0.1:33389/mcp-oauth-callback` and `http://localhost:9999/*` for `mcp-call.py`. An audience mapper adds `aud=keycloak-mcp` so a login *without* the delegation scope still reaches the server and gets an explanation instead of a 401 |
| `keycloak-mcp` | the actor: confidential (`keycloak-mcp-secret`), service account **without any admin role**, *Standard Token Exchange* on, *Full scope allowed* off with a role scope of `realm-management` `view-realm, view-users, manage-users, query-users, query-groups, view-events` (`clientScopeMappings` in the realm file). Default scopes include `kc-admin-api`, the audience Keycloak 26.8.2 wants on Admin API tokens |
| Admin Permissions | `init/grant-delegation.sh` (kcadm, idempotent): client policy *keycloak-mcp may act for users* + scope permission *delegate to keycloak-mcp* on the Users resource type with the `delegate` scope. Restrict it to a group with a Groups permission and the `delegate-members` scope instead |
| users | `alice` (`/mcp-admins` → `realm-admin`, realm role `group-manager`), `carol` (`/mcp-support` → `view-users`, `view-events`), `bob` (nothing), `dave` (disabled). Password `<username>-demo` |
| events | `TOKEN_EXCHANGE`, `TOKEN_EXCHANGE_ERROR`, `GRANT_CONSENT`, logins; admin events |

Server side (`env/delegation.env`): `KC_MCP_DELEGATION=exchange`, the actor's `client_credentials`,
`QUARKUS_OIDC_TENANT_ENABLED=true`, `QUARKUS_OIDC_TOKEN_AUDIENCE=keycloak-mcp`, and
`QUARKUS_OIDC_RESOURCE_METADATA_SCOPES=openid,delegation:client:keycloak-mcp` so the protected resource metadata
tells MCP clients which scope to ask for. `env/delegation-policies.env` adds the server's policy layer on top
(no `keycloak_user_delete`, group scope with `group-manager`, no escalation): the "support user with extra checks"
scenario, where Keycloak limits the data and the server limits the tools.

## Try it

`demo.sh` runs the whole flow with `mcp-call.py`, which walks Keycloak's browser flow (login form, consent page) the
way an MCP client's browser does and then calls one tool. The password grant cannot stand in: a client that
requires consent refuses it.

```shell
./demo.sh
./mcp-call.py --login alice:alice-demo whoami
./mcp-call.py --login carol:carol-demo keycloak_user_set_enabled '{"id": "dave", "enabled": true}'
./mcp-call.py --login alice:alice-demo --scope openid whoami        # without the delegation scope
./mcp-call.py --login alice:alice-demo --show-tokens                # the three tokens, raw and decoded
```

`--show-tokens` (or `SHOW_TOKENS=1 ./demo.sh` for step 1) prints to stderr the tokens of one delegated call, each
raw for jwt.io and decoded:

| token | what to look at |
|---|---|
| 1. the user's (`mcp-consumer`) | `aud` ∋ `keycloak-mcp`, `may_act` = the actor's service account, alice's full `realm-management` roles |
| 2. the actor's (`client_credentials` of `keycloak-mcp`) | `sub` = the service account, no admin role at all, `aud` = the Admin API (`kc-admin-api`) |
| 3. the delegated one (token exchange of 1 with 2) | `sub` = alice, `act` = the actor, `azp` = `keycloak-mcp`, roles cut down to the actor's role scope |

Tokens 2 and 3 never leave the server, so the script requests them a second time with the actor's demo credentials
(`ACTOR_CLIENT_ID` / `ACTOR_CLIENT_SECRET`), exactly as the server does. You get the same claims with other ids and
timestamps, and Keycloak logs one more `TOKEN_EXCHANGE` event. With `--scope openid`, the third token is missing and
the output shows Keycloak's refusal (`Invalid may_act claim in the subject_token`).

| who | what happens |
|---|---|
| `alice` (realm-admin) | `whoami`: `keycloakCallsRunAs` is her account through a delegated token, `delegation: {mode: exchange, consented: true, actor: keycloak-mcp}`, roles `view-users, manage-users, …` only: **her `realm-admin` is cut down to the actor's scope**. Users work, `keycloak_client_list` → `forbidden`, missing `query-clients` |
| `carol` (view-users) | reads work, `keycloak_user_set_enabled` → `forbidden`, missing `manage-users` |
| `bob` | `forbidden`: no admin roles in realm `demo` |
| anyone, scope `openid` only | the token has no `may_act`; `whoami` shows `delegation: {consented: false, error: delegation_failed, …}` and every tool answers `delegation_failed` with what to do: ask for the scope, consent, or have an admin grant the permission |

Keycloak's side of the audit (`demo.sh` step 5): the `TOKEN_EXCHANGE` event carries the actor
(`keycloak-mcp`'s service account) and the subject user; the admin event of alice's change names alice as the
authenticated user, not a service account; the server's audit line says `caller=alice(<sub>) delegated`.

### MCP clients

LM Studio: copy `mcp-oauth.json` (`"auth": {"CLIENT_ID": "mcp-consumer"}`), connect, log in and consent in the
browser. The client must request the delegation scope: clients that honour `scopes_supported` of the protected
resource metadata (RFC 9728) do that on their own; with one that does not, `whoami` reports `consented: false` and
the login has to be repeated with the scope requested. Other clients need their callback URL in `mcp-consumer`'s
redirect URIs (Keycloak allows `*` only at the end of a URI). To switch users, log out in the Keycloak account
console (`http://localhost:8096/realms/demo/account`) and reconnect.

## Tightening

- **Who may delegate**: replace the Users permission with a Groups permission (`delegate-members`, e.g. on
  `/mcp-admins` and `/mcp-support`) so only those groups can hand the agent their rights.
- **What the agent may carry**: the actor's role scope. Drop `manage-users` for a read-only agent; nobody's login
  changes that.
- **The `may-act` client policy executor** re-validates every `may_act` claim Keycloak is about to issue (issuer,
  actor, `delegate` permission, consent), catching one a protocol mapper injected without either check, and can
  reject the claim outright for clients that must never delegate. The realm ships two profiles and two policies,
  **both switched off** so the demo runs without them (*Realm settings → Client policies*):

  | policy | profile | what it does when enabled |
  |---|---|---|
  | `validate-delegation-claims` | `may-act-validate` (all options off) | any client: every `may_act` is re-checked; a legitimate delegation is unaffected |
  | `no-delegation-for-confidential-clients` | `may-act-reject` (*Reject any may_act claim*) | confidential clients never get a `may_act` claim; only the public `mcp-consumer` may hand `keycloak-mcp` a delegation |

  Switch one on in the console or with kcadm, then log in again (`./mcp-call.py --login alice:alice-demo whoami`):
  with either policy enabled alice and carol still delegate (their client is public). Point the reject policy at
  *any client* instead and the login with the delegation scope is refused at the token endpoint
  (`invalid_request: The may_act claim is rejected for this client`), while a login without the scope still works.

  ```shell
  KCADM="docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh"
  $KCADM config credentials --server http://keycloak:8080 --realm master --user admin --password admin
  $KCADM get client-policies/policies -r demo \
    | jq '.policies |= map(if .name == "validate-delegation-claims" then .enabled = true else . end)' \
    | $KCADM update client-policies/policies -r demo -f -
  ```
- **Tool-level rules**: the server's policies provider (`env/delegation-policies.env`), `KC_MCP_DENIED_TOOLS`,
  `KC_MCP_READ_ONLY`, or an `AccessCheck` extension (`examples/extensions`); Keycloak Authorization Services on the
  `keycloak-mcp` client (resources = tool areas, scopes = verbs) are the next step for policies managed in the
  console.

## Notes

- Preview feature: Keycloak ≥ 26.8 started with both features; `kc-mcp.delegation=exchange` on an older server
  answers `delegation_failed` naming the missing feature.
- The delegated token has no refresh token; the server exchanges again when the caller's token or the delegated one
  expires (the caller's lives 30 min in this realm).
- Both tokens reach the token endpoint with the actor's client authentication: `client_secret` here,
  `private_key_jwt` works the same (`KC_MCP_JWT_KEY_FILE`).
