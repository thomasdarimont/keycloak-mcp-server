# Demo setup for keycloak-mcp-server

A ready-to-run Keycloak 26.8.2 with a `demo` realm shaped for the tool surface, plus Mailpit to catch the
action emails. Everything is throw-away (`docker compose down -v` resets it).

## Start

```shell
cd examples/run-modes
docker compose up -d
# Keycloak: http://localhost:8080  (admin console: admin / admin)
# Mailpit:  http://localhost:8025
```

Then run the MCP server on the host with one of the access levels in `env/`:

```shell
./server.sh                 # env/realm-admin.env; MCP endpoint: http://localhost:8081/mcp
./server.sh read-only       # another access level: the name of an env file
```

`server.sh` starts `quarkus:dev` with the settings of the env file and nothing else: `KC_MCP_*` and `QUARKUS_*` variables
the terminal still carries from another example are dropped, and none are exported into it. `./server.sh --jar` runs
the packaged server instead.

Or let compose run it from the packaged jar (`./mvnw package` first):

```shell
KC_MCP_ENV_FILE=env/realm-manager.env docker compose --profile mcp up -d --build
docker compose logs mcp | grep 'tools registered'    # shows version, build time and tool count
```

After changing the server, run `./mvnw package` and `up --build` again; without `--build` compose reuses the
previous image. With `quarkus:dev` on the host nothing is needed.

Point your MCP client at `http://localhost:8081/mcp` (LM Studio: copy `mcp.json`; with `env/user-login.env` copy
`mcp-oauth.json` instead, see below). IntelliJ: `.run/` holds one `quarkus:dev` run configuration per env file and the
demo stack, next to the configurations of the other examples (regenerate all with `examples/gen-run-configs.sh` after
editing an env file).

An existing stack keeps its old realm: after changes to `realms/demo-realm.json` run `docker compose down -v` first.

## What is in the `demo` realm

| thing | details |
|---|---|
| users | `alice` (admins, team-a, mcp-admins, `group-manager`, R&D), `bob` (devs/backend, `demo-app` app-user), `carol` (team-b, mcp-support, `support`), `dave` (disabled). Password = `<username>-demo`. |
| groups | `/admins` (→ editor), `/devs` (→ viewer) with `backend`, `frontend`, `/team-a` with `ops`, `/team-b`; `/mcp-admins` (→ realm-management `realm-admin`) and `/mcp-support` (→ `view-users`, `view-events`) for the user login demo |
| realm roles | `viewer`, `editor` (composite of viewer), `group-manager`, `support` |
| clients | `demo-app` (confidential, PKCE, client roles `app-user`/`app-admin`), `mcp-consumer` (public PKCE client MCP clients log the user in with; an audience mapper adds `aud=mcp-admin`, redirect URIs are LM Studio's `http://127.0.0.1:33389/mcp-oauth-callback` and the loopback callbacks of Claude Code, Cursor and Codex (`http://localhost/callback`, `http://localhost/oauth/callback`, any port), access tokens live 30 min) |
| MCP service accounts | `mcp-admin` → `realm-admin`; `mcp-manager` → view-users, manage-users, view-clients, view-events; `mcp-readonly` → view-* only. Secrets: `<clientId>-secret`. `mcp-jwt` → `realm-admin`, authenticates with `private_key_jwt` (JWKS URL → the MCP server) |
| identity provider | `corp-oidc` (disabled stub, hidden on login) |
| organization | `ACME Corp` (`acme`, domain acme.com) |
| realm settings | login + admin events on, organizations on, SMTP → Mailpit, password policy `length(8)`, unmanaged user attributes enabled (`department`) |
| second realm | `other` with user `zed`, deliberately outside `KC_MCP_SYSTEMS_DEFAULT_ALLOWED_REALMS` |

## Access levels to demonstrate

| env file | what the model can do |
|---|---|
| `env/full-admin.env` | everything, every realm (admin user via admin-cli) |
| `env/realm-admin.env` | everything inside `demo` |
| `env/realm-manager.env` | user management only; client/realm/flow tools are hidden; `keycloak_user_delete` denied; group scope + no-escalation policies on |
| `env/read-only.env` | reads only, lazy exposure (just `search_tools` / `execute_tool`) |
| `env/multi-system.env` | two systems `prod` and `staging` (both this Keycloak) to show the `system` argument |
| `env/private-key-jwt.env` | client authentication with a signed JWT instead of a secret; see below |
| `env/user-login.env` | the user logs in through the browser and every call runs with *their* roles, through a delegated token; see below |
| `env/shared.env` | the same under the `shared` security profile; see below |

## private_key_jwt demo

```shell
./gen-key.sh                                          # writes keys/mcp-jwt.pem (git-ignored)
./server.sh private-key-jwt
curl http://localhost:8081/.well-known/jwks.json      # the public key Keycloak will fetch
```

The `mcp-jwt` client in the realm is configured with *Client Authenticator = Signed JWT* and
*JWKS URL = http://host.docker.internal:8081/.well-known/jwks.json*. On the first tool call the server signs a
client assertion with the private key, Keycloak fetches the JWKS from the running MCP server, validates the
assertion and issues the service-account token. The assertion's `kid` equals the JWK's `kid` (RFC 7638
thumbprint), so key rotation is a matter of swapping the PEM and restarting. Compose runs the same setup with
`KC_MCP_ENV_FILE=env/private-key-jwt.env docker compose --profile mcp up -d --build` (the key is mounted at `/keys`).

## User login demo (`env/user-login.env`)

The MCP endpoint answers anonymous requests with a `401` and
`WWW-Authenticate: Bearer resource_metadata="http://localhost:8081/.well-known/oauth-protected-resource"`; LM Studio
follows that, logs the user in at Keycloak as the public client `mcp-consumer` (authorization code + PKCE) and sends
the user's access token. That token only opens the MCP server. For the Admin API the server exchanges it at Keycloak
for a delegated token (`KC_MCP_DELEGATION=exchange`, Keycloak's token exchange delegation, preview in 26.8): `sub` is
the user, `act` the server's client `keycloak-mcp`. So Keycloak enforces the user's own `realm-management` roles, its
events name both, and the audit line names the human. The server's client holds no admin role; without a user's
token its credentials reach nothing. The user's own token is never sent to the Admin API: the MCP specification
forbids passing it through.

What this needs in Keycloak is in the realm file and the compose file: the features `token-exchange-delegation` and
`parameterized-scopes`, consent on `mcp-consumer` (the login shows a page asking whether `keycloak-mcp` may act on
the user's behalf, every session), the client `keycloak-mcp` with *Standard Token Exchange*, and the Admin
Permissions grant that the `keycloak-init` job creates. [delegated-auth](../delegated-auth/) explains each of them
and shows a client whose role scope narrows what a delegated token may carry; here it lets `realm-admin` through.

```shell
docker compose up -d                                        # Keycloak must be up before the server starts
./server.sh user-login
curl -i http://localhost:8081/mcp                           # 401 + WWW-Authenticate … resource_metadata=…
curl http://localhost:8081/.well-known/oauth-protected-resource
```

LM Studio: copy `mcp-oauth.json` (`"auth": {"CLIENT_ID": "mcp-consumer"}`), connect, log in in the browser:

| user | roles via group | what happens |
|---|---|---|
| `alice / alice-demo` | `/mcp-admins` → `realm-admin` | everything works; audit: `caller=alice(…) delegated` |
| `carol / carol-demo` | `/mcp-support` → `view-users`, `view-events` | "list users" works, "disable dave" → `forbidden`, missing `manage-users`; `search_tools` already marks such tools `allowed: false` |
| `bob / bob-demo` | none | every tool → `forbidden` ("no admin roles in realm 'demo'") |

`env/shared.env` is the same stack under `KC_MCP_SECURITY_PROFILE=shared`, the settings a server other people reach needs:
authenticated callers with an audience, the Keycloak host listed, `confirm: true` no longer accepted (destructive tools
need a client with elicitation, LM Studio has none, so "delete dave" is refused with `confirmation_required`), and
destructive tools must pass `realm` although a default realm is set. Remove `KC_MCP_ALLOWED_HOSTS` from the file to
see the startup check list what is missing.

"What am I allowed to do?" (or "Was darf ich?") calls `whoami`, which lists the user's roles with readable labels
(`language: de` gives German ones) and a per-area summary such as `users: view, clients: none`.
To switch users, remove the server in LM Studio and add it again, or log the user out in the Keycloak account
console. Other MCP clients need their own callback added to `mcp-consumer`'s redirect URIs (Keycloak allows `*`
only at the end of a URI). A token obtained for `demo-app` is rejected with `401` because it lacks `aud=keycloak-mcp`.

`mcp-consumer` asks for consent, so a script cannot fetch a user token with a password grant. For scripted checks
`./mcp-call.py --login alice:alice-demo whoami` walks the browser flow instead (login form, consent page, code with
PKCE) and calls the tool with the token; `--show-tokens` prints the user's, the client's and the delegated token.

## Management UI

Every env file also turns the [management UI](../../docs/management-ui.md) on: <http://localhost:8081/ui/>, sign in
at the `demo` realm as `alice` / `alice-demo` (operator) or `carol` / `carol-demo` (viewer, read-only). *Systems*
shows what the env file configured, *Audit* the tool calls.

It runs without HTTPS in dev mode (`KC_MCP_DEV_MODE=true`: the session cookie drops `Secure`, for one person's
machine only) and keeps its sessions and the audit trail in an H2 file under `data/` (git-ignored). The server
therefore has to be the default H2 build, not a `-Ppostgresql` one. [management-ui](../management-ui/) shows the UI
with HTTPS, registration of systems and two identity providers.

## MCP prompts

The server also offers task recipes as MCP prompts (`keycloak_onboard_user`, `keycloak_login_troubleshoot` and two
more for redirect loops and slow logins, see [troubleshooting](../troubleshooting/)), each with the tools it needs
attached. Clients that expose prompts show them in their prompt picker; for one that does
not, fetch the rendered text and paste it into the chat:

```shell
examples/run-modes/prompt.sh                                                       # list prompts and arguments
examples/run-modes/prompt.sh keycloak_onboard_user realm=demo username=nina email=nina@example.com groups=/devs
MCP_TOKEN=<access token> examples/run-modes/prompt.sh ...                          # with env/user-login.env
```

## Prompts to try

1. "Which users are in the demo realm?"
2. "Disable the user dave" / "Is dave enabled?" (dave starts disabled; enable him first)
3. "Add carol to the devs/backend group and tell me which roles she effectively has now."
4. "Send bob an email to reset his password" (then open Mailpit).
5. "Create a confidential client `billing-api` with redirect URI https://billing.example.com/* and PKCE."
6. "Show the client secret of demo-app" (masked) / "...reveal it".
7. "Which authentication flow is bound as browser flow? Copy it to `browser-mfa` and add a conditional OTP sub-flow."
8. "List failed logins of the last day."
9. "Turn on self-registration in the demo realm." (destructive → confirmation)
10. "Link the identity provider corp-oidc to the ACME organization."
11. With `realm-manager.env`: "Delete user dave" (denied), "Create a client" (tool not visible),
    "Give carol the admin role" (escalation refused).
12. With `other` realm: "List users in realm other" (realm_not_allowed).
13. With `user-login.env` as carol: "Which users are in the demo realm?" (works), "Disable dave" (forbidden, she
    lacks `manage-users`); as alice the same prompt succeeds and the audit log shows `caller=alice`.
14. "What would alice's access token for demo-app contain with the offline_access scope?" / "...her ID token" /
    "...the userinfo response" (the admin console's *Evaluate* tab; unsigned examples), then "Which mappers and
    realm roles does demo-app get?".
15. "Quels rôles a l'utilisateur bob ?" or "Désactiver l'utilisateur dave" (French queries are translated for the
    tool search like German ones).

## Reset

```shell
docker compose down -v
```
