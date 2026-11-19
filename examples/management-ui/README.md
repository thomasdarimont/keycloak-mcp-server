# Management UI (BFF)

The server as OIDC relying party for a browser: authorization code flow with PKCE at Keycloak, the tokens in the
database (`kc_mcp_user_session`, encrypted like the other secrets), the browser holding an HttpOnly, Secure cookie with
an opaque id. The Lit UI (`modules/backend/src/main/resources/frontend`, Quarkus Web Bundler) is served at `/ui/`, its
API under `/bff`. Runs on the run-modes stack.

```shell
etc/mkcert.sh                                         # once; mkcert's CA into the trust stores, .certs/localhost*.pem
(cd examples/run-modes && docker compose up -d)
examples/management-ui/server.sh                      # env/ui.env and nothing else from this terminal
open https://localhost:8443/ui/
```

| user | password | outcome |
|---|---|---|
| `alice` | `alice-demo` | `/mcp-admins` → `realm-management.realm-admin` (operator): signs in, can list and edit mutable systems |
| `carol` | `carol-demo` | `/mcp-support` → `realm-management.view-users` (viewer via `KC_MCP_UI_VIEWER_ROLE`): signs in, can read systems; writes answer 403 |

- `env/ui.env`: one identity provider (`KC_MCP_UI_ISSUER`, the demo realm, client `keycloak-mcp-ui`), H2 file database,
  the mkcert certificate, admin API over bearer tokens too
- `env/ui-two-idps.env`: two providers (`KC_MCP_UI_IDPS_DEMO_*`, `KC_MCP_UI_IDPS_MASTER_*`), one button each;
  `master-client.sh` registers the client in the master realm first
- IntelliJ: `.run/management-ui-mkcert`, `.run/dev-ui`, `.run/dev-ui-two-idps`
- Live-reload: edit files under `modules/backend/src/main/resources/frontend` while `quarkus:dev` is running
- A stack that was up before the UI client changed keeps its old realm (`docker compose down -v` re-imports it); the
  client needs its *Backchannel logout URL* for the back-channel logout to reach the server

## What to look at

- Keycloak client `keycloak-mcp-ui` (`examples/run-modes/realms/demo-realm.json`): public, PKCE S256, redirect URI
  `https://localhost:8443/bff/login`, post logout redirect URI `https://localhost:8443/ui/*`, audience mapper
  `aud=mcp-admin` like `mcp-consumer`
- The cookie: `q_session_kc-mcp-ui-<alias>` with a 43 character id, `Secure; HttpOnly; SameSite=Lax`, no token in it
- The row: `select id, idp, subject, substr(id_token, 1, 12), expires_at from kc_mcp_user_session` in `data/kc-mcp-ui`
  (H2) shows `enc:v2:...`; `GET /admin/storage` counts the table's key ids; logout deletes the row
- Roles: `/bff/me` lists them from the access token (`realm:...`, `<client>.<role>`); `admin` / `viewer` and
  `capabilities` (`systems:read`, `systems:write`, …) drive the sidebar. Operator = `KC_MCP_ADMIN_ROLE` (reads and
  writes); optional viewer = `KC_MCP_UI_VIEWER_ROLE` (reads only). The bearer admin API still needs the operator role.
- Expiry: the ID token lives 5 minutes (realm setting), Quarkus renews it for `KC_MCP_UI_SESSION_AGE_EXTENSION`
  (default 30 minutes, Keycloak's SSO idle timeout) of idling; after that `/bff/api/*` answers 499 and the page shows
  the sign-in buttons again
- Logout elsewhere: sign in to the UI, open http://localhost:8080/realms/demo/account in a second tab, sign out there,
  switch back: the tab's visibility change runs `POST /bff/check-session`, Keycloak refuses the refresh
  (`invalid_grant: Session not active`), the row goes and the sign-in buttons are back. "Check now" does the same on
  demand; "Last session check" shows the outcome
- Back-channel logout: the client's *Backchannel logout URL* is `http://host.docker.internal:8081/bff/backchannel-logout`
  (Keycloak in Docker reaching the server on the host over http: it does not trust the mkcert CA). Sign out in the
  Keycloak account console (http://localhost:8080/realms/demo/account) or `Sessions → Sign out` in the admin console
  while signed in to the UI: the row is gone at once, the next click in the UI shows the sign-in buttons

## Several identity providers

`kc-mcp.ui.idps.<alias>.issuer|client-id|client-secret|display-name|session-age-extension` make one OIDC tenant
(`kc-mcp-ui-<alias>`) and one sign-in button each; `/bff/login?idp=<alias>` starts the flow there, the callback and every later request find the
provider through the cookie. A logout returns to `/ui/?idp=<alias>`, so the page offers that provider first; nothing is remembered beyond that.
`KC_MCP_UI_IDPS_<ALIAS>_HIDE_ON_LOGIN_PAGE=true` keeps a provider off the page: its users sign in through
`/bff/login?idp=<alias>`.
A session records its `idp`, `issuer`, `subject` and `sid`; a back-channel logout token
is matched by issuer and `sid`, so one logout URL serves every provider. Which systems a provider's users may manage is
not modelled yet: today `kc-mcp.admin.role` is the one gate for every provider (so a master admin in `ui-two-idps.env`
signs in but gets `forbidden`); a per-provider or per-system role mapping is the next step.
