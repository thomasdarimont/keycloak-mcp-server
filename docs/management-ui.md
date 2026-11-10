# Management UI

[keycloak-mcp-server](../README.md) › documentation

A browser UI for the server at `/ui`, with its backend-for-frontend (BFF) under `/bff`.

**Status: work in progress.** Sign in at Keycloak, browse and edit mutable systems (create / replace via the BFF), see
who you are, sign out. Secrets and storage pages are still placeholders. The plumbing underneath is covered by
integration tests: the login, sessions in the database, several identity providers, session checks and back-channel
logout. See `modules/backend/src/main/resources/frontend/README.md` for the contract and the development loop.

## How it works

The UI is a [Lit](https://lit.dev) single-page app under `modules/backend/src/main/resources/frontend`, bundled by
[Quarkus Web Bundler](https://docs.quarkiverse.io/quarkus-web-bundler/dev/) (mvnpm, no Node) and served by the backend.
The server is the OpenID Connect relying party: it runs the authorization code flow with PKCE at Keycloak, the
browser gets an HttpOnly, Secure, `SameSite=Lax` cookie holding an opaque session id, and the tokens stay on the server,
in the database (`kc_mcp_user_session`, encrypted like the other secrets). The browser never sees a token.

It needs the [database storage](storage.md) and HTTPS.

## Turning it on

| setting | meaning |
|---|---|
| `kc-mcp.ui.enabled=true` | serves `/ui` and `/bff` |
| `kc-mcp.ui.issuer` | the realm users sign in at; default `kc-mcp.admin.issuer`, else the auth realm |
| `kc-mcp.ui.client-id` | the Keycloak client, `keycloak-mcp-ui` by default: public, PKCE S256, redirect URI `<server>/bff/login`, post-logout redirect URI `<server>/ui/*`; `kc-mcp.ui.client-secret` for a confidential client |
| `QUARKUS_TLS_KEY_STORE_PEM_UI_CERT` / `_KEY`, `quarkus.http.ssl-port` | HTTPS; `etc/mkcert.sh` writes `.certs/localhost*.pem` for local use; behind a TLS proxy set `quarkus.http.proxy.proxy-address-forwarding=true` instead |
| `kc-mcp.ui.tls-configuration-name` | a named trust store for the server's own calls to the identity providers (private CA) |
| `kc-mcp.ui.connect-timeout` / `read-timeout` | timeouts of those calls, default `kc-mcp.http.*` |

`./mvnw package` bundles the UI with Quarkus Web Bundler; turn it off at runtime with `kc-mcp.ui.enabled=false`.
A `-Pdist` build ships the same bundle as a static jar (`modules/ui-bundle`) without the extension, which cannot run
when `bin/kcmcp.sh build` re-augments an unpacked distribution.
Edit files under `modules/backend/src/main/resources/frontend` while `quarkus:dev` is running for live reload.
`bin/kcmcp.sh start-dev` in an H2 distribution turns the UI on with a database in `data/` and no HTTPS, as its session
cookies drop `Secure`; only for one person's machine.
A working setup with one or two identity providers: `examples/management-ui/`.

## Several identity providers

`kc-mcp.ui.idps.<alias>.issuer`, `.client-id`, `.client-secret`, `.display-name` add one provider per alias. Each one
becomes an OIDC tenant `kc-mcp-ui-<alias>` and a sign-in button that starts `/bff/login?idp=<alias>`; a session records
which provider and subject it belongs to.

- `hide-on-login-page=true` keeps a provider off the login page, so a shared server does not advertise its tenants.
  Its users sign in through `/bff/login?idp=<alias>` directly, and the UI names the provider once they are in.
- Nothing is remembered between sessions. A logout returns to `/ui/?idp=<alias>`, and the page offers that provider
  first.
- `kc-mcp.ui.idps.<alias>.session-age-extension` sets the session renewal per provider (below).

## Sessions

- **Renewal.** A session is kept alive with its refresh token for `kc-mcp.ui.session-age-extension` past the ID
  token's expiry, 30 minutes by default, the usual SSO idle timeout. Rows carry provider, issuer, subject and the
  provider's session id (`sid`), and are deleted once their tokens are of no use.
- **Session check.** The UI calls `POST /bff/check-session` whenever its tab becomes visible again. The server redeems
  the refresh token at the provider, which proves the SSO session still exists and extends it, and renews the stored
  tokens and the cookie. A session that ended elsewhere (account console, another application, an administrator, the
  idle timeout) answers 401 `session_ended` and loses its row; 503 when the provider cannot be asked.
- **Back-channel logout.** `POST /bff/backchannel-logout` takes the provider's logout token, verifies it against the
  provider its `iss` and `aud` name, and deletes the sessions with that issuer and `sid` (or subject) at once, on every
  instance. On the Keycloak client: *Backchannel logout URL* `<server>/bff/backchannel-logout`, *session required* on.
- **Several instances.** Set `QUARKUS_OIDC_KC_MCP_UI_<ALIAS>_AUTHENTICATION_STATE_SECRET` so any instance can finish a
  login another one started; the session rows are shared through the database.

## Endpoints

| call | does |
|---|---|
| `GET /bff/me` | who is signed in and the providers of the login page |
| `GET /bff/login[?idp=<alias>]` | starts the login, then `/ui/` |
| `GET /bff/logout` | RP-initiated logout, session row deleted |
| `GET /bff/api/systems[/{alias}]` | the systems, as `GET /admin/systems`; needs `kc-mcp.admin.role` on the access token |
| `PUT /bff/api/systems/{alias}` | replace a mutable system, as `PUT /admin/systems/{alias}` (CSRF header) |
| `POST /bff/check-session` | the session check above |
| `POST /bff/backchannel-logout` | for the identity provider, not the browser |

Browser requests carry `X-Requested-With: JavaScript`. With it, a request without a session answers 499 instead of a
redirect; writes are refused without it. Errors are `{"error": "<code>", "message": "..."}` like the admin API.
