# Management UI

[keycloak-mcp-server](../README.md) › documentation

A browser UI for the server at `/ui`, with its backend-for-frontend (BFF) under `/bff`.

**Status: work in progress.** Sign in at Keycloak, land on Overview, browse **Systems** (each system is a Keycloak
cluster / environment), open a system for **Settings** (connection and realm allowlist), **Realms** (allowlist merged
with per-realm settings from the admin realm API) and **Keys** (signing key / rotate). Create, replace and delete
mutable systems via the BFF; edit realm labels and presets on their own pages. Secrets and Storage are placeholders
(vault provenance and encryption / system sources later — no secret writing in the UI). **Audit** lists the tool
calls of the audit trail, filtered and paged on the server. The plumbing underneath is
covered by integration tests: the login, sessions in the database, several identity providers, session checks and
back-channel logout. See `modules/backend/src/main/resources/frontend/README.md` for the contract and the development
loop.

## Pages

| path | page |
|---|---|
| `/ui/overview` | who you are, system count; framing for systems → realms |
| `/ui/systems` | list of systems with source, read-only marker, realms summary |
| `/ui/systems/new` | create a mutable system |
| `/ui/systems/{alias}` | system Settings (default tab): connection, allowlist, trusted issuers, delete |
| `/ui/systems/{alias}/realms` | Realms: allowlist + stored settings, MCP entries, add settings |
| `/ui/systems/{alias}/realms/{realm}` | realm labels, realm id, preset; delete settings |
| `/ui/systems/{alias}/adopt` | adopt realms: the Keycloak client (JSON and a kcadm script for Linux/macOS or Windows, from an installation or the Keycloak image; copy or download), the realms its service account sees, adopt a selection or every realm ([Adopting](systems.md#adopting-a-keycloaks-realms)) |
| `/ui/systems/{alias}/keys` | signing key details; rotate (operator, mutable / writable vault) |
| `/ui/audit` | the audit trail, newest first: filters for caller, system, realm and tool (completed from the recorded values), level, outcome and time (the last N minutes, hours, days or weeks, or between two moments), and signed-in or anonymous callers, applied as they are chosen and listed as removable chips; When, Caller and Took sort the table; an entry opens to its details (message, subject, client, connection, the OpenTelemetry trace and span, linked through `kc-mcp.ui.trace-url`), and its arguments are fetched only on *Show arguments*; the address bar carries them (`?system=&realm=&tool=&level=&outcome=&anonymous=&last=2w` or `from=&to=`, `sort=&order=`, `size=`), so a view can be bookmarked or shared, without the caller: names stay out of URLs; 25, 50, 100 or 250 per page (25 by default), paged with the total |
| `/ui/secrets`, `/ui/storage` | stubs |

A system is one Keycloak front door (`url`). Realms are not a top-level nav section: the allowlist is
`allowedRealms` / `defaultRealm` on the system; stored per-realm settings use
`GET`/`PUT`/`DELETE /admin/systems/{alias}/realms[/{realm}]` (mirrored under `/bff/api/...`). Empty `allowedRealms`
means all realms on that cluster. Realm import / discover and Test connection still need server endpoints.

## Roles

| role | config | access |
|---|---|---|
| operator | `kc-mcp.admin.role` (default `realm:admin`) | read and write `/bff/api/*` |
| viewer | `kc-mcp.ui.viewer-role` (optional; unset = off) | read-only `/bff/api/*` |

The BFF enforces; the UI hides what `/bff/me` `capabilities` does not list (`systems:read`, `systems:write`,
`secrets:read`, `storage:read`, `audit:read`). An operator sees everything a viewer sees. The bearer admin API is unchanged and still
requires the operator role. One `systems:write` covers systems, realms and key rotate.

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
| `kc-mcp.ui.scopes` / `kc-mcp.ui.auth-params.<name>` | scopes besides `openid` and extra parameters of the authorization request, also per provider (`kc-mcp.ui.idps.<alias>.scopes`, `.auth-params.<name>`, used instead of the top-level ones when set); for providers that issue a refresh token only when asked ([below](#providers-without-a-refresh-token)) |

`./mvnw package` bundles the UI with Quarkus Web Bundler; turn it off at runtime with `kc-mcp.ui.enabled=false`.
A `-Pdist` build ships the same bundle as a static jar (`modules/ui-bundle`) without the extension, which cannot run
when `bin/kcmcp.sh build` re-augments an unpacked distribution.
Edit files under `modules/backend/src/main/resources/frontend` while `quarkus:dev` is running for live reload.
`bin/kcmcp.sh start-dev` in an H2 distribution turns the UI on with a database in `data/`, registration of systems
(*Add system*) and no HTTPS, as its session cookies drop `Secure`; only for one person's machine
([Development mode](configuration.md#development-mode-start-dev)).
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
  idle timeout) answers 401 `session_ended` and loses its row; 503 when the provider cannot be asked. Only
  `invalid_grant` ends a session: a refusal of the server's client (`invalid_client`, ...) is a 503 and the session
  stays. Concurrent checks of one session share one refresh, and a check whose (rotated) refresh token was already
  replaced by another request keeps the renewed session instead of deleting it. A logout that comes while a session's
  tokens are renewed (by the check or by the OIDC layer's own refresh) wins: the renewal is stored only while the row
  still exists (`UserSessionStore.renew` / `replace`, one locked row in the database), so a removed session never comes
  back. In a rare race a renewal that loses against the cleanup after an `invalid_grant` ends the session too; the
  next request signs in again through the provider's SSO session.
- **Back-channel logout.** `POST /bff/backchannel-logout` takes the provider's logout token, verifies it against the
  provider its `iss` and `aud` name, and deletes the sessions with that issuer and `sid` (or subject) at once, on every
  instance. On the Keycloak client: *Backchannel logout URL* `<server>/bff/backchannel-logout`, *session required* on.
- **A sign-in that cannot be completed.** When the callback to `/bff/login` fails (the code exchange is refused, or
  the ID token does not verify, e.g. already expired because the provider's clock is behind after a laptop's
  suspend), a browser (`Accept: text/html`) is sent to `/ui/?signin=failed`, which says so and offers to sign in
  again; other clients get 401 `sign_in_failed`. The server logs the reason without the token's claims. The login is
  not restarted on its own: while the cause lasts that would loop.
- **Server errors.** An unexpected error under `/ui` or `/bff` gets the UI's own answer instead of Quarkus' error
  page: a browser a small page with the error id and *Try again*, the BFF's callers `{"error": "server_error",
  "message", "errorId"}`; the server logs the error under that id. Dev mode's *Error restarting Quarkus* page (the
  application failed to reload, e.g. a compile error) comes from Quarkus itself and stays.
- **Several instances.** Set `QUARKUS_OIDC_KC_MCP_UI_<ALIAS>_AUTHENTICATION_STATE_SECRET` so any instance can finish a
  login another one started; the session rows are shared through the database.

### Providers without a refresh token

The session check and the renewal both redeem the refresh token. A session without one lasts as long as its ID token:
the check reports it active without asking the provider (`"renewable": false`), ends it once the ID token expired,
and the cookie gets no `session-age-extension`. A logout at the provider (another application, an administrator)
then reaches the server only through the back-channel logout; without one, keep the provider's ID token lifetime
short.

Keycloak issues a refresh token in the authorization code flow unless the client's *Use refresh tokens* switch
(*Advanced* › *OpenID Connect Compatibility Modes*) is off; leave it on. Other providers need asking:

| provider | settings |
|---|---|
| Microsoft Entra ID | `kc-mcp.ui.idps.<alias>.scopes=offline_access` |
| Auth0, Okta | `scopes=offline_access`; Auth0 also *Allow Offline Access* on the API, Okta the *Refresh Token* grant on the app |
| Google | `auth-params.access_type=offline`, `auth-params.prompt=consent` (Google issues a refresh token only at consent) |

Never `offline_access` at Keycloak: that is an offline token, which survives the SSO session, so the session check
would keep sessions the user ended. The server warns at startup when a provider whose issuer is a Keycloak realm asks
for it. The code flow's own parameters (`client_id`, `redirect_uri`, `scope`, `state`, `nonce`, PKCE, ...) cannot be
set through `auth-params`; startup fails on them.

## Endpoints

| call | does |
|---|---|
| `GET /bff/me` | who is signed in, providers, `admin` / `viewer`, and `capabilities` |
| `GET /bff/login[?idp=<alias>]` | starts the login, then `/ui/overview` |
| `GET /bff/logout` | RP-initiated logout, session row deleted |
| `GET /bff/api/systems[/{alias}]` | the systems, as `GET /admin/systems`; operator or viewer |
| `PUT /bff/api/systems/{alias}` | replace a mutable system; operator only (+ CSRF header) |
| `DELETE /bff/api/systems/{alias}` | remove a mutable system; operator only (+ CSRF) |
| `POST /bff/api/systems/{alias}/signing-key` | rotate the signing key; operator only (+ CSRF) |
| `GET /bff/api/systems/{alias}/realms[/{realm}]` | realm settings, as the admin API |
| `PUT` / `DELETE /bff/api/systems/{alias}/realms/{realm}` | add, replace or remove realm settings; operator (+ CSRF) |
| `GET /bff/api/systems/{alias}/client-setup` | the Keycloak client to create, as the admin API |
| `GET /bff/api/systems/{alias}/keycloak-realms` | the realms Keycloak lists for the system's service account |
| `POST /bff/api/systems/{alias}/adoption` | adopt realms; operator only (+ CSRF) |
| `DELETE /bff/api/systems/{alias}/adoption/{realm}` | give an adopted realm up (`?restrict=true` without an allowlist); operator only (+ CSRF) |
| `GET /bff/api/audit` | the audit trail, as `GET /admin/audit`; operator or viewer |
| `GET /bff/api/audit/{id}` | one event with its arguments, as `GET /admin/audit/{id}` |
| `GET /bff/api/audit/values/{field}` | completions for its filters, as `GET /admin/audit/values/{field}` |
| `POST /bff/check-session` | the session check above |
| `POST /bff/backchannel-logout` | for the identity provider, not the browser |

Browser requests carry `X-Requested-With: JavaScript`. With it, a request without a session answers 499 instead of a
redirect; writes are refused without it. Errors are `{"error": "<code>", "message": "..."}` like the admin API.
