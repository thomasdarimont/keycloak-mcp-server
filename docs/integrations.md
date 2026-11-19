# Integrations: connecting MCP clients

[keycloak-mcp-server](../README.md) › documentation

How to add the server to LM Studio, Claude Code, Claude Desktop, VS Code with GitHub Copilot, Cursor and the Codex CLI,
and what the login needs on the Keycloak side. The server speaks streamable HTTP at `/mcp`; a client bound to one
system or realm uses `/mcp/systems/<system>[/<realm>]` instead ([Several Keycloak systems](systems.md)).

Two cases run through every client:

- **No login** (`local` profile, the server holds a service account): the client only needs the URL.
- **Login** (`KC_MCP_MCP_OAUTH_ENABLED=true`, with `KC_MCP_DELEGATION=exchange` or `KC_MCP_REQUIRE_CALLER=true`): the server answers 401
  with a `resource_metadata` link, the client reads the protected resource metadata, finds the realm and logs the user
  in with authorization code and PKCE in the browser. The client needs an OAuth client at Keycloak, `mcp-consumer` in
  the examples, and Keycloak needs the client's callback address.

Tested with this server: LM Studio. The other clients follow their own documentation and have not been run against
this server yet; their callback addresses below are what they document.

## LM Studio

`mcp.json` (Program → Install → Edit mcp.json), without login:

```json
{ "mcpServers": { "keycloak": { "url": "http://localhost:8081/mcp" } } }
```

With login, name the pre-registered client (`examples/run-modes/mcp-oauth.json`):

```json
{ "mcpServers": { "keycloak": { "url": "http://localhost:8081/mcp", "auth": { "CLIENT_ID": "mcp-consumer" } } } }
```

LM Studio opens the browser on connect. Its callback is fixed: `http://127.0.0.1:33389/mcp-oauth-callback`. Without
the `auth` block it tries dynamic client registration. The CIBA two-step flow works: the model shows the number, calls
again and waits for the decision ([CIBA confirmation](ciba-confirmation.md)). If the login once worked and then
fails after the realm changed, remove the server and add it again; LM Studio keeps the old token.
A complete setup with login, run from the packaged distribution, is `examples/distribution/`.

## Claude Code

Without login:

```shell
claude mcp add --transport http keycloak http://localhost:8081/mcp
```

With login, name the client and fix the callback port, then start the login with `/mcp` inside a session:

```shell
claude mcp add --transport http --client-id mcp-consumer --callback-port 33418 keycloak http://localhost:8081/mcp
```

The callback is `http://localhost:<port>/callback`. `-s project` writes the entry to `.mcp.json` for the whole
repository. `claude mcp list` and `/mcp` show the state; `/mcp` also clears a stale login.

Claude Code requests `offline_access` along with the scopes the server advertises, so the client needs that scope as
well, and the user the `offline_access` role ([The Keycloak side of the login](#the-keycloak-side-of-the-login)).

## Claude Desktop and claude.ai

Custom connectors (Settings → Connectors → Add custom connector) are reached from Anthropic's cloud, not from the
machine Claude Desktop runs on, so `localhost` does not work. The server and Keycloak need a public HTTPS address
(`shared` profile, see [Security](security.md)). The connector's callback is `https://claude.ai/api/mcp/auth_callback`.
The dialog offers to register the client automatically (dynamic client registration) or to use a client ID you
registered; the authentication settings cannot be changed afterwards, remove and re-add the connector instead.
Documentation: <https://claude.com/docs/connectors/custom/remote-mcp>.

For a local server, a stdio bridge such as `mcp-remote` in `claude_desktop_config.json` forwards to the HTTP endpoint
and runs the login itself, with its own callback (`http://localhost:<port>/oauth/callback`). Keep such bridges current;
`mcp-remote` had a critical vulnerability in 2025.

## VS Code and GitHub Copilot

`.vscode/mcp.json` in the workspace (or the user profile's `mcp.json`):

```json
{ "servers": { "keycloak": { "type": "http", "url": "http://localhost:8081/mcp" } } }
```

With login, VS Code first tries dynamic client registration and otherwise asks for a client ID and secret when the
server is started; for the demo realms enter `mcp-consumer` and leave the secret empty (public client). Register both
callbacks on the client, the loopback one with its trailing slash: `http://127.0.0.1:33418/` (or `http://127.0.0.1/`
for any port) and `https://vscode.dev/redirect`. The demo realms of `run-modes`, `distribution` and `ciba-confirm`
register both. A bearer token can also be passed as an `Authorization`
header through an input variable. Documentation: <https://code.visualstudio.com/api/extension-guides/ai/mcp>.

A Keycloak with the experimental `cimd` feature needs no client for VS Code at all: `examples/cimd-vscode/`.

## Cursor

`~/.cursor/mcp.json` for the user or `.cursor/mcp.json` in the project:

```json
{ "mcpServers": { "keycloak": { "url": "http://localhost:8081/mcp" } } }
```

With login, Cursor discovers the realm from the resource metadata and opens the browser; a pre-registered client goes
into an `auth` block like LM Studio's (`"auth": { "CLIENT_ID": "mcp-consumer" }`). Callbacks: `http://localhost:8787/callback`
for the desktop app, `https://www.cursor.com/agents/mcp/oauth/callback` for the web and cloud agents.
Documentation: <https://cursor.com/docs/mcp>.

## Codex CLI

```shell
codex mcp add keycloak --url http://localhost:8081/mcp
codex mcp login keycloak          # with login: opens the browser, keeps the tokens in the keychain
```

The entry lands in `~/.codex/config.toml` as `[mcp_servers.keycloak]` with `url`; a bearer token can come from an
environment variable instead (`bearer_token_env_var`). The callback uses a random port by default; a provider that
needs a fixed one gets `mcp_oauth_callback_url = "http://localhost:8432/oauth/callback"` at the top level of the file,
and that URL goes on the Keycloak client.

## Scripts and curl

`examples/run-modes/prompt.sh` fetches a rendered prompt; the examples' `mcp-call.py` logs a user in with the password
grant of `mcp-consumer` (enabled for the demos only) and calls a tool:

```shell
examples/ciba-confirm/mcp-call.py --login alice:alice-demo whoami
```

Without login, any HTTP client works: `POST /mcp` with `Accept: application/json, text/event-stream` and a JSON-RPC
body; the `Mcp-Session-Id` header of the `initialize` answer goes on every later request.

## The Keycloak side of the login

- **The client.** A public client with PKCE, `mcp-consumer` in the demo realms, holding an *Audience* mapper that adds
  the server's audience (`aud=mcp-admin`, what `KC_MCP_MCP_OAUTH_AUDIENCE` requires) and the `kc-admin-api` client
  scope (Keycloak 26.8.2+ checks it for Admin API tokens). The humans carry the `realm-management` roles, groups
  preferred. `KC_MCP_DELEGATION=exchange` also needs consent on the client and the delegation scope
  ([Security](security.md#callers), `examples/delegated-auth/`).
- **Callbacks.** Every client's callback must be a redirect URI of that client. The demo realms register LM Studio's,
  most also Claude Code's, Codex's and VS Code's; add the ones you use from the sections above. For a loopback callback (`127.0.0.1`, `localhost`) Keycloak ignores
  the port when the registered URI has none, host and path still have to match: `http://localhost/callback` covers
  Claude Code's variable port and `http://localhost/oauth/callback` Codex's, with the path pinned. `127.0.0.1` and
  `localhost` are different hosts to Keycloak, so register the one the client uses. `*` is allowed only at the end of
  a pattern.
- **Dynamic client registration.** Clients without a configured client ID try to register one. Keycloak's anonymous
  registration policies (trusted hosts) usually refuse that, and a pre-registered client keeps the audience mapper and
  redirect URIs under control. Name the client in the MCP client's configuration instead.
- **Client ID Metadata Documents.** With `--features=cimd` and a client policy, a client's published metadata URL is
  its `client_id` and Keycloak creates the client at first use. Such a client gets realm-level scopes only and no roles
  unless a scope maps them (`examples/cimd-vscode/`).
- **Scopes.** Clients ask for what the protected resource metadata lists (`KC_MCP_MCP_OAUTH_RESOURCE_METADATA_SCOPES`,
  default the admin API scope); every listed scope must exist on the client, or Keycloak answers `invalid_scope`.
  Claude Code also requests `offline_access`: assign it to the client as an optional scope, as the demo realms do. The
  user needs the realm role `offline_access` too, or the token request answers `not_allowed`. It is part of the realm's
  default roles, which users from a realm import only get if their `realmRoles` name `default-roles-<realm>`.
- **Internal addresses.** When the server reaches Keycloak as `http://keycloak:8080` (Docker), set
  `KC_MCP_MCP_OAUTH_TOKEN_ISSUER` and `KC_MCP_MCP_OAUTH_RESOURCE_METADATA_AUTHORIZATION_SERVER` to the public realm URL,
  otherwise the browser is sent to `keycloak:8080` ([Configuration](configuration.md)).

## When the login fails

1. `curl -s http://localhost:8081/.well-known/oauth-protected-resource`: `authorization_servers` must be the public
   realm URL the browser can reach, `scopes_supported` what the client may ask for. A per-system entry whose login
   realm is not the default one has its own document at the well-known path plus the entry's path, for example
   `/.well-known/oauth-protected-resource/mcp/systems/acme`; the 401 of the entry names it.
2. Keycloak's admin console events (`LOGIN_ERROR`): `invalid_redirect_uri` means the client's callback is missing,
   `invalid_scope` a scope from `scopes_supported` the client lacks, or `offline_access`. The message `Invalid scopes:`
   repeats everything the client requested, so the scopes it names are not all at fault.
3. 401 after a successful login: wrong audience (the mapper, `KC_MCP_MCP_OAUTH_AUDIENCE`) or issuer mismatch
   (`KC_MCP_MCP_OAUTH_TOKEN_ISSUER`).
4. After changing the realm, clear the client's stored login: LM Studio by removing and re-adding the server, Claude
   Code in `/mcp`, Codex with `codex mcp logout`.
