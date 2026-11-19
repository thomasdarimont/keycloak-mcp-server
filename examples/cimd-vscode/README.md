# VS Code without a pre-registered client (CIMD)

The realm has no OAuth client for VS Code. VS Code uses the URL of its published metadata document as its `client_id` via CIMD
([Client ID Metadata Documents](https://client.dev/)), Keycloak fetches that document and creates the client on first
use. Keycloak's guide: [Integrating with MCP](https://www.keycloak.org/securing-apps/mcp-authz-server).

The user consents to the MCP server's client `keycloak-mcp` acting on their behalf, and the server exchanges the
user's token for a delegated one before it calls the Admin API (`KC_MCP_DELEGATION=exchange`, Keycloak's token
exchange delegation, preview). [delegated-auth](../delegated-auth/) explains that part in detail.

CIMD is an experimental Keycloak feature (`--features=cimd`) and the specification is still a draft. Keycloak fetches
`https://vscode.dev/oauth/client-metadata.json`, so its container needs internet access.

## Start

```shell
cd examples/cimd-vscode
../../etc/mkcert.sh                 # once: a trusted certificate for localhost in .certs/, its CA in the trust stores
docker compose up -d --wait         # Keycloak 26.8.2 on https://localhost:8100 (admin / admin)
docker compose logs keycloak-init   # the init job grants keycloak-mcp the permission to act for users
../../mvnw -f ../../pom.xml package -DskipTests
set -a; . env/cimd.env; set +a
java -jar ../../modules/backend/target/quarkus-app/quarkus-run.jar start     # the MCP server on http://localhost:8101
```

`.vscode/mcp.json`, with no client ID or secret:

```json
{ "servers": { "keycloak": { "type": "http", "url": "http://localhost:8101/mcp" } } }
```

Start the server in VS Code and choose to authenticate. The browser opens Keycloak's login page at
`https://localhost:8100`; sign in as one of these users and accept the consent screen, which asks *Allow keycloak-mcp
to act on your behalf?*:

| user | password | can |
|---|---|---|
| `alice` | `alice-demo` | everything in the realm (`realm-admin`) |
| `carol` | `carol-demo` | read users (`view-users`) |
| `dave` | `dave-demo` | reach the server; every Admin API tool is forbidden |

The tool `whoami` shows `delegation: {mode: exchange, consented: true, actor: keycloak-mcp}`.

Once signed in, ask the chat about the realm, for example *list users in the demo realm on keycloak*:

![VS Code chat listing the users of the demo realm](vscode-chat-demo.png)

If no Keycloak page opens, VS Code is not logging in to Keycloak: a prompt can also be for its GitHub account. Check
`Failed to create MCP auth provider` in the Window log. The server's log shows tool calls only, so a client that has
not logged in leaves no entries.

`docker compose down -v` resets everything. After a reset, clear VS Code's stored login for the server.

## Management UI

`env/cimd.env` also turns the [management UI](../../docs/management-ui.md) on, over HTTPS with the mkcert
certificate: <https://localhost:8443/ui/>, sign in as `alice` / `alice-demo`. *Systems* shows the system and its
realm, *Audit* the tool calls VS Code made.

Plain HTTP is not an option here. Keycloak on `https://localhost:8100` sends `Strict-Transport-Security`, after
which a browser opens every `http://localhost` address with HTTPS. Sessions and the audit trail live in an H2 file
under `data/` (git-ignored), so the server has to be the default H2 build, not a `-Ppostgresql` one.

## Why HTTPS

VS Code can read the login server's metadata from its window, whose content security policy allows `https:` but not
`http:`. Keycloak on plain `http://localhost` then fails with `Failed to fetch authorization server metadata from all
attempted URLs`, and no login starts. The MCP server itself can stay on plain HTTP here. The JVM running it needs
mkcert's CA in its trust store: `etc/mkcert.sh` adds it to the JDK named by `JAVA_HOME` when it runs.

## What is configured

**`realms/demo-realm.json`** has an executor and a policy for CIMD under `clientProfiles` and `clientPolicies`:

- The `client-id-uri` condition matches `https` client IDs on `vscode.dev`.
- The `client-id-metadata-document` executor accepts documents whose URLs are on `vscode.dev`,
  `code.visualstudio.com` and `127.0.0.1`. *Restrict same domain* is off because VS Code's loopback redirect is on
  another host than its document.

A client ID from any other domain is refused, `client_not_found` in Keycloak's events. For other clients, add their
domains to both lists; the guide lists the values for Claude Code and Claude Desktop.

The realm file also has the one client the example needs, **`keycloak-mcp`**, which is the MCP server itself: a
confidential client (`keycloak-mcp-secret`) with a service account that holds no admin role, *Standard Token Exchange*
on, and *Full scope allowed* off with the role scope `realm-management` `realm-admin` (`clientScopeMappings`). The
role scope is the most a delegated token may carry. *Admin Permissions* are enabled for the realm.

**`init/grant-delegation.sh`**, run by the `keycloak-init` job, grants `keycloak-mcp` the Admin Permission *delegate*
on the Users resource type. A realm import cannot carry it. Without it Keycloak drops the delegation scope silently
and the token carries no `may_act` claim.

A client created from a document needs nothing else. It gets the realm's default and optional scopes, and with the
features `token-exchange-delegation` and `parameterized-scopes` on, `delegation:client` is one of the realm's optional
scopes:

| scope | gives the token | without it |
|---|---|---|
| `delegation:client:keycloak-mcp` | `aud=keycloak-mcp` and `may_act` naming `keycloak-mcp` | the MCP server answers 401 |

The server advertises `openid` and that scope in its protected resource metadata
(`QUARKUS_OIDC_RESOURCE_METADATA_SCOPES`), and VS Code asks for what is advertised. The user's token carries no roles
and no Admin API audience, it opens the MCP server only. The server (`env/cimd.env`) logs in as `keycloak-mcp` and
exchanges the user's token for a delegated one: `sub` is the user, `act` is `keycloak-mcp`, the roles are the user's
`realm-management` roles within the role scope of `keycloak-mcp`. Admin events name the user.

## Three things that differ from a pre-registered client

- **No roles by default.** Keycloak creates these clients with `fullScopeAllowed=false`, so tokens carry no roles
  until a client scope maps them. This example does not need them: the roles come with the delegated token.
- **Consent is always on.** Keycloak creates these clients with *Consent required*, which is what the delegation scope
  demands: on a client without consent Keycloak refuses it with `invalid_scope`. It asks for the delegation in every
  login session and does not store that consent.
- **The clients persist.** The first login creates a real client whose `clientId` is the URL. Tightening the policy
  later does not remove it; delete it in the admin console.

## Why not resource indicators

MCP clients send `resource=<server URL>`. With Keycloak's `resource-indicators` feature on, `aud` is reduced to that
value, here `http://localhost:8101`. The token still carries `may_act`, but it no longer names `keycloak-mcp` in
`aud`, and Keycloak 26.8.2 then refuses the token exchange: `access_denied: Client is not within the token audience`.
This example leaves the feature off, so Keycloak ignores `resource` and the audience comes from the delegation scope.

MCP 2025-06-18 and later require resource indicators of the authorization server, so this is a deliberate departure.
With the feature on, the `client-id-metadata-document` executor also needs the server's URL in its *resource
indicator allow list* (`cimd-resource-indicator-allow-list`); otherwise the login ends with `invalid_target`.

## Limits

- Not a template for production: `start-dev`, a local CA, an MCP server on plain HTTP and demo passwords.
- Anyone can publish a document, so keep the trusted domains narrow: VS Code's document says nothing about who runs it,
  and the loopback redirect fits any local program. The user's consent and roles are the protection here.
- The login, the consent and the tool calls were tested by scripting VS Code's authorization code flow with PKCE, its
  real client ID and redirect URI, and the scopes the server advertises. That script is not subject to VS Code's
  content security policy, and it does not show whether VS Code asks for a scope with a parameter as advertised.
