# CIBA confirmation: destructive tools approved on the user's own device

Neither `confirm: true` nor elicitation proves that a human agreed to a destructive operation: the model writes the
first, the MCP client answers the second. This example asks the user directly instead, with OpenID Connect
**Client Initiated Backchannel Authentication (CIBA)**:

1. Before a destructive tool runs, the MCP server sends an authentication request for the signed-in user to Keycloak.
2. Keycloak delivers it to the user's device, naming the operation.
3. The user approves there by entering a number shown in the chat, and the tool runs. The model never touches
   that channel.

## How it works

```
MCP client ──(OAuth 2.1 / PKCE)──▶ Keycloak            alice logs in and consents to keycloak-mcp acting on her
   │                                                     behalf; her token opens the MCP server only
   │ tools/call keycloak_user_delete {id, username}                                   (first call)
   ▼
MCP server (Confirmer chain: ciba confirmer)
   │ 1. POST backchannel_authentication_endpoint        client mcp-ciba, login_hint=alice,
   │                                                     binding_message=kc-mcp-<hash of tool+realm+args>,
   │                                                     code=42, requester=<MCP client>, operation=Delete user (realm demo)
   │ 2. answers confirmation_required at once           "approve on your device, the device asks for the number 42"
   │ 3. Keycloak → authentication channel → the device  here: the "approver" at http://localhost:8095/, which shows
   │                                                     who asks for what and asks the user for the number
   │ tools/call keycloak_user_delete {id, username}                                   (second call)
   │ 4. poll token endpoint (grant urn:openid:params:grant-type:ciba): approved / declined / still pending / expired
   │        declined → cancelled; pending → call again
   │ 5. approved: token exchange, alice's token + the server's client keycloak-mcp
   │        → a delegated token (sub=alice, act=keycloak-mcp)
   ▼
Admin REST API with the delegated token                 → the user is deleted
```

- **Number matching**, as in Entra ID: the number is shown where the request starts (the chat) and asked for where
  it is approved (the device). A push the user did not trigger carries a number they cannot know, so approval
  fatigue does not help an attacker who holds a session.
- **Context on the device**: it shows the requester (the MCP client's name) and the operation with its target
  (`Delete user: dave (realm demo)`). Both are sent as additional CIBA request parameters, which Keycloak forwards.
- **Any CIBA provider**: the server uses only the standard flow (discovery, `backchannel_authentication_endpoint`,
  `login_hint`, `binding_message`, poll mode). Only the *authentication device* differs per provider: a bank's app,
  a push notification, a hardware token.
- **The device in this example** is the `approver` service. Keycloak's HTTP authentication channel POSTs each
  request to it. It is a small web app and a relying party of the same realm (public client `ciba-approver`, code
  flow with PKCE): users sign in, see only the requests meant for them, approve with the number or decline, and sign
  out again.

The MCP server is what CIBA calls the consumption device; it has no user-facing part in this flow.

**Whose token reaches the Admin API.** Not alice's own: the MCP specification forbids passing it through. The server
exchanges it at Keycloak for a delegated token for alice and the server's client `keycloak-mcp` (token exchange
delegation, a preview feature of Keycloak 26.8). Keycloak enforces alice's roles on it, and its events name both.
For this, the login at Keycloak ends with a consent page that asks *Allow keycloak-mcp to act on your behalf?*.
[Delegated authentication](../delegated-auth/README.md) explains the setup; the CIBA confirmation does not depend
on it.

## Start

```shell
cd examples/ciba-confirm
docker compose up -d        # Keycloak 26.8.2 on http://localhost:8098 (admin / admin), the approver on http://localhost:8095
```

The one-shot job `keycloak-init` then grants `keycloak-mcp` the permission to act for the realm's users
(`init/grant-delegation.sh`), which a realm import cannot carry.

Then run the MCP server on the host, in a second terminal:

```shell
./server.sh                 # env/ciba.env; MCP endpoint: http://localhost:8099/mcp
```

`server.sh` starts `quarkus:dev` with the settings of the env file and nothing else: `KC_MCP_*` and `QUARKUS_*` variables
the terminal still carries from another example are dropped, and none are exported into it. `./server.sh --jar` runs
the packaged server instead.

Or let compose run it from the packaged jar (`./mvnw package -DskipTests` first):

```shell
docker compose --profile mcp up -d --build
```

Users, all in realm `demo`:

| user | password | role |
|---|---|---|
| `alice` | `alice-demo` | realm admin |
| `carol` | `carol-demo` | `view-users` |
| `dave` | `dave-demo` | none |

## Run the demo

```shell
./demo.sh
```

| step | what happens |
|---|---|
| 1 | alice logs in and consents; `whoami` shows her as the caller and the delegation to `keycloak-mcp` |
| 2 | alice creates a throw-away user and asks to delete it. The first call answers `confirmation_required` with a number. Her device shows the request: a wrong number is refused, the right one approves. The second call deletes the user |
| 3 | the same with a decline: the second call answers `cancelled` and the user stays |
| 4 | carol, signed in to the device as herself, sees none of alice's requests and cannot decide them |
| 5 | `confirm: true` changes nothing: the request reaches the device all the same |

The script logs alice in to the MCP server once, the way an MCP client's browser does: it walks Keycloak's login
form and the consent page (`./mcp-call.py --login alice:alice-demo --print-token`) and uses that token for all
calls. It plays alice's device with an access token of the approver's client, the way the browser holds her session
there.
`./demo.sh --users=5` only creates five users with random names, so there is someone to delete.

## Try it yourself

After `demo.sh` the realm still holds the users whose deletion was declined (`temp-…`). Delete one yourself and
approve it in the browser:

1. Open <http://localhost:8095/> and sign in as `alice` / `alice-demo`. This is alice's device.
2. Find a user to delete:

   ```shell
   ./mcp-call.py --login alice:alice-demo keycloak_user_search '{"search": "temp-"}' | jq -c '.items[] | {username, id}'
   ```

3. Ask to delete it. The answer is `confirmation_required` with the number, here 22:

   ```shell
   ./mcp-call.py --login alice:alice-demo keycloak_user_delete '{"id": "<id>", "username": "<username>"}'
   ```

   ```
   "message": "'Delete user: temp-aaf5627a (realm demo)' needs alice's approval on their device: ...
               The device asks for the number 22.",
   ```

4. The request appears on the page. Enter the number and approve, or decline.
5. Run the same command again. It deletes the user, or answers `cancelled` if you declined. Started before you
   decide, it waits up to 25 s for your decision.

Variations:

- Enter a wrong number: the page refuses it, and the request stays pending.
- Wait more than 90 s before deciding: the next call reports that the request expired, and the one after that
  files a new request.
- Sign in to the page as `carol`: alice's requests do not show up.
- Add `"confirm": true` to the arguments: it changes nothing.
- "Sign out" ends the session on the page and at Keycloak.

`mcp-call.py` keeps the MCP session between runs, as a real client does, because an approval belongs to the session
that asked for it. `--new-session` starts over. `--login` walks Keycloak's login form and consent page on each run
and prints what the consent page asked for; the password grant is not available, because a client that requires
consent refuses it. To log in once for several calls:

```shell
TOKEN=$(./mcp-call.py --login alice:alice-demo --print-token)
./mcp-call.py --token "$TOKEN" whoami
```

### With an MCP client

LM Studio or another OAuth-capable client:

1. Add `mcp-oauth.json` and log in as `alice` / `alice-demo`. Keycloak asks whether `keycloak-mcp` may act on your
   behalf; say yes.
2. Ask it to delete a user (`./demo.sh --users=3` creates some).
3. Approve or decline on the device page, signed in as alice. The model's answer names the binding message and the
   number, so you can tell which request belongs to which operation.

The model calls the tool again at once, and that call waits up to 25 s (`KC_MCP_SPI_CONFIRMER_CIBA_POLL_WAIT_SECONDS`)
for your decision, so you need not write in the chat. A small model may still stop and ask; then say "done".

## Management UI

`env/ciba.env` also turns the [management UI](../../docs/management-ui.md) on: <http://localhost:8099/ui/>, sign in as
`alice` / `alice-demo`. *Systems* shows the system and its realm, *Audit* the tool calls of the demo, the declined and the approved deletions among them.

It runs without HTTPS in dev mode (`KC_MCP_DEV_MODE=true`: the session cookie drops `Secure`, for one person's
machine only) and keeps its sessions and the audit trail in an H2 file under `data/` (git-ignored). The server
therefore has to be the default H2 build, not a `-Ppostgresql` one. The realm's public client `keycloak-mcp-ui` signs
people in; `carol` reaches the login but not the API, which asks for `realm-admin`.

## What to look at

| where | what |
|---|---|
| `env/ciba.env` | `KC_MCP_SPI_CONFIRMER_CIBA_*`: client, timeout, `when`, `login-hint`, `client-auth`, `flow`, `number-matching`. `KC_MCP_CONFIRM_FALLBACK=deny`, so a client without elicitation cannot fall back to `confirm: true`. `KC_MCP_DELEGATION=exchange` with the server's client `keycloak-mcp`, and the delegation scope in `QUARKUS_OIDC_RESOURCE_METADATA_SCOPES` |
| `realms/demo-realm.json` | the realm's CIBA policy (`cibaInterval`, `cibaExpiresIn`, `login_hint` as the user hint); the confidential client `mcp-ciba` with `oidc.ciba.grant.enabled`; the public client `mcp-consumer` with consent, whose tokens carry `aud=keycloak-mcp`; the server's client `keycloak-mcp` and its role scope (`clientScopeMappings`); the public client `ciba-approver` the device signs its users in with |
| `docker-compose.yml` | Keycloak's `--spi-ciba-auth-channel--ciba-http-auth-channel--http-authentication-channel-uri`, pointing at the approver; the preview features `token-exchange-delegation` and `parameterized-scopes`; the job `keycloak-init` |
| `approver/Approver.java` | the device, plain JDK, no build (below) |
| the server log | `CIBA request …<id> for alice: keycloak_user_delete realm demo (binding message kc-mcp-…, code 42, up to 90 s)`, then `approved by alice` or `declined by alice`, then the audit line of the tool call |

**The approver.** Its contract with Keycloak: answer the request with `201`, later `POST {"status": "SUCCEED" |
"CANCELLED"}` with Keycloak's bearer token to `/realms/demo/protocol/openid-connect/ext/ciba/auth/callback`.

- It reads `code`, `requester` and `operation` from the request: Keycloak forwards additional CIBA request
  parameters as top-level JSON fields.
- It shows a request only to the signed-in user it names (`login_hint` = username or email), and refuses an
  approval whose number does not match.
- It learns who the user is from the `userinfo` endpoint, after the code exchange in the browser or for a bearer
  token in scripts: `GET /pending`, `POST /approve/{id|latest}?code=NN`, `POST /decline/{id|latest}`,
  `POST /decline-all`, `POST /history/clear`.
- The page lists requests newest first, with "Decline all" above several pending ones and "Clear" above the
  decided ones.

## Beyond the demo

- **Other providers.** Point `KC_MCP_SPI_CONFIRMER_CIBA_ISSUER` at the provider, or leave `caller` to follow the
  issuer of the caller's token. Register a confidential CIBA client there.
  - In a container that reaches the provider at an internal URL, set that URL as the issuer and the public one as
    `TOKEN_ISSUER`, as `docker-compose.yml` does.
  - `client-auth=client_secret_post` for providers that do not take HTTP Basic.
  - `login-hint`: the claim the provider resolves users by (`email`, `sub`, ...).
  - `requested-expiry=true` asks the provider to keep the request as long as the server waits.
  - `binding-message=false` drops the message for providers that reject it.
- **Clients with elicitation.** `KC_MCP_SPI_CONFIRMER_CIBA_WHEN=without-elicitation` keeps CIBA for clients that
  cannot ask the human, and lets the others (Claude Desktop, ...) ask in the chat.
- **Several MCP server instances.** Turn the database storage on (`QUARKUS_DATASOURCE_JDBC_URL`, PostgreSQL build).
  Pending approvals then live in `kc_mcp_pending_approval`, and the second call may reach any instance. This example
  runs one instance with the in-memory store.
- **One call instead of two.** `KC_MCP_SPI_CONFIRMER_CIBA_FLOW=blocking` makes the tool call wait for the device.
  Simpler for scripts, but the chat shows nothing while waiting, so there is no number to match (`number-matching`
  only applies to the two-step flow).
- **Simple devices.** Devices that cannot show additional parameters still get the binding message;
  `extra-parameters=false` stops sending them.
- **Which tools.** Only DESTRUCTIVE tools are confirmed; `keycloak_realm_update` and `keycloak_auth_flow_bind` count
  as such. Other `Confirmer`s (a change ticket check, see `examples/extensions`) run before this one and may confirm
  or decline first.
