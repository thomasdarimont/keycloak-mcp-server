# CIBA confirmation: approval on the user's device

[keycloak-mcp-server](../README.md) › documentation

A destructive tool runs only after the caller approved it on their own device. Off by default; `examples/ciba-confirm/`
runs the whole thing.

## Why

The two usual ways to confirm a destructive tool prove little. `confirm: true` is written by the model. An elicitation
prompt is answered by the MCP client, and nothing says a human saw it. Both leave the decision inside the channel the
model controls.

The built-in `ciba` confirmer moves the decision out of that channel. Before a destructive tool runs, the server files
an authentication request for the signed-in user with the OpenID provider (OpenID Connect Client Initiated
Backchannel Authentication, CIBA). The provider delivers it to the user's device, the device shows who asks for what,
and the tool runs once the user approves there. Neither the model nor the MCP client takes part in that exchange.

## CIBA in one picture

CIBA separates the device a transaction starts on from the device the user approves it on. The client asks the
authorization server over a back channel; no browser redirect connects the two devices. The server uses poll mode,
the one of CIBA's three delivery modes that needs nothing reachable on the client's side (in ping and push mode the
authorization server calls the client).

```mermaid
sequenceDiagram
    autonumber
    participant C as Consumption device
    participant R as Client
    participant A as Authorization server
    participant D as Authentication device
    C->>R: the user starts a transaction
    rect rgba(127,127,127,0.10)
    R->>A: backchannel authentication request:<br/>scope openid, login_hint, binding_message
    A-->>R: acknowledgment: auth_req_id, expires_in, interval
    end
    rect rgba(127,127,127,0.10)
    A->>D: asks the user, out of band
    D-->>A: the user approves or declines
    end
    rect rgba(127,127,127,0.10)
    loop every interval seconds, until decided or expired
        R->>A: token request: grant type ciba, auth_req_id
        A-->>R: authorization_pending
    end
    A-->>R: tokens of the user, or access_denied / expired_token
    end
    R-->>C: the transaction runs, or does not
```

| CIBA's role | here |
|---|---|
| consumption device | the MCP client: the chat the model runs in, where the user asked for the operation |
| client | keycloak-mcp-server, with a confidential client of its own for CIBA |
| authorization server | the OpenID provider that knows the user: Keycloak in the example |
| authentication device | whatever the provider reaches the user on: a phone app, a push notification; the `approver` web app in the example |

Two things differ from the textbook use. The server does not want the tokens for anything: an ID token coming back
is the proof that this user approved, and the tool then runs with the token it would have used without CIBA. And the
request says what is to be approved, through the `binding_message` and the additional parameters `code`, `requester`
and `operation`.

More on the flow itself: [OpenID Connect CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html),
[Curity: CIBA flow](https://curity.io/resources/learn/ciba-flow/).

## How a call goes

```mermaid
sequenceDiagram
    autonumber
    actor U as alice
    participant M as Model / MCP client
    participant S as keycloak-mcp-server
    participant K as Keycloak
    participant D as alice's device
    U->>M: "delete the user dave"
    rect rgba(127,127,127,0.10)
    M->>S: first call: keycloak_user_delete dave
    S->>K: Admin REST API: who is dave?
    S->>K: backchannel authentication request: login_hint alice,<br/>binding_message, code 42, requester, operation
    K-->>S: auth_req_id
    S-->>M: confirmation_required: status requested, code 42, howTo
    M-->>U: "approve on your device and enter 42"
    end
    rect rgba(127,127,127,0.10)
    K->>D: Delete user: dave (realm demo), requested by LM Studio
    U->>D: enters 42, approves
    D-->>K: approved
    end
    rect rgba(127,127,127,0.10)
    M->>S: second call: keycloak_user_delete dave, same arguments
    loop up to poll-wait-seconds
        S->>K: token request: auth_req_id
        K-->>S: authorization_pending
    end
    K-->>S: ID token of alice
    S->>S: verifies the ID token: it is alice, for this operation
    S->>K: Admin REST API: delete dave
    S-->>M: deleted
    end
```

The default is the two-step flow:

1. **The first call files the request.** The server sends a CIBA authentication request to the provider for the
   caller: `login_hint` is their username (or the claim named by `login-hint`), `binding_message` is
   `<prefix>-<hash>` over tool, system, realm and arguments, and three additional parameters tell the device what is
   going on: `code`, a two-digit number; `requester`, the MCP client's name; and `operation`, for example
   `Delete user: dave (realm demo)`, with the system named when the server has several. The target is the name
   Keycloak has for what the call acts on, looked up before the request is filed, not the argument the model sent
   ([Confirming destructive tools](security.md#confirming-destructive-tools)). The call answers
   `confirmation_required` at once with `approval: {status: requested, code, bindingMessage, expiresInSeconds}` and a
   `howTo` for the model.
2. **The model shows the number and calls again.** The `howTo` tells it to have the user approve on their device and
   enter the number, and to call again right away with the same arguments, without waiting for a reply.
3. **The device asks the user.** It shows the requester, the operation and the binding message, and asks for the
   number. The user approves or declines.
4. **The second call collects the decision.** It waits up to `poll-wait-seconds` for the device, polling the
   provider's token endpoint. Approved: the tool runs and the call answers like a direct one. Declined: `cancelled`.
   Still waiting: `confirmation_required` with `status: pending`, so the model calls again. Expired: `status: expired`,
   nothing was changed, and the next call files a new request.

The number works like Entra ID's number matching. It is shown where the request originates, the chat, and asked for
where it is approved, the device. A request the user did not trigger carries a number they cannot know, so approval
fatigue does not help someone who holds a stolen session.

**Blocking flow.** `flow=blocking` waits for the device inside the first call instead. There is no number, because
nothing could show it while the call waits. A request without an MCP session (no `Mcp-Session-Id`) always takes this
path, since nothing would tie a second call to the first.

## The requests and responses

What goes over the wire in the picture above, with the example's realm (`examples/ciba-confirm/`). The exchanges
with Keycloak were recorded against Keycloak 26.8.2; long tokens are cut.

**1. The first call, and what the MCP client gets back.** An ordinary `tools/call`; the answer is the tool's result:

```json
{
  "error": "confirmation_required",
  "message": "'Delete user: dave (realm demo)' needs alice's approval on their device: a request (binding message kc-mcp-3f9a1c27b4) was sent. The device asks for the number given in approval.code.",
  "approval": {
    "status": "requested",
    "user": "alice",
    "bindingMessage": "kc-mcp-3f9a1c27b4",
    "code": "42",
    "expiresInSeconds": 90
  },
  "howTo": "Tell the user now to approve the request on their device and to enter the number 42 there. Then, without waiting for a reply, call this tool again with the same arguments: ..."
}
```

The number is in `approval.code` and `howTo` only, not in `message`: the message is what the audit trail keeps.

**2. The backchannel authentication request.** The server to the provider's `backchannel_authentication_endpoint`
(from its discovery document), as the confidential client of the confirmer. `requested_expiry` and `acr_values` are
added when configured. The body is one line, wrapped here:

```http
POST /realms/demo/protocol/openid-connect/ext/ciba/auth HTTP/1.1
Host: localhost:8098
Authorization: Basic bWNwLWNpYmE6bWNwLWNpYmEtc2VjcmV0
Content-Type: application/x-www-form-urlencoded

scope=openid&login_hint=alice&code=42&requester=LM+Studio
&operation=Delete+user%3A+dave+%28realm+demo%29&binding_message=kc-mcp-3f9a1c27b4
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"auth_req_id": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0..8v78pEf3...", "expires_in": 120, "interval": 2}
```

The server keeps the `auth_req_id` with the pending approval, encrypted when the database storage is on. It never
reaches the MCP client.

**3. Keycloak to the device.** Not part of CIBA, which leaves this leg to the provider. Keycloak's HTTP
authentication channel posts the request to the configured URL, with the additional parameters next to the standard
ones and a bearer token the device answers with:

```http
POST /auth HTTP/1.1
Host: approver:8095
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6...
Content-Type: application/json

{
  "scope": "openid profile roles email",
  "binding_message": "kc-mcp-3f9a1c27b4",
  "login_hint": "alice",
  "is_consent_required": false,
  "requester": "LM Studio",
  "code": "42",
  "operation": "Delete user: dave (realm demo)"
}
```

The device answers `201 Created` at once and reports the user's decision later, with that bearer token:

```http
POST /realms/demo/protocol/openid-connect/ext/ciba/auth/callback HTTP/1.1
Host: keycloak:8080
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6...
Content-Type: application/json

{"status": "SUCCEED"}
```

`CANCELLED` declines. Checking the number is the device's job: the example's approver compares what the user
entered with `code` before it answers `SUCCEED`.

**4. The token request.** The second call polls the provider's `token_endpoint`, no more often than `interval`
allows:

```http
POST /realms/demo/protocol/openid-connect/token HTTP/1.1
Host: localhost:8098
Authorization: Basic bWNwLWNpYmE6bWNwLWNpYmEtc2VjcmV0
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aopenid%3Aparams%3Agrant-type%3Aciba&auth_req_id=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0..8v78pEf3...
```

| the provider answers | meaning | what the tool call answers |
|---|---|---|
| `400` `{"error": "authorization_pending", "error_description": "The authorization request is still pending as the end-user hasn't yet been authenticated."}` | the user has not decided | it keeps polling up to `poll-wait-seconds`, then `confirmation_required` with `status: pending` |
| `400` `{"error": "slow_down", "error_description": "too early to access"}` | polled sooner than `interval` | it waits longer before the next poll |
| `400` `{"error": "access_denied", "error_description": "not authorized"}` | the user declined | `cancelled`, nothing was changed |
| `400` `{"error": "expired_token", ...}` or `{"error": "invalid_grant", "error_description": "Invalid auth_req_id"}` | the request ran out, or was redeemed before | `confirmation_required` with `status: expired`; the next call files a new request |
| `200` with tokens | the user approved | the tool runs |

The approval:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "access_token": "eyJ...",
  "expires_in": 1800,
  "refresh_expires_in": 1800,
  "refresh_token": "eyJ...",
  "token_type": "Bearer",
  "id_token": "eyJ...",
  "not-before-policy": 0,
  "session_state": "85apwVtexx6ZrchEQ75woYYf",
  "scope": "openid profile email"
}
```

Of these the server reads the `id_token` and nothing else. Its claims say who approved:

```json
{
  "iss": "http://localhost:8098/realms/demo",
  "aud": "mcp-ciba",
  "azp": "mcp-ciba",
  "sub": "9a61d85c-e177-49fe-a9e1-5c5b294762ef",
  "preferred_username": "alice",
  "auth_time": 1795099979,
  "iat": 1795099979,
  "exp": 1795101779,
  "typ": "ID"
}
```

The server verifies the signature against the provider's keys, the issuer, its CIBA client as audience and the
expiry, and that `sub` is the caller of the tool ([What makes the approval trustworthy](#what-makes-the-approval-trustworthy)).
Only then does the tool run, and the second call answers like a direct one. An `auth_req_id` is good for one
approval: Keycloak answers `invalid_grant` when it is presented again.

## Any CIBA provider

The confirmer uses the standard flow only: discovery, the backchannel authentication endpoint, `login_hint`,
`binding_message` and poll mode. What differs per provider is the device side: a bank's app, a push notification, a
hardware token. Keycloak ships an HTTP authentication channel that posts each request to a URL of your choice and
forwards up to five additional parameters; the example's `approver` is such a URL, a small web app standing in for the
device. Keycloak allows 50 characters without spaces in the binding message.

## What makes the approval trustworthy

- **Bound to the full operation.** The approval's key is a SHA-256 over the MCP session, the caller, the issuer and
  the hash of tool, system, realm and arguments. The stored approval carries that hash, and the collecting call must
  match it. The device's binding message shows a 40-bit prefix of it, for people to compare.
- **One approval per session and operation.** The entry is reserved atomically in the `PendingApprovalStore` with an
  opaque generation that every later change names. A late filer whose reservation expired cannot overwrite the next
  one, and an old generation cannot be consumed. One collector at a time holds a short claim and polls the provider;
  parallel calls answer `pending` without polling. The claim is renewed before every poll and lasts the read timeout
  plus a margin, so it cannot run out during a slow poll. An approval the provider confirmed is recorded for its
  generation before it is consumed, so a collector that stalls afterwards cannot lose it. A decision is consumed once.
- **Who approved is verified.** The ID token the token endpoint returns on approval must verify against the
  provider's JWKS: signature, issuer, the CIBA client as audience, expiry. Its identity must be the person asked: the
  same `sub` as the MCP caller when their token comes from the same issuer, else the username or email of the login
  hint. Anything else answers `cancelled` with the reason and confirms nothing.
- **Nothing falls back to the model.** The confirmer refuses to start unless callers are required
  (`kc-mcp.mcp.require-caller`, a delegation mode or the `shared` profile). An anonymous or unaddressable caller gets
  `confirmation_required`, never the default confirmer's `confirm: true`. The one deliberate hand-over is
  `when=without-elicitation`, which leaves the question to clients that can ask the human themselves.
- **Several instances.** With the [database storage](storage.md) on, pending approvals live in
  `kc_mcp_pending_approval` (approval store `db`, the `auth_req_id` encrypted under the storage key, purged hourly),
  so the collecting call may reach any instance. Without the storage the in-memory store `memory-approvals` serves a single instance.

## Setup

On the Keycloak side, as in `examples/ciba-confirm/realms/demo-realm.json`:

- The realm's CIBA policy: delivery mode `poll`, how long a request lives (`cibaExpiresIn`, 120 s in the example),
  the polling interval, and `login_hint` as the way the user is identified.
- A confidential client for the server with *OIDC CIBA Grant* enabled (`mcp-ciba` in the example) and a secret.
- The HTTP authentication channel: a server-wide Keycloak option naming the URL that receives the requests,
  `--spi-ciba-auth-channel--ciba-http-auth-channel--http-authentication-channel-uri`. The address is global to the
  Keycloak server, not per realm.
- The device application behind that URL: it receives Keycloak's POST, lets the right user approve or decline, and
  answers Keycloak's callback. The example's `approver` shows the shape of it.
- Callers must be authenticated at the MCP server, because the login hint is the caller's username: exchange
  delegation, or `kc-mcp.mcp.require-caller=true` ([Security](security.md#callers)).

On the server side, the example's `env/ciba.env` is a template:

```shell
KC_MCP_SPI_CONFIRMER_CIBA_ENABLED=true
KC_MCP_SPI_CONFIRMER_CIBA_CLIENT_ID=mcp-ciba
KC_MCP_SPI_CONFIRMER_CIBA_CLIENT_SECRET=...
KC_MCP_SPI_CONFIRMER_CIBA_TIMEOUT_SECONDS=90
KC_MCP_SPI_CONFIRMER_CIBA_POLL_WAIT_SECONDS=25     # the second call waits this long, so the model notices the decision itself
KC_MCP_CONFIRM_FALLBACK=deny                       # no confirm: true for clients without elicitation
```

When the server reaches Keycloak at an internal address (Docker), set `issuer` to that address and `token-issuer` to
the public one the tokens name.

The model is told about the device by `kc-mcp.confirm.model`: in `auto` it picks `server` whenever a confirmer
asks the human itself, so the model calls right away and relays the answer instead of asking "shall I really?"
([Guardrails](security.md#guardrails)). The `kc_mcp.ciba.*` metrics count requests and decisions by outcome
([Metrics](metrics.md)); alert on `rejected`, which means an approval's ID token was invalid or named someone else.

## Settings

`kc-mcp.spi.confirmer.ciba.*`, environment `KC_MCP_SPI_CONFIRMER_CIBA_*`.

| setting | default | meaning |
|---|---|---|
| `enabled` | `false` | |
| `issuer` | `caller` | issuer URL of the CIBA client; `caller` follows the `iss` of the caller's token (the auth realm without one) |
| `token-issuer` | = `issuer` | the `iss` the provider's tokens carry when the server reaches it at an internal URL (Docker) |
| `tls-configuration-name` | | named `quarkus.tls.<name>.*` configuration whose trust store the calls to the provider use (private CA); unset: the JVM's default trust |
| `connect-timeout` / `read-timeout` | `kc-mcp.http.*` | timeouts of the calls to the provider (`10s`, `500ms`, ...) |
| `client-id` / `client-secret` | | the confidential client registered for CIBA (required when on) |
| `client-auth` | `client_secret_basic` | or `client_secret_post` |
| `scope` | `openid` | |
| `acr-values` | | optional, e.g. to demand a second factor on the device |
| `login-hint` | `username` | or a token claim (`email`, `sub`) the provider resolves the user by |
| `binding-message` / `binding-message-prefix` | `true` / `kc-mcp` | the message on the device; Keycloak allows 50 characters without spaces |
| `requested-expiry` | `false` | send `requested_expiry` = the timeout |
| `timeout-seconds` | `confirm-timeout-seconds` | how long to wait; capped by the provider's `expires_in` |
| `when` | `always` | `without-elicitation`: only for clients that cannot ask the human themselves |
| `flow` | `two-step` | or `blocking` (the call waits for the device; no number matching) |
| `number-matching` | `true` | two-step: send a two-digit `code` the device asks the user for; shown to the model in `approval.code` and `howTo`, never in the message, so the audit trail does not record it |
| `extra-parameters` | `true` | send `requester` and `operation` as additional request parameters |
| `poll-wait-seconds` | `5` | two-step: how long the collecting call waits for the device before answering `pending` |
