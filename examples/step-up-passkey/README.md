# Step-up with a passkey: destructive tools only after a fresh passkey login

A user signs in to their MCP client once, with a password, and works for hours. This example makes destructive tools
ask for more: a **passkey login that is at most one minute old**. The `step-up`
[access check](../../docs/security.md#step-up-authentication) refuses the call otherwise, and since MCP clients cannot
send their user through such a login, the server runs it:

1. The refused call answers `insufficient_user_authentication` with a link.
2. The user opens the link and signs in at Keycloak with their passkey.
3. The next call runs, and so do the destructive calls of the following minute. One minute is short on purpose, so that the demo shows
   the step-up running out; a real setup would rather take five.

## How it works

```
MCP client ──(OAuth 2.1 / PKCE)──▶ Keycloak            alice logs in with her password: acr=password
   │ tools/call keycloak_user_delete {id, username}                                   (first call)
   ▼
MCP server (access checks: ... step-up)
   │ 1. the token has acr=password, the check wants acr=passkey, at most 1 min old
   │ 2. POST device_authorization_endpoint               client mcp-step-up (confidential), PKCE
   │ 3. answers insufficient_user_authentication         "open http://localhost:8108/realms/demo/device?user_code=…"
   │        alice opens the link ──▶ Keycloak: password (if she has no session there), then her passkey
   │ tools/call keycloak_user_delete {id, username}                                   (second call)
   │ 4. POST token_endpoint (device_code grant)          pending → the link again; signed in → ID token
   │ 5. the ID token is alice's, acr=passkey, auth_time fresh → kept for 1 min for this system and realm
   ▼
Admin REST API with alice's token (forward delegation)   → the user is deleted
```

- **The realm decides what a passkey login is.** *Realm settings › ACR to LoA mapping* names two levels,
  `password` (1) and `passkey` (2). The browser flow `browser step-up` asks for the password under the first and
  for a passkey (*WebAuthn Passwordless Authenticator*) under the second, again after one minute.
- **A client for stepping up only.** `mcp-step-up` has the device authorization grant and `passkey` as its
  *Default ACR Value*: Keycloak takes the level of a device login from there, not from the request. It is
  confidential, so nobody but the server can start a device authorization with it, and its tokens open nothing:
  no roles, no audience, 60 seconds, no refresh token. The MCP clients' own client, `mcp-consumer`, has no device
  grant: nobody signs in to the MCP server that way.
- **What the user is asked to grant.** Keycloak ends a device login with a consent page. It does not ask for
  alice's profile, which the server does not read, but shows the client's own text: *Confirm sensitive actions you
  asked for through the Keycloak MCP server*. It cannot name the operation; Keycloak has no rich authorization
  requests (RFC 9396) that would carry it there.
- **Only alice's own login counts.** The server compares the subject of the login's ID token with the caller of
  the refused call. A link opened by someone else grants nothing.
- **Two ways to hand out the link.** `env/step-up-device.env` uses the device authorization above: the user's
  browser only has to reach Keycloak. `env/step-up-browser.env` hands out a link to a page of the MCP server
  instead, which names the tool that asks and leads to Keycloak and back (code flow with PKCE); for that the user's
  browser has to reach the MCP server.

## Start

```shell
cd examples/step-up-passkey
docker compose up -d --wait # Keycloak 26.8.2 on http://localhost:8108 (admin / admin); returns once it is up
```

Then run the MCP server on the host, in a fresh shell:

```shell
cd ../..
set -a; source examples/step-up-passkey/env/step-up-device.env; set +a
./mvnw quarkus:dev -pl modules/backend -am     # MCP endpoint: http://localhost:8109/mcp
```

Users: `alice` / `alice-demo` (realm admin), `carol` / `carol-demo` (may only view users).

## Register a passkey first

Keycloak does not let a user register a passkey in the middle of a step-up; someone without one gets an error page
there. So once, before the demo:

1. Open <http://localhost:8108/realms/demo/account/> and sign in as `alice` / `alice-demo`.
2. *Account security › Signing in › Passkey › Set up*, and follow the browser.

Passkeys are bound to the host name, here `localhost`.

## Try it

```shell
./demo.sh
```

It logs alice in, creates a throw-away user, asks to delete it, prints the refusal with the link and waits. Open the
link, sign in with the passkey, press Enter: the delete runs, and so does a second one without asking again. The
step-up counts for the session it was asked in: run the script again and it asks again, because each run logs alice
in anew.

With an MCP client (LM Studio: `mcp-oauth.json`): ask it to delete a user. It
shows the link; sign in, tell it you are done.

By hand, with one token for all calls (`--login` would log alice in anew each time, and a step-up counts for one
session):

```shell
TOKEN=$(curl -s -d grant_type=password -d client_id=mcp-consumer -d scope=openid -d username=alice \
  -d password=alice-demo http://localhost:8108/realms/demo/protocol/openid-connect/token | jq -r .access_token)
./mcp-call.py --token "$TOKEN" whoami                                           # caller.acr is "password"
./mcp-call.py --token "$TOKEN" keycloak_user_delete '{"id": "…", "username": "…", "confirm": true}'
```

## What was tested, and what was not

The server side of both logins was run end to end against this Keycloak version with a script in place of the
browser: the refusal with the link, the same link while the login is pending, the login, the call that runs
afterwards and the next one within the time allowed. A script cannot use a passkey, so that run used a copy of this realm
with the one-time-code form at the second level instead of the passkey authenticator; everything else was the same.
With the realm as it is here, the run was taken up to the point where Keycloak asks alice for her passkey. The passkey
step itself needs your browser.

## Settings

`env/step-up-device.env` and `env/step-up-browser.env` carry the server's settings with comments. The ones that
matter:

| setting | here | meaning |
|---|---|---|
| `kc-mcp.spi.access-check.step-up.default` | `on` | the check runs for every system and realm |
| `…acr` | `passkey` | the level the realm maps to its passkey flow |
| `…max-age` | `1m` | how old the login may be; the realm asks for the passkey again after the same time (`loa-max-age` of its passkey level) |
| `…levels` | `destructive` (default) | which tools need it; `tools` names single ones instead |
| `…login` | `device` or `browser` | how the server hands out its own login |
| `…login-client-id`, `…login-client-secret` | `mcp-step-up` | the client of that login |

All of it can differ per system and realm, except the client's secret:
[Access checks](../../docs/access-checks.md).

## Limits

- **A step-up is not an approval of one operation.** After the passkey login every destructive tool runs for
  alice's session on that system and realm for one minute, whoever asked the model for it. Where each destructive call needs
  her own decision, use the [CIBA confirmation](../ciba-confirm/README.md), which binds the approval to the
  operation; the two can be combined.
- **The device page cannot say what asked.** Keycloak's page shows the client's name and a code, not the tool. The
  `browser` login's page names the tool and system.
- **Device authorizations are a known phishing vector** where they sign users in: someone starts one and gets a
  victim to complete it. Here nobody outside the server can start one (confidential client), the tokens it yields
  open nothing, and the server never signs anyone in through it. If your organization blocks the device grant
  altogether, use `login=browser`.
- With several instances, turn the [database storage](../../docs/storage.md) on: the links and logins are then
  shared (`kc_mcp_state`).

## Reset

```shell
docker compose down -v
```
