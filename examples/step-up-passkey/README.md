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
MCP client ──(OAuth 2.1 / PKCE)──▶ Keycloak            alice logs in with her password (acr=password) and consents
   │                                                     to keycloak-mcp acting on her behalf
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
   │ 6. token exchange, alice's token + the server's client keycloak-mcp
   │        → a delegated token (sub=alice, act=keycloak-mcp)
   ▼
Admin REST API with the delegated token                 → the user is deleted
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
- **It counts for the login it was asked in.** The check reads `acr` and `auth_time` from the caller's token, and
  a step-up is kept for the session that token belongs to. A second login of alice at the MCP server starts
  without it.
- **Whose token reaches the Admin API.** Not alice's own: the MCP specification forbids passing it through. The
  server exchanges it at Keycloak for a delegated token for alice and the server's client `keycloak-mcp` (token
  exchange delegation, a preview feature of Keycloak 26.8). Keycloak enforces alice's roles on it. For this, the
  login at Keycloak ends with a consent page that asks *Allow keycloak-mcp to act on your behalf?*.
  [Delegated authentication](../delegated-auth/README.md) explains the setup. The step-up check runs before any
  of that and reads the caller's own token; the step-up login's client `mcp-step-up` takes no part in the exchange.
- **Two ways to hand out the link.** `env/step-up-device.env` uses the device authorization above: the user's
  browser only has to reach Keycloak. `env/step-up-browser.env` hands out a link to a page of the MCP server
  instead, which names the tool that asks and leads to Keycloak and back (code flow with PKCE); for that the user's
  browser has to reach the MCP server.

## Start

```shell
cd examples/step-up-passkey
docker compose up -d --wait # Keycloak 26.8.2 on http://localhost:8108 (admin / admin); returns once it is up
```

The one-shot job `keycloak-init` then grants `keycloak-mcp` the permission to act for the realm's users
(`init/grant-delegation.sh`), which a realm import cannot carry. It takes a few seconds more;
`docker compose logs keycloak-init` ends with `delegation to keycloak-mcp granted`.

Then run the MCP server on the host, in a second terminal:

```shell
./server.sh                 # env/step-up-device.env; MCP endpoint: http://localhost:8109/mcp
```

`server.sh` starts `quarkus:dev` with the settings of the env file and nothing else: `KC_MCP_*` and `QUARKUS_*` variables
the terminal still carries from another example are dropped, and none are exported into it. `./server.sh --jar` runs
the packaged server instead.
`./server.sh step-up-browser` takes the other env file.

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

It logs alice in the way an MCP client's browser does (Keycloak's login form, then the consent page for
`keycloak-mcp`), creates a throw-away user, asks to delete it, prints the refusal with the link and waits. Open the
link, sign in with the passkey, press Enter: the delete runs, and so does a second one without asking again. The
step-up counts for the session it was asked in: run the script again and it asks again, because each run logs alice
in anew.

With an MCP client (LM Studio: `mcp-oauth.json`): log in as alice and say yes when Keycloak asks whether
`keycloak-mcp` may act on your behalf. Then ask it to delete a user. It shows the link; sign in, tell it you are
done.

By hand, with one token for all calls (`--login` with a tool would log alice in anew each time, and a step-up counts
for one session). The password grant is not available: a client that requires consent refuses it.

```shell
TOKEN=$(./mcp-call.py --login alice:alice-demo --print-token)                   # login form and consent page
./mcp-call.py --token "$TOKEN" whoami                                           # caller.acr is "password"
./mcp-call.py --token "$TOKEN" keycloak_user_delete '{"id": "…", "username": "…", "confirm": true}'
```

## Management UI

`Both env files` also turns the [management UI](../../docs/management-ui.md) on: <http://localhost:8109/ui/>, sign in as
`alice` / `alice-demo`. *Systems* shows the system and its realm, *Audit* the tool calls of the demo.

It runs without HTTPS in dev mode (`KC_MCP_DEV_MODE=true`: the session cookie drops `Secure`, for one person's
machine only) and keeps its sessions and the audit trail in an H2 file under `data/` (git-ignored). The server
therefore has to be the default H2 build, not a `-Ppostgresql` one. The realm's public client `keycloak-mcp-ui` signs
people in.

## What was tested, and what was not

Both logins (`device` and `browser`) were run end to end against Keycloak 26.8.2 with the server in delegation mode
`exchange` and a script in place of the browser: alice's login with the consent page, the refusal with the link,
the same link while the login is pending, the step-up login, the delete that runs afterwards with the delegated
token and the next one within the time allowed. A second login of alice was refused again in the same minute, and
with the device login so was the first one after the minute had passed. A script cannot use a passkey, so that run used a copy of this
realm with the one-time-code form at the second level instead of the passkey authenticator, and a one-time-code
credential for alice; everything else was the same.

With the realm as it is here, `demo.sh` and both logins were run up to Keycloak's passkey step: the refusal with the
link, the same link while pending, the link's page, alice's password. Alice has no passkey in a fresh realm, so
Keycloak answered there with *Cannot login, credential setup required*. Registering a passkey and signing in with
it was not run; that needs your browser.

After a device login the server asks Keycloak no more often than every five seconds, the interval Keycloak sets
for device authorizations. A call sent sooner than that after the sign-in still answers with the link; the next one
runs.

## Settings

`env/step-up-device.env` and `env/step-up-browser.env` carry the server's settings with comments. The ones that
matter for the step-up:

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

The login and the Admin API calls:

| setting | here | meaning |
|---|---|---|
| `KC_MCP_DELEGATION` | `exchange` | Admin API calls run with a delegated token for the caller and the server's client |
| `KC_MCP_SYSTEMS_DEFAULT_CLIENT_ID`, `…CLIENT_SECRET` | `keycloak-mcp` | the server's client (the actor); its service account holds no admin role |
| `KC_MCP_SYSTEMS_DEFAULT_VERSION` | `26.8.2` | stated, because the server's client may not read the server info |
| `QUARKUS_OIDC_TOKEN_AUDIENCE` | `keycloak-mcp` | only tokens issued for the MCP server are accepted |
| `QUARKUS_OIDC_RESOURCE_METADATA_SCOPES` | `openid,delegation:client:keycloak-mcp` | what MCP clients are told to ask for; without the delegation scope every tool answers `delegation_failed` |

In the realm, `keycloak-mcp` may carry at most `realm-admin` in a delegated token (`clientScopeMappings`), so alice
can still delete users; carol's `view-users` stays what it is.

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
