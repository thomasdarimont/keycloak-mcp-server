# Troubleshooting with read-only access

[keycloak-mcp-server](../../README.md) › [examples](../README.md)

A support engineer asks why a login misbehaves, and the model finds out from what Keycloak records and how it is
configured, without being able to change anything. The server reads, and nothing else, twice over:

- **Keycloak** gives its service account `mcp-support` only `view-*` roles of the realm, so it refuses any change.
- **The server** runs with `KC_MCP_READ_ONLY=true`: write and destructive tools are neither listed nor callable, and
  a request to the Admin API that is not a `GET` is not sent, whatever a tool declares.

The realm `shop` has one planted fault per question, and `seed.py` produces the symptoms:

| question | what the user sees | what the evidence shows | cause |
|---|---|---|---|
| What causes this redirect loop? | `shop-web` bounces frank between itself and Keycloak until the browser gives up | login events: `LOGIN` and `CODE_TO_TOKEN_ERROR` (`invalid_client_credentials`) take turns; admin events: `ACTION clients/<id>/client-secret` seconds before the first failure | the client secret was regenerated, the application still uses the old one |
| Why can't erin sign in? | "Invalid username or password", with the right password | login events: three `invalid_user_credentials`, then `user_temporarily_disabled`; lockout status: `lockedOut: true` | brute force detection locked the account |
| Why is the login so slow? | every login takes seconds | realm: `passwordPolicy` with `hashIterations(5000000)`; the hash stored with grace's password: `pbkdf2-sha512`, 5000000 iterations | the password policy makes every password check cost seconds |

## Start

```shell
cd examples/troubleshooting
docker compose up -d        # Keycloak 26.8.2 on http://localhost:8104 (admin / admin)
./seed.py                   # the symptoms: a slow login, erin's lockout, frank's loop (python3)
```

Then run the MCP server on the host:

```shell
cd ../..
set -a; source examples/troubleshooting/env/support.env; set +a
./mvnw quarkus:dev -pl modules/backend -am     # MCP endpoint: http://localhost:8105/mcp
```

or packaged, inside compose (`./mvnw package -DskipTests` first):

```shell
docker compose --profile mcp up -d --build && docker compose logs mcp | grep 'tools registered'
```

The startup log says `readOnly=true` and registers the read tools only. Point your MCP client at
`http://localhost:8105/mcp` (LM Studio: copy `mcp.json`). IntelliJ: `.run/` has `quarkus:dev (support)` and the stack
(regenerate with `examples/gen-run-configs.sh`).

Run `seed.py` once per stack. erin's lockout lasts 15 minutes; `docker compose down -v` resets everything.

## Ask

Free questions, or the prompts that carry the procedure and the tools for it:

| ask | or the prompt |
|---|---|
| "The shop-web login is stuck in a redirect loop for frank. What causes it?" | `keycloak_redirect_loop_troubleshoot client=shop-web username=frank` |
| "Why can't erin sign in? She says her password is right." | `keycloak_login_troubleshoot username=erin` |
| "Logins in the shop realm take seconds, for grace for example. Why?" | `keycloak_slow_login_troubleshoot username=grace` |
| "Unlock erin." | none: refused with `read_only_mode`; the model should say who can do it |

A client that does not show MCP prompts: fetch the text and paste it into the chat.

```shell
export MCP_URL=http://localhost:8105/mcp
../run-modes/prompt.sh                                                    # the prompts and their arguments
../run-modes/prompt.sh keycloak_redirect_loop_troubleshoot client=shop-web username=frank
```

## The evidence, without a model

`demo.sh` (python3, jq) walks through the three questions with the tool calls a model makes and prints what comes
back; it runs `seed.py` first if the realm has no events yet.

```shell
./demo.sh
./mcp-call.py keycloak_events_login '{"client": "shop-web", "max": 30}'      # any tool by hand
```

## What read-only access can and cannot answer

| the server sees | it does not see |
|---|---|
| login events: what happened, in which order, with which error | how long a request took: events carry a time, not a duration |
| admin events: what was changed, when, by which account | Keycloak's log, its metrics, the database |
| configuration: clients, realm, flows, password policy, federation, identity providers | the application's log and configuration, the reverse proxy |
| user state: lockout, required actions, sessions, how a password is hashed | the browser: cookies, the network trace |

So a redirect loop whose events show a successful login and a successful code exchange every round is the
application's or the proxy's, and the model's answer is where to look next. The prompts say so instead of guessing.
For the slow login the server finds settings that cost time; measuring belongs to Keycloak's metrics and access log.

Events are the main source: a realm that does not save them (`eventsEnabled`, `adminEventsEnabled`) leaves the
configuration only. The event tools say so when they come back empty.

The administrator who regenerated the secret appears in the admin event as a user id of the realm `master`, which
`mcp-support` cannot look up: access to one realm ends at that realm.

## Beyond one machine

`env/support.env` uses the security profile `local`: nobody logs in at the MCP endpoint, which suits a support
engineer's own machine. For a server other people reach, keep `KC_MCP_READ_ONLY=true` and let the users log in
(`examples/run-modes/env/shared.env`): each call then runs with the caller's own `view-*` roles and the audit trail
names them. Read-only for one system or realm of several: `kc-mcp.systems.<name>.tools.read-only=true`
([Security](../../docs/security.md#tool-restrictions-per-system-and-realm)).

## Reset

```shell
docker compose down -v
```
