# External authorization and AuthZEN

[keycloak-mcp-server](../README.md) › [documentation](security.md)

Tool calls can be decided by an outside policy service. Three parts:

- **Authorization engines** talk to a policy service. The built-in `authzen` engine speaks the OpenID AuthZEN
  Authorization API 1.0 (`POST /access/v1/evaluation`) to a policy decision point (PDP); extensions add vendors' engines
  ([Extending](extending.md#authorization-engines)).
- **The `authorization` entry** of a system's and a realm's [access block](access-checks.md) says whether calls are
  evaluated and by which engine with which settings.
- **The access check `authorization`**, one of the [access checks](access-checks.md), brings them together: for every call it takes the effective block, hands the
  call to the engines it names, and fails closed when something is missing.

The check runs after the server's own checks (static policy, realm allow-list, roles, delegation, the built-in
[policies](security.md#built-in-policies-group-scope-no-escalation-self-protection)) and before the confirmation, so a
policy service can only take away, never grant what Keycloak's roles do not.

Nothing is evaluated by default: the server switches an engine on, the systems and realms decide whether their calls
go through it.

## What the AuthZEN PDP is asked

`keycloak_user_set_enabled` with `id=8f1c, enabled=false`, called by alice through Claude:

```json
{
  "subject":  { "type": "user", "id": "<sub of alice's token>",
                "properties": { "realm": "acme", "name": "alice", "issuer": "https://sso/realms/acme",
                                "roles": ["realm:support"], "delegated": true, "client_id": "claude-desktop" } },
  "action":   { "name": "keycloak_user_set_enabled",
                "properties": { "level": "write", "category": "users", "method": "PUT",
                                "operation": "PUT /admin/realms/{realm}/users/{user-id}" } },
  "resource": { "type": "user", "id": "8f1c", "properties": { "system": "prod", "realm": "acme" } },
  "context":  { "system": "prod", "realm": "acme", "time": "2026-11-10T10:00:00Z",
                "agent": { "client_id": "claude-desktop", "act": { "sub": "..." } },
                "args": { "id": "8f1c", "enabled": false } }
}
```

- **subject**: always the caller from the token, never from what the model sends. `user`, or `client` for a service
  account token (`client_id` claim or a `service-account-` username); `anonymous` while the MCP endpoint is not
  authenticated. `roles` are the caller's token roles (`realm:<role>`, `<client>.<role>`).
- **action**: the tool name, with its level (`read`, `write`, `destructive`), category and the Admin REST operation it
  performs. A tool that reads before it writes is described by the write. Policies can match on the tool name or in
  REST terms ("no `DELETE` under `/users`").
- **resource**: read from the operation's path bindings. The innermost path parameter the call fills is the resource
  (`/clients/{client-uuid}/roles/{role-name}` → `role`), the enclosing ones are in `properties.path`
  (`[{"type": "client", "id": "billing"}]`). The id is the value of the tool argument bound to the parameter: for
  clients that is the `clientId`, not the internal UUID. A call that names nothing in its path (create, list) acts on
  `realm <realm>` with `properties.collection` (`user`); a global tool acts on `system <system>`.
- **context**: system and realm, the acting client (`azp`, and `act` under token exchange or
  [XAA](../examples/xaa/README.md)), the time, and the arguments. Sensitive arguments (passwords, secrets, everything
  [`Sensitive`](security.md#audit-and-sensitive-values) masks for the audit) arrive as `***`; `send-args=false` leaves
  the arguments out.

## What the AuthZEN PDP answers

| answer | effect |
|---|---|
| `{"decision": true}` | allowed |
| `{"decision": true, "context": {"confirmation_required": true}}` | allowed once the human confirms it themselves: elicitation or [CIBA](ciba-confirmation.md), never the model's `confirm: true` (`policy_confirmation`) |
| `{"decision": false}` | `policy_denied`; the model is told `context.reason_user`, else `reason_admin`, else `reason` (a string or `{"en": "..."}`), else which tool on which resource was refused |
| HTTP error, timeout, no boolean `decision` | `authorization_unavailable`, unless `on-error=allow` |

Every request carries an `X-Request-ID`, logged with a denial at debug level.

Extensions can add to the request before it is sent (an `AuthZenRequestCustomizer`, e.g. a ticket id in the
context), or talk AuthZEN their own way with the same model ([Extending](extending.md#authzen-for-extensions)).

## Switching it on

1. Server-wide: the engine, `kc-mcp.spi.authorization-engine.authzen.enabled=true`. Without an engine, no call is
   evaluated; a system that asks for one has its calls denied.
2. Per system: the system's `access.authorization.enabled`. Unset, the engine's `default` decides, `off` unless configured
   otherwise.
3. Per realm: the realm's `access.authorization.enabled` overrides the system's switch for that realm.

The most specific switch wins: realm, then system, then the engine's `default`. A global tool (no realm) follows the
system.

| system | realm | engine `default=off` | engine `default=on` |
|---|---|---|---|
| unset | unset | not evaluated | evaluated |
| `enabled: true` | unset | evaluated | evaluated |
| `enabled: false` | unset | not evaluated | not evaluated |
| any | `enabled: true` | evaluated | evaluated |
| any | `enabled: false` | not evaluated | not evaluated |

With `default=on` every system is governed unless it opts out. Whoever may register systems through the
[admin API](systems.md#admin-api-registering-systems-at-runtime) may then also opt one out; keep `default=off` and
switch systems on where that matters, or keep registration closed.

## The authorization entry

```json
{
  "access": { "authorization": {
    "enabled": true,
    "authzen": { "url": "https://pdp.acme.example/access/v1/evaluation", "auth": "system-client", "scope": "authzen-pdp" }
  } }
}
```

- `enabled`: the switch above.
- Every other key names an engine by its id (`authzen`, or an extension's) and holds that engine's settings over the
  engine's own defaults. A block that names engines sends its calls to those only; one that names none, to every
  engine the server has.
- A block that needs an engine the server does not have (not installed, not switched on, not supported) gets its calls
  denied (`authorization_unavailable`); a configured system like that stops the start, the admin API refuses one
  (`unknown_authorization_engine`). So does `"enabled": true` on a server without any engine.
- A realm's block overlays its system's: the realm's `enabled` wins, its engine settings win key by key. A realm can
  switch evaluation off, or bring a PDP of its own (`{"authzen": {"url": "..."}}`).
- An engine's denial refuses the call, an engine that fails denies it, an engine's request for confirmation hands the
  call to the human.

The block in the three places a system can come from:

```properties
# configured systems (kebab-case keys)
kc-mcp.systems.prod.access.authorization.enabled=true
kc-mcp.systems.prod.access.authorization.authzen.url=https://pdp-prod.example/access/v1/evaluation
kc-mcp.systems.prod.access.authorization.authzen.auth=system-client
kc-mcp.systems.prod.access.authorization.authzen.scope=authzen-pdp
kc-mcp.systems.prod.realms.sandbox.display-name=Sandbox
kc-mcp.systems.prod.realms.sandbox.access.authorization.enabled=false
kc-mcp.systems.prod.realms.acme.access.authorization.authzen.url=https://pdp-acme.example/access/v1/evaluation
```

A realm name with dots goes in quotes in configuration keys, as SmallRye maps take it: `realms."acme.eu".access...`.

Systems file (camelCase, as the other fields of a system; kebab-case is accepted too):

```json
{ "name": "prod", "url": "https://sso.acme.example",
  "access": { "authorization": { "enabled": true, "authzen": { "auth": "system-client", "scope": "authzen-pdp" } } },
  "realms": { "sandbox": { "displayName": "Sandbox", "access": { "authorization": { "enabled": false } } } } }
```

Admin API: the system's `authorization` with `PUT /api/admin/systems/<alias>`, a realm's settings with
`PUT /api/admin/systems/<alias>/realms/<realm>` ([Systems](systems.md#admin-api-registering-systems-at-runtime)).

### Realm settings

A realm the server knows something about has settings of its own, beside its system's: `realmId` (Keycloak's internal
id, which stays when the realm is renamed), `displayName`, `description`, and its `authorization` block. In the
database each is a row of `kc_mcp_realm` linked to its system: replacing the system keeps them, removing it removes
them.

### Secrets and what a registered system may ask for

- Secret values (`clientSecret`, `headerValue`, the `jwt-*` passwords, and for any engine every setting whose name ends
  like a secret: `...Secret`, `...Password`, `...Token`, `...Key`) may be literals or `vault:<name>` references,
  resolved like a system's own client secret. The admin API shows literals as `***`; the database keeps every block
  encrypted with the other secrets, and a storage key rotation rewrites them.
- A system or realm registered through the admin API is held to what such a registrant may ask of the server,
  whatever the engine: URL-valued settings must pass `kc-mcp.allowed-hosts` and the private-host rule like the system's
  own URL (`host_not_allowed`, `private_host`); settings ending in `-file` would make the server read one of its files
  and are refused (`local_file_setting`; `private_key_jwt` then signs with the system's own vault key); unknown
  `vault:` references too (`unknown_secret`); and settings an engine finds wrong answer `invalid_authorization`.
- A system that changes at runtime gets its new settings on its next call.

## The AuthZEN engine

`kc-mcp.spi.authorization-engine.authzen.*` (environment `KC_MCP_SPI_AUTHORIZATION_ENGINE_AUTHZEN_*`). Besides the
switches, these are the defaults of every system's and realm's `authzen` block, which may set every key but
`enabled`, `default`, `systems-without-pdp` and `required`:

| key | default | meaning |
|---|---|---|
| `enabled` | `false` | the engine exists on this server |
| `default` | `off` | `on`: systems that say nothing are evaluated |
| `url` | | evaluation endpoint, e.g. `https://pdp.example/access/v1/evaluation`; may hold [placeholders](access-checks.md#placeholders) such as `{realm.name}` and `{system.name}`, for PDPs with a policy store per tenant |
| `auth` | `none` | `header`, `client-credentials` or `system-client` (below) |
| `header-name`, `header-value` | `Authorization` | `auth=header`: sent as they are (`Bearer ...`, `basic <api key>`) |
| `token-url`, `client-id`, `scope` | | `auth=client-credentials`: the authorization server the PDP trusts; `scope` also for `system-client` |
| `client-auth` | `client_secret_basic` | `auth=client-credentials`: `client_secret_basic` or `client_secret_post` (with `client-secret`), `private_key_jwt`, or a method an extension adds ([Extending](extending.md#client-authenticators)) |
| `jwt-key-file`, `jwt-keystore-file`, `jwt-keystore-password`, `jwt-keystore-type`, `jwt-key-alias`, `jwt-key-password`, `jwt-key-id`, `jwt-algorithm`, `jwt-assertion-audience`, `jwt-assertion-lifespan` | `PKCS12`, from the key, token URL, `60` | `private_key_jwt`: the key; `jwt-algorithm` defaults to `RS256` for an RSA key and `ES256`/`ES384`/`ES512` by the curve of an EC key (P-256/P-384/P-521, as JOSE ties them), `PS256`/`PS384`/`PS512` when set; without a key file or keystore, the key the server holds for the Keycloak system, the one its JWKS endpoint publishes |
| `on-error` | `deny` | `allow` lets calls through while the PDP is unreachable |
| `send-args` | `true` | arguments in `context.args` (sensitive ones masked either way) |
| `connect-timeout`, `read-timeout` | `kc-mcp.http.connect-timeout`, `5s` | every tool call waits for the PDP |
| `tls-configuration-name` | | `quarkus.tls.<name>.*` for the PDP and its token endpoint |
| `systems-without-pdp` | `deny` | a call that is evaluated but has no `url`, neither its block's nor the default: `deny` it or `skip` the engine |
| `required` | `false` | `true`: the server does not start without the engine (see [Extending](extending.md)) |

At startup the engine builds its default PDP and the PDP of every configured system and realm it evaluates, including
the client authentication, and logs which PDP each uses; a mistake stops the start. A registered system whose settings
still do not work has its calls denied (`authorization_unavailable`) and the reason logged.

### A token from the system's own Keycloak: `auth=system-client`

When the PDP trusts the Keycloak the server administers (the issuer of the server's own service account), there is no
need for credentials of its own:

```properties
kc-mcp.spi.authorization-engine.authzen.auth=system-client
kc-mcp.spi.authorization-engine.authzen.scope=authzen-pdp
```

For each system, the engine requests a token at that system's token endpoint
(`<url>/realms/<auth realm>/protocol/openid-connect/token`) with the system's own client: its secret, or its
`private_key_jwt` key with the audience Keycloak expects of the system's assertions. It asks for `scope`, and sends the
token to the PDP. It never sends the server's Admin API token, which would let the PDP, or anyone who obtains a token
from it, administer Keycloak as the server.

In Keycloak: a client scope `authzen-pdp` with an audience mapper for the audience the PDP checks ("Included Custom
Audience"), added as an optional client scope of the server's client. On the PDP: trust the issuer
(`https://sso.example/realms/master`), require that audience. Each system's tokens come from its own Keycloak, so a
tenant's PDP trusts its tenant's issuer. Systems that log in with the password grant or as a public client cannot use
it.

## Limits

- Only calls are evaluated, not `tools/list`: the model still sees tools the PDP will refuse.
- No decision cache: every call asks the PDP once.
- `tls_client_auth` (mTLS) is not built in; an extension can add it as a client authenticator.
