# Security: guardrails, access levels, callers

[keycloak-mcp-server](../README.md) › documentation

Two layers protect a Keycloak behind this server. The first is Keycloak itself: the server acts as a service account or
as the signed-in user, and the `realm-management` roles of that identity decide what the Admin API allows. The second is
the server: it hides what the roles do not cover, fences in realms, hosts and tools, confirms destructive operations and
audits every call. Flags on the server never grant more than Keycloak would.

## Guardrails

### The two profiles

`KC_MCP_SECURITY_PROFILE` (`kc-mcp.security-profile`) sets the security defaults in one switch. `local` (the default) is one
person's machine; `shared` is a server other people reach over the network. What an instance serves is a separate
setting, `kc-mcp.instance-role`: an `admin` instance has no MCP endpoint, so the MCP endpoint row does not apply to it.

| | `local` | `shared` |
|---|---|---|
| MCP endpoint | anonymous, behind DNS rebinding protection | callers must authenticate: `quarkus.oidc.tenant-enabled=true` **and** `quarkus.oidc.token.audience` |
| destructive tools without elicitation | `confirm: true` accepted (`confirm-fallback=flag`) | refused (`confirm-fallback=deny`) |
| system and realm of destructive tools | defaults fill in (`explicit-target=off`) | must be named (`explicit-target=destructive`) |
| systems registered at runtime on private addresses | allowed (`dynamic-private-hosts=allow`) | only hosts named literally in `allowed-hosts` (`listed`) |
| outbound Keycloak hosts | unrestricted | `kc-mcp.allowed-hosts` required |
| admin API with an issuer | | needs `kc-mcp.admin.audience` |
| `grant-type=password` (a person's account signs in) | allowed | refused: every system needs a service client |
| database storage | encryption warned about | needs `kc-mcp.storage.secret-key` |
| MCP traffic log | allowed | refuses to start with it on |

A `shared` server with a missing setting does not start and lists everything that is missing. Each default can still
be set on its own in either profile.

### Fencing the server in

- **Read-only.** `KC_MCP_READ_ONLY=true` hides and refuses WRITE and DESTRUCTIVE tools.
- **Realms.** `kc-mcp.systems.<name>.allowed-realms=a,b` (or `kc-mcp.system-defaults.allowed-realms` for all systems) restricts every call. The startup check verifies the realms are reachable
  (`kc-mcp.startup-check=warn|fail|off`).
- **Keycloak hosts.** `KC_MCP_ALLOWED_HOSTS=*.example.com,localhost:8080`: every configured Keycloak URL, top level
  and per system, must match a `[scheme://]host[:port]` pattern, or the server does not start.
- **Private addresses of runtime systems.** A system registered at runtime (admin API, repositories) whose host
  resolves to a loopback, link-local, private or otherwise non-public address is refused as `private_host` under
  `kc-mcp.dynamic-private-hosts=listed`, unless `allowed-hosts` names the host literally, without a wildcard. So a
  registered URL cannot point the server at its own network. Static systems are the operator's choice and not checked.
  The admin client and the UI's discovery never follow redirects. The address is checked when the system is registered
  or changes, not on every connection.
- **Tools.** `KC_MCP_ALLOWED_TOOLS`, `KC_MCP_DENIED_TOOLS` and `KC_MCP_ALLOWED_CATEGORIES` narrow the tool set
  explicitly. Per system, realm and preset, a `tools` section narrows it further for the calls into them
  ([Tool restrictions per system and realm](#tool-restrictions-per-system-and-realm)).
- **DNS rebinding.** While the MCP endpoint is anonymous, requests whose `Host` or `Origin` is not localhost answer
  403 `forbidden_host`, so a web page cannot reach the local server through a name rebound to 127.0.0.1
  (`kc-mcp.dns-rebinding-protection`, default `auto`). It is off once callers authenticate.
  `kc-mcp.dns-rebinding-allowed-hosts` adds `host[:port]` values for an anonymous server reached by name or through a
  proxy. The host of `kc-mcp.hostname` counts too. JWKS and admin routes are not covered.

### Tool restrictions per system and realm

A system, a realm and a [preset](access-checks.md#presets) can each have a `tools` section, with the same four
restrictions the server has:

| key (config / JSON) | meaning |
|---|---|
| `read-only` / `readOnly` | only tools that read |
| `denied` | never these tools (names with or without `keycloak_`) |
| `allowed` | only these tools |
| `categories` | only tools of these categories (`users`, `clients`, ...) |
| `unlisted` | what happens to the tools `allowed` does not name: `allow`, `read` (only if they read) or `deny`; unset: `deny` with an `allowed` list, `allow` without |
| `confirm` | these tools need confirmation there, as destructive ones do ([Confirming destructive tools](#confirming-destructive-tools)) |
| `confirm-writes` / `confirmWrites` | every tool that changes Keycloak needs confirmation there |

```properties
kc-mcp.systems.prod.tools.denied=user_delete,realm_update
kc-mcp.systems.prod.realms.support.tools.categories=users,groups
kc-mcp.systems.prod.realms.customers.tools.confirm=user_set_enabled,user_logout
kc-mcp.presets.viewer.tools.read-only=true
kc-mcp.systems.prod.realms.audit.preset=viewer
```

Among the tenant levels the most specific key wins, as with `access`: the system's preset, the system, the realm's
preset, the realm. Against the server a section can only take tools away. The server's `kc-mcp.read-only`,
`denied-tools`, `allowed-tools` and `allowed-categories` are checked first and on their own, so no system or realm can
re-enable what the server closed, and no section can take a confirmation away. The keys of a section do not repeat
"tools" (`confirm`, not `confirm-tools`); an unknown key stops the start rather than be ignored. That is why a `tools` section needs no lock, unlike an access check: whoever
registers a system through the admin API can only narrow its tools. The admin API refuses names of tools that do not
exist (`unknown_tool`) and unknown categories (`unknown_category`), since a misspelt name would deny nothing.

A section is enforced when a tool is called, where system and realm are known (`read_only_mode`, `tool_not_allowed`,
naming system and realm). The tool list and the search are the server's and show tools a system may still refuse.

### New, removed and renamed tools

A new tool, from an upgrade or an extension, is available wherever no allow-list stands in its way. The server's
`kc-mcp.unlisted-tools` (and `tools.unlisted` of a system, realm or preset) decides what happens to the tools nobody
named:

| `unlisted` | a tool no `allowed` list names |
|---|---|
| `allow` | available (the default without an `allowed` list; also in profile `shared`) |
| `read` | available if it only reads: new read tools appear by themselves, new write and destructive tools wait until someone lists them |
| `deny` | not available (the default with an `allowed` list) |

`read-only` is the stronger switch: it refuses write tools even when listed. As every tool setting, a system or realm
can only be stricter than the server (`deny` before `read` before `allow`).

A removed tool, an uninstalled extension or a switched-off provider takes the tool out of the catalog: it is neither
listed nor found, and a call answers `unknown_tool`. What still names it is reported: at startup as a warning, by
`bin/kcmcp.sh validate` as a problem (stored systems included), since such an entry restricts nothing. That covers the
server's `allowed-tools` and `denied-tools`, the `tools` sections of systems, realms and presets, and
`self-protection.tools`.

A renamed tool keeps its old names as former names (`ToolSpec.Builder.formerly(...)`). They only ever restrict:

- a `denied` list, and `self-protection.tools`, that name a former name still apply to the tool, so a restriction
  survives the rename;
- an `allowed` list does not carry over: the tool has to be listed under its new name;
- calling a former name answers `unknown_tool` with the new name (`renamedTo`); it does not run the tool;
- a former name that is a tool's current name, or claimed by two tools, stops the start, so no tool can take another's
  name or hide behind a disabled one;
- `validate` reports entries that use a former name, with the name to use.

### Read tools only read

A tool declares its level (`read`, `write`, `destructive`); the declaration decides read-only mode, `unlisted=read`
and the confirmation. While a read tool runs, the admin client refuses every Admin API request (`/admin/...`) that is
not `GET`, `HEAD` or `OPTIONS`: the request is not sent, the call fails as `read_only_violation` (even if the tool
catches the error) and the server logs it as an error. Token requests pass. Tools declared `write` or `destructive`
(disabling a user, say: `keycloak_user_set_enabled` is a write) are not affected; no built-in tool declared `read`
needs more than `GET`.

This catches mislabelled tools and mistakes; it is no sandbox. An extension runs in the server's process and can build
its own HTTP client or read the server's secrets: installing a jar in `providers/` is a decision of trust, as with a
Keycloak provider. Work a tool hands to a pooled thread escapes the guard.

### Roles decide what the model sees

Role filtering is on by default (`kc-mcp.role-filter`). Tools declare the roles they need with `ToolSpec.roles(...)`:

| form | meaning |
|---|---|
| `view-users` | a `realm-management` client role |
| `my-app.auditor` | a role of another client, split at the last dot |
| `realm:support` | a realm role |

Implications work as in Keycloak: `manage-x` covers `view-x`, which covers `query-x`, and `realm-admin` covers all.
The server reads its own token, hides the tools it lacks roles for, and answers `forbidden` with the missing role on a
direct call. A token without any admin role switches the filter off. In delegation mode the caller's roles count
instead ([Callers](#callers)).

### Confirming destructive tools

DESTRUCTIVE tools delete users and groups, reset passwords, log users out, unassign roles. `keycloak_realm_update`
and `keycloak_auth_flow_bind` count as destructive too, for the lock-out risk. `keycloak_user_delete` also demands the
matching `username`, so an id alone cannot delete.

More tools can need confirmation, the same way: server-wide `kc-mcp.confirm-tools=user_set_enabled` or
`kc-mcp.confirm-writes=true` (every tool that changes Keycloak), and per system, realm or preset the `confirm` and
`confirm-writes` keys of the [tools section](#tool-restrictions-per-system-and-realm). Confirmation can only be
added: a destructive tool is confirmed everywhere, a read tool never.

- **Elicitation first.** When the MCP client supports it, the server asks the human through the client.
- **Without elicitation**, `kc-mcp.confirm-fallback` decides: `flag` (the `local` default) requires and explains
  `confirm: true`; `deny` (the `shared` default) refuses with `confirmation_required` and does not offer the flag,
  since the model would write it.
- **Own confirmers** run first ([Extending](extending.md)), so a ticket check can still confirm under `deny`.
- **CIBA** (`kc-mcp.spi.confirmer.ciba.enabled=true`, off by default) moves the decision to the caller's own device,
  with number matching ([CIBA confirmation](ciba-confirmation.md)). Neither the model nor the MCP client is in that channel.
- **Explicit targets.** `kc-mcp.explicit-target=off|destructive|write` makes tools of that level answer
  `system_required` or `realm_required` instead of using the default system or realm, so an ambiguous request cannot
  land on the production system. A per-system entry (`/mcp/systems/<system>[/<realm>]`) counts as explicit.

What the model is told about confirming is separate from what is enforced. `kc-mcp.model-confirmation` (default
`auto`) shapes the server instructions, the `search_tools` hits of destructive tools, `whoami` and the
`confirmation_required` answers: in `ask` mode the model asks the user once after `confirmation_required` and then
passes `confirm: true`; in `server` mode it calls right away and relays the answer, because the server asks through the
client's elicitation or on the user's device, or refuses. `auto` picks `server` whenever a confirmer asks the human
itself (`Confirmer.asksTheHuman()`, the CIBA confirmer does), the client supports elicitation, or `confirm: true` is not
accepted; `ask` otherwise. Callers holding one of `kc-mcp.model-confirmation-trusted-roles` are told to pass
`confirm: true` right away in `ask` mode. This stops the "shall I really delete?" question where the device asks anyway;
the confirmers enforce either way.

### Audit and sensitive values

Every executed tool writes one audit line (logger `com.github.thomasdarimont.keycloak.mcp.audit`), and the
`AuditListener` SPI receives the same event: tool, level, system, realm, redacted arguments, outcome, caller, client,
duration.

- Arguments declared `.sensitive()` (JSON Schema `writeOnly` and `format: password`, so clients can mask them) and
  keys of map arguments declared `.sensitiveKeys(...)` never reach the audit log, the elicitation prompt or the CIBA
  device.
- Undeclared names that end like a secret (`password`, `clientSecret`, `bindCredential`, `privateKey`, ...) are treated
  the same way at any depth of nested maps and lists. Settings that only mention the word (`passwordPolicy`) are not.
- Error messages reach the audit with the values of sensitive arguments, bearer tokens, JWTs and `password=...`
  assignments taken out, cut at 500 characters. A log filter takes tokens out of every other log line as well.
- Tools whose result is a secret (`keycloak_client_get_secret`, `..._regenerate_secret`) declare `.sensitiveResult()`:
  the caller gets it, the audit line says `result=sensitive`.
- The MCP traffic log (`quarkus.mcp.server.traffic-logging.enabled`) writes everything verbatim. The `shared` profile
  does not start with it on.

## Access levels

The real boundary is the roles of the identity the server uses. Pick the level, then narrow with server flags.

| level | Keycloak side | server side |
|---|---|---|
| full admin | client in `master` with `admin`, or an admin user via `admin-cli` | nothing |
| realm admin | confidential client **in the realm** with `realm-admin` | `kc-mcp.systems.default.allowed-realms=<realm>`, `kc-mcp.systems.default.default-realm=<realm>` |
| realm manager | client in the realm with only the `realm-management` roles needed | as realm admin; role filtering hides the rest. Narrow further: `KC_MCP_DENIED_TOOLS=keycloak_user_delete`, `KC_MCP_READ_ONLY=true` |
| user (forward) | the human holds the roles; a public PKCE client whose tokens carry the server's audience | `KC_MCP_DELEGATION=forward` + `QUARKUS_OIDC_TENANT_ENABLED=true`; no server credentials ([Callers](#callers)) |
| delegated agent (exchange) | the human holds the roles and consents to the server's client acting for them (Keycloak 26.8 token exchange delegation, preview); the client's role scope caps every delegated token | `KC_MCP_DELEGATION=exchange` + the client's `client_credentials` + `QUARKUS_OIDC_TENANT_ENABLED=true` ([Callers](#callers), `examples/delegated-auth`) |

A `master` client may also manage realms through `<realm>-realm` client roles; the filter understands both.

**Keycloak 26.8.2 and the Admin API audience.** Since 26.8.2 Keycloak checks the audience of Admin REST API tokens:
every client whose tokens reach the Admin API, the service account client as well as the public client users log in
with, needs the built-in `kc-admin-api` client scope, default or optional. Without it every admin call answers
`unauthorized`. The server requests that scope with every token (`kc-mcp.admin-api-scope`), advertises it to MCP clients
in the protected resource metadata, and asks again without it when a Keycloak answers `invalid_scope`, so one
configuration serves 26.8.1 and 26.8.2. The examples' realm files carry the scope; a 26.8.1 import drops the unknown
name silently. The startup log warns when the server's own token lacks the audience on a 26.8.2+ server.

### Per-tool access checks and delegation

```java
tool("keycloak_user_delete")
    .roles("manage-users")
    .requiresFeatures("organization").minVersion("26.8")       // maxVersion("26") bounds it; see Supported Keycloak versions
    .access(ctx -> ctx.arg("username").startsWith("svc-")
            ? AccessCheck.Decision.deny("protected_user", "service users are deleted by the platform team")
            : AccessCheck.Decision.allow())
    .delegation(Delegation.ALLOWED)   // ALLOWED (default) | FORBIDDEN | REQUIRED
```

- An `AccessCheck` gets the tool, the resolved realm, the validated arguments, the granted roles and the `Caller`. It
  runs after the realm and role checks and before the confirmation. A denial answers `{"error": <code>, "message": ...}`.
- Global checks come from `ToolProvider.accessChecks(...)` or any CDI bean implementing `AccessCheck`. Which of them
  run, in which order and with which settings can differ per system and realm ([Access checks](access-checks.md)).
- `Delegation` says whether a tool may run with a delegated identity. Under `KC_MCP_DELEGATION=forward` every call is
  delegated (`Caller.delegated()`): `FORBIDDEN` tools are refused, `REQUIRED` tools usable; service account mode is the
  reverse. `FORBIDDEN` by default: `client_get_secret`, `client_regenerate_secret`, `realm_update`, `auth_flow_bind`,
  `federation_sync`.
- Version and feature requirements: [Supported Keycloak versions](keycloak-versions.md).
- External policies: authorization engines (the built-in `authzen` speaks AuthZEN to a PDP; extensions add vendors')
  decide about tool calls. The server switches an engine on, each system (configured or registered at runtime) and
  realm decides whether its calls go through it and may bring its own settings ([External authorization](authzen.md)).

### Built-in policies: group scope, no escalation, self-protection

Three caller-relative [access checks](access-checks.md), once callers are authenticated ([Callers](#callers)). Each is
configured as an access check, `kc-mcp.spi.access-check.<id>.*` on the server and `access.<id>` per system and realm,
where it can also be switched off or reordered.

| check, `kc-mcp.spi.access-check.<id>.` | default | meaning |
|---|---|---|
| `group-scope` | off (`default=on` or a system's or realm's `enabled: true` switches it on) | callers manage only the groups of their `scope` |
| `group-scope.scope` | `group` | `group`: groups they belong to, or subgroups of them; `organization`: the groups of their organizations |
| `group-scope.manager-role` | | the role needed for group management, e.g. `realm:group-manager` |
| `no-escalation` | on | grants (direct, client role, group realm or client role, membership, a role added to a composite, the `role` of an identity provider mapper) only within the caller's effective roles; no touching users who outrank them (including their credentials, lockout, consents and organization membership); no self-grants |
| `self-protection` | on | a caller deleting or disabling their own account (`user_delete`, `user_set_enabled`, `user_update` with `enabled=false`) or deleting one of their own credentials (`user_credential_delete`), or removing their own administrative access (`realm:admin`, `realm-management.*`, master `<realm>-realm.*`, super roles; directly, by leaving a group that grants one, by deleting a group whose subtree grants one to them, by taking one from a group they belong to, or by taking one out of a composite role they hold) is caught; a caller or group the directory cannot resolve is caught too, and a group or composite role whose mappings cannot be read fails the call (`access_check_failed`) rather than passing as harmless. Other roles and groups of their own callers may drop; super roles do not bypass it |
| `self-protection.mode` | `reject` | `confirm` lets the call through only after the human confirmed it themselves, by elicitation or a confirmer that asks them such as [CIBA](ciba-confirmation.md), never by the model's `confirm: true` |
| `self-protection.tools` | | more tools the guard covers, `<tool>=<user argument>` comma separated (a tool of another provider is caught whenever it acts on the caller); `<tool>=` removes a built-in one |
| `<each>.anonymous` | `allow` | `deny`: guarded tools are refused without a known caller |
| `<each>.super-roles` | `realm:admin, realm-management.realm-admin` | holders bypass the group scope and escalation checks; for self-protection they count as administrative access |

```properties
kc-mcp.spi.access-check.group-scope.default=on
kc-mcp.spi.access-check.group-scope.scope=organization
kc-mcp.spi.access-check.group-scope.manager-role=realm:group-manager
# prod asks the human instead of refusing
kc-mcp.systems.prod.access.self-protection.mode=confirm
```

The settings of old, `kc-mcp.spi.tools.policies.*`, are gone: one still set stops the start and names its
replacement.

Denials: `group_out_of_scope`, `manager_role_required`, `privilege_escalation`, `target_outranks_caller`, `self_grant`,
`self_protection`, `caller_unknown`, `caller_foreign_realm`, `caller_required`. Effective roles come from Keycloak: direct, through groups,
composite; a caller's group memberships are read in full, page by page, never only the first page.

## Callers

`CallerProvider` reads the Quarkus `SecurityIdentity`: subject, username, issuing realm, roles. The OIDC tenant is off
by default, so the endpoint is anonymous. `QUARKUS_OIDC_TENANT_ENABLED=true` verifies bearer tokens of
the default system's auth realm, `<url>/realms/<auth-realm>` (`quarkus.oidc.auth-server-url` to change it, `QUARKUS_OIDC_TOKEN_AUDIENCE` to
require an audience). `KC_MCP_DELEGATION` then decides whose identity reaches Keycloak:

| | `off` (default) | `forward` | `exchange` |
|---|---|---|---|
| admin calls run as | the service account | the caller's own token | a delegated token Keycloak exchanges the caller's for: `sub` the caller, `act` the server's client |
| roles that count | the service account's (role filter) | the caller's `realm-management` roles from their token, per call; Keycloak enforces again | the delegated token's: the caller's roles within the client's role scope; Keycloak enforces again |
| anonymous requests | allowed unless `KC_MCP_REQUIRE_CALLER=true` or `KC_MCP_SECURITY_PROFILE=shared` | `401` with `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource"` | as forward |
| server credentials | required | optional (the policies provider falls back to them for lookups) | the client's `client_credentials` (secret or `private_key_jwt`); no admin role on it |
| Keycloak side | | a public client with an *Audience* mapper for the server | plus consent on that client, *Standard Token Exchange* on the server's client, an Admin Permissions `delegate` grant for it; Keycloak 26.8+ with `--features=token-exchange-delegation,parameterized-scopes` (preview) |

- **The login.** The `401` challenge drives OAuth-capable MCP clients: they discover the realm, log the user in in the
  browser with code and PKCE, and retry. Per client: [Integrations](integrations.md).
- **Keycloak side.** A public client with an *Audience* mapper for the server (`mcp-consumer` in
  `examples/run-modes/realms/demo-realm.json`); the humans hold the `realm-management` roles, groups preferred.
- **One Keycloak per token.** A caller's token is forwarded only to the system whose Keycloak issued it, compared by
  the issuer's base: the system's URL or its configured `issuer` (set it when the server reaches Keycloak at an
  internal address, as the tokens carry the public one). What the default OIDC tenant verifies does not count: it
  may be another Keycloak. A token whose issuer cannot be read is not forwarded at all. A call that names another
  system answers `caller_foreign_system` before anything is sent; the caller logs in at that system's entry instead. `kc-mcp.systems.<name>.trusted-issuers` names further issuers
  whose tokens the server may hand to that system, a realm's issuer URL for that realm alone or a Keycloak's base URL
  for all of its realms, and a `CallerIssuerPolicy` extension replaces the rule
  ([Extending](extending.md#caller-issuer-policies)). Both decide what the server sends, not what Keycloak accepts:
  that is Keycloak's identity provider and JWT authorization grant configuration (RFC 7523, Keycloak 26.5 preview),
  which the server does not drive yet, so an entry Keycloak does not honour only moves the refusal there.
- **Audit.** The line names the human: `caller=alice(<sub>) delegated`.
- **Exchange mode.** The MCP client must request the scope `delegation:client:<client id>`, advertised as
  `scopes_supported` in the protected resource metadata, and the user consents at login, every session. Without that
  the token has no `may_act` claim and every tool answers `delegation_failed` with what to do; `whoami` shows
  `delegation: {consented, actor}`. Keycloak's `TOKEN_EXCHANGE` event names the actor, its admin events the user.
  Walkthrough and Keycloak setup: `examples/delegated-auth/`.
- **In code.** `Caller` offers `claims()`, `claim("department")` and `rawToken()`; `toString()` never prints the token,
  and audit events get `withoutToken()`. Per-caller admin clients are cached until the token expires.
