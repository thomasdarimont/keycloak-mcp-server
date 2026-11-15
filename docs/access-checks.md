# Access checks per system and realm

[keycloak-mcp-server](../README.md) › [documentation](security.md)

Access checks are the per-call predicates that run after the static policy, the realm allow-list, the roles and the
delegation rules, and before the confirmation. Each one can deny a call or hand it to the human. Which checks run, in
which order and with which settings can differ per Keycloak system and per realm: a check that calls Keycloak or a
policy service may be too expensive, or not possible at all, in one environment and required in another.

## The checks

| id | what it does | runs by default |
|---|---|---|
| `self-protection` | the caller cannot lock themselves out | yes |
| `no-escalation` | grants only within the caller's own rights | yes |
| `group-scope` | group management limited to the caller's groups or organizations | no |
| `step-up` | sensitive tools only for callers who signed in strongly and recently enough ([Security](security.md#step-up-authentication)) | no |
| `rate-limit` | at most so many calls per caller and system within a time window ([Security](security.md#rate-limit)) | no |
| `authorization` | hands the call to authorization engines such as AuthZEN ([External authorization](authzen.md)) | yes, the engines decide whether they are concerned |
| extensions' checks | whatever they check ([Extending](extending.md)) | the check's own choice |

The settings of the built-in checks: [Security](security.md#built-in-policies-group-scope-no-escalation-self-protection).

Checks attached to a single tool in code (`ToolSpec.Builder.access(...)`) are part of the tool and always run.

## Three levels

1. Server: `kc-mcp.spi.access-check.<id>.*`.
2. System: the system's `access.<id>` entry.
3. Realm: the realm's `access.<id>` entry.

For each check the levels go over each other key by key: the most specific `enabled`, `order` and setting win. A
global tool (no realm) follows the system.

| server key | default | meaning |
|---|---|---|
| `enabled` | `true` | the check exists on this server; `false` removes it everywhere |
| `default` | the check's own (above) | whether it runs where neither system nor realm says otherwise: `on` or `off` |
| `order` | the check's own | where it runs, lower first; ties by id |
| `locked` | `false` | `true`: systems and realms cannot switch it off, reorder or configure it |
| any other key | | a setting of the check, the default for every system and realm |

The checks of a call run in their effective order; the first denial refuses the call.

```properties
# the ticket check exists, but only systems that ask for it run it
kc-mcp.spi.access-check.acme-ticket.default=off
kc-mcp.spi.access-check.acme-ticket.endpoint=https://tickets.example

# nobody switches the authorization check off
kc-mcp.spi.access-check.authorization.locked=true

# prod: tickets first, with its own ticket system; no group scope
kc-mcp.systems.prod.access.acme-ticket.enabled=true
kc-mcp.systems.prod.access.acme-ticket.order=5
kc-mcp.systems.prod.access.acme-ticket.endpoint=https://tickets.prod.example
kc-mcp.systems.prod.access.group-scope.enabled=false

# but in its sandbox realm the ticket system is not reachable
kc-mcp.systems.prod.realms.sandbox.access.acme-ticket.enabled=false
```

Systems file and admin API (`PUT /admin/systems/<alias>`, a realm's with `PUT /admin/systems/<alias>/realms/<realm>`):

```json
{
  "url": "https://sso.prod.example",
  "access": {
    "acme-ticket": { "enabled": true, "order": 5, "endpoint": "https://tickets.prod.example" },
    "group-scope": { "enabled": false },
    "authorization": { "enabled": true, "authzen": { "auth": "system-client", "scope": "authzen-pdp" } }
  }
}
```

## Presets

A preset is a named set of settings that systems and realms reference instead of repeating them, as a Keycloak client
profile bundles executors. It holds sections, the same ones a system or realm has: `access`, the access checks, and
`tools`, the [tool restrictions](security.md#tool-restrictions-per-system-and-realm).
(The name is not "profile": `kc-mcp.security-profile` is the security profile, and Quarkus has profiles of its own.) A preset
may extend one other preset: the parent's settings first, its own over them.

```properties
# server presets, for every system
kc-mcp.presets.customer.access.authorization.enabled=true
kc-mcp.presets.customer.access.authorization.authzen.url=https://pdp.example/stores/{realm.name}/access/v1/evaluation
kc-mcp.presets.internal.extends=customer
kc-mcp.presets.internal.access.self-protection.mode=confirm
kc-mcp.presets.sandbox.access.authorization.enabled=false
kc-mcp.presets.sandbox.access.group-scope.enabled=false
kc-mcp.presets.sandbox.tools.denied=realm_update

# the realms of prod fall into three groups
kc-mcp.systems.prod.preset=customer
kc-mcp.systems.prod.realms.corp.preset=internal
kc-mcp.systems.prod.realms.play1.preset=sandbox
kc-mcp.systems.prod.realms.play2.preset=sandbox
```

A system can define presets of its own (`kc-mcp.systems.<name>.presets.<preset>...`, or `"presets"` in the systems
file and the admin API). Names resolve in the system's own presets first, then the server's: a system preset may extend
a server preset, never the other way round, and on the server a chain stays on the server.

```json
{
  "url": "https://sso.tenant.example",
  "preset": "tenant",
  "presets": {
    "tenant": { "extends": "customer", "access": { "acme-ticket": { "enabled": true, "order": 5 } } }
  },
  "access": { "group-scope": { "enabled": false } }
}
```

A key outside a known section (`kc-mcp.presets.x.self-protection.mode`, `{"self-protection": {...}}`) is an error,
not ignored: the entry belongs under `access`, a tool restriction under `tools`.

Every section follows the same order. What applies to a call, each over the one before, entry by entry and key by
key:

1. the server's settings (`kc-mcp.spi.access-check.<id>.*`, `kc-mcp.read-only`, ...)
2. the system's preset (with its parents)
3. the system's own section
4. the realm's preset (with its parents)
5. the realm's own section

The sections differ in what the server's level means. Access checks are configured there, so a lower level can switch
a check off unless the operator locked it. Tool restrictions only narrow the server's, so the server's level is a
floor no lower level lifts. A new section picks one of the two and says so.

A realm without a preset or `access` of its own gets the system's.

### Cycles and other mistakes

Resolving a preset walks its `extends` chain with the presets already seen; meeting one again is a cycle, an error that
names the chain (`a -> b -> c -> a`), and so is a chain longer than 16. Presets are checked where they enter the
server, so that a cycle never reaches a call:

- at startup, the server's presets and those of configured systems: the start stops;
- in the admin API, before a system or realm is stored: `preset_cycle`, `unknown_preset`; replacing a system without a
  preset one of its realms still references is refused too;
- systems from the database or the systems file do not stop a start (one tenant must not take the server down): if
  their references no longer resolve (a server preset was removed), their calls are refused
  (`access_check_unavailable`) and the log names the problem.

`bin/kcmcp.sh validate` reports all of it at once, the stored systems included, without starting the server
([Configuration](configuration.md)).

## Placeholders

Settings may hold placeholders, filled per call:

| placeholder | value |
|---|---|
| `{realm.name}` (`{realm}`) | the realm the call targets |
| `{realm.id}` | Keycloak's id of the realm: the realm's stored `realmId`, else read from Keycloak once |
| `{realm.displayName}` | the realm's display name, else its name |
| `{system.name}` (`{system}`) | the system |

`{{` is a literal `{`. A global tool has no realm: `_` stands for its name and id. In a setting that is a URL the
values are percent-encoded, so that a realm's name cannot leave its place in the URL; the admin API refuses
placeholders in a URL's host (`placeholder_in_host`). A placeholder that is not known, or has no value (a realm whose
id cannot be read), refuses the call (`access_check_failed`) rather than fill in nothing. The `${...}` syntax is
not used because the configuration itself expands it.

## What a block may not do

- Name a check the server does not have: a configured system like that stops the start, the admin API answers 400
  `unknown_access_check`, and should one get in anyway (a check removed later), its calls are denied
  (`access_check_unavailable`) rather than run without it. An entry that only switches such a check off is harmless.
- Touch a locked check (`access_check_locked`).
- In the admin API, whatever the check: URL-valued settings must pass `kc-mcp.allowed-hosts` and the private-host rule
  like the system's own URL (`host_not_allowed`, `private_host`); settings ending in `-file` would make the server
  read one of its files (`local_file_setting`); `vault:` references must exist (`unknown_secret`).

Secret settings (names ending like a secret: `...secret`, `...password`, `...token`, `...key`, and `header-value`)
may be `vault:<name>` references, resolved before the check sees them. The admin API shows literals as `***`; the
database keeps every block encrypted, and a storage key rotation rewrites them.

Whoever may register systems through the admin API can switch unlocked checks off for them. On a server that hosts
tenants, lock the checks that must hold everywhere, `self-protection` and `authorization` at least, or keep
registration closed.

## Writing a check

A check reads its effective settings for the call from `context.settings()`: the server's with the system's and the
realm's over them, a `ProviderConfig` as at startup. Read them per call to follow systems and realms; a check that
keeps reading what `configure` gave it works as before, with the server's settings only. `settings()` holds
`enabled` when the system or realm switched the check itself, for a check that tells "asked for here" from "on by the
server's default". See [Extending](extending.md#access-checks).
