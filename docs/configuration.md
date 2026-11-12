# Configuration

[keycloak-mcp-server](../README.md) › documentation

Every property, its default and meaning. Property → environment variable: `kc-mcp.systems.default.url` →
`KC_MCP_SYSTEMS_DEFAULT_URL` (a system name from the environment is lower-case letters and digits).

Where a setting comes from, the first one found wins:

1. the command line: `bin/kcmcp.sh start --kc-mcp.tool-exposure=lazy`, or `java -Dkc-mcp.tool-exposure=lazy -jar ...`
2. the environment: `KC_MCP_TOOL_EXPOSURE=lazy`, also from a `.env` file in the working directory, which ranks just below it
3. the configuration files, `conf/kcmcp.conf` and those given with `--config`, a later file over an earlier one
4. the server's defaults

An option other than `--kc-mcp.*` and `--quarkus.*` is refused; other Java system properties take `-D`. Secrets are
better kept in a file or the environment, since a command line is visible in the process list and the shell history.

Run the server with a command, `start` or `start-dev`, also with `java -jar quarkus-run.jar start`; without one it prints
the help. The launch scripts add `build`, which fixes the database kind ([Storage](storage.md)).

### Development mode (`start-dev`)

`bin/kcmcp.sh start-dev` runs the same configuration with less to set up, for trying the server on one person's
machine; it sets `kc-mcp.dev-mode=true`. Compared to `start`:

- the `local` security profile applies whatever the files say, and the startup checks warn instead of stopping the
  start: a setting the `shared` profile would insist on, or a Keycloak that is down, is a warning
- without any configured system, the Keycloak of the examples is assumed: system `default` at
  `http://localhost:8080`, the server's client in `master`; a system of any name, or `kc-mcp.static-systems=false`,
  switches this off
- in a distribution built for H2 (the default; not after `build --db=postgresql`), unless `kc-mcp.storage.enabled=false`:
  - a database in `data/` ([Storage](storage.md)): signing keys, secrets, audit and sessions survive a restart;
    without `kc-mcp.storage.secret-key` it keeps them unencrypted, which the `local` profile only warns about
  - the management UI at `/ui/` ([Management UI](management-ui.md)); the realm needs its client `keycloak-mcp-ui`
  - `kc-mcp.dynamic-systems=true`: the admin API and the UI's *Add system* register systems in that database, next to
    the configured ones, which keep precedence ([Several Keycloak systems](systems.md)); the `local` profile does not
    require `kc-mcp.allowed-hosts`, so they may point at any host
- the UI's session cookies drop `Secure`, so it works over plain HTTP

Whatever is configured wins over each of these: a `quarkus.datasource.jdbc.url` replaces the H2 file (for PostgreSQL
after `build --db=postgresql`), `kc-mcp.ui.enabled=false` or `kc-mcp.dynamic-systems=false` keep the UI or the
registration off, and a certificate (`conf/scenarios/https.conf.example`) serves HTTPS. `bin/kcmcp.sh show-config`
names `kc-mcp start-dev` as the source of what development mode assumed. Not for a server other people reach: use
`start` with a [scenario](scenarios.md) there.

`./mvnw quarkus:dev` is something else, the live-reload mode for working on the server's code
([Development](development.md)).

A setting that does not exist stops the start, whether from a file or the command line, which also suggests the closest
name; in the environment it is a warning, and `kc-mcp.spi.*` is not checked, since extensions define those keys.

`bin/kcmcp.sh show-config` prints each `kc-mcp.*` setting in effect and where it comes from, without starting the server;
`show-config all` adds the `quarkus.*` ones. Secrets are masked by name, and every `kc-mcp.spi.*` value.

`bin/kcmcp.sh validate` runs the startup checks, reports every problem and exits non-zero if there is one; it
also checks the access blocks and presets of the systems in the database (when it can be read) and the systems
file, which do not stop a normal start. It opens no
port, runs no migration and changes no data; `--offline` leaves out the checks that contact Keycloak. It does not test
the database connection.

| property                        | default                     | meaning |
|---------------------------------|-----------------------------|---------|
| `kc-mcp.systems.<name>.url`     |                             | a Keycloak system: base URL, context path included (`https://sso.example.com/auth`); a system exists when its url is set, one Keycloak is usually named `default` ([Several Keycloak systems](systems.md)) |
| `kc-mcp.systems.<name>.auth-realm` | `master`                 | realm of the system's client / admin user |
| `kc-mcp.systems.<name>.grant-type` | `client_credentials`     | or `password` (deprecated by OAuth 2.1; local dev only, refused by the `shared` profile): one Keycloak session for the admin user, renewed with its refresh token and logged out when the server stops |
| `kc-mcp.systems.<name>.client-auth` | inferred                | `client_secret`, `private_key_jwt`, `none` |
| `kc-mcp.systems.<name>.client-id` | `admin-cli` for password+none | client id |
| `kc-mcp.systems.<name>.client-secret` |                       | for `client_secret` |
| `kc-mcp.systems.<name>.username` / `password` |               | password grant |
| `kc-mcp.systems.<name>.default-realm` |                       | makes `realm` optional for this system |
| `kc-mcp.systems.<name>.allowed-realms` | all                  | csv allow-list of this system's realms |
| `kc-mcp.systems.<name>.trusted-issuers` |                     | issuers besides the system's own Keycloak whose caller tokens the server may hand to it (default none): a realm's issuer URL for that realm alone, a Keycloak's base URL for all of its realms; whether Keycloak accepts them is configured in Keycloak |
| `kc-mcp.systems.<name>.access.<check>.*` |                     | which access checks govern the system, in which order and with which settings (`enabled`, `order`, the check's own, e.g. `access.authorization.authzen.url`) over `kc-mcp.spi.access-check.<check>.*` ([Access checks](access-checks.md)) |
| `kc-mcp.systems.<name>.realms.<realm>.*` |                     | settings of one realm: `realm-id`, `display-name`, `description`, `preset`, and `access.<check>.*` over the system's ([Realm settings](authzen.md#realm-settings)) |
| `kc-mcp.systems.<name>.preset`, `...realms.<realm>.preset` |  | the preset the system's or realm's `access` goes over ([Presets](access-checks.md#presets)) |
| `kc-mcp.systems.<name>.presets.<preset>.*` |  | the system's own presets: `extends`, `access.<check>.<key>`, `tools.<key>` |
| `kc-mcp.presets.<preset>.*` |  | presets every system can reference: `extends`, `access.<check>.<key>`, `tools.<key>` ([Presets](access-checks.md#presets)) |
| `kc-mcp.systems.<name>.tools.*`, `...realms.<realm>.tools.*` |  | tool restrictions over the server's, which they can only narrow: `read-only`, `allowed`, `denied`, `categories`, `unlisted`, `confirm`, `confirm-writes` ([Security](security.md#tool-restrictions-per-system-and-realm)) |
| `kc-mcp.systems.<name>.issuer`  | `<url>/realms/<auth-realm>` | realm issuer as Keycloak states it, audience of `private_key_jwt` assertions; set when the url is internal |
| `kc-mcp.systems.<name>.version` | read from server            | Keycloak version override / fallback ([Supported Keycloak versions](keycloak-versions.md)) |
| `kc-mcp.system-defaults.*`      |                             | the same keys except `url`, shared by every system that does not set its own |
| `kc-mcp.default-system`         | the only system | system when `system` is omitted; the OIDC default tenant verifies callers against its auth realm. Several systems have no default without it (a system called `default` is not picked by its name); with caller login they need it or `quarkus.oidc.auth-server-url` |
| `kc-mcp.jwt.key-file`           |                             | PKCS#8 PEM private key for `private_key_jwt` |
| `kc-mcp.jwt.keystore-file` / `keystore-password` / `key-alias` / `key-password` / `keystore-type` | | keystore alternative |
| `kc-mcp.jwt.algorithm`          | `RS256`                     | RS256/384/512, PS256/384/512, ES256/384/512 |
| `kc-mcp.jwt.key-id`             | JWK thumbprint              | `kid` in assertion header and JWKS |
| `kc-mcp.jwt.public-key-file`    | derived                     | public key / certificate PEM to publish |
| `kc-mcp.jwt.jwks-enabled` / `jwks-path` | `true` / `/.well-known/jwks.json` | configured key (else default system's) at `jwks-path`; every system at `/auth/keys/<system>/jwks.json` |
| `kc-mcp.jwt.key-size`           | `2048`                      | RSA modulus bits of generated keys; algorithm decides RSA vs EC curve |
| `kc-mcp.dynamic-systems`        | `false`                     | let `KeycloakSystemRepository`s add systems |
| `kc-mcp.systems-file`           |                             | JSON file (`{"systems": [...]}`) of the file repository, re-read on change; needs `dynamic-systems` |
| `kc-mcp.static-systems-order`   | `-1000`                     | rank of static configuration among repositories (lower first, repositories default 0) |
| `kc-mcp.static-systems`         | `true`                      | `false`: repositories only |
| `kc-mcp.keys-dir`               | `data/keys`                 | read-only built-in `KeyVault`: `<system>.pem`, `secrets/<name>` |
| `quarkus.datasource.jdbc.url`   |                             | turns database storage on: `jdbc:h2:file:./data/kc-mcp`, or `jdbc:postgresql://...` after `bin/kcmcp.sh build --db=postgresql` (from source: `-Ppostgresql`) (+ `quarkus.datasource.username`/`password`) |
| `kc-mcp.storage.enabled`        | `true` with a jdbc url      | force storage on or off |
| `kc-mcp.storage.secret-key`     |                             | AES-256-GCM key for stored private keys, client secrets, passwords; base64 of 32 bytes or passphrase (Argon2id) |
| `kc-mcp.storage.previous-secret-keys` |                       | rotated-away keys (csv) that still decrypt; rows are rewritten under `secret-key` at startup and by `POST /admin/storage/rekey` |
| `kc-mcp.spi.audit-scrubber.pii.pseudonym-key` | `secret-key`   | HMAC key of the audit pseudonyms, independent of storage key rotation |
| `kc-mcp.instance-role`          | `all`                       | what this instance serves: `all`, `mcp` (the MCP endpoint only: admin API and UI off) or `admin` (admin API on, MCP endpoint off, the UI as configured); a switch below set against the role stops the start ([Several instances](storage.md#several-instances-on-one-database)) |
| `kc-mcp.mcp.enabled`            | `true`                      | `false`: the MCP endpoint and its entries answer a plain 404 (no hint at what else the instance serves); for an instance that serves only the admin API or the UI ([Several instances](storage.md#several-instances-on-one-database)) |
| `kc-mcp.admin.enabled` / `token` / `issuer` / `audience` / `role` | `false` / / / / `realm:admin` | admin API at `/admin`: static token and/or trusted issuer with role |
| `kc-mcp.admin.allow-new-systems` | `true`                     | `false`: the admin API changes known systems only, new aliases answer 403 `registration_closed` |
| `quarkus.mcp.server.http.root-path` | `/mcp`                  | where the MCP endpoint lives (build time); the entries, the caller authentication and the DNS rebinding protection follow it, as they do `quarkus.http.root-path` in front of everything. Known gap behind such a prefix: Quarkus writes the `resource` of an entry's protected resource metadata without the prefix, which a client that compares it with the URL it connected to may reject |
| `kc-mcp.admin.openapi`          | `true`                      | `false`: the admin API's OpenAPI document (`/q/openapi`) and Swagger UI (`/q/swagger-ui`) answer 404 ([Several Keycloak systems](systems.md)) |
| `kc-mcp.spi.system-repository.db.cache-seconds` | `10`                  | snapshot age of stored systems |
| `kc-mcp.spi.audit-listener.db.retention-days` |                        | delete audit rows older than this (startup, then hourly); unset keeps all |
| `kc-mcp.spi.key-vault.db.retired-key-grace-seconds` | `3600`    | how long a rotated-away key stays in the JWKS |
| `kc-mcp.spi.audit-scrubber.pii.mode` | `keep`                  | `keep`, `pseudonymize`, `drop`; `args` argument names, `targets` listeners (default `db`) |
| `kc-mcp.delegation`             | `off`                       | `forward`: calls run with the caller's token; `exchange`: with a delegated token Keycloak issues for caller + server client (26.8 token exchange delegation); both need `quarkus.oidc.tenant-enabled=true` |
| `kc-mcp.admin-api-scope`        | `kc-admin-api`              | scope requested with Admin API tokens and advertised to MCP clients (Keycloak 26.8.2+ audience check); dropped on `invalid_scope`; blank: none |
| `kc-mcp.dns-rebinding-protection` | `auto`                    | `auto` (on while anonymous), `on`, `off`: `Host`/`Origin` of MCP requests must be localhost or in `kc-mcp.dns-rebinding-allowed-hosts` |
| `kc-mcp.dev-mode`               | `false`                     | what `bin/kcmcp.sh start-dev` sets; see [Development mode](#development-mode-start-dev) |
| `kc-mcp.security-profile`       | `local`                     | `local` or `shared`: defaults of the four rows below, and `shared` refuses to start without caller authentication + audience (on instances that serve the MCP endpoint, see `kc-mcp.instance-role`), `allowed-hosts`, admin audience, storage `secret-key` ([Guardrails](security.md#guardrails)) |
| `kc-mcp.require-caller`         | `false`, `shared`: always   | refuse anonymous requests with the OAuth challenge even with `delegation=off` |
| `kc-mcp.confirm-fallback`       | `flag`, `shared`: `deny`    | without elicitation: `flag` accepts `confirm: true`, `deny` refuses destructive tools |
| `kc-mcp.explicit-target`        | `off`, `shared`: `destructive` | `destructive` or `write` tools must pass `system` (several systems) and `realm` instead of the defaults |
| `kc-mcp.dynamic-private-hosts`  | `allow`, `shared`: `listed` | `listed`: a runtime-registered system on a private, loopback or link-local address needs its host named literally in `allowed-hosts` |
| `kc-mcp.model-confirmation`     | `auto`                      | guidance to the model about destructive tools: `ask`, `server`, `auto` ([Guardrails](security.md#guardrails)) |
| `kc-mcp.model-confirmation-trusted-roles` |                   | role refs whose holders are told to pass `confirm: true` right away in `ask` mode |
| `quarkus.oidc.tenant-enabled`   | `false`                     | verify bearer tokens of the default system's auth realm (`quarkus.oidc.auth-server-url`, derived unless set) |
| `quarkus.oidc.token.audience`   |                             | required `aud` (recommended with `forward`) |
| `quarkus.oidc.token.issuer`     |                             | public issuer when the system url is internal (Docker) |
| `quarkus.oidc.resource-metadata.authorization-server` | `quarkus.oidc.auth-server-url` | login address MCP clients are sent to; the public issuer when the system url is internal |
| `kc-mcp.explanations`           | `auto`                      | refusal wording: `admins` (config details, `howToFix`), `users` (plain words), `auto` (by caller roles in delegation mode, else admins) |
| `kc-mcp.allowed-hosts`          | any                         | `[scheme://]host[:port]` patterns with `*`, checked at startup |
| `kc-mcp.tool-prefix`            |                             | prefix for all tool names (`prod_`) |
| `kc-mcp.read-only`              | `false`                     | |
| `kc-mcp.allowed-tools` / `denied-tools` / `allowed-categories` | all | explicit narrowing; systems and realms can narrow further (`tools`) |
| `kc-mcp.unlisted-tools` | `deny` with `allowed-tools`, else `allow` | what happens to tools `allowed-tools` does not name: `allow`, `read` (only if they read), `deny` ([New, removed and renamed tools](security.md#new-removed-and-renamed-tools)) |
| `kc-mcp.confirm-tools` | | tools that need confirmation as destructive ones do ([Confirming destructive tools](security.md#confirming-destructive-tools)) |
| `kc-mcp.confirm-writes` | `false` | every tool that changes Keycloak needs confirmation |
| `kc-mcp.role-filter`            | `true`                      | hide/refuse tools the token's roles do not cover |
| `kc-mcp.startup-check`          | `warn`                      | `warn`, `fail`, `off` |
| `kc-mcp.tool-exposure`          | `hybrid`                    | `direct` / `lazy` / `hybrid` / `progressive` |
| `kc-mcp.hot-tools`              | user_search, user_get, realm_get_config, server_info | listed directly in hybrid mode |
| `kc-mcp.search-limit-default`   | `5`                         | hits per `search_tools` (max 10) |
| `kc-mcp.result-max-items`       | `100`                       | cap for list results |
| `kc-mcp.structured-content`     | `true`                      | mirror results as `structuredContent` |
| `kc-mcp.confirm-timeout-seconds`| `120`                       | elicitation timeout |
| `kc-mcp.config-files`           |                             | comma-separated properties files read at startup, between the built-in defaults and the environment; a directory stands for its `*.conf` and `*.properties` files in name order; a later file overrides an earlier one (the distribution's `conf/kcmcp.conf`, then its `--config` files); a missing path stops the start; a path cannot contain a comma |
| `kc-mcp.providers-dir`          | `providers`                 | extension jars ([Extension jars](extending.md#extension-jars-providers)) |
| `kc-mcp.prompts-dir`            | `prompts`                   | prompts as text files, one `.md` per prompt; resolved like `providers-dir`, the distribution sets `conf/prompts` ([Prompts as text files](tools.md#prompts-as-text-files)) |
| `kc-mcp.prompt-overrides`       | `true`                      | a later prompt replaces an earlier one of the same name, logged at startup; `false`: a name used twice stops the start |
| `kc-mcp.spi.<spi>.provider`    | lowest `order()`            | which extension serves `key-vault`, `key-generator`, `session-store` or `approval-store` ([Extending](extending.md)) |
| `kc-mcp.spi.<spi>.<id>.<key>`         |                             | per extension; `enabled=false` disables; id kebab-case (`acmeTicketChecker` → `acme-ticket-checker`, env `KC_MCP_SPI_ACCESS_CHECK_ACME_TICKET_CHECKER_*`, resolved by the server) |
| `quarkus.http.cors.origins`     | local origins               | browser MCP clients; set to the client origin(s) in production |
| `quarkus.otel.sdk.disabled`     | `true`                      | `false` exports metrics and traces to `quarkus.otel.exporter.otlp.endpoint` ([Metrics](metrics.md)) |
| `kc-mcp.metrics.include-realm` | `false`                    | tool call metrics carry the realm |
| `kc-mcp.ui.trace-url`           |                             | where the Audit page links an event's trace: a URL with `{traceId}` (and `{spanId}`), e.g. `https://jaeger.example.com/trace/{traceId}`; unset: the ids without a link |
| `kc-mcp.ui.viewer-role`         |                             | optional read-only management UI role (`realm:<role>` or `<client>.<role>`); unset: only `kc-mcp.admin.role` opens `/bff/api` |
| `kc-mcp.ui.tls-configuration-name` |                        | named `quarkus.tls` configuration (trust store) for the server's own calls to the UI's identity providers: discovery, keys, session checks |
| `kc-mcp.truststore-paths`       |                             | additional trusted certificates for outbound TLS: PEM or unencrypted PKCS12 files, directories ([HTTPS and trusted certificates](tls.md)) |
| `kc-mcp.hostname`               | from each request           | the address clients use, `scheme://host[:port]`: links in the login metadata and the 401 challenge, JWKS URLs ([The public address](tls.md#the-public-address)) |
| `kc-mcp.https-*`, `kc-mcp.http-enabled` |                     | HTTPS for the server, Keycloak's option names ([HTTPS and trusted certificates](tls.md)) |
| `kc-mcp.http.connect-timeout` / `read-timeout` | `10s` / `60s` | outbound HTTP of the server's own clients (`10s`, `500ms`, `2m`, `PT1M`): CIBA, the UI's provider calls, and the read timeout of the Keycloak admin client (its connect timeout is the client's built-in 15 s); the read default leaves room for long admin calls such as a directory sync |
| `kc-mcp.ui.connect-timeout` / `read-timeout` | `kc-mcp.http.*` | the same for the UI's calls to its identity providers |

```properties
# one Keycloak, a service account with a secret (recommended)
kc-mcp.systems.default.url=https://sso.example.com
kc-mcp.systems.default.auth-realm=demo
kc-mcp.systems.default.client-id=mcp-admin
kc-mcp.systems.default.client-secret=...

# the same with private_key_jwt
kc-mcp.systems.default.client-auth=private_key_jwt
kc-mcp.jwt.key-file=/etc/keycloak-mcp/mcp-admin.pem
# Keycloak: client mcp-admin -> Credentials -> "Signed JWT", "Use JWKS URL" on,
# JWKS URL = https://<this server>/.well-known/jwks.json (or import the key it prints);
# Client scopes -> add kc-admin-api as default (Keycloak 26.8.2+)

# local dev: the admin user via admin-cli
kc-mcp.systems.default.url=http://localhost:8080
kc-mcp.systems.default.grant-type=password
kc-mcp.systems.default.username=admin
kc-mcp.systems.default.password=admin

# several systems sharing one client setup
kc-mcp.system-defaults.client-id=keycloak-mcp-server
kc-mcp.system-defaults.client-auth=private_key_jwt
kc-mcp.systems.prod.url=https://sso.example.com
kc-mcp.systems.staging.url=https://sso-staging.example.com
kc-mcp.default-system=prod
```

Port 8081 (`quarkus.http.port`), endpoint `http://localhost:8081/mcp`. Service account roles: [Access levels](security.md#access-levels).
