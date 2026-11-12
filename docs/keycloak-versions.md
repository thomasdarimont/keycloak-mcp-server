# Supported Keycloak versions

[keycloak-mcp-server](../README.md) › documentation

The baseline, how version and feature requirements of tools are checked and explained, and how the tool surface is kept aligned with the Admin REST API of a Keycloak release.

Baseline **Keycloak 26.8** (OpenAPI alignment, integration tests against 26.8.0, 26.8.2 and nightly). Newer
expected to work; older unchecked. Since
26.8.2 the Admin API requires the `kc-admin-api` client scope on the calling client ([Access levels](security.md#access-levels)).

- At startup and every ten minutes: version and enabled features per system from the admin server info (server
  credentials), kept as a capability snapshot. `kc-mcp.system-defaults.version` / `kc-mcp.systems.<name>.version` override and fill in;
  mismatch logged.
- Tool requirements: `requiresFeatures("organization", ...)` (CLI feature names), `minVersion("26.9")`,
  `maxVersion("26")` (inclusive at the given precision; above it the refusal says "removed"). Organization tools carry
  the feature requirement.
- Unmet requirements explain, never hide:
  - `search_tools`: `allowed=false`, reason `unsupported`
  - call: error `unsupported` + `howToFix` per deployment form (`KC_FEATURE_ORGANIZATION=enabled`,
    `kc.sh start --feature-organization=enabled`, `keycloak.conf`, container, Operator CR, `--features=`), restart note,
    `keycloak_server_features` to verify, <https://www.keycloak.org/server/features>
  - `whoami`: `server` version, baseline, `unavailableTools` by reason, `howToFix`; `keycloak_server_features`:
    `howToEnable` / `howToDisable`
  - startup check: logs version and unavailable tools; below baseline is a problem (`fail` aborts)
- Wording by `kc-mcp.explanations`: `admins` technical + `howToFix`; `users` plain ("the 'organization' feature is
  switched off. A Keycloak administrator can enable it") with a hint to keep it plain; `auto` picks `users` for forward
  callers without master admin or `realm-admin`, else `admins`. Support desk: `KC_MCP_EXPLANATIONS=users`.
- Unknown capabilities never block; Keycloak decides.
- Version differences under one endpoint live in the handler (`call.capabilities()`: `atLeast("26.9")`,
  `hasFeature(...)`), one schema with optional version-specific parameters. Never two `ToolSpec`s with one name: the
  tool list must not depend on the target system.

## Keeping the tools aligned with a Keycloak version

- Every tool declares its Admin REST operations (`ToolSpec.api(...)`, `ApiOperation`): method, path, argument → path/query
  parameter, body fields written.
- `OpenApiAlignmentTest` checks against `src/test/resources/openapi/keycloak-<version>.json` (26.8.2 checked in):
  operation exists, not deprecated, parameters and body fields exist with compatible types/enums. Unexposed spec
  parameters: drift report.
- Server info and user storage sync are missing from the published document: marked `unspecified` with a reason.
- The Java admin client is versioned independently since Keycloak 26.1; this test plus Testcontainers tie the tool
  surface to a server version.

```shell
curl -o src/test/resources/openapi/keycloak-26.9.0.json https://www.keycloak.org/docs-api/26.9.0/rest-api/openapi.json
./mvnw test -Dtest=OpenApiAlignmentTest -Dsurefire.failIfNoSpecifiedTests=false -Dkeycloak.openapi.version=26.9.0
```

## Admin client and server versions

The admin client (`keycloak-admin-client`) is released on its own and is older or newer than the server it talks to.
One client version serves every system; there is no client per server version.

- Unknown fields in responses are ignored (Quarkus' object mapper), so reads work against newer servers.
- Updates never send a representation class back as it is: a newer server's fields the class lacks would be dropped
  on read and reset on write. Tools read, change and then call `KeycloakAdmin.save(representation, realm, path...)`:
  it reads the stored JSON, adds back every field the class cannot hold (nested objects field by field, lists of
  objects matched by `id`, `name` or `alias`) and sends that. Fields the class knows come from the change only, so
  a removed attribute or config key stays removed (`Representations`, `RepresentationsTest`).
  `NoTypedUpdatesTest` fails on an admin client `update(...)` in a tool; a representation built from scratch with
  only the changed fields is listed there as an exception.
- Endpoints that differ between versions: `minVersion` / `maxVersion` on the tool, or a branch on
  `call.capabilities()` in the handler (above). Calls the admin client has no binding for go through JAX-RS proxies
  (`AdminQueries`, `ScopeEvaluation`).

The integration tests run against any image:

```shell
./mvnw verify -DskipITs=false -pl modules/backend -am -Dkeycloak.image=quay.io/keycloak/keycloak:26.8.0
```

CI (`.github/workflows/keycloak-versions.yml`) runs them against the oldest baseline release (must pass) and
Keycloak's nightly build (an early warning, allowed to fail), on every pull request and every Monday.

Known differences, handled:

- Before 26.8.2 the `kc-admin-api` scope does not exist and the token request fails with `invalid_scope`; the
  first token of a new admin client is requested right away, and on a 400 the client is rebuilt without the scope.
- After 26.8 (nightly, November 2026) `GET /clients/{id}/service-account-user` is gone; the client representation
  names the user in `serviceAccountUserId` instead (`KeycloakAdmin.serviceAccountUser`, which reads the client as
  JSON, since the admin client's class lacks the field). The nightly OpenAPI document differs from 26.8.2 in this
  operation and a new `GET /clients/{id}/available-client-scopes`.
