# Writing extensions

A Maven project against the `api` module only, built into a jar that the server loads from its `providers/` directory.
No Quarkus, no server code: the classes are discovered through `META-INF/services` (`@AutoService`). It is a module of
this repository's build for convenience; as a project of your own, replace the parent in `pom.xml` with explicit versions.

| file | extension point | shows |
|---|---|---|
| `AcmeToolProvider` | `ToolProvider` | two tools: a READ with `roles("view-users")`, a DESTRUCTIVE with a per-tool `access` check, `ticket` argument, `KeycloakAdmin` lookups, `Views` |
| `AcmePrompts` | `PromptProvider` | a recipe with its tools attached |
| `META-INF/kc-mcp/prompts/acme_access_review.md` | prompt as a text file | a recipe without code: header, placeholders, a step that depends on an argument |
| `TicketConfirmer` | `Confirmer` | a change ticket confirms the offboarding, no ticket declines it, other tools abstain |
| `ProtectedUsersCheck` | `AccessCheck` (global) | `svc-*` users cannot be changed, whatever the caller's roles |
| `JsonLinesAuditListener` | `AuditListener` | one JSON line per call in a file |
| `NoEmailScrubber` | `AuditScrubber` | e-mail arguments masked for every sink, message dropped for the console only |
| `AcmeTenantRepository` | `KeycloakSystemRepository` | tenants from a setting, `KeycloakSystem.builder`; `isSupported` leaves it out without tenants |
| `AuditFileProfileCheck` | `ProfileCheck` | a shared server does not start while the audit file is unset or in `/tmp`; a local one warns |
| `AcmeExtensionsTest` | | all of it tested without a server |

Settings follow the id and arrive through `configure(ProviderConfig)`: `kc-mcp.spi.<spi>.<id>.<key>` in a configuration file or `KC_MCP_SPI_<SPI>_<ID>_<KEY>` (`acme` → `KC_MCP_SPI_AUDIT_LISTENER_ACME_FILE`);
`KC_MCP_SPI_<SPI>_<ID>_ENABLED=false` switches one extension off.

## Docker

```
../../mvnw -f ../../pom.xml package -DskipTests     # the server and the extension jar (target/)
docker compose up -d --build                        # Keycloak :8093 with the demo realm of examples/run-modes, MCP :8094
./demo.sh                                           # every extension once; idempotent
docker compose down -v
```

`docker-compose.yml` mounts `target/acme-keycloak-mcp-extensions-1.0-SNAPSHOT.jar` into the image's `/deployments/providers/`
and sets the extensions' `KC_MCP_SPI_*` variables; the server acts as the realm-admin service account `mcp-admin` of realm
`demo`.

## Build and run on the host

```
./mvnw package                                               # repository root: server and extension jar, with the tests
cp examples/extensions/target/acme-keycloak-mcp-extensions-1.0-SNAPSHOT.jar modules/backend/target/quarkus-app/providers/
set -a; source examples/run-modes/env/full-admin.env; set +a  # any run mode; Keycloak from examples/run-modes
KC_MCP_SPI_AUDIT_LISTENER_ACME_FILE=/tmp/acme-audit.jsonl java -jar modules/backend/target/quarkus-app/quarkus-run.jar start
```

Startup log: `Extensions directory .../providers: [acme-keycloak-mcp-extensions-1.0-SNAPSHOT.jar]` and the two tools in
the count. Try it (`mcp-call.py` from `examples/dynamic-systems`):

```
./mcp-call.py http://localhost:8081/mcp keycloak_acme_user_summary '{"realm": "demo", "username": "alice"}'
./mcp-call.py http://localhost:8081/mcp keycloak_acme_user_offboard '{"realm": "demo", "username": "bob"}'                        # declined: no ticket
./mcp-call.py http://localhost:8081/mcp keycloak_acme_user_offboard '{"realm": "demo", "username": "bob", "ticket": "ACME-42"}'  # done
./mcp-call.py http://localhost:8081/mcp keycloak_user_delete '{"realm": "demo", "id": "svc-backup", "username": "svc-backup"}'    # protected_user
tail -1 /tmp/acme-audit.jsonl
```

Dev mode instead of the jar: `KC_MCP_PROVIDERS_DIR=examples/extensions/target ./mvnw quarkus:dev -pl modules/backend -am`
(the directory's jars are loaded; `target/` holds the one jar). IntelliJ: `quarkus:dev (extensions)` in `.run/` does
exactly that against the run-modes stack, `extensions: *` run the compose demo.

## Rules of the road

- Depend on `keycloak-mcp-server-api` with `provided` scope; the server supplies it, with the Keycloak admin client and
  Vert.x JSON. Bundling them again breaks class loading.
- Handlers run on virtual threads: no `synchronized`, use `ReentrantLock` (`JsonLinesAuditListener`).
- `ToolResult.ok(map)` becomes JSON text plus `structuredContent`; `ToolResult.ok("text")` plain text; `ToolResult.done` and
  `ToolResult.error` the standard shapes.
- Tool schemas stay flat (one level, enums, no `oneOf`): small models.
- Secrets never go into results or audit arguments; password-like arguments are already `***` when a listener sees them.
- Extensions loaded from `providers/` are not CDI beans. An extension that needs injection goes on the class path as a
  Maven dependency of the backend instead, as the `storage` module does.
- Jars in `providers/` cannot be in native images.
