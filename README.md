# keycloak-mcp-server

[![CI](https://github.com/thomasdarimont/keycloak-mcp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/thomasdarimont/keycloak-mcp-server/actions/workflows/ci.yml)

An [MCP](https://modelcontextprotocol.io) server that lets an AI assistant administer Keycloak: users, groups, roles,
clients, identity providers, organizations, authentication flows, events and realm settings. A comprehensive set of tools over the Admin
REST API (after [mcp-keycloak-admin](https://github.com/edewit/mcp-keycloak-admin)), built with Quarkus for Keycloak 26.8,
reached over streamable HTTP, and shaped so that small local models can use them too.

The intended setup is **one shared MCP server per environment**: one for dev, one for test, one for QA, one for
production, each in front of the Keycloak systems of that environment (several installations, tenants, clusters) and
their realms. Users log in to it through their MCP client, every Admin API call runs with their own roles, and
policies, confirmations and audit sit in one place instead of on every laptop. The server itself holds no state: systems,
keys, secrets, UI sessions, pending approvals and the audit trail live in a shared database
([Database storage](docs/storage.md), PostgreSQL for several instances), so it can be deployed in a HA setup behind a
load balancer; clients that still hold MCP sessions need it to route them back to the instance that opened them
([Several instances](docs/storage.md#several-instances-on-one-database)).
The same server also runs locally for a single administrator, which is where the quick start below begins.

- **Several Keycloak systems per server.** The systems of an environment are configured or registered at runtime,
  each with its own signing key; the model names the system, or a client gets an MCP entry bound to one system or
  realm. The `shared` profile refuses to start without authentication and the other settings a server other people
  reach needs.
- **The user's own identity, or a service account.** Users log in through their MCP client, so every Admin API call
  runs with their own token and Keycloak enforces their roles; destructive tools can be approved on the user's own
  device through CIBA. As a *delegated agent*, the server instead acts for the user with a token Keycloak exchanges
  for it: the user consents, the token names both (`sub` the user, `act` the server's client), the server's own role
  scope caps what it may do, and Keycloak's events show who acted for whom. A service account is the alternative for a
  local or single-purpose setup.
- **Guardrails by default.** Destructive tools need a confirmation, every call is audited with secrets redacted, roles
  the identity lacks hide the tools they would need, and allow-lists fence in realms, hosts and tools.
- **Small models cope.** By default the model sees three tools: `whoami`, `search_tools` and `execute_tool`. It searches
  for what it needs ("kick a user" finds the logout tool), identifiers are forgiving (user by id or username, group by
  path), errors are structured and results compact.
- **Extensible.** An SPI for your own tools, prompts, access checks, confirmers, audit sinks and system registries,
  loaded from a jar.

## Quick start

The shortest path is local, in the shape the server is meant for: one Keycloak, the server on your machine, and you
logging in through your MCP client, so every call runs with your own roles. Needs Java 21 and Docker.

1. Start the demo Keycloak (realm `demo` with users, groups and the public client `mcp-consumer` that MCP clients log in
   with):

   ```shell
   cd examples/run-modes && docker compose up -d && cd ../..
   ```

2. Run the server with the user's own login. It holds no admin credentials: every Admin API call is made with the token
   of the person who logged in, and Keycloak enforces their roles. Keycloak has to be up first, the server reads the
   realm's discovery document at startup.

   ```shell
   set -a; source examples/run-modes/env/user-forward.env; set +a
   ./mvnw quarkus:dev -pl modules/backend -am        # MCP endpoint: http://localhost:8081/mcp
   ```

3. Connect an MCP client and log in. The browser opens on connect; log in as `alice / alice-demo` (realm admin) or
   `carol / carol-demo` (may only view).

   - LM Studio: add `examples/run-modes/mcp-oauth.json` to its MCP settings:
     ```json
     { "mcpServers": { "keycloak": { "url": "http://localhost:8081/mcp", "auth": { "CLIENT_ID": "mcp-consumer" } } } }
     ```
   - Claude Code: `claude mcp add --transport http --client-id mcp-consumer --callback-port 33418 keycloak http://localhost:8081/mcp`,
     then `/mcp` inside a session starts the login
   - VS Code with GitHub Copilot: add the server to `.vscode/mcp.json` (or the user profile's `mcp.json`):
     ```json
     { "servers": { "keycloak": { "type": "http", "url": "http://localhost:8081/mcp" } } }
     ```
     Start it from the file or the *MCP: List Servers* command. Keycloak refuses VS Code's dynamic client registration,
     so VS Code then asks for a client ID: enter `mcp-consumer` and leave the secret empty. Use the tools from the chat
     in *Agent* mode.
   - Cursor, Codex, Claude Desktop: [Integrations](docs/integrations.md)

4. Ask it something: "who am I" lists your roles with readable labels, "find users named ali", "which groups is alice
   in"; "disable bob" works as alice and comes back `forbidden` as carol, naming the role she lacks.

A service account instead of the login, for a client without OAuth or a single-purpose setup, is one env file away:
`examples/run-modes/env/realm-admin.env` with the plain `examples/run-modes/mcp.json`. The other access levels (full
admin, realm manager, read-only, two systems, `private_key_jwt`) are in [examples/run-modes](examples/run-modes/README.md).

**Without a build:** the [releases](https://github.com/thomasdarimont/keycloak-mcp-server/releases) carry a
`keycloak-mcp-server-<version>.tar.gz` and `.zip`. Unpack, edit `conf/kcmcp.conf` or copy a ready-made setup from
the templates in `conf/scenarios/`, and start with `bin/kcmcp.sh start` (`bin\kcmcp.bat` on Windows); the archive's
README explains the layout. `./mvnw package -Pdist` builds the same archives into `modules/distribution/target/`.

For a shared server per environment, start from `examples/run-modes/env/shared.env` (users log in, profile `shared`) and read
[Security](docs/security.md) for what the profile requires, [Several Keycloak systems](docs/systems.md) for adding
systems and per-system entries, and [multi-tenant](examples/multi-tenant/) or [dynamic-systems](examples/dynamic-systems/)
for a complete stack.

## How it works

- **The model's view.** `tools/list` depends on the exposure mode: `hybrid` (default) lists `search_tools`,
  `execute_tool`, `whoami` and a few hot tools; `direct` lists every tool. `whoami` tells the model who it acts as and
  which tools that unlocks. [Tools](docs/tools.md)
- **One pipeline for every call.** Access policy, argument validation, realm check, confirmation, the handler, audit.
  Errors are structured (`unknown_tool`, `invalid_arguments`, `forbidden`, `confirmation_required`, ...) and say what
  to do next. [Tools](docs/tools.md), [Security](docs/security.md)
- **Keycloak's roles are the boundary.** The server acts with a service account, with the signed-in user's token
  (`forward`), or with a delegated token Keycloak issues for the user and the server's client together (`exchange`,
  Keycloak's token exchange delegation); the `realm-management` roles of that identity decide what works, server
  flags only narrow further. [Security](docs/security.md), [delegated-auth](examples/delegated-auth/)
- **Destructive tools ask first.** Through the client's elicitation, a `confirm: true` flag (local profile), an own
  `Confirmer` such as a ticket check, or CIBA on the user's device. [CIBA confirmation](docs/ciba-confirmation.md)

## Documentation

| page | what it covers |
|---|---|
| [Scenarios in pictures](docs/scenarios.md) | diagrams of the ways the server runs: service account, user login, delegated agent, several systems, a shared deployment, registration, CIBA, read-only troubleshooting, the call pipeline |
| [Tools](docs/tools.md) | what the model sees, the tool areas, prompts |
| [Integrations](docs/integrations.md) | adding the server to LM Studio, Claude Code, Claude Desktop, VS Code and Copilot, Cursor, Codex; the login's Keycloak side |
| [Security](docs/security.md) | guardrails, profiles `local` and `shared`, access levels, per-tool checks, policies, callers and delegation |
| [Configuration](docs/configuration.md) | every property with default and meaning |
| [HTTPS and trusted certificates](docs/tls.md) | HTTPS for the server, a Keycloak behind a private CA |
| [Several Keycloak systems](docs/systems.md) | static and dynamic systems, per-system keys, the admin API, one MCP entry per system or realm |
| [Database storage](docs/storage.md) | H2 or PostgreSQL for systems, keys, secrets, audit and sessions; encryption and key rotation |
| [Management UI](docs/management-ui.md) | the browser UI and its backend-for-frontend; work in progress, a login skeleton today |
| [CIBA confirmation](docs/ciba-confirmation.md) | approval of destructive tools on the user's device |
| [Metrics](docs/metrics.md) | OpenTelemetry metrics and what they answer |
| [Extending](docs/extending.md) | the extension SPI: tools, prompts, checks, confirmers, audit listeners, extension jars |
| [Supported Keycloak versions](docs/keycloak-versions.md) | baseline, feature and version requirements, OpenAPI alignment |
| [Development](docs/development.md) | build, test, modules, formatting, roadmap |

## Examples

Runnable setups, from a first demo realm to several tenants, delegation and CIBA: [examples](examples/README.md). Start
with [run-modes](examples/run-modes/).

## Development

```shell
./mvnw test                                     # unit + in-process MCP tests, no Keycloak
./mvnw verify -DskipITs=false                   # + integration tests against Keycloak 26.8.2 in Docker
./mvnw spotless:apply                           # format; `verify` fails on unformatted code
conformance/run.sh                              # MCP conformance suite against the packaged server
```

Modules: `api` (extension SPI, no Quarkus), `storage` (database), `backend` (the Quarkus application and Lit
management UI), `distribution` (the downloadable archives). More in [Development](docs/development.md), including the
roadmap.
