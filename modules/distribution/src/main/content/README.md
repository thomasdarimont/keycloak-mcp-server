# keycloak-mcp-server

An MCP server for Keycloak administration: an AI assistant manages users, groups, roles, clients, identity providers,
organizations, authentication flows, events and realm settings through it, within the roles you give it. The full
documentation is in `docs/`, starting with `docs/README.md`.

## Start

Needs Java 21 or newer.

1. Tell the server which Keycloak to use and how to authenticate: edit `conf/kcmcp.conf`, or copy a complete setup
   from `conf/scenarios/` next to it, without the `.example`, and change the URL and secret in the copy (the
   `.example` files are templates, an upgrade may replace them).
2. Start it:

   ```shell
   bin/kcmcp.sh start                                            # conf/kcmcp.conf
   cp conf/scenarios/service-account.conf.example conf/service-account.conf
   bin/kcmcp.sh start --config conf/service-account.conf
   bin\kcmcp.bat start --config conf\service-account.conf          # Windows
   ```

3. Point an MCP client at `http://localhost:8081/mcp` (`docs/integrations.md` has the settings for LM Studio, Claude
   Code, VS Code, Cursor and others). With a user login, the client opens the browser and the user signs in at Keycloak.

Any setting can go on the command line (`--kc-mcp.systems.default.url=https://sso.example.com`, `--quarkus.http.port=8082`)
or into the environment (`KC_MCP_SYSTEMS_DEFAULT_URL`). `bin/kcmcp.sh --help` lists the options, `--debug [port]` opens a debugger port.
`bin/kcmcp.sh show-config` prints the settings in effect, `bin/kcmcp.sh validate` checks them without starting the server.

The distribution is built for H2. To keep the server's data in PostgreSQL, stop the server and run
`bin/kcmcp.sh build --db=postgresql` once (`docs/storage.md`).

`bin/kcmcp.sh start-dev` runs the same configuration in development mode: the `local` security profile applies whatever
the files say, so a missing setting that the `shared` profile would refuse to start on is only warned about, a
Keycloak that is down at startup is a warning too, and without any configured system the Keycloak of the examples at
`http://localhost:8080` is assumed (system `default`, the server's client in `master`). An H2 build also gets a database
in `data/`, `kc-mcp.dynamic-systems=true` (systems registered through the admin API or the UI's *Add system* are kept
there) and the management UI at `http://localhost:8081/ui/`, without HTTPS because the session cookies drop `Secure`;
the realm needs the client `keycloak-mcp-ui` (`docs/management-ui.md`). Any of these you configure wins: a certificate
(`conf/scenarios/https.conf.example`) serves HTTPS with `Secure` cookies, and a `quarkus.datasource.jdbc.url` replaces H2
(for PostgreSQL after `build --db=postgresql`). Not for a
server other people reach. The details: `docs/configuration.md`, *Development mode*.

## Scenarios

Templates in `conf/scenarios/`, each a complete configuration to copy and adjust:

| file | setup |
|---|---|
| `local-admin.conf.example` | the Keycloak admin user, every realm; local demos only |
| `service-account.conf.example` | a confidential client inside the realm with the roles it needs; the usual single-realm setup |
| `read-only.conf.example` | a view-only service account plus the read-only switch |
| `private-key-jwt.conf.example` | the service account authenticates with a signed JWT instead of a secret |
| `several-systems.conf.example` | several Keycloak installations from one server, each tool with a `system` argument |
| `user-login.conf.example` | users log in through their MCP client; every call runs with their own roles |
| `shared-server.conf.example` | a server for a team or environment: user login plus the `shared` security profile |
| `https.conf.example` | HTTPS for the server and a Keycloak behind a private CA, on top of another scenario |
| `dynamic-systems.conf.example` | no Keycloak configured; systems are registered at runtime through the admin API or a systems file and kept in the database, each with a generated key and its own JWKS |

## Layout

| directory | holds |
|---|---|
| `bin/` | `kcmcp.sh`, `kcmcp.bat` |
| `conf/` | `kcmcp.conf`, `scenarios/` (templates), `systems/` (one file per Keycloak system), `prompts/` (your own prompts as text files), `truststores/` (additional trusted certificates), your keys and certificates |
| `lib/` | the server (Quarkus fast-jar layout); nothing to edit |
| `providers/` | extension jars, loaded at startup |
| `data/` | the embedded database, per-system keys, logs |
| `docs/` | the documentation |

## Container

The same server is available as a container image built from the repository (`modules/backend/src/main/docker/`);
the examples there run it with Docker Compose next to a Keycloak.
