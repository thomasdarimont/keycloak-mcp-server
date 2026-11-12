# Development

[keycloak-mcp-server](../README.md) › documentation

Building, running and testing the server; the modules; formatting; open items.

```shell
./mvnw quarkus:dev -pl modules/backend -am      # dev mode, http://localhost:8081/mcp
./mvnw test                                     # unit + in-process MCP tests, no Keycloak
./mvnw verify -DskipITs=false                   # + Testcontainers Keycloak 26.8.2 and 389 Directory Server, + storage IT on Dev Services PostgreSQL
./mvnw package && java -jar modules/backend/target/quarkus-app/quarkus-run.jar start
./mvnw package -Ppostgresql                     # PostgreSQL build
./mvnw spotless:apply                           # format; `verify` fails on unformatted code
conformance/run.sh                              # MCP conformance suite against the packaged server (conformance/README.md)
```

Dev mode needs `-pl modules/backend -am`; other goals run from the root. The tests ignore `KC_MCP_*` and `QUARKUS_*`
variables of the shell (the root pom clears every variable the examples define), so a shell that sourced an example's
env file still runs the suite; `quarkus:dev` and the packaged server do honour them. `StorageTest` (backend, in-memory H2) always runs.
IntelliJ: `.run/` holds run configurations for every example and the conformance suite (`examples/gen-run-configs.sh`).

Modules under `modules/`:

- `api`: `keycloak-mcp-server-api`, extension SPI, no Quarkus, packages `com.github.thomasdarimont.keycloak.mcp`
- `storage`: `keycloak-mcp-server-storage`, Liquibase changelog, `...mcp.storage` (switch, startup log), `.crypto`,
  `.systems`, `.keys`, `.audit`
- `backend`: `keycloak-mcp-server-backend`, Quarkus application, `...mcp.backend`
- `distribution`: `keycloak-mcp-server-distribution`, the downloadable `keycloak-mcp-server-<version>.tar.gz` and `.zip`
  (`bin/kcmcp.sh`, `bin/kcmcp.bat`, `conf/kcmcp.conf` with the `conf/scenarios/` templates, the server under `lib/`, `providers/`,
  `data/`, `docs/`), assembled from `modules/distribution/src/main/content` and the backend's `quarkus-app` by
  `./mvnw package -Pdist` (the module is behind the `dist` profile; the default build stops at the jars)

## Management UI

The UI ([Management UI](management-ui.md)) is a [Lit](https://lit.dev) app in
`modules/backend/src/main/resources/frontend` (`app/`, `index.html`), bundled by Quarkus Web Bundler from mvnpm jars: no
Node or npm, nothing to install. Work on it in `quarkus:dev` against the run-modes stack, as in
[examples/management-ui](../examples/management-ui/README.md):

```shell
etc/mkcert.sh                                         # once: a trusted localhost certificate in .certs/
cd examples/run-modes && docker compose up -d && cd ../..
set -a; source examples/management-ui/env/ui.env; set +a
./mvnw quarkus:dev -pl modules/backend -am            # https://localhost:8443/ui/, alice / alice-demo (operator)
```

- Edit a file under `frontend/` and reload the page: dev mode bundles it again, no restart. A Java change (the BFF in
  `...backend.ui`, the admin API in `...backend.admin`) restarts the server on the next request as usual. IntelliJ:
  `.run/dev-ui` (and `dev-ui-two-idps` for two identity providers).
- HTTPS is needed: outside `start-dev` the session cookie is `Secure`, and the demo realm's client `keycloak-mcp-ui`
  only accepts `https://localhost:8443` as redirect URI. `carol` / `carol-demo` signs in as viewer (read-only), to see
  what the UI hides without `systems:write`.
- The bundler strips TypeScript types without checking them: a type error shows up in the IDE (it reads
  `frontend/tsconfig.json`), not in the build. Check the browser console after a change.
- Tests: `UiRoutesTest`, `UiTenantTest`, `UiCapabilitiesTest` and `UserSessionTokenStateManagerTest` (BFF, unit), and
  `UiLoginIT` (login, logout and sessions against Keycloak):
  `./mvnw verify -pl modules/backend -am -DskipITs=false -Dit.test=UiLoginIT -Dtest=NoSuchTest -Dsurefire.failIfNoSpecifiedTests=false -Dfailsafe.failIfNoSpecifiedTests=false`.
  The pages themselves have no tests; try a change in the browser.
- The packaged UI (`-Pdist` bundles the same files into `modules/ui-bundle`) is what
  `bin/kcmcp.sh start-dev` of a distribution serves over plain HTTP; use it to try a build, not to develop: every
  change needs a new package.

Conventions of the code:

- Links are plain `<a href=...>`: the router (`@lit-labs/router` in `kc-mcp-outlet.ts`) intercepts clicks on them, in
  shadow DOM too. Navigation from code (after a save or delete) goes through `navigate()` in `router.ts`, not
  `history.pushState` plus a synthetic `popstate`.
- Paths come from the helpers in `router.ts` (`systemsHref()`, `systemHref(alias, tab)`, `realmHref(...)`), never
  written by hand.
- A component never names a method or property after a DOM member: `remove()`, `append()`, `before()`, `after()`,
  `replaceWith()`, `click()`, `focus()`, `blur()`, `closest()`, `matches()`, `title`, `hidden`, `id`, `slot`,
  `role`. It replaces the element's own, and Lit relies on those: a page with an action called `remove()` was never
  taken out of the page on navigation, so the old page stayed above the new one, and leaving the page ran its delete
  action.
- What a page is for goes into a help icon next to its title (`<kc-mcp-help>` in `kc-mcp-help.ts`, the text as its
  content), not into a paragraph under it; lines that show data (alias, source, read-only) stay on the page.
- The BFF decides what a user may do; the UI only hides what `/bff/me` does not list in `capabilities`
  (`systems:write`, ...), so a page has to cope with a 403 anyway.
- Pages read the session (`/bff/me`) from the Lit context `sessionContext` (`session-context.ts`), which
  `kc-mcp-session` provides, rather than calling `/bff/me` themselves.

## Releases

A tag `v<version>` pushed to GitHub runs `.github/workflows/release.yml`: it sets the version from the tag for the
build, runs the full verification, and publishes a GitHub release with the two archives attached. The CI workflow
unpacks the archive and starts it with `kcmcp.sh` on Linux and `kcmcp.bat` on Windows on every push.

Formatting: [Spotless](https://github.com/diffplug/spotless), [Spring Java Format](https://github.com/spring-io/spring-javaformat)
with spaces (`etc/eclipse-formatter.prefs`; imports `java|javax|jakarta`, `org`, `com`, rest, static).

## Status and roadmap

Status: all reference tools, search, exposure modes, guardrails, extension SPI, database storage, admin API and the
management UI (login, sessions, BFF; pages for systems, their realms and signing keys, the audit trail) done. Open items:

- Model-in-the-loop benchmarks with LM Studio: turns to success, tool-choice errors, tokens per mode
- Reference skill recipes as prompts
- Federation sync test against a real LDAP
- `private_key_jwt` end to end in a test: Keycloak fetching the server's JWKS, `client_credentials`
  (`PasswordGrantSessionsIT` covers the token manager against a client-jwt client with a fixed key)
- Admin API read access to the signing-key history
- Management UI pages for secrets and storage (today: placeholders)

## Quarkus notes

Dev UI <http://localhost:8081/q/dev/>; Swagger UI for the admin API <http://localhost:8081/q/swagger-ui/> and the
document at `/q/openapi` are in every build. The server runs on the JVM only: extension jars are loaded from `providers/` at
runtime, the default storage is the embedded H2, and the storage derives keys with Bouncy Castle, none of which fits a
GraalVM native image. The Quarkus native profile and Dockerfiles were removed for that reason; `Dockerfile.jvm` is the
one container build.
