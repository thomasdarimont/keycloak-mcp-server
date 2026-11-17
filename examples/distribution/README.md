# Demo: the distribution against a Keycloak in Docker, users logging in

One Keycloak 26.8.2 on <http://localhost:8080> with a `demo` realm, the keycloak-mcp-server distribution on
<http://localhost:9080>, users logging in through LM Studio, the server authenticating with `private_key_jwt`.
Every Admin API call runs with a delegated token (Keycloak 26.8 token exchange delegation, preview): the user
consents at login to the server's client `keycloak-mcp-server` acting on their behalf, Keycloak exchanges the user's
token for one with `sub` = the user and `act` = that client, and the server's own service account holds no admin
role. The user's own token never reaches the Admin API. Background and the Keycloak settings in detail:
[`../delegated-auth`](../delegated-auth/README.md).

Who may do what:

| user | realm | password | logs in at | may |
|---|---|---|---|---|
| `root` | master | `root-demo` | `/mcp/systems/sso` | administer every realm (master `admin`) |
| `alice` | demo | `alice-demo` | `/mcp/systems/sso/demo` | administer the demo realm (`realm-admin`) |
| `carol` | demo | `carol-demo` | `/mcp/systems/sso/demo` | view the demo realm's users (`view-users`), nothing else |
| `bob`, `dave`, `erin` | demo | `<name>-demo` | | plain users to manage |

The Keycloak is one named system, `sso`, with two MCP entries: the system entry `/mcp/systems/sso`, where
master realm users log in, and the realm entry `/mcp/systems/sso/demo`, where demo realm users log in and every
call is bound to the demo realm. Each entry has its own LM Studio entry and its own protected resource metadata, so the
MCP client logs the user in at the right realm.

## Files

| file | purpose |
|---|---|
| `docker-compose.yml` | Keycloak 26.8.2 on :8080 with the features `token-exchange-delegation` and `parameterized-scopes`, imports `realms/` on the first start, reaches the host as `host.docker.internal` |
| `realms/demo-realm.json` | the demo realm with Admin Permissions on: clients `mcp-consumer` (consent required) and `keycloak-mcp-server` (the actor, `realm-admin` in its role scope, no role on its service account), groups `/mcp-admins` and `/mcp-support`, the users |
| `clients/*.json` | the same two clients and the management UI's `keycloak-mcp-ui` for the master realm, created by `setup.sh` (an import cannot touch `master`); `keycloak-mcp-server` and `keycloak-mcp-ui` get the `admin` role in their role scope |
| `init/grant-delegation.sh` | the Admin Permissions grant that lets `keycloak-mcp-server` act on behalf of a realm's users; run by `setup.sh` inside the Keycloak container for `master` and `demo` (a realm import cannot carry it) |
| `setup.sh` | the server's key pair, the master realm's clients and the user `root`, the delegation grants, the admin API's token |
| `conf/server.conf` | the server: port 9080, user login with delegated tokens (`kc-mcp.delegation=exchange`), `private_key_jwt`, the audience, the admin API on; read in place by `--config` |
| `conf/systems/sso.conf` | the one system: login realm `master`, default realm `master`; read in place by `--config` |
| `mcp.json` | LM Studio: both entries, logging in as `mcp-consumer` |
| `mcp-call.py` | calls a tool from the command line, logging a user in the way a browser does (login form, consent page, code with PKCE) |

## Steps

1. **Build and unpack the distribution.** The `dist` profile assembles it from the repository root into
   `modules/distribution/target/` as `keycloak-mcp-server-<version>.tar.gz` and `.zip` (the tests take a few minutes;
   `-DskipTests` leaves them out). Copy the archive here and unpack it; repeat after every server change.

   ```shell
   (cd ../.. && ./mvnw package -Pdist -DskipTests)
   cp ../../modules/distribution/target/keycloak-mcp-server-1.0-SNAPSHOT.tar.gz .
   rm -rf keycloak-mcp-server-1.0-SNAPSHOT && tar xzf keycloak-mcp-server-1.0-SNAPSHOT.tar.gz
   ```

   A rebuilt archive comes without the key and the admin API token from step 3; `setup.sh` generates both anew (copy
   `conf/keycloak-mcp-server.pem` aside first if Keycloak should keep accepting the old one, or just let Keycloak
   fetch the new JWKS). The configuration is not affected: the server reads it from this folder's `conf/`.

2. **Start Keycloak.** The demo realm is imported on the first start.

   ```shell
   docker compose up -d
   ```

3. **Run the setup.** It generates the server's RSA key into the distribution's `conf/keycloak-mcp-server.pem`
   and prepares the master realm: Admin Permissions on, the client
   `keycloak-mcp-server` (Signed JWT, JWKS URL `http://host.docker.internal:9080/.well-known/jwks.json`, Standard
   Token Exchange on, a service account without roles, the `admin` role in its role scope), the public client
   `mcp-consumer` (PKCE, consent required, the MCP clients' callbacks, audience `keycloak-mcp-server`) and the user
   `root` with the `admin` role. It then grants `keycloak-mcp-server` the `delegate` permission on the users of
   `master` and `demo` (`init/grant-delegation.sh`); without that grant Keycloak drops the delegation scope silently
   and every tool answers `delegation_failed`. It also generates the admin API's token into the
   distribution's `conf/kcmcp.conf` (read on every start, next to the key) and prints it. It can run again at any
   time; the key and the token are kept.

   ```shell
   ./setup.sh
   ```

4. **Start the MCP server** from the distribution, pointing it at this folder's shared settings and systems
   directory (`--config` takes files and directories anywhere; the key is the one file that lives in the
   distribution, `server.conf` names it as `${kcmcp.home.dir}/conf/keycloak-mcp-server.pem`):

   ```shell
   cd keycloak-mcp-server-1.0-SNAPSHOT
   bin/kcmcp.sh start-dev --config ../conf/server.conf --config ../conf/systems/
   ```

   With `start-dev` instead of `start`, the management UI is on as well, with an H2 database under `data/` and no
   certificates: <http://localhost:9080/ui/>, sign in as `root` / `root-demo`.

   The log shows the system connecting with `clientAuth=PRIVATE_KEY_JWT`, `delegation=exchange: actor client
   'keycloak-mcp-server' logs in` and `Listening on: http://127.0.0.1:9080`.
   If the script prints a note about `KC_MCP_*` or `QUARKUS_*` variables inherited from the shell, they override the
   files; `--clean-env` ignores them.

5. **Check from the command line** (optional). `mcp-call.py` logs the user in as `mcp-consumer` the way an MCP
   client's browser does (login form, consent page, authorization code with PKCE; a client that requires consent
   refuses the password grant) and calls a tool:

   ```shell
   ./mcp-call.py --login root:root-demo http://localhost:9080/mcp/systems/sso whoami
   ./mcp-call.py --login root:root-demo http://localhost:9080/mcp/systems/sso keycloak_user_search '{"realm": "demo", "search": "alice"}'
   ./mcp-call.py --login alice:alice-demo@demo http://localhost:9080/mcp/systems/sso/demo keycloak_user_set_enabled '{"id": "bob", "enabled": false}'
   ./mcp-call.py --login carol:carol-demo@demo http://localhost:9080/mcp/systems/sso/demo keycloak_user_search '{"search": "bob"}'
   ./mcp-call.py --login carol:carol-demo@demo http://localhost:9080/mcp/systems/sso/demo keycloak_user_set_enabled '{"id": "bob", "enabled": true}'
   ./mcp-call.py --login alice:alice-demo@demo --scope openid http://localhost:9080/mcp/systems/sso/demo whoami
   ```

   Expected: `whoami` shows `delegation: {mode: exchange, consented: true, actor: keycloak-mcp-server}`; root's
   default realm is `master`, any other realm by name; alice's call succeeds; carol's search succeeds and her write
   answers `forbidden` with the missing role `manage-users`; the last login leaves out the delegation scope, so
   `whoami` reports `delegation_failed` and says what is missing. The server's audit log names the person behind
   every call (`caller=alice(...) delegated`).

   The admin API answers with the token `setup.sh` printed (it is in the distribution's `conf/kcmcp.conf`):

   ```shell
   curl -H "Authorization: Bearer admintoken-..." http://localhost:9080/admin/systems
   ```

   Swagger UI at <http://localhost:9080/q/swagger-ui/> describes the API; *Authorize* takes the same token. The static
   token keeps the demo simple; on a real server the preferred way in is an access token of a trusted issuer
   (`kc-mcp.admin.issuer`), a person's from the authorization code flow or a service account's from the client
   credentials grant, carrying `kc-mcp.admin.role`, so Keycloak governs who administers the server. With `start`
   there is no database and this server only reads: registering a system answers 503 `no_mutable_repository`. With
   `start-dev` the H2 database comes with `kc-mcp.dynamic-systems=true`, so the API and the UI's *Add system* register
   systems there, next to the ones of `conf/systems/`
   ([Several Keycloak systems](../../docs/systems.md), [Database storage](../../docs/storage.md)).

6. **LM Studio.** Add the two servers from `mcp.json` (Program → Install → Edit mcp.json). On connect LM Studio opens
   the browser: log in as `root / root-demo` for `keycloak-sso`, as `alice` or `carol` for
   `keycloak-sso-demo` (the realm entry), and answer the consent page ("Allow keycloak-mcp-server to act on your behalf?") with yes;
   Keycloak asks it in every login session. Then ask, for example: "which users are in the demo realm", "disable bob",
   "which roles does alice have". A destructive request such as "delete erin" is confirmed first; as realm admin,
   alice is told to pass `confirm: true` right away. To switch users, remove the server in LM Studio and add it
   again; LM Studio keeps the token otherwise.

## How the pieces fit

- **User login and delegation.** `kc-mcp.delegation=exchange` with `quarkus.oidc.tenant-enabled=true`: the MCP
  endpoint answers 401 with the protected resource metadata, LM Studio reads it, finds the realm of the entry
  (`master` or `demo`) and the scope to ask for (`delegation:client:keycloak-mcp-server`), logs the user in with PKCE
  as `mcp-consumer` and sends the token. `quarkus.oidc.token.audience=keycloak-mcp-server` requires the audience the
  mapper on `mcp-consumer` adds; that token opens the MCP server only, it carries no admin role and never goes to
  the Admin API. For every Admin API call the server exchanges it at Keycloak for a delegated token (`sub` = the
  user, `act` = `keycloak-mcp-server`), so Keycloak enforces the user's roles. Keycloak needs for this: the two
  preview features, Admin Permissions on in the realm, consent required on `mcp-consumer`, Standard Token Exchange
  on `keycloak-mcp-server` and the `delegate` grant of `init/grant-delegation.sh`.
- **The server's own identity.** `kc-mcp.system-defaults.client-auth=private_key_jwt` with `kc-mcp.jwt.key-file`: the server signs
  its token requests, the token exchange included, with the key in `conf/keycloak-mcp-server.pem` and publishes the
  public key at `/.well-known/jwks.json`; the client `keycloak-mcp-server` in each realm has that JWKS URL. Its
  service account holds no role at all, so the server's credentials alone administer nothing. Full scope is off on
  the client and its role scope caps every delegated token, whoever the user is: `realm-admin` in the demo realm,
  the `admin` role in master. A smaller role scope, as in `../delegated-auth`, narrows what even a realm admin can
  do through the server. Without an admin role the service account cannot read Keycloak's server info, so
  `conf/server.conf` states the version (`kc-mcp.system-defaults.version`).
- **One metadata document per entry.** An MCP client learns where to log in from the protected resource metadata
  the 401 names. The root and `/mcp/systems/sso` share the default document
  (`/.well-known/oauth-protected-resource`, authorization server `.../realms/master`); an entry whose login realm
  differs gets its own: the realm entry's is at `/.well-known/oauth-protected-resource/mcp/systems/sso/demo`,
  naming `.../realms/demo`. Both list the delegation scope in `scopes_supported`.
- **One system, two entries.** `conf/systems/sso.conf` names realm `master` as the login realm and default
  realm. The realm entry `/mcp/systems/sso/demo` needs no configuration of its own: it logs its users in at the
  `demo` realm and binds every call to that realm, so a demo user cannot name another one (`entry_mismatch`). Tools
  keep their `system` and `realm` arguments, with a description saying to omit them at an entry; `whoami` shows the
  binding. One system rather than two also keeps the model from reasoning about "different Keycloaks" that are one.
- **The exchange happens where the user logged in.** Keycloak accepts a token only at the realm that issued it, so
  the server exchanges a caller's token in that realm: root's in `master`, the system's auth realm, alice's and
  carol's in `demo`. For that the client `keycloak-mcp-server` exists in both realms with the same client id and
  the same JWKS URL; at the realm entry the server logs in at `demo` with the same key (the client assertion names
  the demo realm's issuer as audience) and exchanges there. Each realm users log in at needs the same things: the
  client with Standard Token Exchange and a role scope, `mcp-consumer` with consent and the delegation scope, and
  the `delegate` grant, which is why `setup.sh` grants it for `master` and `demo`.
- **Docker to host.** Keycloak reaches the server's JWKS as `host.docker.internal:9080` (the compose file maps that
  name to the host). The server accepts that `Host` header: it switches off the Quarkus host-header filter that
  would otherwise answer 400 to anything but `localhost`, and relies on its own DNS rebinding protection for the
  MCP endpoint. The server listens on `127.0.0.1` only; Docker Desktop (macOS, Windows) reaches that from the
  container, native Linux Docker does not, since `host.docker.internal` is the bridge gateway there. On Linux
  uncomment `quarkus.http.host=0.0.0.0` in `conf/server.conf`, then the server listens on every interface (users
  still have to log in; the JWKS and the metadata are public by design); `setup.sh` reminds you of that on Linux. Keycloak's own port is published on
  `127.0.0.1` only, so the demo admin account (`admin` / `admin`) is not reachable from other machines.

## Reset

```shell
docker compose down -v          # drops Keycloak and the imported realm
rm -rf keycloak-mcp-server-1.0-SNAPSHOT
```

Then start again at step 2 (or at step 1 for a fresh build). `setup.sh` recreates the master realm's clients and
user and the delegation grants, and generates a new key unless `conf/keycloak-mcp-server.pem` still exists. A
Keycloak container from before the move to delegated tokens has to be reset this way: `setup.sh` does not change
clients that exist.
