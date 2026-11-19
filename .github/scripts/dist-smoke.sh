#!/usr/bin/env bash
# Smoke test of the unpacked distribution, as the CI's distribution job runs it on Linux (and by hand):
#
#   .github/scripts/dist-smoke.sh <unpacked distribution> [<realm import file>]
#
# Starts the server with bin/kcmcp.sh from a directory other than the distribution's, with a --config file given as a
# relative path, and initializes an MCP session; then with two system files in conf/systems/. With a realm file, also starts Keycloak 26.8.2 in Docker with that
# realm imported, starts the server again with the service-account scenario against it, and runs keycloak_user_search
# through the MCP protocol: the packaged server administering a real Keycloak. Keycloak is pulled and started in the
# background at the beginning, so that it boots while the steps that do not need it run.
set -euo pipefail
DIST=$1
REALM=${2:-}
PORT=${PORT:-8085}
KC_PORT=${KC_PORT:-18080}
KC_IMAGE=${KC_IMAGE:-quay.io/keycloak/keycloak:26.8.2}
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'

SERVER_PID=""
KC_NAME=""
KC_RUN_PID=""
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null || true
  [ -n "$KC_RUN_PID" ] && wait "$KC_RUN_PID" 2>/dev/null || true
  [ -n "$KC_NAME" ] && docker rm -f "$KC_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [ -n "$REALM" ]; then
  # pulled and started now, used from step 2 on; the name lets the cleanup remove it before docker run returned
  KC_NAME="kcmcp-smoke-keycloak-$$"
  docker run -d --rm --name "$KC_NAME" -p "$KC_PORT:8080" \
    -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
    -e KC_FEATURES=identity-brokering-api:v2 -e KC_FEATURES_DISABLED=twitter-broker \
    -v "$(cd "$(dirname "$REALM")" && pwd)/$(basename "$REALM"):/opt/keycloak/data/import/realm.json:ro" \
    "$KC_IMAGE" start-dev --import-realm > keycloak-run.log 2>&1 &
  KC_RUN_PID=$!
fi

mcp() { # $1 body, $2 session id or empty; prints the answer (JSON or SSE), the session id goes to .session
  curl -sS -D headers.txt -X POST "http://localhost:$PORT/mcp" -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' ${2:+-H "Mcp-Session-Id: $2"} -d "$1"
  sed -n 's/^[Mm]cp-[Ss]ession-[Ii]d: *//p' headers.txt | tr -d '\r' > .session
}

start_server() { # $@ server options; waits for the MCP endpoint
  "$DIST/bin/kcmcp.sh" start "$@" > server.log 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 60); do
    if mcp "$INIT" "" > init.json 2>/dev/null && grep -q '"serverInfo"' init.json; then return 0; fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then break; fi
    sleep 1
  done
  echo "the server did not come up:"; cat server.log; exit 1
}

stop_server() { kill "$SERVER_PID"; wait "$SERVER_PID" 2>/dev/null || true; SERVER_PID=""; }

echo "== version"; "$DIST/bin/kcmcp.sh" --version

echo "== 1. a --config file by relative path, from outside the distribution"
printf 'quarkus.http.port=%s\nkc-mcp.tools.exposure=lazy\n' "$PORT" > "$DIST/conf/smoke.conf"
start_server --config conf/smoke.conf --kc-mcp.startup-check=off --kc-mcp.systems.default.url=http://127.0.0.1:1 \
  --kc-mcp.systems.default.client-id=smoke --kc-mcp.systems.default.client-secret=smoke
grep -q 'exposure=LAZY' server.log || { echo "conf/smoke.conf was not read"; cat server.log; exit 1; }
echo "session $(cat .session), exposure lazy: ok"
stop_server

echo "== 1b. a directory with one file per system"
printf 'kc-mcp.systems.prod.url=http://127.0.0.1:1\nkc-mcp.default-system=prod\n' > "$DIST/conf/systems/prod.conf"
printf 'kc-mcp.systems.staging.url=http://127.0.0.1:2\n' > "$DIST/conf/systems/staging.conf"
start_server --config conf/smoke.conf --config conf/systems/ --kc-mcp.startup-check=warn \
  --kc-mcp.system-defaults.client-id=smoke --kc-mcp.system-defaults.client-secret=smoke
for system in prod staging; do
  grep -q "Keycloak system '$system'" server.log || { echo "system $system not configured"; cat server.log; exit 1; }
done
echo "prod and staging configured from conf/systems/: ok"
stop_server
rm -f "$DIST/conf/systems/prod.conf" "$DIST/conf/systems/staging.conf"

echo "== 1b2. the management UI with its bundle, in the distribution as Maven built it"
start_server --config conf/smoke.conf --kc-mcp.startup-check=off --kc-mcp.ui.enabled=true \
  --kc-mcp.systems.default.url=http://127.0.0.1:1 --kc-mcp.systems.default.client-id=smoke \
  --kc-mcp.systems.default.client-secret=smoke --quarkus.datasource.jdbc.url="jdbc:h2:file:$DIST/data/smoke-ui"
BUNDLE=$(curl -sf "http://localhost:$PORT/ui/" | grep -oE '/static/bundle/[^"]+\.js' | head -1)
[ -n "$BUNDLE" ] || { echo "the UI page names no bundle"; cat server.log; exit 1; }
curl -sf -o /dev/null "http://localhost:$PORT$BUNDLE" || { echo "$BUNDLE is not served"; exit 1; }
echo "/ui/ and $BUNDLE: ok"
stop_server
rm -f "$DIST"/data/smoke-ui.*

echo "== 1c. build: the database kind of the unpacked distribution"
if "$DIST/bin/kcmcp.sh" build --db=db2 2> build.err; then echo "an unsupported database was accepted"; exit 1; fi
grep -q 'build needs --db' build.err || { cat build.err; exit 1; }
# Oracle's driver is not shipped: without it in lib/providers the build is refused before anything changes
if "$DIST/bin/kcmcp.sh" build --db=oracle 2> build.err; then echo "an Oracle build without its driver was accepted"; exit 1; fi
grep -q 'lib/providers' build.err || { cat build.err; exit 1; }
"$DIST/bin/kcmcp.sh" build --db=postgresql
[ ! -e "$DIST/quarkus-app" ] || { echo "the build left quarkus-app/ behind"; exit 1; }
if "$DIST/bin/kcmcp.sh" start --clean-env --quarkus.http.port="$PORT" --kc-mcp.startup-check=off \
    --kc-mcp.systems.default.url=http://127.0.0.1:1 --kc-mcp.systems.default.client-id=smoke \
    --kc-mcp.systems.default.client-secret=smoke --quarkus.datasource.jdbc.url=jdbc:h2:mem:smoke > mismatch.log 2>&1; then
  echo "an H2 URL started on a PostgreSQL build"; exit 1
fi
grep -q 'build --db=h2' mismatch.log || { echo "the failed start does not name the build command:"; cat mismatch.log; exit 1; }
"$DIST/bin/kcmcp.sh" build --db=h2
echo "build for postgresql, refused H2 URL, back to h2: ok"

echo "== 1d. show-config and validate"
SMOKE_SYSTEM="--kc-mcp.systems.default.url=http://127.0.0.1:1 --kc-mcp.systems.default.client-id=smoke --kc-mcp.systems.default.client-secret=hidden-value"
# shellcheck disable=SC2086
"$DIST/bin/kcmcp.sh" show-config --clean-env $SMOKE_SYSTEM > show.out 2>&1
grep -q "kc-mcp.systems.default.url = http://127.0.0.1:1 (command line)" show.out || { cat show.out; exit 1; }
if grep -q hidden-value show.out; then echo "show-config printed a secret"; exit 1; fi
# shellcheck disable=SC2086
"$DIST/bin/kcmcp.sh" validate --clean-env --offline $SMOKE_SYSTEM > validate.out 2>&1 || { cat validate.out; exit 1; }
# shellcheck disable=SC2086
if "$DIST/bin/kcmcp.sh" validate --clean-env $SMOKE_SYSTEM > validate.out 2>&1; then echo "validate passed with Keycloak down"; cat validate.out; exit 1; fi
grep -q "cannot obtain an admin token" validate.out || { cat validate.out; exit 1; }
# shellcheck disable=SC2086
"$DIST/bin/kcmcp.sh" providers --clean-env $SMOKE_SYSTEM > providers.out 2>&1 || { cat providers.out; exit 1; }
grep -Eq "^key-vault +[a-z-]+ +selected" providers.out || { echo "no selected key vault:"; cat providers.out; exit 1; }
echo "show-config masks, validate reports: ok"

if [ -z "$REALM" ]; then exit 0; fi

echo "== 2. Keycloak $KC_IMAGE with the realm $REALM (started at the beginning)"
if ! wait "$KC_RUN_PID"; then KC_RUN_PID=""; echo "Keycloak did not start:"; cat keycloak-run.log; exit 1; fi
KC_RUN_PID=""
for _ in $(seq 1 120); do curl -sf "http://localhost:$KC_PORT/realms/demo" > /dev/null && break; sleep 2; done
curl -sf "http://localhost:$KC_PORT/realms/demo" > /dev/null || { docker logs "$KC_NAME" | tail -20; exit 1; }

echo "== 3. the service-account scenario against it, keycloak_user_search over MCP"
cp "$DIST/conf/scenarios/service-account.conf.example" "$DIST/conf/service-account.conf"
start_server --config conf/service-account.conf --quarkus.http.port="$PORT" \
  --kc-mcp.systems.default.url="http://localhost:$KC_PORT" --kc-mcp.systems.default.client-secret=mcp-admin-secret
SESSION=$(cat .session)
mcp '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$SESSION" > /dev/null
mcp '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"keycloak_user_search","arguments":{"search":"alice"}}}' "$SESSION" > search.out
grep -q '"username"' search.out && grep -q 'alice' search.out || { echo "unexpected answer:"; cat search.out; cat server.log; exit 1; }
grep -q 'tool=keycloak_user_search .*outcome=ok' server.log || { echo "no audit line"; cat server.log; exit 1; }
echo "alice found through the packaged server: ok"
