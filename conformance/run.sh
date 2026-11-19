#!/usr/bin/env bash
# Runs the MCP conformance suite (github.com/modelcontextprotocol/conformance) against this server.
#
#   ./mvnw package -DskipTests                 # once: the server and conformance/fixtures
#   conformance/run.sh                         # starts the packaged server with the fixtures on :8085, runs, stops it
#   conformance/run.sh --url http://host:8081/mcp   # an already running server (fixtures loaded or not)
#
# Exit code: 0 when only baselined scenarios fail (expected-failures.yml), 1 otherwise. Reports: conformance/results/.
set -euo pipefail
cd "$(dirname "$0")/.."
# the alpha covers protocol version 2026-07-28 (stateless requests, header validation); 0.1.16 stops at 2025-06-18
VERSION=${CONFORMANCE_VERSION:-0.2.0-alpha.12}
PORT=${PORT:-8085}
URL=""
SUITE=${SUITE:-all}
while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL=$2; shift 2 ;;
    --suite) SUITE=$2; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done

SERVER_PID=""
stop() { [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true; }
trap stop EXIT

if [ -z "$URL" ]; then
  JAR=modules/backend/target/quarkus-app/quarkus-run.jar
  FIXTURES=$(ls conformance/fixtures/target/keycloak-mcp-server-conformance-fixtures-*.jar 2>/dev/null | grep -v sources | head -1 || true)
  [ -f "$JAR" ] && [ -n "$FIXTURES" ] || { echo "build first: ./mvnw package -DskipTests" >&2; exit 2; }
  rm -rf conformance/providers && mkdir -p conformance/providers && cp "$FIXTURES" conformance/providers/
  # no Keycloak: the fixtures never call one, the Keycloak tools would answer keycloak_unreachable
  KC_MCP_PROVIDERS_DIR="$PWD/conformance/providers" KC_MCP_STARTUP_CHECK=off KC_MCP_SYSTEMS_DEFAULT_URL=http://127.0.0.1:1 \
  KC_MCP_SYSTEMS_DEFAULT_CLIENT_ID=conformance KC_MCP_SYSTEMS_DEFAULT_CLIENT_SECRET=conformance KC_MCP_TOOLS_EXPOSURE=direct \
  QUARKUS_HTTP_PORT=$PORT QUARKUS_LOG_LEVEL=WARN \
    java -jar "$JAR" start > conformance/results-server.log 2>&1 &
  SERVER_PID=$!
  for i in $(seq 1 60); do
    curl -s -o /dev/null "http://localhost:$PORT/" && break
    sleep 1
  done
  URL="http://localhost:$PORT/mcp"
fi

echo "conformance $VERSION against $URL (suite: $SUITE)"
mkdir -p conformance/results
npx -y "@modelcontextprotocol/conformance@$VERSION" server --url "$URL" --suite "$SUITE" \
  --expected-failures conformance/expected-failures.yml -o conformance/results
