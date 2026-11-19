#!/usr/bin/env bash
# Starts the MCP server for this example: https://localhost:8443/ui/, needs the run-modes stack and etc/mkcert.sh.
#
#   ./server.sh [env]           quarkus:dev with env/<env>.env (default: ui); one of: ui-two-idps ui
#   ./server.sh --jar           the packaged server instead (./mvnw package -DskipTests first)
#
# Only the env file's settings reach the server: KC_MCP_* and QUARKUS_* variables this terminal still carries from
# another example are dropped, and nothing is exported into the terminal. The script also stops when the port is
# taken or Keycloak is not up. See ../run-server.sh.
set -euo pipefail
exec "$(dirname "$0")/../run-server.sh" management-ui ui "$@"
