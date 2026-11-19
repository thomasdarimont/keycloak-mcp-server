#!/usr/bin/env bash
# Starts the MCP server for this example: http://localhost:8109/mcp, needs the stack (docker compose up -d).
#
#   ./server.sh [env]           quarkus:dev with env/<env>.env (default: step-up-device); one of:
#                               step-up-browser step-up-device
#   ./server.sh --jar           the packaged server instead (./mvnw package -DskipTests first)
#
# Only the env file's settings reach the server: KC_MCP_* and QUARKUS_* variables this terminal still carries from
# another example are dropped, and nothing is exported into the terminal. The script also stops when the port is
# taken or Keycloak is not up. See ../run-server.sh.
set -euo pipefail
exec "$(dirname "$0")/../run-server.sh" step-up-passkey step-up-device "$@"
