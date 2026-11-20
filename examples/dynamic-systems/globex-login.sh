#!/usr/bin/env bash
# Lets people of Globex log in to the MCP server on port 8092 at the master realm of Globex' Keycloak and act with
# their own roles: the client mcp-consumer, the user globex-support and what delegation needs. After the server's
# client exists in Globex' Keycloak (./demo.sh, or the Adopt tab with ./adopt-setup.sh). See README.md.
set -euo pipefail
cd "$(dirname "$0")"
docker compose exec -T keycloak-globex bash -s < init/globex-login.sh
# the Admin Permissions grant that lets the server's client act for the realm's users who consent to it
docker compose exec -T -e REALMS=master -e ACTOR=keycloak-mcp-server -e KEYCLOAK=http://localhost:8080 \
  keycloak-globex bash -s < init/grant-delegation.sh | grep '^\['
