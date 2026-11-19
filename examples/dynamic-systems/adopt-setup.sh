#!/usr/bin/env bash
# Runs a client setup script of the MCP server inside the second Keycloak (keycloak-globex), logged in as admin: the
# script the Adopt tab of the management UI shows (1. Client in Keycloak, copy), or the "script" of
# GET /admin/systems/<alias>/client-setup. It creates the server's client and gives its service account the roles.
#
#   pbpaste | ./adopt-setup.sh          the script from the clipboard (macOS; xclip -o or wl-paste on Linux)
#   ./adopt-setup.sh client-setup.sh    the script from a file
#
# The script calls kcadm.sh; here that is the one in the Keycloak container, so nothing has to be installed.
set -euo pipefail
cd "$(dirname "$0")"
script=$(cat "${1:-/dev/stdin}")
[ -n "$script" ] || { echo "no script given: paste it on stdin or name a file" >&2; exit 2; }
encoded=$(printf '%s' "$script" | base64 | tr -d '\n')
docker compose exec -T keycloak-globex bash -c "
  set -e
  echo '$encoded' | base64 -d > /tmp/client-setup.sh
  /opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master \
    --user admin --password admin --config /tmp/kcadm.config
  printf '#!/bin/bash\nexec /opt/keycloak/bin/kcadm.sh \"\$@\" --config /tmp/kcadm.config\n' > /tmp/kcadm
  chmod +x /tmp/kcadm
  KCADM=/tmp/kcadm bash /tmp/client-setup.sh"
