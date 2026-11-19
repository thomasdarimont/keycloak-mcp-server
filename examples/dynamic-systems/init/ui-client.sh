#!/bin/bash
# Creates the public client keycloak-mcp-ui in the master realm, which the management UI signs people in with, once
# Keycloak is up (kcadm inside the Keycloak image). So the UI works before demo.sh has run. Idempotent.
#
#   KEYCLOAK  where Keycloak is reached (default: http://keycloak:8080), admin / admin of the master realm
set -euo pipefail
KC=/opt/keycloak/bin/kcadm.sh
KEYCLOAK=${KEYCLOAK:-http://keycloak:8080}
$KC config credentials --server "$KEYCLOAK" --realm master --user "${KC_ADMIN:-admin}" --password "${KC_ADMIN_PASSWORD:-admin}"

id=$($KC get clients -r master -q clientId=keycloak-mcp-ui --fields id --format csv --noquotes | head -1)
if [ -z "$id" ]; then
  $KC create clients -r master -f /keycloak-mcp-ui.json >/dev/null
  id=$($KC get clients -r master -q clientId=keycloak-mcp-ui --fields id --format csv --noquotes | head -1)
  echo "created client keycloak-mcp-ui"
else
  echo "client keycloak-mcp-ui exists"
fi
# the only role the UI needs (kc-mcp.ui.operator-role, by default the admin API's: realm:admin) in the client's role scope
$KC get roles/admin -r master --fields id,name | sed 's/^{/[{/; s/}$/}]/' \
  | $KC create "clients/$id/scope-mappings/realm" -r master -f - >/dev/null
echo "management UI client ready"
