#!/bin/bash
# Grants the Admin Permissions (fine-grained admin permissions V2) that let the MCP server's client act on behalf of
# every user of a realm: a client policy naming that client as the allowed actor and a scope permission `delegate`
# on the Users resource type. Keycloak evaluates it when a login asks for the scope delegation:client:<actor>;
# without it the scope is silently dropped and the token carries no may_act claim. A realm import cannot carry these
# settings, so setup.sh runs this script inside the Keycloak container (kcadm) once the clients exist. Idempotent.
#
#   REALMS    the realms to grant it in, space separated (default: master demo); each needs Admin Permissions enabled
#   ACTOR     the MCP server's client in those realms (default: keycloak-mcp-server)
#   KEYCLOAK  where Keycloak is reached (default: http://localhost:8080), admin / admin of the master realm
set -euo pipefail
KC=/opt/keycloak/bin/kcadm.sh
REALMS=${REALMS:-${REALM:-master demo}}
ACTOR=${ACTOR:-keycloak-mcp-server}
KEYCLOAK=${KEYCLOAK:-http://localhost:8080}
$KC config credentials --server "$KEYCLOAK" --realm master --user "${KC_ADMIN:-admin}" --password "${KC_ADMIN_PASSWORD:-admin}"

for REALM in $REALMS; do
  perms=$($KC get clients -r "$REALM" -q clientId=admin-permissions --fields id --format csv --noquotes | head -1)
  actor=$($KC get clients -r "$REALM" -q clientId="$ACTOR" --fields id --format csv --noquotes | head -1)
  if [ -z "$perms" ] || [ -z "$actor" ]; then
    echo "realm $REALM needs Admin Permissions enabled (client admin-permissions) and the client $ACTOR" >&2
    exit 1
  fi
  authz="clients/$perms/authz/resource-server"

  policy="$ACTOR may act for users"
  if [ -z "$($KC get "$authz/policy/search" -r "$REALM" -q name="$policy" 2>/dev/null)" ]; then
    printf '{"name":"%s","description":"The actors allowed to act on behalf of users: the MCP server'"'"'s client","clients":["%s"],"logic":"POSITIVE"}' \
      "$policy" "$actor" | $KC create "$authz/policy/client" -r "$REALM" -f - >/dev/null
    echo "[$REALM] created client policy '$policy'"
  else
    echo "[$REALM] client policy '$policy' exists"
  fi

  permission="delegate to $ACTOR"
  if [ -z "$($KC get "$authz/permission/search" -r "$REALM" -q name="$permission" 2>/dev/null)" ]; then
    printf '{"name":"%s","description":"Every user of the realm may be acted for by the policy'"'"'s clients","resourceType":"Users","scopes":["delegate"],"policies":["%s"]}' \
      "$permission" "$policy" | $KC create "$authz/permission/scope" -r "$REALM" -f - >/dev/null
    echo "[$REALM] created permission '$permission' (Users / delegate)"
  else
    echo "[$REALM] permission '$permission' exists"
  fi
  echo "[$REALM] delegation to $ACTOR granted"
done
