#!/usr/bin/env bash
# Lets people of Globex log in to the MCP server (mcp-users, :8092) at the master realm of Globex' Keycloak and act
# with their own roles, through a delegated token. Runs inside the Keycloak container (kcadm, no jq), after the
# server's client exists there (client setup of the system, ../adopt-setup.sh or ../demo.sh). Idempotent.
#
#   docker compose exec -T keycloak-globex bash -s < init/globex-login.sh
#
# What it creates in the realm master:
#   - Admin Permissions on, and the grant that lets the server's client act for the realm's users
#   - the server's client: Standard Token Exchange on, full scope on
#   - the public client mcp-consumer MCP clients log users in with: PKCE, consent, the delegation scope, aud=<server's client>
#     Its consent page asks for the delegation alone: no roles, profile or email scope, the user's name comes from
#     a mapper of the client
#   - the user globex-support (globex-support-demo) with user and client management of the realms in REALMS
set -euo pipefail
KC=/opt/keycloak/bin/kcadm.sh
KEYCLOAK=${KEYCLOAK:-http://localhost:8080}
ACTOR=${ACTOR:-keycloak-mcp-server}
REALMS=${REALMS:-globex-staff globex-customers}
SUPPORT=${SUPPORT:-globex-support}
ROLES=${ROLES:-view-realm view-users query-users query-groups manage-users view-clients query-clients manage-clients view-events}
$KC config credentials --server "$KEYCLOAK" --realm master --user "${KC_ADMIN:-admin}" --password "${KC_ADMIN_PASSWORD:-admin}"

if ! $KC get client-scopes -r master --fields name --format csv --noquotes | grep -qx 'delegation:client'; then
  echo "the realm master has no client scope delegation:client: start Keycloak with the features" >&2
  echo "token-exchange-delegation and parameterized-scopes (KC_FEATURES)" >&2
  exit 1
fi
actor=$($KC get clients -r master -q clientId="$ACTOR" --fields id --format csv --noquotes | head -1)
if [ -z "$actor" ]; then
  echo "the realm master has no client $ACTOR: create it first with the system's client setup" >&2
  exit 1
fi

$KC update realms/master -s adminPermissionsEnabled=true
$KC update "clients/$actor" -r master -s fullScopeAllowed=true -s 'attributes."standard.token.exchange.enabled"=true'
echo "[master] Admin Permissions on; $ACTOR: Standard Token Exchange and full scope on"

if [ -z "$($KC get clients -r master -q clientId=mcp-consumer --fields id --format csv --noquotes | head -1)" ]; then
  $KC create clients -r master -f - >/dev/null <<JSON
{
  "clientId": "mcp-consumer",
  "name": "MCP clients",
  "description": "Public PKCE client MCP clients log the user in with. Consent required: the user is asked whether $ACTOR may act on their behalf.",
  "enabled": true,
  "protocol": "openid-connect",
  "publicClient": true,
  "consentRequired": true,
  "standardFlowEnabled": true,
  "directAccessGrantsEnabled": false,
  "fullScopeAllowed": false,
  "redirectUris": [
    "http://127.0.0.1:33389/mcp-oauth-callback",
    "http://localhost/callback",
    "http://localhost/oauth/callback"
  ],
  "webOrigins": [ "+" ],
  "attributes": { "pkce.code.challenge.method": "S256", "access.token.lifespan": "1800" },
  "defaultClientScopes": [ "web-origins", "acr", "basic" ],
  "optionalClientScopes": [ "delegation:client", "offline_access" ],
  "protocolMappers": [ {
    "name": "mcp server audience",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-audience-mapper",
    "config": { "included.client.audience": "$ACTOR", "access.token.claim": "true", "id.token.claim": "false" }
  }, {
    "name": "username",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-usermodel-attribute-mapper",
    "config": { "user.attribute": "username", "claim.name": "preferred_username", "jsonType.label": "String",
                "access.token.claim": "true", "id.token.claim": "true" }
  } ]
}
JSON
  echo "[master] created client mcp-consumer"
else
  echo "[master] client mcp-consumer exists"
fi

if [ -z "$($KC get users -r master -q username="$SUPPORT" -q exact=true --fields id --format csv --noquotes | head -1)" ]; then
  $KC create users -r master -s username="$SUPPORT" -s enabled=true -s email="$SUPPORT@globex.example" \
    -s emailVerified=true -s firstName=Globex -s lastName=Support >/dev/null
  $KC set-password -r master --username "$SUPPORT" --new-password "$SUPPORT-demo"
  echo "[master] created user $SUPPORT ($SUPPORT-demo)"
else
  echo "[master] user $SUPPORT exists"
fi
for REALM in $REALMS; do
  # the master realm's client for a realm carries that realm's management roles
  # shellcheck disable=SC2086
  $KC add-roles -r master --uusername "$SUPPORT" --cclientid "$REALM-realm" $(printf -- '--rolename %s ' $ROLES)
  echo "[master] $SUPPORT manages $REALM"
done
