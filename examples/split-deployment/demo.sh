#!/usr/bin/env bash
# The whole flow. Needs the stack up (docker compose up -d --build), curl, jq and python3.
#
#   1. register the system "acme" on the admin instance (admin API -> PostgreSQL as the writer, key generated there)
#   2. the realm acme-dev with the public mcp-consumer client and the demo users
#   3. the keycloak-mcp-server client in that realm, JWKS URL on the admin instance, allowed to act for the realm's
#      users who consent to it (the actor of the MCP instance's delegated tokens); keycloak-mcp-admin and
#      keycloak-mcp-ui in master, for the admin API and the management UI on the admin instance
#   4. call tools as users on the MCP instance, which reads the system the admin instance stored
#   5. what each side cannot do: no admin API on the MCP instance, no MCP endpoint on the admin instance,
#      no admin API with an MCP token, no writes with the MCP instance's database user
set -euo pipefail
cd "$(dirname "$0")"
ADMIN=http://localhost:8094
MCP=http://localhost:8095
ADMIN_INTERNAL=http://admin:8081                   # how Keycloak reaches the admin instance inside the compose network
ADMIN_TOKEN=${KC_MCP_ADMIN_TOKEN:-demo-admin-token}
KCADM="docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh"
SHARED=../dynamic-systems                          # realm, server client, delegation grant and mcp-call.py of the dynamic-systems example
export KEYCLOAK_URL=http://localhost:8093          # for mcp-call.py --login

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
admin() {
  curl -sS \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'Content-Type: application/json' \
    "$@"
}
status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
as_mcp_user() {
  docker compose exec -T -e PGPASSWORD=kcmcp-mcp postgres psql -h localhost -U kcmcp_mcp -d kcmcp -v ON_ERROR_STOP=1 -tAc "$1" 2>&1
}

step "1. register the system 'acme' on the admin instance (stored by kcmcp_admin, key pair generated there)"
SYSTEM=$(admin -X PUT "$ADMIN/admin/systems/acme" -d @- <<'JSON'
{
  "displayName": "ACME Corp.",
  "url": "http://keycloak:8080",
  "issuer": "http://localhost:8093/realms/acme-dev",
  "authRealm": "acme-dev",
  "clientId": "keycloak-mcp-server",
  "clientAuth": "private_key_jwt",
  "defaultRealm": "acme-dev",
  "allowedRealms": ["acme-dev"],
  "version": "26.8.2",
  "signingKey": "generate"
}
JSON
)
if echo "$SYSTEM" | jq -e '.error == "signing_key_exists"' >/dev/null; then
  echo "(already registered with a key; keeping it)"
  SYSTEM=$(admin "$ADMIN/admin/systems/acme")
fi
echo "$SYSTEM" | jq -c '{alias, source, signingKey: .signingKey.kid}'
JWKS_URL="$ADMIN_INTERNAL$(echo "$SYSTEM" | jq -r .signingKey.jwksPath)"
echo "JWKS for Keycloak: $JWKS_URL (served by the admin instance; the MCP instance signs with the same key)"

step "2. the realm acme-dev: public client mcp-consumer (consent required, audience keycloak-mcp-server), demo users"
$KCADM config credentials --server http://localhost:8080 --realm master --user admin --password admin >/dev/null
if $KCADM get realms/acme-dev >/dev/null 2>&1; then
  echo "realm acme-dev exists"
else
  $KCADM create realms -f - < "$SHARED/realms/acme-dev.json"
  echo "created realm acme-dev (alice = admin, sam = support, dave = developer, bob = disabled)"
fi

step "3. the keycloak-mcp-server client in the realm acme-dev (Signed JWT, that JWKS URL) and keycloak-mcp-admin in master"
CLIENT_ID=$($KCADM get clients -r acme-dev -q clientId=keycloak-mcp-server --fields id --format csv --noquotes | head -1 || true)
if [ -z "$CLIENT_ID" ]; then
  sed "s#\${MCP_JWKS_URL}#$JWKS_URL#" "$SHARED/clients/keycloak-mcp-server.json" | $KCADM create clients -r acme-dev -f - >/dev/null
  CLIENT_ID=$($KCADM get clients -r acme-dev -q clientId=keycloak-mcp-server --fields id --format csv --noquotes | head -1)
  echo "created client keycloak-mcp-server"
fi
# the service account holds realm-admin of acme-dev, and the role is in the client's scope: that scope is also what
# caps the delegated tokens the MCP instance acts with
$KCADM add-roles -r acme-dev --uusername service-account-keycloak-mcp-server --cclientid realm-management --rolename realm-admin
REALM_MGMT_ID=$($KCADM get clients -r acme-dev -q clientId=realm-management --fields id --format csv --noquotes | head -1)
$KCADM get "clients/$REALM_MGMT_ID/roles/realm-admin" -r acme-dev --fields id,name | sed 's/^{/[{/; s/}$/}]/' \
  | $KCADM create "clients/$CLIENT_ID/scope-mappings/clients/$REALM_MGMT_ID" -r acme-dev -f - >/dev/null
# the Admin Permissions grant that lets the client act for the realm's users who consent to it
docker compose exec -T -e REALMS=acme-dev -e ACTOR=keycloak-mcp-server -e KEYCLOAK=http://localhost:8080 \
  keycloak bash -s < "$SHARED/init/grant-delegation.sh" | grep '^\['
ADMIN_CLIENT_ID=$($KCADM get clients -r master -q clientId=keycloak-mcp-admin --fields id --format csv --noquotes | head -1 || true)
if [ -z "$ADMIN_CLIENT_ID" ]; then
  $KCADM create clients -r master -f - < clients/keycloak-mcp-admin.json >/dev/null
  ADMIN_CLIENT_ID=$($KCADM get clients -r master -q clientId=keycloak-mcp-admin --fields id --format csv --noquotes | head -1)
  echo "created client keycloak-mcp-admin (audience keycloak-mcp-admin-api)"
fi
$KCADM get roles/admin -r master --fields id,name | sed 's/^{/[{/; s/}$/}]/' \
  | $KCADM create "clients/$ADMIN_CLIENT_ID/scope-mappings/realm" -r master -f - >/dev/null
ADMIN_AT=$(curl -s "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -d 'grant_type=password&client_id=keycloak-mcp-admin&username=admin&password=admin' | jq -r .access_token)
echo "admin API with a master admin's token: HTTP $(status -H "Authorization: Bearer $ADMIN_AT" "$ADMIN/admin/systems")"

step "3b. the public client keycloak-mcp-ui: the management UI signs master realm admins in with it"
UI_CLIENT_ID=$($KCADM get clients -r master -q clientId=keycloak-mcp-ui --fields id --format csv --noquotes | head -1 || true)
if [ -z "$UI_CLIENT_ID" ]; then
  $KCADM create clients -r master -f - < "$SHARED"/clients/keycloak-mcp-ui.json >/dev/null
  UI_CLIENT_ID=$($KCADM get clients -r master -q clientId=keycloak-mcp-ui --fields id --format csv --noquotes | head -1)
  echo "created client keycloak-mcp-ui"
else
  echo "client keycloak-mcp-ui exists"
fi
# the only role the UI's API needs (kc-mcp.admin.role, realm:admin by default) in the client's role scope
$KCADM get roles/admin -r master --fields id,name | sed 's/^{/[{/; s/}$/}]/' \
  | $KCADM create "clients/$UI_CLIENT_ID/scope-mappings/realm" -r master -f - >/dev/null
echo "management UI: $ADMIN/ui/ (admin / admin)"

step "4. tools on the MCP instance: it knows 'acme' only from the database, as the reader"
U=$MCP/mcp/systems/acme/acme-dev
# the MCP instance reads the systems again every kc-mcp.spi.system-repository.db.cache-seconds (10)
for _ in $(seq 1 15); do
  "$SHARED/mcp-call.py" --login alice:alice-demo "$U" whoami 2>/dev/null | jq -e .system >/dev/null 2>&1 && break
  echo "(the MCP instance does not know 'acme' yet, waiting for its cache)"; sleep 2
done
export MCP_CALL_QUIET=1                             # the login steps (form, consent page) are not printed
"$SHARED/mcp-call.py" --login alice:alice-demo "$U" whoami | jq -c '{caller: .caller.username, system, keycloakCallsRunAs, delegation}'
"$SHARED/mcp-call.py" --login sam:sam-demo "$U" keycloak_user_search '{"search": "bob"}' | jq -c '[.items[]?.username] // .'
"$SHARED/mcp-call.py" --login sam:sam-demo "$U" keycloak_user_set_enabled '{"id": "bob", "enabled": true}' | jq -c '{error}'

step "5a. the admin API on the MCP instance, even with the right token"
echo "GET $MCP/admin/systems: HTTP $(status -H "Authorization: Bearer $ADMIN_TOKEN" "$MCP/admin/systems")"
echo "PUT $MCP/admin/systems/evil: HTTP $(status -X PUT -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' -d '{"url":"http://keycloak:8080"}' "$MCP/admin/systems/evil")"

step "5b. the MCP endpoint on the admin instance"
echo "POST $ADMIN/mcp/systems/acme/acme-dev: HTTP $(status -X POST -H 'Content-Type: application/json' -d '{}' "$ADMIN/mcp/systems/acme/acme-dev")"

step "5c. the admin API with a token issued for the MCP endpoint (alice, realm admin of acme-dev)"
MCP_AT=$("$SHARED/mcp-call.py" --login alice:alice-demo@acme-dev --print-token)
echo "GET $ADMIN/admin/systems: HTTP $(status -H "Authorization: Bearer $MCP_AT" "$ADMIN/admin/systems")"
MASTER_MCP_AT=$(curl -s "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -d 'grant_type=password&client_id=admin-cli&username=admin&password=admin' | jq -r .access_token)
echo "the same with a master admin's token without the admin API audience: HTTP $(status -H "Authorization: Bearer $MASTER_MCP_AT" "$ADMIN/admin/systems")"

step "5d. the MCP instance's database user (kcmcp_mcp) cannot change what the admin side configured"
echo "read systems:            $(as_mcp_user "select string_agg(alias, ',') from kc_mcp_system")"
echo "switch a system:         $(as_mcp_user "update kc_mcp_system set url = 'http://evil:8080'" | tail -1)"
echo "add a secret:            $(as_mcp_user "insert into kc_mcp_secret (name) values ('evil')" | tail -1)"
echo "replace a key:           $(as_mcp_user "delete from kc_mcp_signing_key" | tail -1)"
echo "append to the audit:     what the server does on every tool call (rows below)"
echo "read the audit trail:    $(as_mcp_user "select caller_name from kc_mcp_audit_event limit 1" | tail -1)"
echo "erase the audit trail:   $(as_mcp_user "delete from kc_mcp_audit_event" | tail -1)"
echo "read UI sessions:        $(as_mcp_user "select count(*) from kc_mcp_user_session" | tail -1)"

step "audit rows the MCP instance appended, read as the owner"
docker compose exec -T postgres psql -U kcmcp_admin -d kcmcp -c \
  "select tool, outcome, caller_name, system_alias, realm from kc_mcp_audit_event order by id desc limit 5"
