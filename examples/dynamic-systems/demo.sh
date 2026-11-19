#!/usr/bin/env bash
# The whole flow, step by step. Needs the stack up (docker compose up -d --build), curl, jq and python3.
#
#   1. register the system "acme" in the MCP server (admin API -> PostgreSQL, key pair generated in the database vault)
#   2. create the realm acme-dev with the public mcp-consumer client and the demo users
#   3. create the keycloak-mcp-server client in that realm, JWKS URL = what the API answered: its service account
#      administers the realm (port 8091), and the realm's users may let it act on their behalf (port 8092);
#      keycloak-mcp-admin and keycloak-mcp-ui in master, for the admin API and the management UI
#   4. call tools: as the service account (port 8091) and as the realm's users (port 8092)
#   5. a second Keycloak (:8089) with four realms of its own: register it as the system "globex", create the
#      server's client there with the setup script the admin API generates, list its realms, adopt two of them and
#      call a tool in one; the other two are left to adopt in the management UI (system globex, tab Adopt)
#
#   ./demo.sh                 all steps; idempotent
#   ./demo.sh --skip-adopt    without step 5, to do all of it in the management UI (README.md, "Adopting realms")
set -euo pipefail
cd "$(dirname "$0")"
MCP=http://localhost:8091
MCP_INTERNAL=http://mcp:8081                       # how Keycloak reaches the MCP server inside the compose network
ADMIN_TOKEN=${KC_MCP_ADMIN_TOKEN:-demo-admin-token}
KCADM="docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh"

SKIP_ADOPT=
for arg in "$@"; do
  case "$arg" in
    --skip-adopt) SKIP_ADOPT=1 ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $arg (try --help)" >&2; exit 2 ;;
  esac
done

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
admin() {
  curl -sS \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'Content-Type: application/json' \
    "$@"
}

# docker compose up returns before the servers listen
for _ in $(seq 1 60); do curl -s -o /dev/null "$MCP/mcp" && break; sleep 1; done
curl -s -o /dev/null "$MCP/mcp" || { echo "no MCP server at $MCP: docker compose up -d --build first" >&2; exit 1; }

step "1. register the system 'acme' (stored in PostgreSQL, key pair generated in the database vault)"
SYSTEM=$(admin -X PUT "$MCP/api/admin/systems/acme" -d @- <<'JSON'
{
  "displayName": "ACME Corp.",
  "description": "ACME's Keycloak, administered through the MCP server",
  "url": "http://keycloak:8080",
  "issuer": "http://localhost:8090/realms/acme-dev",
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
echo "$SYSTEM" | jq .
if echo "$SYSTEM" | jq -e '.error == "signing_key_exists"' >/dev/null; then
  echo "(already registered with a key; replacing the settings, keeping the key)"
  SYSTEM=$(admin -X PUT "$MCP/api/admin/systems/acme" -d "$(echo '{}' | jq '. + {"displayName":"ACME Corp.","description":"ACME'"'"'s Keycloak, administered through the MCP server","url":"http://keycloak:8080","issuer":"http://localhost:8090/realms/acme-dev","authRealm":"acme-dev","defaultRealm":"acme-dev","allowedRealms":["acme-dev"],"version":"26.8.2","signingKey":"existing"}')")
fi
JWKS_PATH=$(echo "$SYSTEM" | jq -r .signingKey.jwksPath)
JWKS_URL="$MCP_INTERNAL$JWKS_PATH"
echo "JWKS for Keycloak: $JWKS_URL  (from the host: $MCP$JWKS_PATH)"
curl -s "$MCP$JWKS_PATH" | jq -c '.keys[0] | {kty, alg, kid}'

step "2. the realm acme-dev: public client mcp-consumer (consent required), groups with realm-management roles, users"
$KCADM config credentials --server http://localhost:8080 --realm master --user admin --password admin >/dev/null
if $KCADM get realms/acme-dev >/dev/null 2>&1; then
  echo "realm acme-dev exists"
else
  $KCADM create realms -f - < realms/acme-dev.json
  echo "created realm acme-dev (alice = admin, sam = support, dave = developer, bob = disabled)"
fi

step "3. the keycloak-mcp-server client in the realm acme-dev, Signed JWT with that JWKS URL"
CLIENT_ID=$($KCADM get clients -r acme-dev -q clientId=keycloak-mcp-server --fields id --format csv --noquotes | head -1 || true)
if [ -z "$CLIENT_ID" ]; then
  sed "s#\${MCP_JWKS_URL}#$JWKS_URL#" clients/keycloak-mcp-server.json | $KCADM create clients -r acme-dev -f - >/dev/null
  CLIENT_ID=$($KCADM get clients -r acme-dev -q clientId=keycloak-mcp-server --fields id --format csv --noquotes | head -1)
  echo "created client keycloak-mcp-server ($CLIENT_ID)"
else
  echo "client keycloak-mcp-server exists ($CLIENT_ID)"
fi
# realm-admin of acme-dev: what the server on port 8091 does with this service account ...
$KCADM add-roles -r acme-dev --uusername service-account-keycloak-mcp-server --cclientid realm-management --rolename realm-admin
# ... and the client's role scope lets the role into its tokens (full scope allowed is off, as Keycloak asks). The
# same scope caps the delegated tokens of port 8092: a user's roles count as far as they lie within it
REALM_MGMT_ID=$($KCADM get clients -r acme-dev -q clientId=realm-management --fields id --format csv --noquotes | head -1)
$KCADM get "clients/$REALM_MGMT_ID/roles/realm-admin" -r acme-dev --fields id,name | sed 's/^{/[{/; s/}$/}]/' \
  | $KCADM create "clients/$CLIENT_ID/scope-mappings/clients/$REALM_MGMT_ID" -r acme-dev -f - >/dev/null
echo "service account holds realm-management/realm-admin of acme-dev, in the client's role scope"
# the Admin Permissions grant that lets the client act for the realm's users who consent to it (a realm import
# cannot carry it); Standard Token Exchange is on in clients/keycloak-mcp-server.json
docker compose exec -T -e REALMS=acme-dev -e ACTOR=keycloak-mcp-server -e KEYCLOAK=http://localhost:8080 \
  keycloak bash -s < init/grant-delegation.sh | grep '^\['

step "3b. the public client keycloak-mcp-admin: people call the admin API with their own access token"
ADMIN_CLIENT_ID=$($KCADM get clients -r master -q clientId=keycloak-mcp-admin --fields id --format csv --noquotes | head -1 || true)
if [ -z "$ADMIN_CLIENT_ID" ]; then
  $KCADM create clients -r master -f - < clients/keycloak-mcp-admin.json >/dev/null
  ADMIN_CLIENT_ID=$($KCADM get clients -r master -q clientId=keycloak-mcp-admin --fields id --format csv --noquotes | head -1)
  echo "created client keycloak-mcp-admin ($ADMIN_CLIENT_ID)"
else
  echo "client keycloak-mcp-admin exists ($ADMIN_CLIENT_ID)"
fi
$KCADM get roles/admin -r master --fields id,name | sed 's/^{/[{/; s/}$/}]/' \
  | $KCADM create "clients/$ADMIN_CLIENT_ID/scope-mappings/realm" -r master -f - >/dev/null
# admin-cli tokens are lightweight in Keycloak 26 (no roles, no audience): the admin API refuses them, this client's work
TOKEN_URL=http://localhost:8090/realms/master/protocol/openid-connect/token
ADMIN_AT=$(curl -s "$TOKEN_URL" \
  -d 'grant_type=password&client_id=keycloak-mcp-admin&username=admin&password=admin' | jq -r .access_token)
curl -sS "$MCP/api/admin/systems" \
  -H "Authorization: Bearer $ADMIN_AT" | jq -c '[.systems[] | {alias, source}]'
CLI_AT=$(curl -s "$TOKEN_URL" \
  -d 'grant_type=password&client_id=admin-cli&username=admin&password=admin' | jq -r .access_token)
curl -s "$MCP/api/admin/systems" \
  -H "Authorization: Bearer $CLI_AT" \
  -o /dev/null -w 'the same with an admin-cli token (no audience, no roles): HTTP %{http_code}\n'

step "3c. the public client keycloak-mcp-ui: the management UI signs master realm admins in with it"
UI_CLIENT_ID=$($KCADM get clients -r master -q clientId=keycloak-mcp-ui --fields id --format csv --noquotes | head -1 || true)
if [ -z "$UI_CLIENT_ID" ]; then
  $KCADM create clients -r master -f - < clients/keycloak-mcp-ui.json >/dev/null
  UI_CLIENT_ID=$($KCADM get clients -r master -q clientId=keycloak-mcp-ui --fields id --format csv --noquotes | head -1)
  echo "created client keycloak-mcp-ui"
else
  echo "client keycloak-mcp-ui exists"
fi
# the only role the UI needs (kc-mcp.ui.operator-role, by default the admin API's: realm:admin) in the client's role scope
$KCADM get roles/admin -r master --fields id,name | sed 's/^{/[{/; s/}$/}]/' \
  | $KCADM create "clients/$UI_CLIENT_ID/scope-mappings/realm" -r master -f - >/dev/null
echo "management UI: $MCP/ui/ (admin / admin)"

step "4a. as the service account (port 8091): the entry /mcp/systems/acme/acme-dev"
./mcp-call.py "$MCP/mcp/systems/acme/acme-dev" whoami | jq -c '{system, entry, keycloakCallsRunAs, server: .server.version}'
./mcp-call.py "$MCP/mcp/systems/acme/acme-dev" keycloak_user_search '{"search": "alice"}' | jq -c '[.items[]?.username] // .'

step "4b. as the realm's users (port 8092): alice may do everything, sam reads, dave manages clients"
U=http://localhost:8092/mcp/systems/acme/acme-dev
# what an MCP client does first: the entry answers 401 and names its metadata, which names the realm and the scope
./mcp-call.py "$U" whoami || true
curl -s localhost:8092/.well-known/oauth-protected-resource/mcp/systems/acme/acme-dev | jq -c '{authorization_servers, scopes_supported}'
./mcp-call.py --login alice:alice-demo "$U" whoami | jq -c '{caller: .caller.username, keycloakCallsRunAs, delegation, roles: (.roles["acme-dev"] | length)}'
export MCP_CALL_QUIET=1                             # the login and consent steps were shown once
./mcp-call.py --login alice:alice-demo "$U" keycloak_user_set_enabled '{"id": "bob", "enabled": true}' | jq -c '{username, enabled} // .'
./mcp-call.py --login sam:sam-demo "$U" keycloak_user_search '{"search": "bob"}' | jq -c '[.items[]?.username] // .'
./mcp-call.py --login sam:sam-demo "$U" keycloak_user_set_enabled '{"id": "bob", "enabled": false}' | jq -c '{error, message}'
./mcp-call.py --login dave:dave-demo "$U" keycloak_client_list '{}' | jq -c '[.items[]?.clientId] // .'
./mcp-call.py --login dave:dave-demo "$U" keycloak_user_delete '{"id": "bob", "username": "bob"}' | jq -c '{error, message}'
./mcp-call.py --login alice:alice-demo "$U" keycloak_user_set_enabled '{"id": "bob", "enabled": false}' | jq -c '{username, enabled} // .'

if [ -z "$SKIP_ADOPT" ]; then
  step "5a. a second Keycloak, Globex' (:8089): registered as the system 'globex', its client lives in master"
  GLOBEX_SYSTEM='{"displayName":"Globex Corp.","description":"Globex\u0027 Keycloak, its realms adopted one by one","url":"http://keycloak-globex:8080","issuer":"http://localhost:8089/realms/master","authRealm":"master","clientId":"keycloak-mcp-server","clientAuth":"private_key_jwt","version":"26.8.2"}'
  GLOBEX=$(admin -X PUT "$MCP/api/admin/systems/globex" -d "$(jq -c '. + {signingKey: "generate"}' <<<"$GLOBEX_SYSTEM")")
  if jq -e '.error == "signing_key_exists"' >/dev/null <<<"$GLOBEX"; then
    echo "(already registered with a key; keeping the key and the realms adopted so far)"
    GLOBEX=$(admin "$MCP/api/admin/systems/globex")
  fi
  jq -c '{alias, url, authRealm, clientAuth, allowedRealms, entries}' <<<"$GLOBEX"

  step "5b. the server creates nothing in Keycloak: it hands out the client as JSON and as a kcadm script to run there"
  KCADM_GLOBEX="docker compose exec -T keycloak-globex /opt/keycloak/bin/kcadm.sh"
  $KCADM_GLOBEX config credentials --server http://localhost:8080 --realm master --user admin --password admin >/dev/null
  if [ -n "$($KCADM_GLOBEX get clients -r master -q clientId=keycloak-mcp-server --fields id --format csv --noquotes | head -1)" ]; then
    echo "client keycloak-mcp-server exists in Globex' master realm"
  else
    echo "before the client exists, listing the realms answers:"
    admin "$MCP/api/admin/systems/globex/keycloak-realms" | jq -c '{error}'
    # roles=admin: the master admin role, every realm; credential=public-key: the key is copied into the client,
    # for a Keycloak that cannot fetch it from the server's JWKS URL
    SETUP=$(admin "$MCP/api/admin/systems/globex/client-setup?roles=admin&credential=public-key")
    jq -c '{client: (.client | {clientId, clientAuthenticatorType, fullScopeAllowed}), roles: .roles.mode}' <<<"$SETUP"
    jq -r .script <<<"$SETUP" | ./adopt-setup.sh 2>&1 | sed '/^$/d'      # kcadm reports on stderr
  fi

  step "5c. the realms the client's service account sees there; none is adopted yet on a first run"
  admin "$MCP/api/admin/systems/globex/keycloak-realms" | jq -c '.realms[] | {name, displayName, enabled, adopted}'

  step "5d. adopt two of them: they become the system's allowlist, with Keycloak's realm id and display name"
  admin -X POST "$MCP/api/admin/systems/globex/adoption" -d '{"realms": ["globex-staff", "globex-customers"], "restrict": true}' \
    | jq -c 'del(.system) | with_entries(select(.value != null and .value != []))'
  admin "$MCP/api/admin/systems/globex" | jq -c '{allowedRealms, entries}'

  step "5e. tools in an adopted realm, and in one that was not adopted"
  ./mcp-call.py "$MCP/mcp/systems/globex/globex-staff" keycloak_user_search '{"search": "*"}' | jq -c '[.items[]?.username] // .'
  ./mcp-call.py "$MCP/mcp/systems/globex" keycloak_user_search '{"realm": "globex-partners", "search": "*"}' | jq -c '{error, message}'
  echo "left to adopt in the management UI ($MCP/ui/, system globex, tab Adopt): globex-partners, globex-legacy (disabled)"
fi

step "audit rows in PostgreSQL (the console of mcp-users shows pseudonyms, the rows the real names)"
docker compose exec -T postgres psql -U kcmcp -d kcmcp -c "select tool, outcome, caller_name, system_alias, realm from kc_mcp_audit_event order by id desc limit 8"
