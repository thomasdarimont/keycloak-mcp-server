#!/usr/bin/env bash
# The delegation flow, step by step. Needs the stack up (docker compose up -d) and the MCP server running with
# env/delegation.env (see README.md), plus python3 and jq.
#
#   1. alice (realm-admin) logs in and consents: whoami shows the delegation and her roles as the actor's scope caps them
#   2. alice reads and changes users, but may not even list clients: realm-admin, narrowed by keycloak-mcp's role scope
#   3. carol (view-users) reads, is refused on writes; bob (no admin role) is refused outright
#   4. a login without the delegation scope: the server explains what is missing instead of acting
#   5. Keycloak's audit: the TOKEN_EXCHANGE event names the actor, the admin event names alice
#
# SHOW_TOKENS=1 ./demo.sh also prints the tokens of step 1: alice's, the actor's and the delegated one.
set -euo pipefail
cd "$(dirname "$0")"
export MCP_URL=${MCP_URL:-http://localhost:8097/mcp}
KCADM="docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh"

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
call() { ./mcp-call.py "$@" 2>/dev/null; }

step "1. alice logs in and consents to keycloak-mcp acting on her behalf; whoami"
# is this the server of this example? One started with another example's settings fails later, less clearly
../preflight.sh endpoint "$MCP_URL" login=required
WHOAMI=$(./mcp-call.py --login alice:alice-demo ${SHOW_TOKENS:+--show-tokens} whoami)
../preflight.sh whoami system=default delegation=exchange <<<"$WHOAMI"
jq <<<"$WHOAMI" \
  '{caller: .caller.username, keycloakCallsRunAs, delegation, roles: .roles.demo | map(.role), can: .can.demo}'

step "2. alice is realm-admin, yet the delegated token only carries the roles in keycloak-mcp's scope"
call --login alice:alice-demo keycloak_user_search '{"search": "*"}' | jq -c '[.items[]?.username] // .'
call --login alice:alice-demo keycloak_user_update '{"id": "carol", "lastName": "Danvers"}' | jq -c .
echo "listing clients needs query-clients, which the actor's scope does not carry:"
call --login alice:alice-demo keycloak_client_list | jq -c '{error, missingRoles}'

step "3. carol (view-users, view-events) and bob (nothing)"
call --login carol:carol-demo keycloak_user_get '{"id": "dave"}' | jq -c '{username, enabled} // .'
call --login carol:carol-demo keycloak_user_set_enabled '{"id": "dave", "enabled": true}' | jq -c '{error, missingRoles}'
call --login bob:bob-demo keycloak_user_search '{"search": "*"}' | jq -c '{error, message}'

step "4. a login without the delegation scope (the MCP client did not ask for it): no may_act, no exchange"
call --login alice:alice-demo --scope openid whoami | jq -c '{keycloakCallsRunAs, delegation: (.delegation | {consented, error}), roles}'
call --login alice:alice-demo --scope openid keycloak_user_search '{"search": "*"}' | jq -c '{error, message}'

step "5. Keycloak's audit trail"
$KCADM config credentials --server http://keycloak:8080 --realm master --user admin --password admin >/dev/null
echo "TOKEN_EXCHANGE events (actor = keycloak-mcp's service account, the user = subject):"
$KCADM get events -r demo -q type=TOKEN_EXCHANGE -q max=3 2>/dev/null \
  | jq -c '.[] | {time: (.time / 1000 | todate), user: .userId, client: .clientId, details: (.details | with_entries(select(.key | test("actor|subject|token_type"; "i"))))}'
echo "admin events: the UPDATE of carol was made by alice (authDetails.userId = her id), not by a service account:"
$KCADM get admin-events -r demo -q operationTypes=UPDATE -q resourceTypes=USER -q max=1 2>/dev/null \
  | jq -c '.[] | {time: (.time / 1000 | todate), operation: .operationType, resource: .resourcePath, authUser: .authDetails.userId, authClient: .authDetails.clientId}'
ALICE=$($KCADM get users -r demo -q username=alice -q exact=true --fields id --format csv --noquotes | head -1)
echo "alice's id: $ALICE"
