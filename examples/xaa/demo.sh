#!/usr/bin/env bash
# The Cross-App Access flow, step by step. Needs the stack up (docker compose up -d) and the MCP server running with
# env/xaa.env (see README.md), plus python3 and jq.
#
#   1. alice: discovery, IdP sign-in, ID-JAG, JWT authorization grant, whoami; no login page of Keycloak, no consent
#   2. alice (realm-admin in Keycloak) reads and writes; carol (view-users) reads and is refused on writes
#   3. bob is realm-admin in Keycloak, yet the IdP's policy refuses him the ID-JAG: he never reaches the MCP server
#   4. dave may connect by policy but has no linked account in realm acme: Keycloak refuses the ID-JAG
#   5. a replayed ID-JAG is refused
#   6. Keycloak's audit: JWT_AUTHORIZATION_GRANT events name the IdP, its user id and the client, TOKEN_EXCHANGE
#      events name the MCP server's client as the actor, the admin event names alice
#
# SHOW_TOKENS=1 ./demo.sh also prints the tokens of step 1: ID token, ID-JAG, access token, and the two the MCP server
# gets for it (the actor's and the delegated one).
set -euo pipefail
cd "$(dirname "$0")"
export MCP_URL=${MCP_URL:-http://localhost:8103/mcp}
KCADM="docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh"

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
call() { ./xaa-call.py "$@" 2>/dev/null; }

step "1. alice: the whole chain, progress on stderr"
# is this the server of this example? One started with another example's settings fails later, less clearly
../preflight.sh endpoint "$MCP_URL" login=required
WHOAMI=$(./xaa-call.py --login alice:alice-demo ${SHOW_TOKENS:+--show-tokens} whoami)
../preflight.sh whoami system=default delegation=exchange <<<"$WHOAMI"
jq -c <<<"$WHOAMI" \
  '{caller: .caller.username, keycloakCallsRunAs, delegation, roles: (.roles.acme | length | tostring + " realm-management roles")}'

step "2. what each user may do is Keycloak's call: alice (realm-admin), carol (view-users, view-events)"
call --login alice:alice-demo keycloak_user_search '{"search": "*"}' | jq -c '[.items[]?.username] // .'
call --login alice:alice-demo keycloak_user_update '{"id": "erin", "lastName": "Customer-Verified"}' | jq -c .
call --login carol:carol-demo keycloak_user_get '{"id": "frank"}' | jq -c '{username, enabled} // .'
call --login carol:carol-demo keycloak_user_set_enabled '{"id": "frank", "enabled": true}' | jq -c '{error, missingRoles}'

step "3. whether a user may connect the agent at all is the IdP's call: bob (sales) is refused"
./xaa-call.py --login bob:bob-demo whoami 2>&1 | tail -1 || true

step "4. dave may connect by policy, but realm acme has no account linked to his IdP subject"
./xaa-call.py --login dave:dave-demo whoami 2>&1 | tail -1 || true

step "5. an ID-JAG is single use (jwtAuthorizationGrantAssertionReuseAllowed=false)"
python3 -I - <<'EOF'
import base64, json, urllib.parse, urllib.request
def post(url, form, user, secret):
    req = urllib.request.Request(url, urllib.parse.urlencode(form).encode(),
        {"Authorization": "Basic " + base64.b64encode(f"{user}:{secret}".encode()).decode()})
    try:
        return json.load(urllib.request.urlopen(req))
    except urllib.error.HTTPError as e:
        return json.load(e)
idp = "http://localhost:8102/token"
kc = "http://localhost:8101/realms/acme/protocol/openid-connect/token"
id_token = post(idp, {"grant_type": "password", "username": "alice", "password": "alice-demo"}, "agent", "agent-at-idp")["id_token"]
jag = post(idp, {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                 "requested_token_type": "urn:ietf:params:oauth:token-type:id-jag",
                 "subject_token_type": "urn:ietf:params:oauth:token-type:id_token", "subject_token": id_token,
                 "audience": "http://localhost:8101/realms/acme", "resource": "http://localhost:8103"},
           "agent", "agent-at-idp")["access_token"]
for attempt in ("first", "second"):
    answer = post(kc, {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": jag}, "agent", "agent-at-acme")
    print(f"{attempt} use:", "access token" if "access_token" in answer else f"{answer['error']}: {answer.get('error_description')}")
EOF

step "6. Keycloak's audit trail"
$KCADM config credentials --server http://keycloak:8080 --realm master --user admin --password admin >/dev/null 2>&1
# kcadm keeps only the last of repeated -q type=...: filter in jq
$KCADM get events -r acme -q max=50 2>/dev/null \
  | jq -c '[.[] | select(.type | startswith("JWT_AUTHORIZATION_GRANT"))][:5][] | {time: (.time / 1000 | todate), type, client: .clientId, user: .details.username, idp: .details.identity_provider, idpUser: .details.identity_provider_user_id, error: .details.reason}'
echo "TOKEN_EXCHANGE events (the MCP server's client keycloak-mcp exchanges the user's token, actor = its service account):"
$KCADM get events -r acme -q type=TOKEN_EXCHANGE -q max=3 2>/dev/null \
  | jq -c '.[] | {time: (.time / 1000 | todate), user: .userId, client: .clientId, details: (.details | with_entries(select(.key | test("actor|subject|token_type"; "i"))))}'
echo "admin events: the UPDATE of erin was made by alice (authDetails.userId = her id), not by a service account:"
$KCADM get admin-events -r acme -q operationTypes=UPDATE -q resourceTypes=USER -q max=1 2>/dev/null \
  | jq -c '.[] | {time: (.time / 1000 | todate), operation: .operationType, resource: .resourcePath, authUser: .authDetails.userId, authClient: .authDetails.clientId}'
ALICE=$($KCADM get users -r acme -q username=alice -q exact=true --fields id --format csv --noquotes | head -1)
echo "alice's id: $ALICE"
echo "the IdP's decisions (docker compose logs idp):"
docker compose logs --no-log-prefix idp 2>/dev/null | grep -E 'ID-JAG for' | tail -4
