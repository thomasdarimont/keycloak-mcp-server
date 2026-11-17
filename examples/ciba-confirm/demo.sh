#!/usr/bin/env bash
# The CIBA confirmation, step by step. Needs the stack up (docker compose up -d) and the MCP server running with
# env/ciba.env (see README.md), plus python3, curl and jq.
#
#   1. alice logs in to the MCP server and consents to keycloak-mcp acting on her behalf (the script walks
#      Keycloak's login and consent pages); whoami shows her as the caller and the delegation
#   2. alice creates a throw-away user (a write: no confirmation) and asks to delete it (destructive): the first call
#      files a CIBA request and answers at once with a two-digit number. On her device (the approver, where she is
#      signed in) the request shows who asks for what and asks for that number: a wrong number is refused, the right
#      one approves; the second call deletes the user
#   3. the same with a decline: the second call answers cancelled, nothing is deleted
#   4. carol, signed in to the device as herself, sees none of alice's requests and cannot decide them
#   5. confirm: true changes nothing: a new request reaches the device all the same
#
#   ./demo.sh                 runs the steps above
#   ./demo.sh --users=5       only creates 5 users with random names in the demo realm (as alice, through the MCP
#                             server; a write needs no approval), e.g. to have someone to delete from LM Studio
set -euo pipefail
cd "$(dirname "$0")"
export MCP_URL=${MCP_URL:-http://localhost:8099/mcp}
export KEYCLOAK_URL=${KEYCLOAK_URL:-http://localhost:8098}
KEYCLOAK=$KEYCLOAK_URL
APPROVER=${APPROVER_URL:-http://localhost:8095}

USERS=
for arg in "$@"; do
  case "$arg" in
    --users=*) USERS=${arg#--users=} ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $arg (try --help)" >&2; exit 2 ;;
  esac
done
if [ -n "$USERS" ] && ! [[ "$USERS" =~ ^[1-9][0-9]*$ ]]; then
  echo "--users needs a positive number, got '$USERS'" >&2; exit 2
fi

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
call() { ./mcp-call.py "$@" || true; }
# an access token of the approver's client: what the browser session holds after the OIDC login
device_token() { curl -s -d grant_type=password -d client_id=ciba-approver -d scope=openid -d "username=$1" -d "password=$2" \
  "$KEYCLOAK/realms/demo/protocol/openid-connect/token" | jq -r .access_token; }
# one login of alice at the MCP server for the whole run, as an MCP client has it
ALICE=$(./mcp-call.py --login alice:alice-demo --print-token) || true
[ -n "$ALICE" ] || { echo "alice could not log in at $KEYCLOAK; is the stack up?" >&2; exit 1; }
ALICE_DEVICE=$(device_token alice alice-demo)
CAROL_DEVICE=$(device_token carol carol-demo)
device() { local token=$1; shift; curl -s -H "Authorization: Bearer $token" "$@"; }

# waits until alice's device holds a pending request, prints it
pending() {
  for _ in $(seq 1 40); do
    local p; p=$(device "$ALICE_DEVICE" "$APPROVER/pending")
    if [ "$(jq length <<<"$p")" -gt 0 ]; then jq -c '.[0] | {loginHint, operation, requester, bindingMessage, expectsCode}' <<<"$p"; return 0; fi
    sleep 0.5
  done
  echo "no request reached the approver; is Keycloak's authentication channel pointing at it?" >&2; return 1
}

create() {
  # not $RANDOM: process substitutions may reseed it identically and produce the same name twice
  local name="temp-$(uuidgen | tr 'A-Z' 'a-z' | cut -c1-8)"
  local id; id=$(call --token "$ALICE" keycloak_user_create "{\"username\": \"$name\", \"email\": \"$name@example.com\", \"firstName\": \"Temp\", \"lastName\": \"User\"}" | jq -r '.id')
  echo "$name $id"
}

# --users=N: create N users with random names and stop
if [ -n "$USERS" ]; then
  FIRST_NAMES=(Ada Ben Chloe David Emma Felix Grace Henry Iris Jonas Klara Leo Mia Noah Olivia Paul Rosa Sam Tara Yusuf)
  LAST_NAMES=(Becker Costa Dubois Evans Fischer Garcia Hansen Ito Jansen Kowalski Larsen Meyer Novak Okafor Petrov Rossi Schmidt Tanaka Weber Young)
  for i in $(seq 1 "$USERS"); do
    first=${FIRST_NAMES[$(( $(od -An -N2 -tu2 /dev/urandom) % ${#FIRST_NAMES[@]} ))]}
    last=${LAST_NAMES[$(( $(od -An -N2 -tu2 /dev/urandom) % ${#LAST_NAMES[@]} ))]}
    # a random suffix keeps names unique across runs
    name=$(tr 'A-Z' 'a-z' <<<"$first.$last")-$(uuidgen | tr 'A-Z' 'a-z' | cut -c1-4)
    call --token "$ALICE" keycloak_user_create "{\"username\": \"$name\", \"email\": \"$name@example.com\", \"firstName\": \"$first\", \"lastName\": \"$last\"}" \
      | jq -c --arg n "$name" '{username: $n, id, error, message} | with_entries(select(.value != null))'
  done
  exit 0
fi

step "1. alice logs in to the MCP server; whoami"
call --token "$ALICE" whoami | jq -c '{caller: .caller.username, delegation, can: .can.demo}'

step "2. delete a user: the first call files the request and shows the number, alice's device asks for it"
read -r NAME ID < <(create)
echo "created $NAME ($ID); asking to delete it ..."
FIRST=$(call --token "$ALICE" keycloak_user_delete "{\"id\": \"$ID\", \"username\": \"$NAME\"}")
jq -c '{error, message, approval}' <<<"$FIRST"
CODE=$(jq -r '.approval.code' <<<"$FIRST")
echo "alice's device shows:"; pending
echo "without signing in the device shows nothing:"; curl -s "$APPROVER/pending" | jq -c .
echo "a wrong number is refused:"; device "$ALICE_DEVICE" -X POST "$APPROVER/approve/latest?code=00" | jq -c .
echo "the number from the chat ($CODE) approves:"; device "$ALICE_DEVICE" -X POST "$APPROVER/approve/latest?code=$CODE" | jq -c .
echo "the second call collects the approval and runs:"
call --token "$ALICE" keycloak_user_delete "{\"id\": \"$ID\", \"username\": \"$NAME\"}" | jq -c .
call --token "$ALICE" keycloak_user_search "{\"search\": \"$NAME\", \"exact\": true}" | jq -c '{found: (.items | length)}'

step "3. delete another user: alice declines on her device"
read -r NAME ID < <(create)
echo "created $NAME ($ID); asking to delete it ..."
call --token "$ALICE" keycloak_user_delete "{\"id\": \"$ID\", \"username\": \"$NAME\"}" | jq -c '{error, approval: .approval.status}'
echo "alice's device shows:"; pending

step "4. carol's device: none of alice's requests, and she cannot decide them"
echo "carol's pending list:"; device "$CAROL_DEVICE" "$APPROVER/pending" | jq -c .
LATEST=$(device "$ALICE_DEVICE" "$APPROVER/pending" | jq -r '.[0].id')
echo "carol trying to approve alice's request $LATEST:"; device "$CAROL_DEVICE" -X POST "$APPROVER/approve/$LATEST?code=$CODE" | jq -c .

echo; echo "back to 3.: alice declines ..."; device "$ALICE_DEVICE" -X POST "$APPROVER/decline/latest" | jq -c .
echo "the second call:"
call --token "$ALICE" keycloak_user_delete "{\"id\": \"$ID\", \"username\": \"$NAME\"}" | jq -c '{error, message}'
call --token "$ALICE" keycloak_user_search "{\"search\": \"$NAME\", \"exact\": true}" | jq -c '{found: (.items | length)}'

step "5. confirm: true counts for nothing: a new request reaches the device all the same (declined again)"
call --token "$ALICE" keycloak_user_delete "{\"id\": \"$ID\", \"username\": \"$NAME\", \"confirm\": true}" | jq -c '{error, approval: .approval.status}'
pending >/dev/null && device "$ALICE_DEVICE" -X POST "$APPROVER/decline/latest" >/dev/null
call --token "$ALICE" keycloak_user_delete "{\"id\": \"$ID\", \"username\": \"$NAME\", \"confirm\": true}" | jq -c '{error, message}'
echo; echo "Sign in as alice / alice-demo at $APPROVER/ to see her decisions."
