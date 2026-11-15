#!/usr/bin/env bash
# The step-up, step by step. Needs the stack up (docker compose up -d) and the MCP server running with
# env/step-up-device.env or env/step-up-browser.env (see README.md), plus python3 and jq.
#
#   1. alice logs in to the MCP server with her password; whoami shows her acr
#   2. she creates a throw-away user (a write: no step-up) and asks to delete it (destructive): the call is refused
#      with insufficient_user_authentication and a link
#   3. YOU open the link in a browser and sign in as alice (alice-demo) with a passkey (register one first, see
#      README.md). Then press Enter here, within a minute of the passkey login: it counts for one minute
#   4. the same call runs now, and so does the next destructive call within one minute
# Each run is a new login of alice, so each run asks for the passkey again.
set -euo pipefail
cd "$(dirname "$0")"
export MCP_URL=${MCP_URL:-http://localhost:8109/mcp}
export KEYCLOAK_URL=${KEYCLOAK_URL:-http://localhost:8108}

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
call() { ./mcp-call.py "$@" || true; }

# A server that requires a login names it in its challenge. Without one, the endpoint is not there or does not ask
# for a login (the env file was not sourced): say so instead of running into a 401 at each step.
CHALLENGE=$(curl -s -o /dev/null -D - -X POST "$MCP_URL" -H 'Content-Type: application/json' -d '{}' | tr -d '\r' | grep -i '^www-authenticate:' || true)
if ! grep -q 'resource_metadata=' <<<"$CHALLENGE"; then
  echo "No MCP server that asks for a login answers at $MCP_URL. Start it with env/step-up-device.env or" >&2
  echo "env/step-up-browser.env sourced (see README.md)." >&2
  exit 1
fi

step "1. alice logs in to the MCP server; whoami"
# one login for the whole run, as an MCP client has it: a step-up counts for the session it was asked in
TOKEN=$(curl -s -d grant_type=password -d client_id=mcp-consumer -d scope=openid -d username=alice -d password=alice-demo \
  "$KEYCLOAK_URL/realms/demo/protocol/openid-connect/token" | jq -r '.access_token // empty')
[ -n "$TOKEN" ] || { echo "alice could not log in at $KEYCLOAK_URL; is the stack up?" >&2; exit 1; }
call --token "$TOKEN" whoami | jq -c '{caller: .caller}'

step "2. delete a user: refused, with a link to sign in again"
NAME="temp-$(uuidgen | tr 'A-Z' 'a-z' | cut -c1-8)"
ID=$(call --token "$TOKEN" keycloak_user_create "{\"username\": \"$NAME\", \"email\": \"$NAME@example.com\", \"firstName\": \"Temp\", \"lastName\": \"User\"}" | jq -r '.id')
echo "created $NAME ($ID)"
DELETE="{\"id\": \"$ID\", \"username\": \"$NAME\", \"confirm\": true}"
call --token "$TOKEN" keycloak_user_delete "$DELETE" | jq -r '.error, .message'

step "3. open the link above in a browser, sign in as alice (alice-demo) with a passkey, then press Enter within a minute"
read -r _

step "4. the same call again, and another destructive call within one minute"
call --token "$TOKEN" keycloak_user_delete "$DELETE" | jq -c .
NAME2="temp-$(uuidgen | tr 'A-Z' 'a-z' | cut -c1-8)"
ID2=$(call --token "$TOKEN" keycloak_user_create "{\"username\": \"$NAME2\", \"email\": \"$NAME2@example.com\", \"firstName\": \"Temp\", \"lastName\": \"User\"}" | jq -r '.id')
call --token "$TOKEN" keycloak_user_delete "{\"id\": \"$ID2\", \"username\": \"$NAME2\", \"confirm\": true}" | jq -c .
