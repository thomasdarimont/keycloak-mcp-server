#!/usr/bin/env bash
# The extensions at work. Needs the stack up (docker compose up -d --build), curl, jq and python3.
set -euo pipefail
cd "$(dirname "$0")"
MCP=http://localhost:8094/mcp
CALL=../dynamic-systems/mcp-call.py
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

for i in $(seq 1 60); do curl -s -o /dev/null localhost:8094/ && break; sleep 1; done

step "startup: the jar, its extensions, the tool count"
docker compose logs mcp 2>&1 | grep -E "Extensions directory|Tool provider 'acme'|Access check 'acme|repository 'acme|tools registered|prompts registered" | sed 's/.*INFO  //' | cut -c1-160

step "AcmeToolProvider: keycloak_acme_user_summary (READ, needs view-users)"
$CALL $MCP keycloak_acme_user_summary '{"username": "alice"}' | jq -c '{summary, groups}'

step "TicketConfirmer: offboarding without a ticket is declined ..."
$CALL $MCP keycloak_acme_user_offboard '{"username": "bob"}' | jq -c '{error, message}'
step "... with a ticket it runs (DESTRUCTIVE, no prompt needed)"
BOB_GROUPS=$($CALL $MCP keycloak_user_groups_list '{"userId": "bob"}' | jq -r '[.items[]?.path] | join(" ")')
$CALL $MCP keycloak_acme_user_offboard '{"username": "bob", "ticket": "ACME-42"}' | jq -c .

step "ProtectedUsersCheck: svc-* users are off limits for every write, built-in tools included"
$CALL $MCP keycloak_user_set_enabled '{"id": "svc-backup", "enabled": false}' | jq -c '{error, message}'
step "the per-tool access check of the offboarding tool"
$CALL $MCP keycloak_acme_user_offboard '{"username": "admin", "ticket": "ACME-1"}' | jq -c '{error, message}'

step "NoEmailScrubber + JsonLinesAuditListener: the e-mail argument is masked in the file"
$CALL $MCP keycloak_user_search '{"email": "alice@example.com"}' > /dev/null
docker compose exec -T mcp tail -n 4 /deployments/data/acme-audit.jsonl | jq -c '{tool, outcome, args}'

step "AcmeTenantRepository: the system 'globex' from the setting answers at its entry"
curl -s -o /dev/null -w 'POST /mcp/systems/globex initialize: HTTP %{http_code}\n' "$MCP/systems/globex" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}'

step "AcmePrompts: acme_offboard_user with its tools attached"
SESSION=$(curl -s -D - -o /dev/null "$MCP" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}' \
  | grep -i '^mcp-session-id' | awk '{print $2}' | tr -d '\r')
curl -s "$MCP" -H "Mcp-Session-Id: $SESSION" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":2,"method":"prompts/get","params":{"name":"acme_offboard_user","arguments":{"username":"bob","ticket":"ACME-42"}}}' \
  | sed 's/^data: //' | jq -r '.result.messages[0].content.text'

step "a prompt shipped as a text file: acme_access_review, with and without the optional reviewer"
for ARGS in '{"username":"bob","reviewer":"carol"}' '{"username":"bob"}'; do
  curl -s "$MCP" -H "Mcp-Session-Id: $SESSION" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":3,"method":"prompts/get","params":{"name":"acme_access_review","arguments":'"$ARGS"'}}' \
    | sed 's/^data: //' | jq -r '.result.messages[0].content.text' | sed '/^Tools for this task/,$d'
done

step "restore bob for the next run"
$CALL $MCP keycloak_user_set_enabled '{"id": "bob", "enabled": true}' | jq -c '{username, enabled}'
for g in $BOB_GROUPS; do $CALL $MCP keycloak_group_member_add "{\"groupId\": \"$g\", \"userId\": \"bob\"}" | jq -c '{message}'; done
