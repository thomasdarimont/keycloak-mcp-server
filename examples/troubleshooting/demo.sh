#!/usr/bin/env bash
# Three support questions, answered with read-only access. Needs the stack up (docker compose up -d), the MCP server
# running with env/support.env (see README.md), plus python3 and jq. Seeds the symptoms first if seed.py has not run.
#
#   1. who the server acts as: a service account with view-* roles, read-only on top
#   2. "what causes this redirect loop?"   the login events show the pattern, the admin events the trigger
#   3. "why can't erin sign in?"           her events and her lockout status
#   4. "why is the login so slow?"         the password policy and the hash stored with a password
#   5. the fix is not the server's to make: writes are refused
#
# Each step prints the evidence a model gets from the same tools; with a chat client, ask the questions of README.md
# or start from the prompts (../run-modes/prompt.sh lists them).
set -euo pipefail
cd "$(dirname "$0")"
export MCP_URL=${MCP_URL:-http://localhost:8105/mcp}

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
call() { ./mcp-call.py "$@"; }

if [ "$(call keycloak_events_login '{"client": "shop-web", "max": 1}' | jq '.items | length')" = 0 ]; then
  ./seed.py
fi

step "1. the server's access: reads, and nothing else"
call whoami | jq -c '{keycloakCallsRunAs, readOnly, roles: [.roles.shop[].role], tools}'

step "2. what causes this redirect loop? (prompt keycloak_redirect_loop_troubleshoot client=shop-web)"
echo "login events of shop-web, newest first: LOGIN and CODE_TO_TOKEN_ERROR take turns, a second apart"
call keycloak_events_login '{"client": "shop-web", "max": 8}' \
  | jq -r '.items[] | "  \(.time)  \(.type)  \(.error // "")  \(.details.username // "")"'
echo "what changed on a client shortly before:"
call keycloak_events_admin '{"resourceTypes": ["CLIENT"]}' \
  | jq -r '.items[] | "  \(.time)  \(.operation)  \(.resourcePath | sub("clients/[^/]+"; "clients/<shop-web>"))"'
echo "=> Keycloak logs frank in every time; the application redeems the code with a secret that was regenerated"
echo "   seconds before the first failure. Fix: give the application the new secret. Nothing to change in Keycloak."

step "3. why can't erin sign in? (prompt keycloak_login_troubleshoot username=erin)"
call keycloak_events_login '{"user": "erin", "max": 8}' | jq -r '.items[] | "  \(.time)  \(.type)  \(.error // "")"'
call keycloak_user_brute_force_get '{"userId": "erin"}' | jq -c '{username, lockedOut, failures, lastFailure}'
echo "=> three wrong passwords locked the account; the right password is refused since, and the login page"
echo "   still says 'Invalid username or password'. Fix: wait out the lockout or clear it (keycloak_user_brute_force_clear)."

step "4. why is the login so slow? (prompt keycloak_slow_login_troubleshoot username=grace)"
call keycloak_realm_get_config | jq -c '{passwordPolicy}'
call keycloak_user_credentials_list '{"userId": "grace"}' | jq -c '.items[] | {type, hash}'
echo "=> 5 million PBKDF2 iterations where Keycloak's default is 210000: every password check takes seconds."
echo "   Fix: a sane hashIterations in the password policy; each password is rehashed at its owner's next login."

step "5. the fix is somebody else's: this server only reads"
call execute_tool '{"name": "keycloak_user_brute_force_clear", "arguments": {"userId": "erin"}}' | jq -c .
