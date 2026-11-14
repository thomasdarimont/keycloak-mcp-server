#!/usr/bin/env bash
# What the MCP instance does while its database is away: latency and outcome of every tool call before, during and
# after the outage, how long it takes to recover, how many calls left no audit row and how many changes were refused
# (audit_unavailable, profile shared: kc-mcp.audit-on-failure=refuse-changes). Each round is a read (sam searches
# bob) and a change (alice sets the disabled bob to disabled). Run ./demo.sh first.
#
#   ./db-outage.sh            cut off only the MCP instance's database user: its pooled connections are terminated and
#                             new ones refused, as in a restart, while Keycloak keeps its database (the default)
#   ./db-outage.sh restart    stop and start the PostgreSQL container; Keycloak shares it, so the logins and calls
#                             fail there too: this measures the whole stack, not the MCP instance alone
#
# OUTAGE_SECONDS (30) sets how long the database stays away. Rebuild the mcp image after changing the server
# (docker compose up -d --build mcp).
set -euo pipefail
cd "$(dirname "$0")"
MODE=${1:-cutoff}
OUTAGE_SECONDS=${OUTAGE_SECONDS:-30}
MCP=http://localhost:8095
U=$MCP/mcp/systems/acme/acme-dev
CALL=../dynamic-systems/mcp-call.py
export KEYCLOAK_URL=http://localhost:8093

case "$MODE" in cutoff|restart) ;; *) echo "usage: $0 [cutoff|restart]" >&2; exit 2 ;; esac

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
millis() { perl -MTime::HiRes=time -e 'printf "%d", time * 1000'; }
# the superuser of the container (POSTGRES_USER) may change roles and end sessions
as_superuser() { docker compose exec -T postgres psql -U keycloak -d kcmcp -v ON_ERROR_STOP=1 -tAc "$1"; }
audit_rows() { docker compose exec -T postgres psql -U kcmcp_admin -d kcmcp -tAc "select count(*) from kc_mcp_audit_event"; }

START=$(millis)
CALLS=0
OK=0
REFUSED=0
# one tool call, read or change: prints the time since the start, its duration and the outcome; 0 when it worked
call() {
  local kind=$1 t0 t1 out outcome rc=1
  t0=$(millis)
  if [ "$kind" = read ]; then
    out=$("$CALL" --login sam:sam-demo "$U" keycloak_user_search '{"search": "bob"}' 2>&1) || true
  else
    out=$("$CALL" --login alice:alice-demo "$U" keycloak_user_set_enabled '{"id": "bob", "enabled": false}' 2>&1) || true
  fi
  t1=$(millis)
  CALLS=$((CALLS + 1))
  if echo "$out" | jq -e 'type == "object" and (has("error") | not)' >/dev/null 2>&1; then
    outcome=ok; OK=$((OK + 1)); rc=0
  else
    outcome=$(echo "$out" | jq -r '.error // empty' 2>/dev/null || true)
    # the last line: an HTTP status from the MCP instance, or the exception of a failed login at Keycloak
    [ -n "$outcome" ] || outcome=$(echo "$out" | tail -1 | cut -c1-110)
  fi
  [ "$outcome" != audit_unavailable ] || REFUSED=$((REFUSED + 1))
  printf '  +%5.1fs  %-6s %6d ms  %s\n' "$(echo "($t0 - $START) / 1000" | bc -l)" "$kind" $((t1 - t0)) "$outcome"
  return $rc
}
# a read and a change; 0 when both worked
round() {
  local rc=0
  call read || rc=1
  call change || rc=1
  return $rc
}

restore() {
  if [ "$MODE" = cutoff ]; then
    as_superuser "alter role kcmcp_mcp login" >/dev/null 2>&1 || true
  else
    docker compose start postgres >/dev/null 2>&1 || true
  fi
}
trap restore EXIT

step "before: the MCP instance reads systems and appends audit rows as usual"
for _ in 1 2; do round || true; done
ROWS_BEFORE=$(audit_rows)
CALLS_BEFORE=$CALLS

if [ "$MODE" = cutoff ]; then
  step "outage: kcmcp_mcp may no longer log in, its sessions are terminated (${OUTAGE_SECONDS}s)"
  as_superuser "alter role kcmcp_mcp nologin" >/dev/null
  as_superuser "select count(pg_terminate_backend(pid)) from pg_stat_activity where usename = 'kcmcp_mcp'" \
    | sed 's/^/  terminated sessions: /'
else
  step "outage: PostgreSQL stopped (${OUTAGE_SECONDS}s); Keycloak loses its database as well"
  docker compose stop postgres >/dev/null
fi
OUTAGE_START=$(millis)
while [ $(( $(millis) - OUTAGE_START )) -lt $((OUTAGE_SECONDS * 1000)) ]; do
  round || true
  sleep 1
done
CALLS_DURING=$((CALLS - CALLS_BEFORE))

step "the database is back"
restore
if [ "$MODE" = restart ]; then
  until docker compose exec -T postgres pg_isready -U keycloak -d kcmcp >/dev/null 2>&1; do sleep 1; done
fi
BACK=$(millis)
streak=0
RECOVERED=""
while [ $(( $(millis) - BACK )) -lt 120000 ]; do
  if round; then
    streak=$((streak + 1))
    [ -n "$RECOVERED" ] || RECOVERED=$(( $(millis) - BACK ))
    [ $streak -lt 3 ] || break
  else
    streak=0; RECOVERED=""
  fi
  sleep 1
done

step "summary"
ROWS_AFTER=$(audit_rows)
CALLS_AFTER_OUTAGE=$((CALLS - CALLS_BEFORE))
echo "  calls during the outage:   $CALLS_DURING (half of them changes), changes refused: $REFUSED"
echo "  recovered after:           ${RECOVERED:-not within 120 s} ms after the database came back"
echo "  calls since it began:      $CALLS_AFTER_OUTAGE, audit rows they left: $((ROWS_AFTER - ROWS_BEFORE))"
echo "  calls without an audit row: $((CALLS_AFTER_OUTAGE - (ROWS_AFTER - ROWS_BEFORE)))"
echo
echo "  what the MCP instance logged about its database:"
docker compose logs --no-log-prefix --since "$(( ( $(millis) - START ) / 1000 + 5 ))s" mcp 2>/dev/null \
  | grep -E 'WARN|ERROR|INFO.*again' | grep -iE 'database|audit|systems|datasource|acquisition|connection' \
  | cut -c1-200 | sort | uniq -c | sort -rn | head -15 || true
