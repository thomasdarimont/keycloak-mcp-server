#!/usr/bin/env bash
# Checks, before a demo.sh starts, that the MCP server it talks to is the one of its example. A server started with
# another example's settings, or one left running on the same port, otherwise fails somewhere in the middle of the
# demo with an answer that explains nothing.
#
#   preflight.sh endpoint <mcp-url> login=required|none     is a server there, and does it ask for a login as expected
#   preflight.sh whoami key=value ...  < whoami.json        does whoami describe the server the demo expects:
#                                                           system=<name>|none  delegation=exchange|off
#                                                           readOnly=true|false
#
# Exit 0 when everything matches, 1 with an explanation otherwise. Needs curl and jq.
set -euo pipefail
kind=$1; shift
advice="Stop it and start this example's server with ./server.sh (see README.md)."
fail() { printf '%s\n' "$@" >&2; exit 1; }

case "$kind" in
  endpoint)
    url=$1; shift
    headers=$(curl -s -m 5 -o /dev/null -D - -X POST "$url" -H 'Content-Type: application/json' -d '{}' | tr -d '\r') \
      || fail "No MCP server answers at $url. Start it with ./server.sh (see README.md)."
    challenge=none; grep -qi '^www-authenticate:.*resource_metadata=' <<<"$headers" && challenge=required
    for want in "$@"; do
      case "$want" in
        login=*) [ "${want#login=}" = "$challenge" ] || fail \
          "The MCP server at $url $([ "$challenge" = required ] && echo "asks for a login" || echo "does not ask for a login"), which this example does not expect." \
          "It was probably started with another example's settings. $advice" ;;
        *) fail "preflight.sh: unknown expectation $want" ;;
      esac
    done ;;
  whoami)
    answer=$(cat)
    jq -e 'type == "object"' >/dev/null 2>&1 <<<"$answer" || fail "whoami gave no usable answer: ${answer:0:300}"
    for want in "$@"; do
      key=${want%%=*} expected=${want#*=}
      case "$key" in
        system) actual=$(jq -r '.system // "none"' <<<"$answer") ;;
        delegation) actual=$(jq -r '.delegation.mode // "off"' <<<"$answer") ;;
        readOnly) actual=$(jq -r '.readOnly // false' <<<"$answer") ;;
        *) fail "preflight.sh: unknown expectation $want" ;;
      esac
      [ "$actual" = "$expected" ] || fail \
        "The MCP server is not set up for this example: $key is '$actual', expected '$expected'." \
        "It was probably started with another example's settings. $advice"
    done ;;
  *) fail "preflight.sh: endpoint or whoami, not $kind" ;;
esac
