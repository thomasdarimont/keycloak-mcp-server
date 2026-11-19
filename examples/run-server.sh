#!/usr/bin/env bash
# Starts the MCP server for one example with that example's settings and nothing else. Each example's server.sh
# calls this; it is not meant to be run by hand.
#
#   run-server.sh <example> <default-env> [env-name] [--jar] [--list] [maven or server options]
#
# What it takes care of, so that a terminal used for another example before does no harm:
#   - every KC_MCP_* and QUARKUS_* variable of the calling shell is dropped (the names are printed), then the env
#     file is loaded; all of it happens in this process, so nothing stays behind in the terminal either
#   - the server's port must be free: a server of another example still running would answer the demo instead
#   - the example's Keycloak must answer: the server reads the realm's discovery document at startup
# The rest of the environment (JAVA_HOME, proxies, ...) is passed on as it is.
set -euo pipefail
example=$1 env_name=$2; shift 2
root=$(cd "$(dirname "$0")/.." && pwd)
mode=dev list= extra=()
for arg in "$@"; do
  case "$arg" in
    --jar) mode=jar ;;
    --list) list=1 ;;
    -h|--help) sed -n '2,/^set -euo/p' "$root/examples/$example/server.sh" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) extra+=("$arg") ;;
    *) env_name=$(basename "$arg" .env) ;;
  esac
done
available() { for f in "$root/examples/$example"/env/*.env; do basename "$f" .env; done | tr '\n' ' '; }
if [ -n "$list" ]; then available; echo; exit 0; fi
file=$root/examples/$example/env/$env_name.env
[ -f "$file" ] || { echo "no env file examples/$example/env/$env_name.env; there are: $(available)" >&2; exit 2; }

# QUARKUS_HOME belongs to the Quarkus CLI, not to the server
dropped=()
while IFS= read -r name; do
  [ "$name" = QUARKUS_HOME ] && continue
  dropped+=("$name"); unset "$name"
done < <(compgen -e | grep -E '^(KC_MCP_|QUARKUS_)' || true)
if [ ${#dropped[@]} -gt 0 ]; then
  echo "Ignoring ${#dropped[@]} server settings this terminal still carries (from another example?):" >&2
  printf '  %s\n' "${dropped[@]}" >&2
fi

cd "$root"                                           # the env files name keys and certificates relative to it
set -a; . "$file"; set +a

port=${QUARKUS_HTTP_PORT:-8081}
if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
  echo "Port $port is taken: is the server of this or another example still running? Stop it first." >&2
  command -v lsof >/dev/null && lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | sed 's/^/  /' >&2
  exit 1
fi
keycloak=$(compgen -v | grep -E '^KC_MCP_SYSTEMS_[A-Z0-9_]+_URL$' | head -1 || true)
if [ -n "$keycloak" ] && ! curl -sk -o /dev/null -m 5 "${!keycloak}/realms/master"; then
  echo "Keycloak does not answer at ${!keycloak}: bring the example's stack up first (docker compose up -d, see" >&2
  echo "examples/$example/README.md)." >&2
  exit 1
fi

echo "examples/$example/env/$env_name.env -> MCP endpoint http://localhost:$port/mcp" >&2
if [ "${KC_MCP_UI_ENABLED:-}" = true ]; then
  if [ -n "${QUARKUS_HTTP_SSL_PORT:-}" ] || [ -n "${QUARKUS_TLS_KEY_STORE_PEM_UI_CERT:-}" ]; then
    echo "management UI: https://localhost:${QUARKUS_HTTP_SSL_PORT:-8443}/ui/" >&2
  else
    echo "management UI: http://localhost:$port/ui/" >&2
  fi
fi
if [ "$mode" = jar ]; then
  jar=modules/backend/target/quarkus-app/quarkus-run.jar
  [ -f "$jar" ] || { echo "$jar is missing: ./mvnw package -DskipTests first" >&2; exit 1; }
  exec java -jar "$jar" start ${extra[@]+"${extra[@]}"}
fi
exec ./mvnw quarkus:dev -pl modules/backend -am ${extra[@]+"${extra[@]}"}
