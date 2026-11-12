#!/usr/bin/env bash
# Generates the IntelliJ run configurations in .run/ (shared via git). Re-run after changing an env file or a demo.
#
#   run-modes:        one "quarkus:dev (<scenario>)" Maven configuration per examples/run-modes/env/*.env, the demo stack
#   extensions:       "quarkus:dev (extensions)" loading examples/extensions/target as providers directory, build/demo/down
#   dynamic-systems:  PostgreSQL build + stack, mounted-jar dev stack, demo, down
#   delegated-auth:   one quarkus:dev per env file, stack up, demo, down
#   xaa:              one quarkus:dev per env file, stack up, demo, down
#   troubleshooting:  quarkus:dev read-only, stack up + seed, demo, down
#   ciba-confirm:     one quarkus:dev per env file, stack up, demo, down
#   management-ui:    mkcert, one quarkus:dev per env file with the UI on
#   multi-tenant:     keys + stack, down
#   conformance:      conformance/run.sh
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .run
xml() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' <<<"$1"; }

# quarkus:dev -pl modules/backend -am with environment variables: name, file, env lines on stdin ("KEY=value", # comments)
maven_dev() {
  local name=$1 out=".run/$2.run.xml"
  {
    echo '<component name="ProjectRunConfigurationManager">'
    echo "  <configuration default=\"false\" name=\"$(xml "$name")\" type=\"MavenRunConfiguration\" factoryName=\"Maven\">"
    echo '    <MavenSettings>'
    echo '      <option name="myGeneralSettings" />'
    echo '      <option name="myRunnerSettings">'
    echo '        <MavenRunnerSettings>'
    echo '          <option name="delegateBuildToMaven" value="false" />'
    echo '          <option name="environmentProperties">'
    echo '            <map>'
    while IFS= read -r line || [ -n "$line" ]; do
      [[ "$line" =~ ^[[:space:]]*# || -z "${line// }" ]] && continue
      key=${line%%=*}; value=${line#*=}
      echo "              <entry key=\"$(xml "$key")\" value=\"$(xml "$value")\" />"
    done
    echo '            </map>'
    echo '          </option>'
    echo '          <option name="jreName" value="#USE_PROJECT_JDK" />'
    echo '          <option name="mavenProperties"><map /></option>'
    echo '          <option name="passParentEnv" value="true" />'
    echo '          <option name="runMavenInBackground" value="true" />'
    echo '          <option name="skipTests" value="false" />'
    echo '          <option name="vmOptions" value="" />'
    echo '        </MavenRunnerSettings>'
    echo '      </option>'
    echo '      <option name="myRunnerParameters">'
    echo '        <MavenRunnerParameters>'
    echo '          <option name="profiles"><set /></option>'
    echo '          <option name="goals"><list><option value="quarkus:dev" /><option value="-pl" /><option value="modules/backend" /><option value="-am" /></list></option>'
    echo '          <option name="pomFileName" value="pom.xml" />'
    echo '          <option name="profilesMap"><map /></option>'
    echo '          <option name="resolveToWorkspace" value="false" />'
    echo '          <option name="workingDirPath" value="$PROJECT_DIR$" />'
    echo '        </MavenRunnerParameters>'
    echo '      </option>'
    echo '    </MavenSettings>'
    echo '    <method v="2" />'
    echo '  </configuration>'
    echo '</component>'
  } > "$out"
  echo "wrote $out"
}

# a shell command in a terminal: name, file, working directory (below the project), script
shell() {
  cat > ".run/$2.run.xml" <<XML
<component name="ProjectRunConfigurationManager">
  <configuration default="false" name="$(xml "$1")" type="ShConfigurationType">
    <option name="SCRIPT_TEXT" value="$(xml "$4")" />
    <option name="INDEPENDENT_SCRIPT_PATH" value="true" />
    <option name="SCRIPT_PATH" value="" />
    <option name="SCRIPT_OPTIONS" value="" />
    <option name="INDEPENDENT_SCRIPT_WORKING_DIRECTORY" value="true" />
    <option name="SCRIPT_WORKING_DIRECTORY" value="\$PROJECT_DIR\$${3:+/$3}" />
    <option name="INDEPENDENT_INTERPRETER_PATH" value="true" />
    <option name="INTERPRETER_PATH" value="/bin/zsh" />
    <option name="INTERPRETER_OPTIONS" value="" />
    <option name="EXECUTE_IN_TERMINAL" value="true" />
    <option name="EXECUTE_SCRIPT_FILE" value="false" />
    <envs />
    <method v="2" />
  </configuration>
</component>
XML
  echo "wrote .run/$2.run.xml"
}

# --- run-modes: one dev configuration per access level, the demo stack
for f in examples/run-modes/env/*.env; do
  name=$(basename "$f" .env)
  maven_dev "quarkus:dev ($name)" "dev-$name" < "$f"
done
shell "demo stack: up (Keycloak + Mailpit)" "demo-stack-up" "examples/run-modes" \
  "docker compose up -d && docker compose logs -f keycloak"
shell "demo stack: reset (down -v, re-imports the realm)" "demo-stack-reset" "examples/run-modes" \
  "docker compose down -v && docker compose up -d && docker compose logs -f keycloak"

# --- extensions: dev mode against the demo stack, with the example jar as providers directory
{
  grep -v '^#' examples/run-modes/env/realm-admin.env
  echo "KC_MCP_PROVIDERS_DIR=examples/extensions/target"
  echo "KC_MCP_SPI_AUDIT_LISTENER_ACME_FILE=target/acme-audit.jsonl"
  echo "KC_MCP_DYNAMIC_SYSTEMS=true"
  echo "KC_MCP_SPI_SYSTEM_REPOSITORY_ACME_TENANTS_SYSTEMS=globex=https://sso.globex.example|globex-prod"
} | maven_dev "quarkus:dev (extensions: realm-admin + examples/extensions/target as providers)" "dev-extensions"
shell "extensions: build jar + stack up (Keycloak :8093, MCP :8094)" "extensions-up" "examples/extensions" \
  "../../mvnw -f ../../pom.xml package -DskipTests && docker compose up -d --build && docker compose logs -f mcp"
shell "extensions: demo.sh" "extensions-demo" "examples/extensions" "./demo.sh"
shell "extensions: down -v" "extensions-down" "examples/extensions" "docker compose down -v"

# --- dynamic-systems: the PostgreSQL build in Docker, the mounted-jar variant, the demo
shell "dynamic-systems: build (PostgreSQL) + stack up (:8090-8092, :5490)" "dynamic-systems-up" "examples/dynamic-systems" \
  "../../mvnw -f ../../pom.xml package -DskipTests -Ppostgresql && docker compose up -d --build && docker compose logs -f mcp"
shell "dynamic-systems: dev stack (target/quarkus-app mounted, no image build)" "dynamic-systems-dev-up" "examples/dynamic-systems" \
  "../../mvnw -f ../../pom.xml package -DskipTests -Ppostgresql && docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d && docker compose logs -f mcp"
shell "dynamic-systems: restart servers from target/quarkus-app (dev stack)" "dynamic-systems-dev-restart" "examples/dynamic-systems" \
  "../../mvnw -f ../../pom.xml package -DskipTests -Ppostgresql && docker compose -f docker-compose.yml -f docker-compose.dev.yml restart mcp mcp-users && docker compose logs -f mcp"
shell "dynamic-systems: demo.sh" "dynamic-systems-demo" "examples/dynamic-systems" "./demo.sh"
shell "dynamic-systems: down -v" "dynamic-systems-down" "examples/dynamic-systems" \
  "docker compose -f docker-compose.yml -f docker-compose.dev.yml down -v"

# --- troubleshooting: read-only dev mode against a realm with planted faults (Keycloak :8104), seed and demo
maven_dev "quarkus:dev (support: troubleshooting stack on :8104, MCP :8105)" "dev-support" \
  < examples/troubleshooting/env/support.env
shell "troubleshooting: stack up (Keycloak :8104) + seed" "troubleshooting-up" "examples/troubleshooting" \
  "docker compose up -d --wait && ./seed.py"
shell "troubleshooting: demo.sh" "troubleshooting-demo" "examples/troubleshooting" "./demo.sh"
shell "troubleshooting: down -v" "troubleshooting-down" "examples/troubleshooting" "docker compose down -v"

# --- delegated-auth: dev mode as the actor client against its own stack (Keycloak :8096 with delegation), the demo
for f in examples/delegated-auth/env/*.env; do
  name=$(basename "$f" .env)
  maven_dev "quarkus:dev ($name: delegated-auth stack on :8096, MCP :8097)" "dev-$name" < "$f"
done
shell "delegated-auth: stack up (Keycloak :8096 + delegation grant)" "delegated-auth-up" "examples/delegated-auth" \
  "docker compose up -d && docker compose logs keycloak-init && docker compose logs -f keycloak"
shell "delegated-auth: demo.sh" "delegated-auth-demo" "examples/delegated-auth" "./demo.sh"
shell "delegated-auth: down -v" "delegated-auth-down" "examples/delegated-auth" "docker compose down -v"

# --- xaa: dev mode forwarding the tokens Keycloak issues for ID-JAGs (Keycloak :8101, stand-in IdP :8102), the demo
for f in examples/xaa/env/*.env; do
  name=$(basename "$f" .env)
  maven_dev "quarkus:dev ($name: xaa stack on :8101, IdP :8102, MCP :8103)" "dev-$name" < "$f"
done
shell "xaa: stack up (Keycloak :8101 + enterprise IdP :8102)" "xaa-up" "examples/xaa" \
  "docker compose up -d --wait && docker compose logs -f idp"
shell "xaa: demo.sh" "xaa-demo" "examples/xaa" "./demo.sh"
shell "xaa: down -v" "xaa-down" "examples/xaa" "docker compose down -v"

# --- ciba-confirm: dev mode against its own stack (Keycloak :8098 with the CIBA channel, approver :8095), the demo
for f in examples/ciba-confirm/env/*.env; do
  name=$(basename "$f" .env)
  maven_dev "quarkus:dev ($name: ciba-confirm stack on :8098, approver :8095, MCP :8099)" "dev-$name" < "$f"
done
shell "ciba-confirm: stack up (Keycloak :8098 + approver :8095)" "ciba-confirm-up" "examples/ciba-confirm" \
  "docker compose up -d && docker compose logs -f approver"
shell "ciba-confirm: demo.sh" "ciba-confirm-demo" "examples/ciba-confirm" "./demo.sh"
shell "ciba-confirm: down -v" "ciba-confirm-down" "examples/ciba-confirm" "docker compose down -v"

# --- management-ui: dev mode with the UI on https://localhost:8443/ui/ against the run-modes stack, the certificate
shell "management-ui: mkcert (writes .certs/localhost*.pem)" "management-ui-mkcert" "" "etc/mkcert.sh"
for f in examples/management-ui/env/*.env; do
  name=$(basename "$f" .env)
  maven_dev "quarkus:dev ($name: run-modes stack :8080, UI https://localhost:8443/ui/)" "dev-$name" < "$f"
done
# --- multi-tenant
shell "multi-tenant: keys + stack up (:8090-8092)" "multi-tenant-up" "examples/multi-tenant" \
  "./gen-keys.sh && ../../mvnw -f ../../pom.xml package -DskipTests && docker compose up -d --build && docker compose logs -f mcp"
shell "multi-tenant: down -v" "multi-tenant-down" "examples/multi-tenant" "docker compose down -v"

# --- conformance
shell "conformance: run.sh (packaged server + fixtures)" "conformance-run" "" \
  "./mvnw package -DskipTests && conformance/run.sh"
