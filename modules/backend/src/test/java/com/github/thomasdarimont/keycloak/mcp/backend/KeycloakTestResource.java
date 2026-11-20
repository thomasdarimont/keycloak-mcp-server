package com.github.thomasdarimont.keycloak.mcp.backend;

import java.util.Map;

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;

/**
 * Points the server at the {@link SharedKeycloak} with password auth, the master realm's
 * admin. Image overridable with {@code -Dkeycloak.image=...}.
 */
public class KeycloakTestResource implements QuarkusTestResourceLifecycleManager {

    static final String IMAGE = System.getProperty("keycloak.image", "quay.io/keycloak/keycloak:26.8.2-3");

    @Override
    public Map<String, String> start() {
        String url = SharedKeycloak.base();
        return Map.ofEntries(Map.entry("kc-mcp.system-defaults.grant-type", "password"),
                Map.entry("kc-mcp.system-defaults.auth-realm", "master"),
                Map.entry("kc-mcp.system-defaults.username", "admin"),
                Map.entry("kc-mcp.system-defaults.password", "admin"), Map.entry("kc-mcp.tools.exposure", "direct"),
                // the baseline's "default" system is switched off: this test has primary
                // and mirror
                Map.entry("kc-mcp.systems.default.url", ""), Map.entry("kc-mcp.systems.primary.url", url),
                Map.entry("kc-mcp.systems.mirror.url", url),
                Map.entry("kc-mcp.systems.mirror.allowed-realms", "master"),
                Map.entry("kc-mcp.default-system", "primary"),
                Map.entry("kc-mcp.spi.access-check.group-scope.default", "on"),
                Map.entry("kc-mcp.spi.access-check.group-scope.scope", "group"),
                Map.entry("kc-mcp.spi.access-check.group-scope.manager-role", "realm:create-realm"),
                Map.entry("kc-mcp.spi.access-check.no-escalation.default", "on"));
    }

    /** The shared Keycloak outlives the test class. */
    @Override
    public void stop() {
    }
}
