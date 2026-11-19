package com.github.thomasdarimont.keycloak.mcp.backend;

import java.util.Map;
import java.util.Set;

import org.eclipse.microprofile.config.spi.ConfigSource;

import com.google.auto.service.AutoService;

/**
 * Baseline configuration of every test, pinned above the environment (ordinal 350: above
 * env vars at 300, below the system properties at 400 that {@code QuarkusTestProfile}s
 * and {@code QuarkusTestResource}s use). A shell that still has one of the demo env files
 * sourced ({@code KC_MCP_CLIENT_SECRET}, {@code KC_MCP_DELEGATION},
 * {@code KC_MCP_MCP_OAUTH_ENABLED}, ...) must not change what the tests see. Empty values
 * clear a leaked setting: SmallRye treats them as absent for optional properties.
 */
@AutoService(ConfigSource.class)
public class TestConfig implements ConfigSource {

    private static final Map<String, String> VALUES = Map.ofEntries(
            // tests never talk to a real Keycloak: a closed port fails fast with
            // keycloak_unreachable
            Map.entry("kc-mcp.systems.default.url", "http://127.0.0.1:1"),
            Map.entry("kc-mcp.systems.default.grant-type", "password"),
            Map.entry("kc-mcp.systems.default.auth-realm", "master"),
            Map.entry("kc-mcp.systems.default.username", "admin"),
            Map.entry("kc-mcp.systems.default.password", "admin"), Map.entry("kc-mcp.systems.default.client-id", ""),
            Map.entry("kc-mcp.systems.default.client-secret", ""), Map.entry("kc-mcp.systems.default.client-auth", ""),
            Map.entry("kc-mcp.jwt.key-file", ""), Map.entry("kc-mcp.jwt.algorithm", "RS256"),
            Map.entry("kc-mcp.delegation", "off"), Map.entry("kc-mcp.default-system", ""),
            Map.entry("kc-mcp.systems.default.default-realm", ""),
            Map.entry("kc-mcp.systems.default.allowed-realms", ""), Map.entry("kc-mcp.allowed-hosts", ""),
            Map.entry("kc-mcp.denied-tools", ""), Map.entry("kc-mcp.read-only", "false"),
            Map.entry("kc-mcp.tool-exposure", "hybrid"), Map.entry("kc-mcp.startup-check", "off"),
            Map.entry("kc-mcp.keys-dir", "target/test-keys"),
            // the runtime system repository of the tests is opt-in per profile
            Map.entry("kc-mcp.dynamic-systems", "false"), Map.entry("kc-mcp.systems-file", ""),
            Map.entry("kc-mcp.static-systems", "true"),
            // provider settings are a map of plain strings, so they take real values
            // rather than blanks
            Map.entry("kc-mcp.spi.access-check.group-scope.default", "off"),
            Map.entry("kc-mcp.spi.access-check.no-escalation.default", "on"),
            Map.entry("kc-mcp.mcp.oauth.enabled", "false"), Map.entry("kc-mcp.mcp.oauth.audience", ""));

    @Override
    public Set<String> getPropertyNames() {
        return VALUES.keySet();
    }

    @Override
    public String getValue(String propertyName) {
        return VALUES.get(propertyName);
    }

    @Override
    public String getName() {
        return "keycloak-mcp test baseline";
    }

    @Override
    public int getOrdinal() {
        return 350;
    }
}
