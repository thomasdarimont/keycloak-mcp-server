package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfigBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UiCapabilitiesTest {

    @Test
    void operatorGetsReadAndWrite() {
        McpServerConfig config = config(Map.of("kc-mcp.admin.role", "realm:admin"));
        Caller alice = Caller.of("a", "alice", "demo", Set.of("realm:admin"));
        assertTrue(UiCapabilities.canAccessApi(alice, config));
        assertTrue(UiCapabilities.canWrite(alice, config));
        assertEquals(
                List.of(UiCapabilities.SYSTEMS_READ, UiCapabilities.SECRETS_READ, UiCapabilities.STORAGE_READ,
                        UiCapabilities.AUDIT_READ, UiCapabilities.SERVER_READ, UiCapabilities.SYSTEMS_WRITE),
                UiCapabilities.forCaller(alice, config));
    }

    @Test
    void viewerGetsReadsOnlyWhenConfigured() {
        McpServerConfig config = config(
                Map.of("kc-mcp.admin.role", "realm:admin", "kc-mcp.ui.viewer-role", "realm-management.view-users"));
        Caller carol = Caller.of("c", "carol", "demo", Set.of("realm-management.view-users"));
        assertTrue(UiCapabilities.isViewer(carol, config));
        assertFalse(UiCapabilities.canWrite(carol, config));
        assertEquals(List.of(UiCapabilities.SYSTEMS_READ, UiCapabilities.SECRETS_READ, UiCapabilities.STORAGE_READ,
                UiCapabilities.AUDIT_READ), UiCapabilities.forCaller(carol, config));
    }

    @Test
    void theServerInfoIsForOperatorsOnly() {
        assertTrue(UiCapabilities.operatorOnly("/bff/api/server-info"));
        assertTrue(UiCapabilities.operatorOnly("/bff/api/server-info/anything"));
        assertFalse(UiCapabilities.operatorOnly("/bff/api/systems"));
        assertFalse(UiCapabilities.operatorOnly("/bff/api/server-information"));
        McpServerConfig config = config(
                Map.of("kc-mcp.admin.role", "realm:admin", "kc-mcp.ui.viewer-role", "realm-management.view-users"));
        Caller carol = Caller.of("c", "carol", "demo", Set.of("realm-management.view-users"));
        assertFalse(UiCapabilities.forCaller(carol, config).contains(UiCapabilities.SERVER_READ));
    }

    @Test
    void withoutViewerRoleConfiguredOnlyOperatorOpensTheApi() {
        McpServerConfig config = config(Map.of("kc-mcp.admin.role", "realm:admin"));
        Caller carol = Caller.of("c", "carol", "demo", Set.of("realm-management.view-users"));
        assertFalse(UiCapabilities.canAccessApi(carol, config));
        assertTrue(UiCapabilities.forCaller(carol, config).isEmpty());
    }

    private static McpServerConfig config(Map<String, String> properties) {
        return new SmallRyeConfigBuilder().withMapping(McpServerConfig.class)
            .withSources(new PropertiesConfigSource(properties, "test", 100))
            .build()
            .getConfigMapping(McpServerConfig.class);
    }
}
