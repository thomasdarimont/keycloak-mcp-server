package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.backend.Fixtures;
import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ToolCatalog;
import com.github.thomasdarimont.keycloak.mcp.backend.exposure.ProgressiveState;
import com.github.thomasdarimont.keycloak.mcp.backend.meta.MetaTools;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.AuditOnFailure;
import com.github.thomasdarimont.keycloak.mcp.config.ConfirmFallback;
import com.github.thomasdarimont.keycloak.mcp.config.DelegationMode;
import com.github.thomasdarimont.keycloak.mcp.config.ExplicitTarget;
import com.github.thomasdarimont.keycloak.mcp.config.ExposureMode;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.config.PrivateHosts;
import com.github.thomasdarimont.keycloak.mcp.confirm.Decision;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The security regression matrix in one place: what each profile defaults to, and that a
 * tool the policy hides is neither found nor executed, whichever way it is called.
 */
class SecurityMatrixTest {

    private final ToolCatalog catalog = Fixtures.catalog(null);

    private static McpServerConfig config(Map<String, String> values) {
        SmallRyeConfig config = new SmallRyeConfigBuilder().withMapping(McpServerConfig.class)
            .withSources(new PropertiesConfigSource(values, "test", 500))
            .build();
        return config.getConfigMapping(McpServerConfig.class);
    }

    private static Map<String, Object> payload(ToolResult r) {
        return new JsonObject(r.toJson()).getMap();
    }

    private MetaTools meta(AccessPolicy policy) {
        return new MetaTools(catalog, policy, new ToolInvoker(catalog, policy, req -> Decision.CONFIRMED, 50),
                new ProgressiveState(), 5);
    }

    private static List<String> names(ToolResult search) {
        return ((List<?>) payload(search).get("tools")).stream()
            .map(t -> String.valueOf(((Map<?, ?>) t).get("name")))
            .toList();
    }

    @Test
    void localProfileKeepsTheConvenientDefaults() {
        McpServerConfig c = config(Map.of());
        assertFalse(c.securityProfile().shared());
        assertFalse(c.callerRequired());
        assertEquals(ConfirmFallback.FLAG, c.effectiveConfirmFallback());
        assertEquals(ExplicitTarget.OFF, c.effectiveExplicitTarget());
        assertEquals(PrivateHosts.ALLOW, c.effectiveDynamicPrivateHosts());
        assertEquals(AuditOnFailure.ALLOW, c.effectiveAuditOnFailure());
    }

    @Test
    void sharedProfileTurnsEveryDefaultAround() {
        McpServerConfig c = config(Map.of("kc-mcp.security-profile", "shared"));
        assertTrue(c.securityProfile().shared());
        assertTrue(c.callerRequired(), "require-caller is implied");
        assertEquals(ConfirmFallback.DENY, c.effectiveConfirmFallback());
        assertEquals(ExplicitTarget.DESTRUCTIVE, c.effectiveExplicitTarget());
        assertEquals(PrivateHosts.LISTED, c.effectiveDynamicPrivateHosts());
        assertEquals(AuditOnFailure.REFUSE_CHANGES, c.effectiveAuditOnFailure());
    }

    @Test
    void explicitSettingsWinOverTheProfile() {
        McpServerConfig loosened = config(
                Map.of("kc-mcp.security-profile", "shared", "kc-mcp.confirm-fallback", "flag", "kc-mcp.explicit-target",
                        "off", "kc-mcp.dynamic-private-hosts", "allow", "kc-mcp.audit-on-failure", "allow"));
        assertEquals(ConfirmFallback.FLAG, loosened.effectiveConfirmFallback());
        assertEquals(ExplicitTarget.OFF, loosened.effectiveExplicitTarget());
        assertEquals(PrivateHosts.ALLOW, loosened.effectiveDynamicPrivateHosts());
        assertEquals(AuditOnFailure.ALLOW, loosened.effectiveAuditOnFailure());
        assertTrue(loosened.callerRequired(), "shared always requires callers");

        McpServerConfig tightened = config(Map.of("kc-mcp.confirm-fallback", "deny", "kc-mcp.explicit-target", "write",
                "kc-mcp.dynamic-private-hosts", "listed", "kc-mcp.require-caller", "true", "kc-mcp.audit-on-failure",
                "refuse-changes"));
        assertEquals(ConfirmFallback.DENY, tightened.effectiveConfirmFallback());
        assertEquals(ExplicitTarget.WRITE, tightened.effectiveExplicitTarget());
        assertEquals(PrivateHosts.LISTED, tightened.effectiveDynamicPrivateHosts());
        assertEquals(AuditOnFailure.REFUSE_CHANGES, tightened.effectiveAuditOnFailure());
        assertTrue(tightened.callerRequired());
    }

    @Test
    void readOnlyHidesAndRefusesWritesEveryWay() {
        AccessPolicy policy = new AccessPolicy(true, List.of());
        MetaTools meta = meta(policy);
        List<String> found = names(meta.search("disable user", null, 5, "c1", ExposureMode.HYBRID));
        assertFalse(found.contains("keycloak_user_set_enabled"), found.toString());
        assertFalse(found.contains("keycloak_user_delete"), found.toString());

        Map<String, Object> args = Map.of("realm", "demo", "id", "1", "enabled", false);
        Map<String, Object> viaExecute = payload(
                meta.execute("keycloak_user_set_enabled", args, null, InvocationContext.none()));
        assertEquals("read_only_mode", viaExecute.get("error"), viaExecute.toString());
        ToolSpec spec = catalog.get("keycloak_user_set_enabled").orElseThrow();
        Map<String, Object> direct = payload(new ToolInvoker(catalog, policy, req -> Decision.CONFIRMED, 50)
            .invoke(spec, args, false, InvocationContext.none()));
        assertEquals("read_only_mode", direct.get("error"), direct.toString());
    }

    @Test
    void deniedToolsAreNeitherFoundNorExecuted() {
        AccessPolicy policy = new AccessPolicy(false, List.of(), List.of(), List.of("keycloak_user_delete"), List.of(),
                null);
        MetaTools meta = meta(policy);
        List<String> found = names(meta.search("delete user", null, 5, "c1", ExposureMode.HYBRID));
        assertFalse(found.contains("keycloak_user_delete"), found.toString());

        Map<String, Object> args = Map.of("realm", "demo", "id", "1", "username", "bob");
        Map<String, Object> viaExecute = payload(
                meta.execute("keycloak_user_delete", args, true, InvocationContext.none()));
        assertTrue(Boolean.TRUE.equals(viaExecute.get("isError")) || viaExecute.containsKey("error"),
                viaExecute.toString());
        assertTrue(List.of("tool_not_allowed", "unknown_tool").contains(String.valueOf(viaExecute.get("error"))),
                viaExecute.toString());
        ToolSpec spec = catalog.get("keycloak_user_delete").orElseThrow();
        Map<String, Object> direct = payload(new ToolInvoker(catalog, policy, req -> Decision.CONFIRMED, 50)
            .invoke(spec, args, true, InvocationContext.none()));
        assertEquals("tool_not_allowed", direct.get("error"), direct.toString());
    }

    @Test
    void delegatingServersRefuseAnonymousCallers() {
        AccessPolicy policy = new AccessPolicy(false, List.of());
        ToolInvoker forward = new ToolInvoker(catalog, policy, req -> Decision.CONFIRMED, 50, null,
                DelegationMode.FORWARD);
        ToolSpec spec = catalog.get("keycloak_user_search").orElseThrow();
        Map<String, Object> r = payload(forward.invoke(spec, Map.of("realm", "demo"), false, InvocationContext.none()));
        assertEquals("caller_required", r.get("error"), r.toString());
        ToolInvoker exchange = new ToolInvoker(catalog, policy, req -> Decision.CONFIRMED, 50, null,
                DelegationMode.EXCHANGE);
        assertEquals("caller_required",
                payload(exchange.invoke(spec, Map.of("realm", "demo"), false, InvocationContext.none())).get("error"));
    }
}
