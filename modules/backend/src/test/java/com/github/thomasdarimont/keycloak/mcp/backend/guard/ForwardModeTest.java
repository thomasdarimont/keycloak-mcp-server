package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.access.Delegation;
import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ToolCatalog;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.DelegationMode;
import com.github.thomasdarimont.keycloak.mcp.confirm.Decision;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Delegation mode {@code forward} without Keycloak: caller required, roles judged from
 * the caller's token.
 */
class ForwardModeTest {

    /** Fixtures carry no role requirements; these two do. */
    private final ToolCatalog catalog = new ToolCatalog(List.of(
            ToolSpec.builder("keycloak_user_search")
                .title("Search users")
                .description("Find users.")
                .category(Category.USERS)
                .read()
                .roles("view-users")
                .schema(InputSchema.builder().string("search", "Free text"))
                .handler(call -> ToolResult.ok(List.of()))
                .build(),
            ToolSpec.builder("keycloak_user_set_enabled")
                .title("Enable a user")
                .description("Set enabled.")
                .category(Category.USERS)
                .write()
                .roles("manage-users")
                .schema(InputSchema.builder()
                    .string("id", "User id")
                    .required()
                    .bool("enabled", "New value")
                    .required())
                .handler(call -> ToolResult.done("updated"))
                .build(),
            ToolSpec.builder("keycloak_client_get_secret")
                .title("Client secret")
                .description("Reveal a secret.")
                .category(Category.CLIENTS)
                .read()
                .roles("view-clients")
                .delegation(Delegation.FORBIDDEN)
                .schema(InputSchema.builder().string("id", "Client id").required())
                .handler(call -> ToolResult.ok(Map.of()))
                .build()),
            "demo", 50, List.of());

    private static Map<String, Object> payload(ToolResult r) {
        return new JsonObject(r.toJson()).getMap();
    }

    private static String token(String... realmManagementRoles) {
        JsonObject access = new JsonObject();
        if (realmManagementRoles.length > 0) {
            access.put("realm-management", new JsonObject().put("roles", new JsonArray(List.of(realmManagementRoles))));
        }
        return GrantedRolesTest.jwt(new JsonObject().put("resource_access", access)
            .put("sub", "u1")
            .put("preferred_username", "carol")
            .put("iss", "http://kc/realms/demo"));
    }

    private static TransportContext caller(String token) {
        return TransportContext.none().withCaller(Caller.of("u1", "carol", "demo", Set.of()), token);
    }

    private ToolInvoker invoker() {
        return new ToolInvoker(catalog, new AccessPolicy(false, List.of()), req -> Decision.CONFIRMED, 50, null,
                DelegationMode.FORWARD);
    }

    @Test
    void anonymousCallerIsRefused() {
        ToolSpec spec = catalog.get("keycloak_user_search").orElseThrow();
        ToolResult r = invoker().invoke(spec, Map.of(), false, TransportContext.none());
        assertTrue(r.isError());
        assertEquals("caller_required", payload(r).get("error"));
    }

    @Test
    void callerRolesDecide() {
        ToolSpec write = catalog.get("keycloak_user_set_enabled").orElseThrow();
        ToolResult denied = invoker().invoke(write, Map.of("id", "x", "enabled", true), false,
                caller(token("view-users")));
        assertTrue(denied.isError(), denied.toJson());
        assertEquals("forbidden", payload(denied).get("error"));
        assertTrue(String.valueOf(payload(denied).get("message")).contains("carol"), denied.toJson());
        assertEquals(List.of("manage-users"), payload(denied).get("missingRoles"));

        ToolResult ok = invoker().invoke(write, Map.of("id", "x", "enabled", true), false,
                caller(token("manage-users")));
        assertFalse(ok.isError(), ok.toJson());

        ToolResult noRoles = invoker().invoke(catalog.get("keycloak_user_search").orElseThrow(), Map.of(), false,
                caller(token()));
        assertEquals("forbidden", payload(noRoles).get("error"), noRoles.toJson());
        assertTrue(String.valueOf(payload(noRoles).get("message")).contains("no admin roles"), noRoles.toJson());
    }

    @Test
    void callsAreDelegatedSoForbiddenToolsStayClosed() {
        ToolSpec forbidden = catalog.get("keycloak_client_get_secret").orElseThrow();
        ToolResult r = invoker().invoke(forbidden, Map.of("id", "x"), false, caller(token("realm-admin")));
        assertEquals("delegation_not_allowed", payload(r).get("error"), r.toJson());
        ToolResult ok = invoker().invoke(catalog.get("keycloak_user_search").orElseThrow(), Map.of(), false,
                caller(token("view-users")));
        assertFalse(ok.isError(), ok.toJson());
    }

    @Test
    void forwardNeedsTheOidcTenant() {
        CallerAuth off = new CallerAuth(DelegationMode.FORWARD, false, false);
        assertThrows(IllegalStateException.class, () -> off.validate(null));
        assertTrue(new CallerAuth(DelegationMode.OFF, true, true).required());
        assertFalse(new CallerAuth(DelegationMode.OFF, false, true).required());
        new CallerAuth(DelegationMode.FORWARD, false, true).validate(null);
    }
}
