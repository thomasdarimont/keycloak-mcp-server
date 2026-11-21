package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.lang.reflect.Proxy;
import java.util.Map;
import jakarta.ws.rs.ProcessingException;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCall;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;

import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A change to a user's roles or groups reports the effective roles after it. When they
 * cannot be read, the change has still been made and the result must say so.
 */
class RoleChangeResultTest {

    @Test
    void aFailedReadAfterTheChangeDoesNotTurnItIntoAFailure() {
        KeycloakAdmin unreachable = (KeycloakAdmin) Proxy.newProxyInstance(KeycloakAdmin.class.getClassLoader(),
                new Class<?>[] { KeycloakAdmin.class }, (proxy, method, args) -> {
                    throw new ProcessingException("Read timed out");
                });
        ToolCall call = new ToolCall("demo", Map.of(), 50, Caller.NONE, "main", unreachable);

        ToolResult result = RoleToolProvider.changed(call, "u1", "Role assigned", "username", "alice", "role",
                "editor");

        assertFalse(result.isError());
        JsonObject json = new JsonObject(result.toJson());
        assertEquals(true, json.getBoolean("ok"));
        assertEquals("Role assigned", json.getString("message"));
        assertEquals("editor", json.getString("role"));
        assertFalse(json.containsKey("now"));
        assertTrue(json.getString("warning").contains("Read timed out"), json.encode());
        assertTrue(json.getString("warning").contains("Do not repeat"), json.encode());
    }

    @Test
    void whatWasReadBackComesAfterTheOtherFields() {
        JsonObject json = new JsonObject(
                ToolResult.doneThenRead("Group created", "path", () -> "/admins/ops", "id", "g1").toJson());

        assertEquals(java.util.List.of("ok", "message", "id", "path"), java.util.List.copyOf(json.fieldNames()));
        assertEquals("/admins/ops", json.getString("path"));
    }
}
