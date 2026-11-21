package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.core.Response;

import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.ClientScopesResource;
import org.keycloak.admin.client.resource.RealmResource;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCall;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;

import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A tool that changes Keycloak in two steps and fails at the second says what the first
 * one changed, instead of an error that reads as if nothing had happened.
 */
class PartlyAppliedTest {

    private final List<String> requests = new ArrayList<>();
    private boolean refuseRealmDefault;

    private ToolCall call(Map<String, Object> args) {
        ClientScopesResource scopes = fake(ClientScopesResource.class, (p, m, a) -> {
            requests.add(m.getName());
            return Response.created(URI.create("http://kc/admin/realms/demo/client-scopes/s1")).build();
        });
        RealmResource realm = fake(RealmResource.class, (p, m, a) -> {
            requests.add(m.getName());
            return switch (m.getName()) {
                case "clientScopes" -> scopes;
                case "getDefaultDefaultClientScopes", "getDefaultOptionalClientScopes" -> List.of();
                case "addDefaultDefaultClientScope" -> {
                    if (refuseRealmDefault) {
                        throw new ForbiddenException("HTTP 403 Forbidden");
                    }
                    yield null;
                }
                default -> throw new UnsupportedOperationException(m.getName());
            };
        });
        KeycloakAdmin admin = fake(KeycloakAdmin.class, (p, m, a) -> {
            if (m.getName().equals("realm")) {
                return realm;
            }
            throw new UnsupportedOperationException(m.getName());
        });
        return new ToolCall("demo", args, 50, Caller.NONE, "main", admin);
    }

    private static <T> T fake(Class<T> type, InvocationHandler handler) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type }, handler));
    }

    @Test
    void aScopeCreatedButNotMadeARealmDefaultIsReportedAsCreated() {
        refuseRealmDefault = true;

        ToolResult result = new ClientScopeToolProvider()
            .create(call(Map.of("name", "tenant", "realmDefault", "default")));

        assertTrue(result.isError());
        JsonObject json = new JsonObject(result.toJson());
        assertEquals("partially_applied", json.getString("error"));
        assertEquals("s1", json.getString("id"), "the id of what exists now");
        assertEquals("client scope 'tenant' created", json.getString("applied"));
        assertEquals("make it a realm default scope", json.getString("notApplied"));
        assertTrue(json.getString("message").contains("HTTP 403 Forbidden"), json.encode());
        assertTrue(json.getString("message").contains("Do not repeat the whole call"), json.encode());
    }

    @Test
    void aScopeCreatedAsARealmDefaultIsDone() {
        ToolResult result = new ClientScopeToolProvider()
            .create(call(Map.of("name", "tenant", "realmDefault", "default")));

        assertFalse(result.isError());
        assertEquals("default", new JsonObject(result.toJson()).getString("realmDefault"));
    }

    @Test
    void aScopeThatIsNoRealmDefaultAsksNothingAboutThem() {
        ToolResult result = new ClientScopeToolProvider().create(call(Map.of("name", "tenant")));

        assertFalse(result.isError());
        assertEquals(List.of("clientScopes", "create"), requests);
    }
}
