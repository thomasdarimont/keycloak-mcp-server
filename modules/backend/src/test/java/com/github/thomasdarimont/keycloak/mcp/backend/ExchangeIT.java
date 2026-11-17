package com.github.thomasdarimont.keycloak.mcp.backend;

import org.junit.jupiter.api.Test;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Delegation mode {@code exchange} against a real Keycloak 26.8: the caller consents to
 * the server acting for them, the server exchanges their token for a delegated one, and
 * the Admin API sees the caller (narrowed to the actor client's scope) with the server as
 * {@code act}. Run with {@code ./mvnw verify -DskipITs=false}.
 */
@QuarkusTest
@QuarkusTestResource(value = ExchangeTestResource.class, restrictToAnnotatedClass = true)
class ExchangeIT {

    private static McpClient as(String user, String scope) {
        return new McpClient().bearer(ExchangeTestResource.login(user, user, scope)).initialize(false);
    }

    private static McpClient delegating(String user) {
        return as(user, "openid " + ExchangeTestResource.DELEGATION_SCOPE);
    }

    @Test
    void metadataAdvertisesTheDelegationScope() {
        Response r = given().header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .body("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}")
            .post("/mcp");
        assertEquals(401, r.statusCode());
        assertTrue(r.header("WWW-Authenticate").contains("resource_metadata=\""), r.header("WWW-Authenticate"));
        JsonObject meta = new JsonObject(given().get("/.well-known/oauth-protected-resource").asString());
        assertTrue(meta.getJsonArray("scopes_supported").contains(ExchangeTestResource.DELEGATION_SCOPE),
                meta.encode());
    }

    @Test
    void adminActsThroughTheDelegatedTokenWithinTheActorsScope() {
        McpClient alice = delegating("alice");
        JsonObject me = McpClient.text(alice.callTool("whoami", new JsonObject()));
        assertEquals("alice", me.getJsonObject("caller").getString("username"), me.encode());
        assertTrue(me.getString("keycloakCallsRunAs").contains("delegated"), me.encode());
        JsonObject delegation = me.getJsonObject("delegation");
        assertNotNull(delegation, me.encode());
        assertEquals("exchange", delegation.getString("mode"));
        assertEquals(true, delegation.getBoolean("consented"), me.encode());
        assertEquals(ExchangeTestResource.ACTOR, delegation.getString("actor"), me.encode());
        // alice is realm-admin, the delegated token carries only the actor's role scope
        JsonObject can = me.getJsonObject("can").getJsonObject("demo");
        assertEquals("manage", can.getString("users"), me.encode());
        assertEquals("none", can.getString("clients"), me.encode());
        assertTrue(me.getJsonObject("tools").getInteger("forbidden") > 0, me.encode());

        JsonObject found = McpClient
            .text(alice.callTool("keycloak_user_search", new JsonObject().put("search", "carol")));
        assertEquals("carol", found.getJsonArray("items").getJsonObject(0).getString("username"), found.encode());
        JsonObject updated = alice.callTool("keycloak_user_update",
                new JsonObject().put("id", "carol").put("lastName", "Danvers"));
        assertFalse(updated.getBoolean("isError", false), McpClient.text(updated).encode());
        JsonObject denied = McpClient.text(alice.callTool("keycloak_client_list", new JsonObject()));
        assertEquals("forbidden", denied.getString("error"), denied.encode());
        assertTrue(denied.getJsonArray("missingRoles").contains("query-clients"), denied.encode());
        assertTrue(denied.getString("message").contains("alice"), denied.encode());

        // Keycloak's audit: the exchange names the actor, the admin event names alice
        JsonArray exchanges = ExchangeTestResource.adminGetArray("/admin/realms/demo/events?type=TOKEN_EXCHANGE");
        assertFalse(exchanges.isEmpty(), "TOKEN_EXCHANGE events");
        JsonObject exchange = exchanges.getJsonObject(0);
        assertTrue(exchange.encode().contains(ExchangeTestResource.ACTOR), exchange.encode());
        String aliceId = ExchangeTestResource.adminGetArray("/admin/realms/demo/users?username=alice&exact=true")
            .getJsonObject(0)
            .getString("id");
        JsonArray adminEvents = ExchangeTestResource
            .adminGetArray("/admin/realms/demo/admin-events?operationTypes=UPDATE&resourceTypes=USER");
        assertFalse(adminEvents.isEmpty(), "admin events");
        assertEquals(aliceId, adminEvents.getJsonObject(0).getJsonObject("authDetails").getString("userId"),
                adminEvents.encode());
    }

    @Test
    void viewerKeepsOnlyHerOwnRoles() {
        McpClient carol = delegating("carol");
        JsonObject found = McpClient
            .text(carol.callTool("keycloak_user_search", new JsonObject().put("search", "alice")));
        assertEquals("alice", found.getJsonArray("items").getJsonObject(0).getString("username"), found.encode());
        JsonObject denied = carol.callTool("keycloak_user_update",
                new JsonObject().put("id", "alice").put("lastName", "X"));
        assertTrue(denied.getBoolean("isError", false));
        JsonObject body = McpClient.text(denied);
        assertEquals("forbidden", body.getString("error"), body.encode());
        assertTrue(body.getJsonArray("missingRoles").contains("manage-users"), body.encode());
    }

    @Test
    void viewerIsToldUpFrontWhatSheMayDo() {
        McpClient carol = delegating("carol");
        JsonObject search = McpClient
            .text(carol.callTool("search_tools", new JsonObject().put("query", "disable user")));
        JsonObject disable = search.getJsonArray("tools")
            .stream()
            .map(t -> (JsonObject) t)
            .filter(t -> t.getString("name").equals("keycloak_user_set_enabled"))
            .findFirst()
            .orElseThrow();
        assertEquals(false, disable.getBoolean("allowed"), disable.encode());
        assertTrue(disable.getJsonArray("missingRoles").contains("manage-users"), disable.encode());
        assertTrue(search.getString("hint").contains("whoami"), search.encode());

        JsonObject me = McpClient.text(carol.callTool("whoami", new JsonObject().put("language", "de")));
        assertEquals("carol", me.getJsonObject("caller").getString("username"), me.encode());
        JsonArray roles = me.getJsonObject("roles").getJsonArray("demo");
        assertTrue(roles.stream().map(r -> ((JsonObject) r).getString("label")).toList().contains("Benutzer anzeigen"),
                me.encode());
        JsonObject can = me.getJsonObject("can").getJsonObject("demo");
        assertEquals("view", can.getString("users"), me.encode());
        assertEquals("none", can.getString("clients"), me.encode());
        assertTrue(me.getJsonObject("tools").getInteger("forbidden") > 0, me.encode());
    }

    @Test
    void withoutConsentTheExchangeFailsAndSaysWhy() {
        McpClient alice = as("alice", "openid");
        JsonObject me = McpClient.text(alice.callTool("whoami", new JsonObject()));
        JsonObject delegation = me.getJsonObject("delegation");
        assertNotNull(delegation, me.encode());
        assertEquals(false, delegation.getBoolean("consented"), me.encode());
        assertEquals("delegation_failed", delegation.getString("error"), me.encode());
        assertEquals("unknown", me.getString("roles"), me.encode());
        JsonObject denied = alice.callTool("keycloak_user_search", new JsonObject().put("search", "carol"));
        assertTrue(denied.getBoolean("isError", false));
        JsonObject body = McpClient.text(denied);
        assertEquals("delegation_failed", body.getString("error"), body.encode());
        assertTrue(body.getString("message").contains(ExchangeTestResource.DELEGATION_SCOPE), body.encode());
    }

    @Test
    void userWithoutAdminRolesIsRefused() {
        McpClient bob = delegating("bob");
        JsonObject denied = bob.callTool("keycloak_user_search", new JsonObject().put("search", "alice"));
        assertTrue(denied.getBoolean("isError", false));
        assertEquals("forbidden", McpClient.text(denied).getString("error"), McpClient.text(denied).encode());
    }
}
