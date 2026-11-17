package com.github.thomasdarimont.keycloak.mcp.backend;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.backend.CibaTestResource.Entity;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The CIBA confirmer against a real Keycloak: a destructive tool runs only after the
 * caller approved it on their device, a decline cancels it, silence leaves it
 * unconfirmed, and {@code confirm: true} counts for nothing. Run with
 * {@code ./mvnw verify -DskipITs=false -Dit.test=CibaIT}.
 */
@QuarkusTest
@QuarkusTestResource(value = CibaTestResource.class, restrictToAnnotatedClass = true)
class CibaIT {

    private static McpClient alice() {
        return new McpClient().bearer(CallerTestResource.token("mcp-consumer", "alice", "alice")).initialize(false);
    }

    @BeforeEach
    void reset() {
        Entity.delivered.clear();
        Entity.mode = Entity.Mode.APPROVE;
    }

    /** A throw-away user of the demo realm; returns its id. */
    private static String user(String name) throws Exception {
        HttpResponse<String> r = HttpClient.newHttpClient()
            .send(HttpRequest.newBuilder(URI.create(CallerTestResource.base + "/admin/realms/demo/users"))
                .header("Authorization", "Bearer " + CallerTestResource.adminToken())
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(new JsonObject().put("username", name)
                    .put("enabled", true)
                    .put("email", name + "@example.com")
                    .put("emailVerified", true)
                    .put("firstName", name)
                    .put("lastName", "Temp")
                    .encode()))
                .build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(201, r.statusCode(), r.body());
        String location = r.headers().firstValue("Location").orElseThrow();
        return location.substring(location.lastIndexOf('/') + 1);
    }

    private static boolean exists(String username) {
        JsonObject found = McpClient.text(
                alice().callTool("keycloak_user_search", new JsonObject().put("search", username).put("exact", true)));
        JsonArray items = found.getJsonArray("items", new JsonArray());
        return items.stream().anyMatch(i -> username.equals(((JsonObject) i).getString("username")));
    }

    /** The two-step answer of the first call. */
    private static JsonObject requested(JsonObject r) {
        assertEquals("confirmation_required", r.getString("error"), r.encode());
        JsonObject approval = r.getJsonObject("approval");
        assertEquals("requested", approval.getString("status"), r.encode());
        assertEquals("alice", approval.getString("user"));
        assertTrue(approval.getString("code").matches("[1-9][0-9]"), r.encode());
        assertTrue(r.getString("howTo").contains("call again"), r.encode());
        return approval;
    }

    @Test
    void approvalOnTheDeviceRunsTheTool() throws Exception {
        String id = user("ciba-approve");
        McpClient alice = alice();
        JsonObject args = new JsonObject().put("id", id).put("username", "ciba-approve");
        JsonObject approval = requested(McpClient.text(alice.callTool("keycloak_user_delete", args)));
        assertEquals(1, Entity.delivered.size(), Entity.delivered.toString());
        Entity.Delivered d = Entity.delivered.getFirst();
        assertEquals("alice", d.loginHint(), "the caller of the MCP session is asked");
        assertEquals(approval.getString("bindingMessage"), d.bindingMessage());
        assertEquals(approval.getString("code"), d.code(), "the device received the number the chat shows");
        assertTrue(d.bindingMessage().startsWith("kc-mcp-"), d.bindingMessage());
        assertEquals("Delete user: ciba-approve (realm demo)", d.operation(), "the device names the target");
        assertNotNull(d.requester(), "the MCP client's name");

        // the device approved (the entity answers at once): the second call runs the tool
        JsonObject r = McpClient.text(alice.callTool("keycloak_user_delete", args));
        assertFalse(r.containsKey("error"), r.encode());
        assertFalse(exists("ciba-approve"), "deleted after the approval");
    }

    @Test
    void declineOnTheDeviceCancelsTheTool() throws Exception {
        Entity.mode = Entity.Mode.CANCEL;
        String id = user("ciba-cancel");
        McpClient alice = alice();
        JsonObject args = new JsonObject().put("id", id).put("username", "ciba-cancel");
        requested(McpClient.text(alice.callTool("keycloak_user_delete", args)));
        JsonObject r = McpClient.text(alice.callTool("keycloak_user_delete", args));
        assertEquals("cancelled", r.getString("error"), r.encode());
        assertTrue(r.getString("message").contains("alice declined"), r.encode());
        assertTrue(exists("ciba-cancel"), "nothing was deleted");
    }

    @Test
    void silenceLeavesTheToolUnconfirmedAndTheFlagDoesNotCount() throws Exception {
        Entity.mode = Entity.Mode.IGNORE;
        String id = user("ciba-ignore");
        McpClient alice = alice();
        JsonObject args = new JsonObject().put("id", id).put("username", "ciba-ignore").put("confirm", true);
        JsonObject first = requested(McpClient.text(alice.callTool("keycloak_user_delete", args)));
        JsonObject again = McpClient.text(alice.callTool("keycloak_user_delete", args));
        assertEquals("confirmation_required", again.getString("error"), again.encode());
        assertEquals("pending", again.getJsonObject("approval").getString("status"), again.encode());
        assertEquals(first.getString("code"), again.getJsonObject("approval").getString("code"));
        assertTrue(exists("ciba-ignore"), "nothing was deleted");
        assertEquals(1, Entity.delivered.size(), "one request, although confirm: true was passed twice");
    }
}
