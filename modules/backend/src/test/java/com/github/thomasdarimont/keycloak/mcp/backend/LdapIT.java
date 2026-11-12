package com.github.thomasdarimont.keycloak.mcp.backend;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The FEDERATION tools against a real directory, a 389 Directory Server federated into
 * realm {@code ldap} of the shared Keycloak ({@link LdapTestResource}): listing, masked
 * settings, connection and bind tests through the stored credential, full and changed
 * sync, and the imported users.
 */
@QuarkusTest
@QuarkusTestResource(value = LdapTestResource.class, restrictToAnnotatedClass = true)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class LdapIT {

    static McpClient mcp;

    @BeforeEach
    void connect() {
        if (mcp == null) {
            mcp = new McpClient().initialize(false);
        }
    }

    static JsonObject call(String tool, JsonObject args) {
        JsonObject result = mcp.callTool(tool, args);
        JsonObject body = McpClient.text(result);
        assertFalse(result.getBoolean("isError", false), tool + " -> " + body.encode());
        return body;
    }

    static JsonObject error(String tool, JsonObject args) {
        JsonObject result = mcp.callTool(tool, args);
        assertTrue(result.getBoolean("isError", false), tool + " should fail");
        return McpClient.text(result);
    }

    static JsonObject user(String username) {
        JsonArray items = call("keycloak_user_search", new JsonObject().put("username", username))
            .getJsonArray("items");
        assertEquals(1, items.size(), username + ": " + items.encode());
        return items.getJsonObject(0);
    }

    @Test
    @Order(1)
    void listsTheProvidersWithTheirSettings() {
        JsonObject list = call("keycloak_federation_list", new JsonObject());
        assertEquals(2, list.getInteger("count"), list.encode());
        JsonObject corp = list.getJsonArray("items")
            .stream()
            .map(JsonObject.class::cast)
            .filter(p -> "corp-ldap".equals(p.getString("name")))
            .findFirst()
            .orElseThrow();
        assertEquals("ldap", corp.getString("providerId"));
        assertEquals("rhds", corp.getString("vendor"));
        assertEquals("READ_ONLY", corp.getString("editMode"));
        assertEquals(LdapTestResource.PEOPLE, corp.getString("usersDn"));
        assertTrue(corp.getString("connectionUrl").startsWith("ldap://host.docker.internal:"), corp.encode());

        JsonObject detail = call("keycloak_federation_get", new JsonObject().put("id", "corp-ldap"));
        JsonObject config = detail.getJsonObject("config");
        assertEquals("****", config.getString("bindCredential"), "the bind password never leaves the server");
        assertEquals("cn=Directory Manager", config.getString("bindDn"));
        assertFalse(detail.encode().contains(LdapTestResource.DM_PASSWORD));
    }

    @Test
    @Order(2)
    void testsConnectionAndBindWithTheStoredCredential() {
        JsonObject reach = call("keycloak_federation_test_connection",
                new JsonObject().put("id", "corp-ldap").put("check", "connection"));
        assertEquals(true, reach.getBoolean("ok"), reach.encode());
        JsonObject bind = call("keycloak_federation_test_connection", new JsonObject().put("id", "corp-ldap"));
        assertEquals("authentication", bind.getString("check"));
        assertEquals(true, bind.getBoolean("ok"), bind.encode());

        // the server is reachable, the stored password is wrong
        JsonObject brokenReach = call("keycloak_federation_test_connection",
                new JsonObject().put("id", "broken-ldap").put("check", "connection"));
        assertEquals(true, brokenReach.getBoolean("ok"), brokenReach.encode());
        JsonObject brokenBind = call("keycloak_federation_test_connection", new JsonObject().put("id", "broken-ldap"));
        assertEquals(false, brokenBind.getBoolean("ok"), brokenBind.encode());
        assertEquals(400, brokenBind.getInteger("status"), brokenBind.encode());

        assertEquals("not_found",
                error("keycloak_federation_test_connection", new JsonObject().put("id", "no-such-ldap"))
                    .getString("error"));
    }

    @Test
    @Order(3)
    void fullSyncImportsTheDirectory() {
        JsonObject sync = call("keycloak_federation_sync", new JsonObject().put("id", "corp-ldap").put("mode", "full"));
        assertEquals(2, sync.getInteger("added"), sync.encode());
        assertEquals(0, sync.getInteger("failed"), sync.encode());

        JsonObject alice = user("alice");
        assertEquals("alice@example.com", alice.getString("email"));
        assertEquals("Liddell", alice.getString("lastName"));
        String corpId = call("keycloak_federation_get", new JsonObject().put("id", "corp-ldap")).getString("id");
        JsonObject detail = call("keycloak_user_get", new JsonObject().put("id", alice.getString("id")));
        assertEquals(corpId, detail.getString("federationLink"), detail.encode());
        assertEquals("uid=alice," + LdapTestResource.PEOPLE,
                detail.getJsonObject("attributes").getString("LDAP_ENTRY_DN"), detail.encode());
        assertEquals(2, call("keycloak_user_count", new JsonObject()).getInteger("count"));
    }

    @Test
    @Order(4)
    void changedSyncPicksUpNewEntries() throws Exception {
        LdapTestResource.addUser("carol", "Carol", "Danvers");
        JsonObject sync = call("keycloak_federation_sync", new JsonObject().put("id", "corp-ldap"));
        assertEquals("changed", sync.getString("mode"));
        assertEquals(1, sync.getInteger("added"), sync.encode());
        assertEquals("carol@example.com", user("carol").getString("email"));
        List<String> usernames = call("keycloak_user_search", new JsonObject()).getJsonArray("items")
            .stream()
            .map(u -> ((JsonObject) u).getString("username"))
            .sorted()
            .toList();
        assertEquals(List.of("alice", "bob", "carol"), usernames);
    }

    @Test
    @Order(5)
    void readOnlyDirectoryRefusesChanges() {
        String id = user("bob").getString("id");
        JsonObject refused = error("keycloak_user_update", new JsonObject().put("id", id).put("lastName", "Changed"));
        assertFalse(refused.getString("error").isBlank(), refused.encode());
        assertEquals("Builder", call("keycloak_user_get", new JsonObject().put("id", id)).getString("lastName"));
    }
}
