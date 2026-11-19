package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import com.github.thomasdarimont.keycloak.mcp.backend.McpClient;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A server that starts without any system (the dynamic-systems example) must still search
 * and list its tools, before and after the first registration. Regression: the role and
 * capability discovery used to copy the (empty) system list at startup and hid
 * everything.
 */
@QuarkusTest
@TestProfile(NoSystemsProfile.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class NoSystemsSearchTest {

    static JsonArray search(McpClient mcp, String query) {
        return McpClient.text(mcp.callTool("search_tools", new JsonObject().put("query", query))).getJsonArray("tools");
    }

    @Test
    @Order(1)
    void withoutAnySystemTheCatalogIsVisible() {
        McpClient mcp = new McpClient().initialize(false);
        JsonArray hits = search(mcp, "list users");
        assertFalse(hits.isEmpty(), "search finds tools with no system registered");
        assertEquals("keycloak_user_search", hits.getJsonObject(0).getString("name"));
        JsonArray categories = McpClient.text(mcp.callTool("search_tools", new JsonObject()))
            .getJsonArray("categories");
        assertFalse(categories.isEmpty(), "categories are listed");
        assertTrue(
                mcp.listTools()
                    .stream()
                    .anyMatch(t -> "keycloak_user_search".equals(((JsonObject) t).getString("name"))),
                "hot tools are listed");
    }

    @Test
    @Order(2)
    void aRegisteredSystemKeepsTheCatalogVisible() {
        given().header("Authorization", "Bearer " + AdminProfile.TOKEN)
            .contentType("application/json")
            .body("{\"url\": \"http://127.0.0.1:1\", \"defaultRealm\": \"acme-dev\", \"allowedRealms\": [\"acme-dev\"]}")
            .put("/api/admin/systems/acme")
            .then()
            .statusCode(201);
        McpClient entry = new McpClient().path("/mcp/systems/acme/acme-dev").initialize(false);
        JsonArray hits = search(entry, "what keycloak features are enabled?");
        assertFalse(hits.isEmpty(), "the question that started this");
        assertEquals("keycloak_server_features", hits.getJsonObject(0).getString("name"));
        assertEquals("keycloak_server_features",
                search(entry, "is the organizations feature enabled").getJsonObject(0).getString("name"));
        assertEquals("keycloak_user_search", search(entry, "list users").getJsonObject(0).getString("name"));
        assertEquals("keycloak_client_list", search(entry, "search clients").getJsonObject(0).getString("name"));
        assertEquals("keycloak_user_groups_list",
                search(entry, "list the groups of a user").getJsonObject(0).getString("name"));
        assertTrue(entry.listTools()
            .stream()
            .anyMatch(t -> "keycloak_user_search".equals(((JsonObject) t).getString("name"))));
    }
}
