package com.github.thomasdarimont.keycloak.mcp.backend;

import java.util.Map;

import org.junit.jupiter.api.Test;

import io.quarkiverse.mcp.server.McpProtocolVersion;
import io.quarkiverse.mcp.server.test.McpAssured;
import io.quarkiverse.mcp.server.test.McpAssured.McpStreamableTestClient;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.vertx.core.json.JsonObject;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The protocol versions the endpoint serves, with the MCP extension's own test client: a
 * stateless (2026-07-28) client discovers the server with {@code server/discover} and
 * calls tools without a session, and a session-based client of the previous version still
 * connects to the same endpoint. An upgrade of the extension that changes either shows
 * here.
 */
@QuarkusTest
class McpProtocolVersionTest {

    static final String LATEST = McpProtocolVersion.V_2026_07_28.version();

    @Test
    void serverDiscoverNamesTheServerAndTheLatestVersionFirst() {
        JsonObject discover = new JsonObject().put("jsonrpc", "2.0")
            .put("id", 1)
            .put("method", McpAssured.SERVER_DISCOVER);
        McpAssured.injectStatelessMeta(discover);

        RestAssured.given()
            .contentType("application/json")
            .accept("application/json, text/event-stream")
            .header("MCP-Protocol-Version", LATEST)
            .header("Mcp-Method", McpAssured.SERVER_DISCOVER)
            .body(discover.encode())
            .post("/mcp")
            .then()
            .statusCode(200)
            .header("Mcp-Session-Id", nullValue())
            .body("result.supportedVersions[0]", equalTo(LATEST))
            .body("result._meta.'io.modelcontextprotocol/serverInfo'.name", equalTo("keycloak-mcp-server"));
    }

    @Test
    void aStatelessClientListsAndCallsToolsWithoutASession() {
        McpStreamableTestClient client = McpAssured.newStreamableClient()
            .setStateless()
            .build()
            .connect(init -> assertEquals("keycloak-mcp-server", init.serverName()));
        assertNull(client.mcpSessionId());

        client.when()
            .toolsList(page -> assertNotNull(page.findByName("search_tools")))
            .toolsCall("search_tools", Map.of("query", "disable user bob"), response -> {
                assertFalse(response.isError());
                assertTrue(response.firstContent().asText().text().contains("keycloak_user_set_enabled"));
            })
            .thenAssertResults();
        client.disconnect();
    }

    @Test
    void aSessionBasedClientOfThePreviousVersionStillConnects() {
        McpStreamableTestClient client = McpAssured.newStreamableClient()
            .setProtocolVersion(McpProtocolVersion.V_2025_11_25)
            .build()
            .connect(init -> assertEquals(McpProtocolVersion.V_2025_11_25.version(), init.protocolVersion()));
        assertNotNull(client.mcpSessionId());

        client.when().toolsList(page -> assertNotNull(page.findByName("whoami"))).thenAssertResults();
        client.disconnect();
    }
}
