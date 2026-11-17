package com.github.thomasdarimont.keycloak.mcp.backend;

import java.util.Map;

import org.junit.jupiter.api.Test;

import io.quarkiverse.mcp.server.JsonRpcErrorCodes;
import io.quarkiverse.mcp.server.McpProtocolVersion;
import io.quarkiverse.mcp.server.test.McpAssured;
import io.quarkiverse.mcp.server.test.McpAssured.McpStreamableTestClient;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.vertx.core.json.JsonObject;

import static org.hamcrest.Matchers.containsString;
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

    /**
     * SEP-2243: a stateless request mirrors the method and the tool name in headers, for
     * proxies that route or limit by them. The server must not act on a body that says
     * something else than the headers a proxy has judged.
     */
    @Test
    void aRequestWhoseHeadersDoNotMatchItsBodyIsRefused() {
        JsonObject call = new JsonObject().put("jsonrpc", "2.0")
            .put("id", 7)
            .put("method", "tools/call")
            .put("params", new JsonObject().put("name", "search_tools")
                .put("arguments", new JsonObject().put("query", "delete a user")));
        McpAssured.injectStatelessMeta(call);

        // the headers say what the body says: the call runs
        stateless("tools/call", "search_tools", call).then().statusCode(200);
        // another tool in the header than in the body
        stateless("tools/call", "whoami", call).then()
            .statusCode(400)
            .body("error.code", equalTo(JsonRpcErrorCodes.HEADER_MISMATCH))
            .body("error.message", containsString("Mcp-Name"));
        // another method
        stateless("tools/list", "search_tools", call).then()
            .statusCode(400)
            .body("error.code", equalTo(JsonRpcErrorCodes.HEADER_MISMATCH));
        // method values are case-sensitive
        stateless("TOOLS/CALL", "search_tools", call).then().statusCode(400);
        // and the headers are required
        stateless(null, "search_tools", call).then()
            .statusCode(400)
            .body("error.code", equalTo(JsonRpcErrorCodes.HEADER_MISMATCH));
        stateless("tools/call", null, call).then()
            .statusCode(400)
            .body("error.code", equalTo(JsonRpcErrorCodes.HEADER_MISMATCH));
    }

    /**
     * Most tools run through {@code execute_tool}, so its {@code name} argument is
     * mirrored as {@code Mcp-Param-Tool}, and the target of a call as
     * {@code Mcp-Param-System} and {@code Mcp-Param-Realm}: what a proxy routes or limits
     * by is then what the server runs.
     */
    @Test
    void theToolBehindExecuteToolAndTheTargetAreMirroredInHeaders() {
        McpStreamableTestClient client = McpAssured.newStreamableClient().setStateless().build().connect();
        client.when().toolsList(page -> {
            JsonObject execute = page.findByName("execute_tool").inputSchema();
            assertEquals("Tool", execute.getJsonObject("properties").getJsonObject("name").getString("x-mcp-header"),
                    execute.encode());
            JsonObject who = page.findByName("whoami").inputSchema();
            JsonObject system = who.getJsonObject("properties").getJsonObject("system");
            assertTrue(system == null || "System".equals(system.getString("x-mcp-header")), who.encode());
        }).thenAssertResults();
        client.disconnect();

        JsonObject call = new JsonObject().put("jsonrpc", "2.0")
            .put("id", 8)
            .put("method", "tools/call")
            .put("params",
                    new JsonObject().put("name", "execute_tool")
                        .put("arguments", new JsonObject().put("name", "keycloak_user_search")
                            .put("arguments", new JsonObject().put("search", "x"))));
        McpAssured.injectStatelessMeta(call);
        // without the header, and with another tool in it than in the body
        stateless("tools/call", "execute_tool", call).then()
            .statusCode(400)
            .body("error.code", equalTo(JsonRpcErrorCodes.HEADER_MISMATCH))
            .body("error.message", containsString("Mcp-Param-Tool"));
        param("Mcp-Param-Tool", "keycloak_user_get", call).then()
            .statusCode(400)
            .body("error.code", equalTo(JsonRpcErrorCodes.HEADER_MISMATCH));
        // the header that says what the body says gets past the check
        param("Mcp-Param-Tool", "keycloak_user_search", call).then().statusCode(200);
    }

    private static io.restassured.response.Response param(String header, String value, JsonObject body) {
        return RestAssured.given()
            .contentType("application/json")
            .accept("application/json, text/event-stream")
            .header("MCP-Protocol-Version", LATEST)
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", "execute_tool")
            .header(header, value)
            .body(body.encode())
            .post("/mcp");
    }

    private static io.restassured.response.Response stateless(String method, String name, JsonObject body) {
        var request = RestAssured.given()
            .contentType("application/json")
            .accept("application/json, text/event-stream")
            .header("MCP-Protocol-Version", LATEST);
        if (method != null) {
            request.header("Mcp-Method", method);
        }
        if (name != null) {
            request.header("Mcp-Name", name);
        }
        return request.body(body.encode()).post("/mcp");
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
