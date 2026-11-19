package com.github.thomasdarimont.keycloak.mcp.backend.http;

import java.util.Map;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;

/**
 * An admin-only instance: the MCP endpoint and its entries are off, the rest is served.
 */
@QuarkusTest
@TestProfile(McpEndpointOffTest.Profile.class)
class McpEndpointOffTest {

    public static class Profile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("kc-mcp.mcp.enabled", "false");
        }
    }

    static final String INITIALIZE = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{"
            + "\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"1\"}}}";

    @Test
    void theEndpointAndItsEntriesAnswer404TheRestIsServed() {
        for (String path : new String[] { "/mcp", "/mcp/systems/default", "/mcp/systems/default/demo" }) {
            given().header("Accept", "application/json, text/event-stream")
                .contentType("application/json")
                .body(INITIALIZE)
                .post(path)
                .then()
                .statusCode(404)
                // a plain 404: nothing about the switch or the admin API leaks to whoever
                // asks
                .body(containsString("not_found"))
                .body(not(containsString("admin")))
                .body(not(containsString("kc-mcp")));
        }
        given().get("/api/admin/systems").then().statusCode(404).body(containsString("admin_api_disabled"));
        given().get("/q/openapi").then().statusCode(200);
    }
}
