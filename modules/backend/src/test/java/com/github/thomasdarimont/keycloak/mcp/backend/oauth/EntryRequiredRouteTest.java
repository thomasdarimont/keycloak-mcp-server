package com.github.thomasdarimont.keycloak.mcp.backend.oauth;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.backend.admin.NoSystemsProfile;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;

/**
 * A server like <code>mcp-users</code> of the dynamic-systems example: systems come from
 * the repository only and callers have to log in. The MCP endpoint itself has no
 * authorization server then. It used to answer with a 401 without a challenge and its
 * metadata with a 500, which left an MCP client guessing at a login page of the server.
 */
@QuarkusTest
@TestProfile(EntryRequiredRouteTest.Profile.class)
class EntryRequiredRouteTest {

    public static class Profile implements QuarkusTestProfile {

        @Override
        public Map<String, String> getConfigOverrides() {
            Map<String, String> m = new HashMap<>(new NoSystemsProfile().getConfigOverrides());
            m.put("quarkus.datasource.jdbc.url", "jdbc:h2:mem:kc-mcp-entry-required-test;DB_CLOSE_DELAY=-1");
            m.put("kc-mcp.mcp.oauth.enabled", "true");
            m.put("kc-mcp.mcp.require-caller", "true");
            return m;
        }

    }

    @Test
    void theEndpointItselfNamesTheEntriesToUse() {
        given().contentType("application/json")
            .body("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}")
            .post("/mcp")
            .then()
            .statusCode(404)
            .body("error", equalTo("entry_required"))
            .body("message", containsString("/mcp/systems/<system>[/<realm>]"));
        given().get("/mcp").then().statusCode(404).body("error", equalTo("entry_required"));
    }

    @Test
    void theEndpointItselfHasNoResourceMetadata() {
        given().get("/.well-known/oauth-protected-resource/mcp").then().statusCode(404);
        given().get("/.well-known/oauth-protected-resource").then().statusCode(404);
    }

    @Test
    void anEntryOfAnUnknownSystemIsNotAnswered() {
        given().get("/mcp/systems/nobody").then().statusCode(org.hamcrest.Matchers.not(equalTo(200)));
    }

}
