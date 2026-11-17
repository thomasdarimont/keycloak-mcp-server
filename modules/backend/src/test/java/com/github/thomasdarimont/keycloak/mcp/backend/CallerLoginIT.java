package com.github.thomasdarimont.keycloak.mcp.backend;

import org.junit.jupiter.api.Test;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import io.vertx.core.json.JsonObject;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Callers that must log in, against a real Keycloak: the endpoint challenges anonymous
 * clients the way the MCP authorization spec expects, accepts only tokens issued for it,
 * and the admin calls run as the server's service account. Calls with the caller's own
 * roles: {@link ExchangeIT}. Run with {@code ./mvnw verify -DskipITs=false}.
 */
@QuarkusTest
@QuarkusTestResource(value = CallerTestResource.class, restrictToAnnotatedClass = true)
class CallerLoginIT {

    @Test
    void adminApiAcceptsAccessTokensOfTheTrustedIssuerWithTheRole() {
        given().get("/admin/systems").then().statusCode(401).header("WWW-Authenticate", startsWith("Bearer"));
        // a realm admin's token opens the API ...
        given().header("Authorization", "Bearer " + CallerTestResource.token("mcp-consumer", "alice", "alice"))
            .get("/admin/systems")
            .then()
            .statusCode(200)
            .body("systems.alias", hasItem("default"));
        // ... a viewer's does not, nor a token without the audience
        given().header("Authorization", "Bearer " + CallerTestResource.token("mcp-consumer", "carol", "carol"))
            .get("/admin/systems")
            .then()
            .statusCode(403)
            .body("error", equalTo("forbidden"));
        given().header("Authorization", "Bearer " + CallerTestResource.token("other-app", "alice", "alice"))
            .get("/admin/systems")
            .then()
            .statusCode(401);
        given().header("Authorization", "Bearer not-a-token").get("/admin/systems").then().statusCode(401);
        // registering needs a mutable repository, which this profile lacks
        given().header("Authorization", "Bearer " + CallerTestResource.token("mcp-consumer", "alice", "alice"))
            .contentType("application/json")
            .body("{\"url\": \"" + CallerTestResource.base + "\"}")
            .put("/admin/systems/acme")
            .then()
            .statusCode(503)
            .body("error", equalTo("no_mutable_repository"));
        // and secrets a vault that stores them, which the file vault does not
        given().header("Authorization", "Bearer " + CallerTestResource.token("mcp-consumer", "alice", "alice"))
            .contentType("application/json")
            .body("{\"value\": \"s3cr3t\"}")
            .put("/admin/secrets/acme/client-secret")
            .then()
            .statusCode(409)
            .body("error", equalTo("vault_read_only"));
        given().header("Authorization", "Bearer " + CallerTestResource.token("mcp-consumer", "alice", "alice"))
            .get("/admin/secrets")
            .then()
            .statusCode(200)
            .body("vault", equalTo("file"))
            .body("writable", equalTo(false));
        given().header("Authorization", "Bearer " + CallerTestResource.token("mcp-consumer", "alice", "alice"))
            .get("/admin/storage")
            .then()
            .statusCode(503)
            .body("error", equalTo("storage_disabled"));
    }

    @Test
    void anonymousRequestsGetTheOAuthChallenge() {
        Response r = given().header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .body(new JsonObject().put("jsonrpc", "2.0")
                .put("id", 1)
                .put("method", "initialize")
                .put("params",
                        new JsonObject().put("protocolVersion", "2025-06-18")
                            .put("capabilities", new JsonObject())
                            .put("clientInfo", new JsonObject().put("name", "t").put("version", "1")))
                .encode())
            .post("/mcp");
        assertEquals(401, r.statusCode());
        String challenge = r.header("WWW-Authenticate");
        assertNotNull(challenge, "WWW-Authenticate");
        assertTrue(challenge.startsWith("Bearer"), challenge);
        assertTrue(challenge.contains("resource_metadata=\""), challenge);

        Response meta = given().get("/.well-known/oauth-protected-resource");
        assertEquals(200, meta.statusCode(), meta.asString());
        JsonObject body = new JsonObject(meta.asString());
        assertTrue(body.getJsonArray("authorization_servers").contains(CallerTestResource.base + "/realms/demo"),
                body.encode());
        assertTrue(body.getString("resource").endsWith("/mcp") || body.getString("resource").contains("localhost"),
                body.encode());

        // RFC 9728: the document of a resource is found at the well-known path followed
        // by
        // the resource's own path, also for the endpoint and an entry of its realm
        for (String resource : new String[] { "/mcp", "/mcp/systems/default", "/mcp/systems/default/demo" }) {
            JsonObject inserted = new JsonObject(given().get("/.well-known/oauth-protected-resource" + resource)
                .then()
                .statusCode(200)
                .extract()
                .asString());
            assertTrue(inserted.getString("resource").endsWith(resource), inserted.encode());
            assertEquals(body.getJsonArray("authorization_servers"), inserted.getJsonArray("authorization_servers"));
            assertEquals(body.getJsonArray("scopes_supported"), inserted.getJsonArray("scopes_supported"));
        }
        given().get("/.well-known/oauth-protected-resource/mcp/systems/no-such-system").then().statusCode(404);
        given().get("/.well-known/oauth-protected-resource/elsewhere").then().statusCode(404);
    }

    @Test
    void boundEntriesWorkWithTheCallersLogin() {
        // anonymous: the bound entry challenges like the root
        Response r = given().header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .body("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}")
            .post("/mcp/systems/default/demo");
        assertEquals(401, r.statusCode());
        assertTrue(r.header("WWW-Authenticate").startsWith("Bearer"), r.header("WWW-Authenticate"));

        McpClient alice = new McpClient().path("/mcp/systems/default/demo")
            .bearer(CallerTestResource.token("mcp-consumer", "alice", "alice"))
            .initialize(false);
        JsonObject who = McpClient.text(alice.callTool("whoami", new JsonObject()));
        assertEquals("alice", who.getJsonObject("caller").getString("username"), who.encode());
        assertEquals("demo", who.getJsonObject("entry").getString("realm"), who.encode());
        assertTrue(who.getString("keycloakCallsRunAs").contains("service account"), who.encode());
        JsonObject found = McpClient
            .text(alice.callTool("keycloak_user_search", new JsonObject().put("search", "carol")));
        assertEquals("carol", found.getJsonArray("items").getJsonObject(0).getString("username"), found.encode());
        JsonObject elsewhere = McpClient
            .text(alice.callTool("keycloak_user_search", new JsonObject().put("realm", "master").put("search", "x")));
        assertEquals("entry_mismatch", elsewhere.getString("error"), elsewhere.encode());
    }

    @Test
    void tokenWithoutTheServerAudienceIsRejected() {
        String token = CallerTestResource.token("other-app", "alice", "alice");
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> new McpClient().bearer(token).initialize(false));
        assertTrue(e.getMessage().startsWith("HTTP 401"), e.getMessage());
    }
}
