package com.github.thomasdarimont.keycloak.mcp.backend;

import org.junit.jupiter.api.Test;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import io.vertx.core.json.JsonObject;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Two independent Keycloaks behind one server in delegation mode exchange: a caller of
 * the first never has their token sent to the second, a caller of the second administers
 * it through its entry.
 */
@QuarkusTest
@QuarkusTestResource(value = TwoKeycloaksTestResource.class, restrictToAnnotatedClass = true)
class TwoKeycloaksIT {

    @Test
    void aCallerOfOneKeycloakCannotActOnTheOther() {
        String aliceToken = CallerTestResource.token("mcp-consumer", "alice", "alice");

        // her own Keycloak, through its entry: her token may be used there, so it gets as
        // far as that Keycloak's token exchange (which this realm is not set up for)
        McpClient own = new McpClient().path("/mcp/systems/default").bearer(aliceToken).initialize(false);
        JsonObject found = McpClient
            .text(own.callTool("keycloak_user_search", new JsonObject().put("search", "carol")));
        assertEquals("delegation_failed", found.getString("error"), found.encode());

        // the root entry: the default tenant verified her token (first Keycloak), the
        // default system is the second;
        // that the tenant trusts her issuer does not make it the second system's issuer
        McpClient root = new McpClient().bearer(aliceToken).initialize(false);
        JsonObject who = McpClient.text(root.callTool("whoami", new JsonObject()));
        assertEquals("alice", who.getJsonObject("caller").getString("username"), who.encode());
        JsonObject implicit = McpClient
            .text(root.callTool("keycloak_user_search", new JsonObject().put("realm", "master").put("search", "x")));
        assertEquals("caller_foreign_system", implicit.getString("error"), implicit.encode());
        JsonObject named = McpClient.text(root.callTool("keycloak_user_search",
                new JsonObject().put("system", "other").put("realm", "master").put("search", "x")));
        assertEquals("caller_foreign_system", named.getString("error"), named.encode());
        assertTrue(named.getString("message").contains("/mcp/systems/other"), named.encode());
    }

    @Test
    void aCallerOfTheOtherKeycloakAdministersItThroughItsEntry() {
        String adminToken = TwoKeycloaksTestResource.otherToken("mcp-consumer", "admin", "admin");

        McpClient other = new McpClient().path("/mcp/systems/other").bearer(adminToken).initialize(false);
        JsonObject who = McpClient.text(other.callTool("whoami", new JsonObject()));
        assertEquals("admin", who.getJsonObject("caller").getString("username"), who.encode());
        // the token of the second Keycloak may be used at it: it is handed to that
        // Keycloak's token exchange (which is not set up there)
        JsonObject found = McpClient
            .text(other.callTool("keycloak_user_search", new JsonObject().put("search", "admin")));
        assertEquals("delegation_failed", found.getString("error"), found.encode());
        // the first Keycloak's realm is not his to reach: the bound entry refuses the
        // system argument before the issuer is even looked at
        JsonObject foreign = McpClient.text(other.callTool("keycloak_user_search",
                new JsonObject().put("system", "default").put("realm", "demo").put("search", "alice")));
        assertEquals("entry_mismatch", foreign.getString("error"), foreign.encode());

        // and the first system's entry does not accept his token either
        Response r = given().header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer " + adminToken)
            .body("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}")
            .post("/mcp/systems/default");
        assertEquals(401, r.statusCode(), r.asString());
    }

    @Test
    void theOtherSystemsEntryDoesNotAcceptTheFirstKeycloaksTokens() {
        Response r = given().header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer " + CallerTestResource.token("mcp-consumer", "alice", "alice"))
            .body("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}")
            .post("/mcp/systems/other");
        assertEquals(401, r.statusCode(), r.asString());
    }

    private static int initialize(String path, String token) {
        return given().header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer " + token)
            .body("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\","
                    + "\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"1\"}}}")
            .post(path)
            .statusCode();
    }

    @Test
    void anEntrysMetadataIsServedBeforeTheEntryWasEverAskedFor() {
        // a system nobody has sent a request to: its tenant does not exist yet
        String alice = CallerTestResource.token("mcp-consumer", "alice", "alice");
        given().header("Authorization", "Bearer " + alice)
            .contentType("application/json")
            .body(new JsonObject().put("url", TwoKeycloaksTestResource.otherBase)
                .put("authRealm", "master")
                .put("defaultRealm", "master")
                .put("clientAuth", "client_secret")
                .put("clientId", "mcp-admin")
                .put("clientSecret", "unused-here")
                .encode())
            .put("/admin/systems/untouched")
            .then()
            .statusCode(201);
        String wellKnown = "/.well-known/oauth-protected-resource/mcp/systems/untouched";
        JsonObject first = new JsonObject(given().get(wellKnown).then().statusCode(200).extract().asString());
        assertTrue(first.getString("resource").endsWith("/mcp/systems/untouched"), first.encode());
        assertEquals(TwoKeycloaksTestResource.otherBase + "/realms/master",
                first.getJsonArray("authorization_servers").getString(0), first.encode());
        JsonObject realm = new JsonObject(
                given().get(wellKnown + "/some-realm").then().statusCode(200).extract().asString());
        assertEquals(TwoKeycloaksTestResource.otherBase + "/realms/some-realm",
                realm.getJsonArray("authorization_servers").getString(0), realm.encode());

        // once the entry was asked, Quarkus serves the document: the same one
        Response challenge = given().header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .body("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}")
            .post("/mcp/systems/untouched");
        assertEquals(401, challenge.statusCode());
        assertTrue(challenge.header("WWW-Authenticate").contains(wellKnown), challenge.header("WWW-Authenticate"));
        assertEquals(first, new JsonObject(given().get(wellKnown).then().statusCode(200).extract().asString()));

        // a path that names no system stays unknown
        given().get("/.well-known/oauth-protected-resource/mcp/systems/no-such-system").then().statusCode(404);
    }

    @Test
    void replacingASystemsKeycloakRevokesTheOldIssuersTokens() {
        // alice, realm-admin of the first Keycloak's demo realm, may use the admin API
        String alice = CallerTestResource.token("mcp-consumer", "alice", "alice");
        JsonObject service = new JsonObject().put("authRealm", "master")
            .put("defaultRealm", "master")
            .put("clientAuth", "client_secret")
            .put("clientId", "mcp-admin")
            .put("clientSecret", "unused-here");
        given().header("Authorization", "Bearer " + alice)
            .contentType("application/json")
            .body(service.copy().put("url", TwoKeycloaksTestResource.otherBase).encode())
            .put("/admin/systems/moved")
            .then()
            .statusCode(201);
        String otherAdmin = TwoKeycloaksTestResource.otherToken("mcp-consumer", "admin", "admin");
        assertEquals(200, initialize("/mcp/systems/moved", otherAdmin), "the second Keycloak's admin logs in");

        // the system now points at the first Keycloak (its master realm, not the default
        // tenant's demo realm)
        given().header("Authorization", "Bearer " + alice)
            .contentType("application/json")
            .body(service.copy().put("url", CallerTestResource.base).encode())
            .put("/admin/systems/moved")
            .then()
            .statusCode(200);
        assertEquals(401, initialize("/mcp/systems/moved", otherAdmin),
                "the old Keycloak's tokens are no longer accepted at the entry");
        String firstAdmin = TwoKeycloaksTestResource.firstMasterToken("mcp-consumer", "admin", "admin");
        assertEquals(200, initialize("/mcp/systems/moved", firstAdmin), "the new Keycloak's admin logs in");
        McpClient moved = new McpClient().path("/mcp/systems/moved").bearer(firstAdmin).initialize(false);
        JsonObject who = McpClient.text(moved.callTool("whoami", new JsonObject()));
        assertEquals("admin", who.getJsonObject("caller").getString("username"), who.encode());
        assertEquals("moved", who.getString("system"), who.encode());
    }
}
