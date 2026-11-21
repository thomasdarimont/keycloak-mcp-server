package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.vertx.core.json.JsonObject;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * An admin instance that Keycloak does not reach: the JWKS URL it hands out, in a
 * system's description and in the client setup, names the address of
 * {@code kc-mcp.admin.jwks-hostname}, not its own. The keys are served here all the same.
 */
@QuarkusTest
@TestProfile(JwksHostnameTest.Profile.class)
class JwksHostnameTest {

    public static class Profile implements QuarkusTestProfile {

        @Override
        public Map<String, String> getConfigOverrides() {
            Map<String, String> m = new HashMap<>(new AdminProfile().getConfigOverrides());
            m.put("quarkus.datasource.jdbc.url", "jdbc:h2:mem:kc-mcp-jwks-hostname-test;DB_CLOSE_DELAY=-1");
            m.put("kc-mcp.hostname", "https://mcp-admin.internal");
            m.put("kc-mcp.admin.jwks-hostname", "https://mcp.example.com");
            return m;
        }

    }

    @Test
    void theJwksUrlNamesTheConfiguredAddress() {
        JsonObject body = new JsonObject().put("url", "http://127.0.0.1:1")
            .put("issuer", "https://sso.example.com/realms/master")
            .put("version", "26.8.2");
        JsonObject system = new JsonObject(given().header("Authorization", "Bearer " + AdminProfile.TOKEN)
            .contentType("application/json")
            .body(body.encode())
            .put("/api/admin/systems/acme")
            .then()
            .statusCode(201)
            .extract()
            .asString());
        String path = system.getJsonObject("signingKey").getString("jwksPath");
        assertEquals("https://mcp.example.com" + path, system.getJsonObject("signingKey").getString("jwksUrl"));

        JsonObject setup = new JsonObject(given().header("Authorization", "Bearer " + AdminProfile.TOKEN)
            .get("/api/admin/systems/acme/client-setup")
            .then()
            .statusCode(200)
            .extract()
            .asString());
        assertEquals("https://mcp.example.com" + path,
                setup.getJsonObject("client").getJsonObject("attributes").getString("jwks.url"), setup.encode());
        assertTrue(setup.getString("script").contains("https://mcp.example.com" + path), setup.getString("script"));

        // this instance serves the keys too: every instance on the database does
        given().get(path).then().statusCode(200).body("keys.size()", equalTo(1));
    }

}
