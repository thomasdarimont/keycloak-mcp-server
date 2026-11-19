package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.util.Map;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;

/**
 * {@code kc-mcp.admin.openapi=false}: the document and Swagger UI are gone, the rest
 * stays.
 */
@QuarkusTest
@TestProfile(OpenApiOffTest.Profile.class)
class OpenApiOffTest {

    public static class Profile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("kc-mcp.admin.openapi", "false");
        }
    }

    @Test
    void theDocumentAndTheUiAnswer404() {
        given().get("/q/openapi").then().statusCode(404);
        given().get("/q/openapi?format=json").then().statusCode(404);
        given().get("/q/swagger-ui/").then().statusCode(404);
        // other routes are untouched: the admin API still answers for itself
        given().get("/api/admin/systems").then().statusCode(404).body(containsString("admin_api_disabled"));
    }
}
