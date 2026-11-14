package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.DefaultKeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.specification.RequestSpecification;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;

/**
 * With {@code kc-mcp.admin.allow-new-systems=false} the stored systems are served and
 * manageable, but no alias the server does not know can be registered.
 */
@QuarkusTest
@TestProfile(ClosedRegistrationProfile.class)
class ClosedRegistrationTest {

    @Inject
    DefaultKeycloakSystems systems;

    static RequestSpecification admin() {
        return given().header("Authorization", "Bearer " + AdminProfile.TOKEN).contentType("application/json");
    }

    @Test
    void knownSystemsStayManageableNewOnesAreRefused() {
        // a system that exists already (written by a control plane earlier)
        systems.mutableRepository()
            .orElseThrow()
            .save(KeycloakSystem.builder("frozen", "http://127.0.0.1:1")
                .grantType(GrantType.CLIENT_CREDENTIALS)
                .clientAuth(ClientAuth.PRIVATE_KEY_JWT)
                .clientId("keycloak-mcp-server")
                .build());

        admin().body("{\"url\": \"http://127.0.0.1:1\"}")
            .put("/admin/systems/newcomer")
            .then()
            .statusCode(403)
            .body("error", equalTo("registration_closed"));
        admin().body("{\"alias\": \"newcomer\", \"url\": \"http://127.0.0.1:1\"}")
            .post("/admin/systems")
            .then()
            .statusCode(403)
            .body("error", equalTo("registration_closed"));
        admin().get("/admin/systems").then().statusCode(200).body("systems.alias", hasItem("frozen"));

        // the known system: readable, changeable, rotatable, removable
        admin().get("/admin/systems/frozen").then().statusCode(200).body("source", equalTo("db"));
        admin().body("{\"url\": \"http://127.0.0.1:1\", \"displayName\": \"Frozen Inc.\"}")
            .put("/admin/systems/frozen")
            .then()
            .statusCode(200)
            .body("displayName", equalTo("Frozen Inc."));
        admin().post("/admin/systems/frozen/signing-key").then().statusCode(200);
        admin().body("{\"value\": \"s3cr3t\"}").put("/admin/secrets/frozen/secret").then().statusCode(201);
        admin().delete("/admin/secrets/frozen/secret").then().statusCode(204);
        admin().delete("/admin/systems/frozen").then().statusCode(204);
        admin().get("/admin/systems/frozen").then().statusCode(404);
    }
}
