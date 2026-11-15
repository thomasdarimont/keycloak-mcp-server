package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.backend.spi.Extensions;
import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.ServerInfo;
import com.github.thomasdarimont.keycloak.mcp.spi.ServerInfoContributor;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The server info through the admin API: the server, its runtime and the extensions with
 * what they report about themselves.
 */
@QuarkusTest
@TestProfile(AdminProfile.class)
class AdminServerInfoTest {

    @Test
    void theServerInfoNeedsTheTokenAndDescribesServerRuntimeAndExtensions() {
        given().get("/admin/server-info").then().statusCode(401);
        given().header("Authorization", "Bearer " + AdminProfile.TOKEN)
            .get("/admin/server-info")
            .then()
            .statusCode(200)
            .body("server.version", notNullValue())
            .body("server.startedAt", notNullValue())
            .body("server.toolExposure", notNullValue())
            .body("server.instanceRole", equalTo("all"))
            .body("server.securityProfile", equalTo("local"))
            .body("extensionPoints.'state-store'.displayName", equalTo("State store"))
            .body("extensionPoints.'state-store'.displayNameKey", equalTo("state-store.display-name"))
            .body("extensionPoints.'state-store'.description",
                    org.hamcrest.Matchers.startsWith("Keeps short-lived state every instance must see"))
            .body("extensionPoints.'state-store'.descriptionKey", equalTo("state-store.description"))
            .body("runtime.javaVersion", equalTo(System.getProperty("java.version")))
            .body("runtime.memoryMaxBytes", greaterThan(0L))
            .body("systems.count", notNullValue())
            // every built-in extension point has its English texts; the one the tests
            // declare has none and goes by its name, and it is listed without an
            // extension
            .body("extensionPoints.findAll { it.value.displayName == it.key }.collect { it.key }",
                    equalTo(List.of("test-point")))
            .body("extensionPoints.findAll { it.value.description == null }.collect { it.key }",
                    equalTo(List.of("test-point")))
            .body("providers.'test-point'", empty())
            .body("extensionPoints.'test-point'.singleProvider", equalTo(true))
            .body("extensionPoints.'state-store'.extensionType",
                    equalTo("com.github.thomasdarimont.keycloak.mcp.state.StateStore"))
            .body("extensionPoints.'access-check'.singleProvider", equalTo(false))
            .body("providers", hasKey("access-check"))
            // the database state store is the selected one and says how it keeps its
            // values; the profile sets a key
            .body("providers.'state-store'.find { it.id == 'db' }.status", equalTo("selected"))
            .body("providers.'state-store'.find { it.id == 'db' }.info.encryption", equalTo("on"))
            .body("providers.'state-store'.find { it.id == 'db' }.info", hasKey("key-id"))
            .body("providers.'state-store'.find { it.id == 'db' }.warnings", empty())
            // the one in memory was not selected: it is listed, and not asked
            .body("providers.'state-store'.find { it.id == 'memory-state' }.info", not(hasKey("entries")))
            .body("warnings.findAll { it.spi == 'state-store' }", empty());
    }

    @Test
    void onlyExtensionsThatTakePartAreAskedAndAFailingOneIsAWarning() {
        Extension talkative = new Reporting(
                info -> info.put("table", "acme").put("skipped", null).warn("Look at this."));
        ServerInfo said = AdminServerInfo.contribution(talkative, status("active"));
        assertEquals(Map.of("table", "acme"), said.values());
        assertEquals(List.of("Look at this."), said.warnings());

        for (String out : List.of("disabled", "not supported", "not selected", "available")) {
            ServerInfo silent = AdminServerInfo.contribution(talkative, status(out));
            assertTrue(silent.values().isEmpty() && silent.warnings().isEmpty(), out);
        }

        ServerInfo failed = AdminServerInfo.contribution(new Reporting(info -> {
            info.put("half", "done");
            throw new IllegalStateException("database away");
        }), status("selected"));
        assertTrue(failed.values().isEmpty(), "nothing half reported");
        assertEquals(List.of("This extension could not report on itself: database away"), failed.warnings());

        Extension plain = new Extension() {
        };
        assertTrue(AdminServerInfo.contribution(plain, status("active")).values().isEmpty());
    }

    private static Extensions.ProviderStatus status(String status) {
        return new Extensions.ProviderStatus("tools", "acme", status, "built-in", "Acme");
    }

    private record Reporting(
            java.util.function.Consumer<ServerInfo> report) implements Extension, ServerInfoContributor {

        @Override
        public void contributeServerInfo(ServerInfo info) {
            report.accept(info);
        }
    }
}
