package com.github.thomasdarimont.keycloak.mcp.backend;

import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;
import io.restassured.specification.RequestSpecification;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Adopting the realms of a Keycloak: a system is registered with a generated
 * {@code private_key_jwt} key, its client is created in Keycloak from the client setup
 * (the public key copied in, so Keycloak needs no way back to the test server), the
 * realms its service account sees are listed and some adopted. The {@code kcadm.sh}
 * script of the client setup runs in the Keycloak container for a second system that may
 * only read two realms.
 */
@QuarkusTest
@QuarkusTestResource(value = AdoptionTestResource.class, restrictToAnnotatedClass = true)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AdoptionIT {

    static final String ADMIN_SYSTEM = "adopt-admin";
    static final String READER_SYSTEM = "adopt-reader";
    static final List<String> REALMS = List.of("adopt-a", "adopt-b", "adopt-c");

    static RequestSpecification admin() {
        return given().header("Authorization", "Bearer " + AdoptionTestResource.TOKEN).contentType("application/json");
    }

    @BeforeAll
    static void realms() {
        for (String realm : REALMS) {
            if (AdoptionTestResource.keycloak("GET", "/admin/realms/" + realm, null).statusCode() == 404) {
                HttpResponse<String> r = AdoptionTestResource.keycloak("POST", "/admin/realms",
                        new JsonObject().put("realm", realm)
                            .put("enabled", true)
                            .put("displayName", "Realm " + realm.substring(realm.length() - 1).toUpperCase())
                            .encode());
                assertEquals(201, r.statusCode(), r.body());
            }
        }
    }

    static void register(String alias, String clientId) {
        admin()
            .body(new JsonObject().put("url", SharedKeycloak.base())
                .put("authRealm", "master")
                .put("clientAuth", "private_key_jwt")
                .put("clientId", clientId)
                .encode())
            .put("/admin/systems/" + alias)
            .then()
            .statusCode(201);
    }

    static String keycloakId(String path) {
        return field(path, "id");
    }

    /**
     * The service account user of a client in master. Keycloak after 26.8 names it on the
     * client and drops the service-account-user endpoint.
     */
    static String serviceAccountUserId(String clientUuid) {
        String id = field("/admin/realms/master/clients/" + clientUuid, "serviceAccountUserId");
        return id != null ? id : keycloakId("/admin/realms/master/clients/" + clientUuid + "/service-account-user");
    }

    /**
     * A field of the JSON object Keycloak returns for the path; {@code null} when absent.
     */
    private static String field(String path, String name) {
        return new JsonObject(AdoptionTestResource.keycloak("GET", path, null).body()).getString(name);
    }

    static String clientUuid(String clientId) {
        return new JsonArray(
                AdoptionTestResource.keycloak("GET", "/admin/realms/master/clients?clientId=" + clientId, null).body())
            .getJsonObject(0)
            .getString("id");
    }

    @Test
    @Order(1)
    void withoutTheClientInKeycloakTheTokenRequestIsRefused() {
        register(ADMIN_SYSTEM, "kc-mcp-adopt-admin");
        admin().get("/admin/systems/" + ADMIN_SYSTEM + "/keycloak-realms")
            .then()
            .statusCode(502)
            .body("error", equalTo("token_refused"))
            .body("message", containsString("kc-mcp-adopt-admin"));
    }

    @Test
    @Order(2)
    void theClientSetupCreatesAWorkingClient() {
        JsonPath setup = admin().queryParam("credential", "public-key")
            .get("/admin/systems/" + ADMIN_SYSTEM + "/client-setup")
            .then()
            .statusCode(200)
            .body("client.clientAuthenticatorType", equalTo("client-jwt"))
            .body("client.attributes.'use.jwks.url'", equalTo("false"))
            .body("client.defaultClientScopes", hasItems("kc-admin-api", "service_account"))
            .body("roles.realmRoles", equalTo(List.of("admin")))
            .extract()
            .jsonPath();
        Map<String, Object> client = setup.getMap("client");
        HttpResponse<String> created = AdoptionTestResource.keycloak("POST", "/admin/realms/master/clients",
                new JsonObject(client).encode());
        assertEquals(201, created.statusCode(), created.body());
        // what the script does for roles=admin: the role, and the role in the client's
        // scope
        String uuid = clientUuid("kc-mcp-adopt-admin");
        String user = serviceAccountUserId(uuid);
        JsonArray role = new JsonArray()
            .add(new JsonObject(AdoptionTestResource.keycloak("GET", "/admin/realms/master/roles/admin", null).body()));
        assertEquals(204,
                AdoptionTestResource
                    .keycloak("POST", "/admin/realms/master/users/" + user + "/role-mappings/realm", role.encode())
                    .statusCode());
        assertEquals(204,
                AdoptionTestResource
                    .keycloak("POST", "/admin/realms/master/clients/" + uuid + "/scope-mappings/realm", role.encode())
                    .statusCode());

        JsonPath listed = admin().get("/admin/systems/" + ADMIN_SYSTEM + "/keycloak-realms")
            .then()
            .statusCode(200)
            .body("restricted", equalTo(false))
            .body("realms.name", hasItems("master", "adopt-a", "adopt-b", "adopt-c"))
            .extract()
            .jsonPath();
        assertEquals("Realm A", listed.getString("realms.find { it.name == 'adopt-a' }.displayName"));
        assertEquals(false, listed.getBoolean("realms.find { it.name == 'adopt-a' }.adopted"));
    }

    @Test
    @Order(3)
    void adoptingASelectionRestrictsOnlyWhenAskedTo() {
        // without an allowlist adopting only stores settings: every realm stays reachable
        admin().body("{\"realms\": [\"adopt-a\"]}")
            .post("/admin/systems/" + ADMIN_SYSTEM + "/adoption")
            .then()
            .statusCode(200)
            .body("adopted", equalTo(List.of("adopt-a")))
            .body("restricted", equalTo(false))
            .body("allowedRealms", equalTo(List.of()))
            .body("unreachable", equalTo(List.of()));
        admin().body("{\"realms\": [\"adopt-b\", \"nope\"], \"restrict\": true}")
            .post("/admin/systems/" + ADMIN_SYSTEM + "/adoption")
            .then()
            .statusCode(400)
            .body("error", equalTo("unknown_keycloak_realm"));

        // restricting keeps the realm adopted before on the allowlist
        admin().body("{\"realms\": [\"adopt-b\"], \"restrict\": true}")
            .post("/admin/systems/" + ADMIN_SYSTEM + "/adoption")
            .then()
            .statusCode(200)
            .body("adopted", equalTo(List.of("adopt-b")))
            .body("allowedRealms", equalTo(List.of("adopt-a", "adopt-b")))
            .body("unreachable", hasItems("adopt-c", "master"));
        admin().get("/admin/systems/" + ADMIN_SYSTEM + "/realms/adopt-a")
            .then()
            .statusCode(200)
            .body("realmId", equalTo(keycloakId("/admin/realms/adopt-a")))
            .body("displayName", equalTo("Realm A"));
        admin().get("/admin/systems/" + ADMIN_SYSTEM + "/keycloak-realms")
            .then()
            .statusCode(200)
            .body("restricted", equalTo(true))
            .body("realms.find { it.name == 'adopt-b' }.adopted", equalTo(true))
            .body("realms.find { it.name == 'adopt-c' }.allowed", equalTo(false));

        // a second adoption adds to the allowlist; the adopted realm stays as it is
        admin().body("{\"realms\": [\"adopt-b\", \"adopt-c\"]}")
            .post("/admin/systems/" + ADMIN_SYSTEM + "/adoption")
            .then()
            .statusCode(200)
            .body("adopted", equalTo(List.of("adopt-c")))
            .body("unchanged", equalTo(List.of("adopt-b")))
            .body("allowedRealms", equalTo(List.of("adopt-a", "adopt-b", "adopt-c")));

        // and the adopted realms are reachable through the MCP entry
        McpClient mcp = new McpClient().path("/mcp/systems/" + ADMIN_SYSTEM + "/adopt-c").initialize(false);
        JsonObject result = mcp.callTool("keycloak_realm_get_config", new JsonObject());
        JsonObject realm = McpClient.text(result);
        assertTrue(!result.getBoolean("isError", false) && realm.encode().contains("\"adopt-c\""), realm.encode());
    }

    @Test
    @Order(4)
    void theScriptGivesReadRolesInTheNamedRealmsOnly() {
        register(READER_SYSTEM, "kc-mcp-adopt-reader");
        String script = admin().queryParam("credential", "public-key")
            .queryParam("roles", "read")
            .queryParam("realms", "adopt-a,adopt-b")
            .get("/admin/systems/" + READER_SYSTEM + "/client-setup")
            .then()
            .statusCode(200)
            .body("roles.clientRoles.'adopt-a-realm'", hasItems("view-realm", "query-users"))
            .body("roles.clientRoles.'adopt-a-realm'", not(hasItems("manage-users")))
            .extract()
            .path("script");
        Map.Entry<Integer, String> run = AdoptionTestResource.kcadm(script);
        assertEquals(0, run.getKey(), run.getValue());

        JsonPath listed = admin().get("/admin/systems/" + READER_SYSTEM + "/keycloak-realms")
            .then()
            .statusCode(200)
            .extract()
            .jsonPath();
        List<String> names = listed.getList("realms.name");
        assertTrue(names.containsAll(List.of("adopt-a", "adopt-b")), names.toString());
        assertTrue(!names.contains("adopt-c"), "the account has no role in adopt-c: " + names);

        admin().body("{\"allRealms\": true}")
            .post("/admin/systems/" + READER_SYSTEM + "/adoption")
            .then()
            .statusCode(200)
            .body("adopted", hasItems("adopt-a", "adopt-b"))
            .body("restricted", equalTo(false));
    }

    @Test
    @Order(5)
    void unadoptingEndsTheAccessAndRemovesTheSettings() {
        admin().delete("/admin/systems/" + ADMIN_SYSTEM + "/adoption/adopt-c")
            .then()
            .statusCode(200)
            .body("settingsRemoved", equalTo(true))
            .body("allowedRealms", equalTo(List.of("adopt-a", "adopt-b")));
        admin().get("/admin/systems/" + ADMIN_SYSTEM + "/realms/adopt-c").then().statusCode(404);
        McpClient mcp = new McpClient().path("/mcp/systems/" + ADMIN_SYSTEM + "/adopt-c").initialize(false);
        JsonObject result = mcp.callTool("keycloak_realm_get_config", new JsonObject());
        assertTrue(result.getBoolean("isError", false), result.encode());

        admin().delete("/admin/systems/" + ADMIN_SYSTEM + "/adoption/adopt-b").then().statusCode(200);
        admin().delete("/admin/systems/" + ADMIN_SYSTEM + "/adoption/adopt-a")
            .then()
            .statusCode(409)
            .body("error", equalTo("last_realm"));

        // the reader reaches every realm: giving one up makes the others its allowlist
        admin().delete("/admin/systems/" + READER_SYSTEM + "/adoption/adopt-a")
            .then()
            .statusCode(409)
            .body("error", equalTo("would_restrict"));
        admin().queryParam("restrict", true)
            .delete("/admin/systems/" + READER_SYSTEM + "/adoption/adopt-a")
            .then()
            .statusCode(200)
            .body("restricted", equalTo(true))
            .body("allowedRealms", equalTo(List.of("adopt-b")));
    }
}
