package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.util.Map;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import com.github.thomasdarimont.keycloak.mcp.backend.McpClient;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.specification.RequestSpecification;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Registering a system through the admin API: stored in the database, its key created in
 * the vault, its JWKS served, its entries reachable, and gone again on DELETE.
 */
@QuarkusTest
@TestProfile(AdminProfile.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AdminResourceTest {

    static RequestSpecification admin() {
        return given().header("Authorization", "Bearer " + AdminProfile.TOKEN).contentType("application/json");
    }

    @Test
    @Order(1)
    void theAdminApiNeedsTheToken() {
        given().get("/admin/systems").then().statusCode(401).header("WWW-Authenticate", containsString("Bearer"));
        given().header("Authorization", "Bearer nope").get("/admin/systems").then().statusCode(401);
        admin().get("/admin/systems").then().statusCode(200).body("systems.alias", hasItem("default"));
    }

    @Test
    @Order(2)
    void registersASystemWithAGeneratedKeyAndServesItsJwks() {
        JsonObject body = new JsonObject().put("displayName", "ACME Corp.")
            .put("description", "ACME's production Keycloak, owned by the platform team")
            .put("url", "http://127.0.0.1:1")
            .put("issuer", "https://sso.example.com/realms/master")
            .put("defaultRealm", "acme-dev")
            .put("allowedRealms", new JsonArray().add("acme-dev").add("acme-prod"))
            .put("version", "26.8.2");
        String response = admin().body(body.encode())
            .put("/admin/systems/acme")
            .then()
            .statusCode(201)
            .body("alias", equalTo("acme"))
            .body("displayName", equalTo("ACME Corp."))
            .body("description", equalTo("ACME's production Keycloak, owned by the platform team"))
            .body("createdAt", startsWith("20"))
            .body("updatedAt", startsWith("20"))
            .body("clientAuth", equalTo("private_key_jwt"))
            .body("clientId", equalTo("keycloak-mcp-server"))
            .body("source", equalTo("db"))
            .body("signingKey.vault", equalTo("db"))
            .body("signingKey.algorithm", equalTo("RS256"))
            .body("signingKey.jwksPath", equalTo("/auth/keys/acme/jwks.json"))
            .body("signingKey.jwksUrl", startsWith("http://localhost:"))
            .body("signingKey.jwksUrl", containsString("/auth/keys/acme/jwks.json"))
            .body("entries", hasItem("/mcp/systems/acme"))
            .body("entries", hasItem("/mcp/systems/acme/acme-dev"))
            .body("entries", hasItem("/mcp/systems/acme/acme-prod"))
            .body("$", not(hasKey("clientSecret")))
            .extract()
            .asString();
        String kid = new JsonObject(response).getJsonObject("signingKey").getString("kid");
        assertTrue(kid != null && kid.length() > 10, response);

        // the JWKS Keycloak fetches carries that key
        given().get("/auth/keys/acme/jwks.json")
            .then()
            .statusCode(200)
            .body("keys[0].kid", equalTo(kid))
            .body("keys[0].kty", equalTo("RSA"));

        // the system is live: its entry answers
        JsonObject who = McpClient
            .text(new McpClient().path("/mcp/systems/acme").initialize(false).callTool("whoami", new JsonObject()));
        assertEquals("acme", who.getString("system"), who.encode());

        // and visible in the listing and alone
        admin().get("/admin/systems").then().statusCode(200).body("systems.alias", hasItem("acme"));
        admin().get("/admin/systems/acme").then().statusCode(200).body("defaultRealm", equalTo("acme-dev"));

        // a second registration with generate is refused, a plain replace keeps the key
        admin().body(body.copy().put("signingKey", "generate").encode())
            .put("/admin/systems/acme")
            .then()
            .statusCode(409)
            .body("error", equalTo("signing_key_exists"));
        String createdAt = new JsonObject(response).getString("createdAt");
        admin().body(body.copy().put("displayName", "ACME Inc.").encode())
            .put("/admin/systems/acme")
            .then()
            .statusCode(200)
            .body("displayName", equalTo("ACME Inc."))
            .body("description", equalTo("ACME's production Keycloak, owned by the platform team"))
            .body("createdAt", equalTo(createdAt))
            .body("signingKey.kid", equalTo(kid));
        // the static system has no record to date
        admin().get("/admin/systems/default").then().statusCode(200).body("$", not(hasKey("createdAt")));

        // rotation: new kid, new JWKS
        String rotated = admin().post("/admin/systems/acme/signing-key")
            .then()
            .statusCode(200)
            .extract()
            .path("signingKey.kid");
        assertNotEquals(kid, rotated);
        // the new key first; the retired one stays published for the vault's grace
        // period, for
        // other instances that still sign with it
        given().get("/auth/keys/acme/jwks.json")
            .then()
            .statusCode(200)
            .body("keys[0].kid", equalTo(rotated))
            .body("keys.kid", hasItem(kid))
            .body("keys.size()", equalTo(2));
    }

    @Test
    @Order(3)
    void refusesWhatItCannotRegister() {
        admin().body("{\"displayName\": \"no url\"}")
            .put("/admin/systems/broken")
            .then()
            .statusCode(400)
            .body("error", equalTo("invalid_system"));
        admin().body("not json").put("/admin/systems/broken").then().statusCode(400);
        admin().body("{\"url\": \"http://127.0.0.1:1\"}")
            .put("/admin/systems/bad alias")
            .then()
            .statusCode(400)
            .body("error", equalTo("invalid_alias"));
        admin()
            .body("{\"url\": \"http://127.0.0.1:1\", \"grantType\": \"password\", \"clientAuth\": \"none\","
                    + " \"username\": \"admin\", \"password\": \"admin\"}")
            .put("/admin/systems/by-password")
            .then()
            .statusCode(400)
            .body("error", equalTo("grant_not_supported"));
        admin().body("{\"url\": \"http://kc.evil.test\"}")
            .put("/admin/systems/evil")
            .then()
            .statusCode(400)
            .body("error", equalTo("host_not_allowed"));
        admin().body("{\"url\": \"http://127.0.0.1:1\", \"signingKey\": \"existing\"}")
            .put("/admin/systems/no-key")
            .then()
            .statusCode(400)
            .body("error", equalTo("no_signing_key"));
        admin()
            .body("{\"url\": \"http://127.0.0.1:1\", \"clientAuth\": \"client_secret\","
                    + " \"clientSecret\": \"vault:acme/client-secret\"}")
            .put("/admin/systems/by-secret")
            .then()
            .statusCode(400)
            .body("error", equalTo("unknown_secret"));
        // the static configuration is not the admin API's to change
        admin().body("{\"url\": \"http://127.0.0.1:1\"}")
            .put("/admin/systems/default")
            .then()
            .statusCode(409)
            .body("error", equalTo("system_configured"));
        admin().delete("/admin/systems/default").then().statusCode(409);
        admin().delete("/admin/systems/nope").then().statusCode(404);
        admin().post("/admin/systems/nope/signing-key").then().statusCode(404);
    }

    @Test
    @Order(4)
    void deleteRemovesTheSystem() {
        admin().delete("/admin/systems/acme").then().statusCode(204);
        admin().get("/admin/systems/acme").then().statusCode(404);
        given().get("/auth/keys/acme/jwks.json").then().statusCode(404);
        admin().get("/admin/systems").then().statusCode(200).body("systems.alias", not(hasItem("acme")));
    }

    @Test
    @Order(5)
    void secretsAreStoredByNameAndNeverReadBack() {
        admin().get("/admin/secrets")
            .then()
            .statusCode(200)
            .body("vault", equalTo("db"))
            .body("writable", equalTo(true))
            .body("secrets.name", not(hasItem("acme/client-secret")));
        admin().get("/admin/secrets/acme/client-secret")
            .then()
            .statusCode(404)
            .body("error", equalTo("unknown_secret"));
        admin().delete("/admin/secrets/acme/client-secret").then().statusCode(404);

        admin().body("{\"value\": \"\"}")
            .put("/admin/secrets/acme/client-secret")
            .then()
            .statusCode(400)
            .body("error", equalTo("invalid_secret"));
        admin().body("{\"value\": \"x\"}")
            .put("/admin/secrets/acme/a..b")
            .then()
            .statusCode(400)
            .body("error", equalTo("invalid_secret_name"));

        admin().body("{\"value\": \"top-secret\"}")
            .put("/admin/secrets/acme/client-secret")
            .then()
            .statusCode(201)
            .body("name", equalTo("acme/client-secret"))
            .body("reference", equalTo("vault:acme/client-secret"))
            .body("vault", equalTo("db"))
            .body("usedBy", empty())
            .body("$", not(hasKey("value")));
        admin().body("{\"value\": \"top-secret-2\"}").put("/admin/secrets/acme/client-secret").then().statusCode(200);
        admin().get("/admin/secrets/acme/client-secret").then().statusCode(200).body("$", not(hasKey("value")));
        admin().get("/admin/secrets").then().statusCode(200).body("secrets.name", hasItem("acme/client-secret"));

        // a system may now refer to it; the representation shows the reference, not the
        // value
        admin()
            .body("{\"url\": \"http://127.0.0.1:1\", \"clientAuth\": \"client_secret\","
                    + " \"clientSecret\": \"vault:acme/client-secret\"}")
            .put("/admin/systems/by-secret")
            .then()
            .statusCode(201)
            .body("clientAuth", equalTo("client_secret"))
            .body("clientSecret", equalTo("vault:acme/client-secret"))
            .body("writable", equalTo(true));
        admin().get("/admin/secrets/acme/client-secret").then().statusCode(200).body("usedBy", hasItem("by-secret"));

        // UI / replace: omit or mask the secret so the stored vault reference stays
        admin()
            .body("{\"url\": \"http://127.0.0.1:1\", \"clientAuth\": \"client_secret\","
                    + " \"displayName\": \"by vault\"}")
            .put("/admin/systems/by-secret")
            .then()
            .statusCode(200)
            .body("displayName", equalTo("by vault"))
            .body("clientSecret", equalTo("vault:acme/client-secret"));
        admin()
            .body("{\"url\": \"http://127.0.0.1:1\", \"clientAuth\": \"client_secret\","
                    + " \"clientSecret\": \"***\"}")
            .put("/admin/systems/by-secret")
            .then()
            .statusCode(200)
            .body("clientSecret", equalTo("vault:acme/client-secret"));

        // which protects the secret from removal until the system is gone
        admin().delete("/admin/secrets/acme/client-secret")
            .then()
            .statusCode(409)
            .body("error", equalTo("secret_in_use"))
            .body("message", containsString("by-secret"));
        admin().delete("/admin/systems/by-secret").then().statusCode(204);
        admin().delete("/admin/secrets/acme/client-secret").then().statusCode(204);
        admin().get("/admin/secrets/acme/client-secret").then().statusCode(404);
    }

    @Test
    @Order(6)
    void theStorageReportsItsKeysAndReencryptsOnDemand() {
        String kid = admin().get("/admin/storage")
            .then()
            .statusCode(200)
            .body("encryption", equalTo(true))
            .body("previousKeys", equalTo(false))
            .body("keyIds", hasKey("kc_mcp_signing_key"))
            .extract()
            .path("currentKeyId");
        assertTrue(kid != null && kid.length() == 8, kid);
        admin().post("/admin/storage/rekey")
            .then()
            .statusCode(200)
            .body("currentKeyId", equalTo(kid))
            .body("rewritten.signingKeys", equalTo(0))
            .body("remaining", equalTo(Map.of()));
    }

    @Test
    @Order(7)
    void systemsBringTheirOwnAuthorizationPolicy() {
        admin().body("{\"value\": \"pdp-api-key\"}").put("/admin/secrets/gov/pdp-key").then().statusCode(201);
        String body = """
                {"url": "http://127.0.0.1:1", "access": {"authorization": {"enabled": true,
                 "authzen": {"url": "https://sso.example.com/pdp/access/v1/evaluation", "auth": "header",
                             "headerValue": "vault:gov/pdp-key"}}}}""";
        admin().body(body)
            .put("/admin/systems/governed")
            .then()
            .statusCode(201)
            .body("access.authorization.enabled", equalTo(true))
            .body("access.authorization.authzen.url", equalTo("https://sso.example.com/pdp/access/v1/evaluation"))
            .body("access.authorization.authzen.headerValue", equalTo("vault:gov/pdp-key"));
        admin().get("/admin/secrets/gov/pdp-key").then().statusCode(200).body("usedBy", hasItem("governed"));

        // a plain secret is stored, never shown
        admin().body(body.replace("vault:gov/pdp-key", "plain-key"))
            .put("/admin/systems/governed")
            .then()
            .statusCode(200)
            .body("access.authorization.authzen.headerValue", equalTo("***"));

        // what a registered system may not ask for
        admin().body(body.replace("https://sso.example.com/pdp", "https://pdp.evil.test"))
            .put("/admin/systems/governed")
            .then()
            .statusCode(400)
            .body("error", equalTo("host_not_allowed"));
        admin().body(body.replace("vault:gov/pdp-key", "vault:gov/missing"))
            .put("/admin/systems/governed")
            .then()
            .statusCode(400)
            .body("error", equalTo("unknown_secret"));
        admin().body("""
                {"url": "http://127.0.0.1:1", "access": {"authorization": {"authzen": {
                 "url": "https://sso.example.com/pdp", "auth": "client-credentials",
                 "tokenUrl": "https://sso.example.com/token", "clientId": "c", "clientAuth": "private_key_jwt",
                 "jwtKeyFile": "/etc/passwd"}}}}""")
            .put("/admin/systems/governed")
            .then()
            .statusCode(400)
            .body("error", equalTo("local_file_setting"));
        admin().body("""
                {"url": "http://127.0.0.1:1", "access": {"authorization": {"authzen": {
                 "url": "https://sso.example.com/pdp", "auth": "header"}}}}""")
            .put("/admin/systems/governed")
            .then()
            .statusCode(400)
            .body("error", equalTo("invalid_authorization"))
            .body("message", containsString("header-value"));
        admin().body("""
                {"url": "http://127.0.0.1:1", "access": {"authorization": {"enabled": true, "acme-opa": {}}}}""")
            .put("/admin/systems/governed")
            .then()
            .statusCode(400)
            .body("error", equalTo("unknown_authorization_engine"));
        admin().body("""
                {"url": "http://127.0.0.1:1", "access": {"no-such-check": {"order": 1}}}""")
            .put("/admin/systems/governed")
            .then()
            .statusCode(400)
            .body("error", equalTo("unknown_access_check"));
        admin().body("""
                {"url": "http://127.0.0.1:1", "realms": {"acme": {"displayName": "ACME"}}}""")
            .put("/admin/systems/governed")
            .then()
            .statusCode(400)
            .body("error", equalTo("realms_separately"));
    }

    @Test
    @Order(8)
    void realmsHaveSettingsOfTheirOwn() {
        String realm = """
                {"realmId": "4f2c", "displayName": "Sandbox", "description": "Where support tries things",
                 "access": {"authorization": {"enabled": false}, "group-scope": {"order": 1}}}""";
        admin().body(realm)
            .put("/admin/systems/governed/realms/sandbox")
            .then()
            .statusCode(201)
            .body("name", equalTo("sandbox"))
            .body("system", equalTo("governed"))
            .body("realmId", equalTo("4f2c"))
            .body("displayName", equalTo("Sandbox"))
            .body("access.authorization.enabled", equalTo(false))
            .body("entry", equalTo("/mcp/systems/governed/sandbox"));
        admin().body(realm).put("/admin/systems/governed/realms/sandbox").then().statusCode(200);
        admin().get("/admin/systems/governed/realms").then().statusCode(200).body("realms.name", hasItem("sandbox"));
        admin().get("/admin/systems/governed")
            .then()
            .statusCode(200)
            .body("realms.sandbox.displayName", equalTo("Sandbox"));

        // replacing the system keeps its realms
        admin().body("""
                {"url": "http://127.0.0.1:1", "description": "replaced"}""")
            .put("/admin/systems/governed")
            .then()
            .statusCode(200)
            .body("realms.sandbox.realmId", equalTo("4f2c"));

        // a realm is held to the same rules as its system
        admin().body("""
                {"access": {"authorization": {"authzen": {"url": "https://pdp.evil.test/e"}}}}""")
            .put("/admin/systems/governed/realms/acme")
            .then()
            .statusCode(400)
            .body("error", equalTo("host_not_allowed"));
        admin().body("""
                {"access": {"authorization": {"vendor": {}}}}""")
            .put("/admin/systems/governed/realms/acme")
            .then()
            .statusCode(400)
            .body("error", equalTo("unknown_authorization_engine"));
        admin().body("{\"color\": \"red\"}")
            .put("/admin/systems/governed/realms/acme")
            .then()
            .statusCode(400)
            .body("error", equalTo("invalid_realm"));
        admin().body("{}").put("/admin/systems/governed/realms/acme").then().statusCode(400);
        admin().get("/admin/systems/governed/realms/acme")
            .then()
            .statusCode(404)
            .body("error", equalTo("unknown_realm"));
        admin().body(realm).put("/admin/systems/default/realms/acme").then().statusCode(409);

        admin().delete("/admin/systems/governed/realms/sandbox").then().statusCode(204);
        admin().delete("/admin/systems/governed/realms/sandbox").then().statusCode(404);
        admin().body(realm).put("/admin/systems/governed/realms/sandbox").then().statusCode(201);
        admin().delete("/admin/systems/governed").then().statusCode(204);
        admin().get("/admin/systems/governed/realms/sandbox").then().statusCode(404);
        admin().delete("/admin/secrets/gov/pdp-key").then().statusCode(204);
    }

    @Test
    @Order(9)
    void systemsBringPresetsAndRealmsReferenceThem() {
        admin().body("""
                {"url": "http://127.0.0.1:1", "preset": "tenant",
                 "presets": {
                   "tenant": {"access": {"self-protection": {"order": 3}}},
                   "lab": {"extends": "tenant", "access": {"group-scope": {"enabled": false}}}}}""")
            .put("/admin/systems/with-presets")
            .then()
            .statusCode(201)
            .body("preset", equalTo("tenant"))
            .body("presets.lab.extends", equalTo("tenant"));
        admin().body("{\"preset\": \"lab\", \"displayName\": \"Lab\"}")
            .put("/admin/systems/with-presets/realms/lab1")
            .then()
            .statusCode(201)
            .body("preset", equalTo("lab"));

        admin().body("{\"preset\": \"nope\"}")
            .put("/admin/systems/with-presets/realms/lab2")
            .then()
            .statusCode(400)
            .body("error", equalTo("unknown_preset"));
        admin().body("""
                {"url": "http://127.0.0.1:1", "presets": {
                   "a": {"extends": "b"}, "b": {"extends": "a"}}}""")
            .put("/admin/systems/with-presets")
            .then()
            .statusCode(400)
            .body("error", equalTo("preset_cycle"))
            .body("message", containsString("a -> b -> a"));
        admin().body("""
                {"url": "http://127.0.0.1:1", "presets": {"tenant": {}, "lab": {"extends": "tenant"}},
                 "access": {"authorization": {"authzen": {"url": "https://{realm.name}.example.com/e"}}}}""")
            .put("/admin/systems/with-presets")
            .then()
            .statusCode(400)
            .body("error", equalTo("placeholder_in_host"));
        // a realm still uses "lab": replacing the system without it is refused
        admin().body("""
                {"url": "http://127.0.0.1:1", "preset": "tenant",
                 "presets": {"tenant": {"access": {"authorization": {"authzen": {
                   "url": "https://sso.example.com/pdp/{realm.name}/access/v1/evaluation"}}}}}}""")
            .put("/admin/systems/with-presets")
            .then()
            .statusCode(400)
            .body("error", equalTo("unknown_preset"))
            .body("message", containsString("lab"));

        admin().delete("/admin/systems/with-presets").then().statusCode(204);
    }

    @Test
    @Order(10)
    void systemsRealmsAndPresetsRestrictTools() {
        admin().body("""
                {"url": "http://127.0.0.1:1", "tools": {"denied": ["user_delete"]},
                 "presets": {"viewer": {"tools": {"readOnly": true, "categories": ["users", "groups"]}}}}""")
            .put("/admin/systems/restricted")
            .then()
            .statusCode(201)
            .body("tools.denied", hasItem("user_delete"))
            .body("presets.viewer.tools.readOnly", equalTo(true));
        admin().body("{\"preset\": \"viewer\", \"tools\": {\"allowed\": [\"keycloak_user_get\"]}}")
            .put("/admin/systems/restricted/realms/support")
            .then()
            .statusCode(201)
            .body("tools.allowed", hasItem("keycloak_user_get"));

        admin().body("{\"url\": \"http://127.0.0.1:1\", \"tools\": {\"denied\": [\"user_delte\"]}}")
            .put("/admin/systems/restricted")
            .then()
            .statusCode(400)
            .body("error", equalTo("unknown_tool"));
        admin().body("{\"tools\": {\"categories\": [\"wizards\"]}}")
            .put("/admin/systems/restricted/realms/support")
            .then()
            .statusCode(400)
            .body("error", equalTo("unknown_category"));
        admin().body("""
                {"url": "http://127.0.0.1:1", "presets": {"viewer": {"tools": {"hidden": true}}}}""")
            .put("/admin/systems/restricted")
            .then()
            .statusCode(400)
            .body("error", equalTo("invalid_system"));

        admin().delete("/admin/systems/restricted").then().statusCode(204);
    }
}
