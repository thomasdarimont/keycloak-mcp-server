package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.specification.RequestSpecification;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * The extensions and their settings through the admin API: the spec with its texts, the
 * values with the confidential ones masked, the problems.
 */
@QuarkusTest
@TestProfile(AdminExtensionsTest.Profile.class)
class AdminExtensionsTest {

    static final String SECRET = "s3cr3t-pseudonym-key";

    /**
     * The admin profile with the PII scrubber configured, a secret and a typo among its
     * settings.
     */
    public static class Profile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            Map<String, String> m = new HashMap<>(new AdminProfile().getConfigOverrides());
            m.put("kc-mcp.spi.audit-scrubber.pii.mode", "pseudonymize");
            m.put("kc-mcp.spi.audit-scrubber.pii.pseudonym-key", SECRET);
            m.put("kc-mcp.spi.audit-scrubber.pii.mdoe", "drop");
            return m;
        }
    }

    static RequestSpecification admin() {
        return given().header("Authorization", "Bearer " + AdminProfile.TOKEN);
    }

    @Test
    void theListNeedsTheTokenAndNamesEveryExtension() {
        given().get("/admin/extensions").then().statusCode(401);
        admin().get("/admin/extensions")
            .then()
            .statusCode(200)
            .body("extensions.find { it.spi == 'audit-scrubber' && it.id == 'pii' }.configurable", equalTo(true))
            .body("extensions.find { it.spi == 'audit-scrubber' && it.id == 'pii' }.warnings", equalTo(1))
            .body("extensions.find { it.spi == 'audit-scrubber' && it.id == 'pii' }.errors", equalTo(0))
            .body("extensions.find { it.id == 'self-protection' }.spi", equalTo("access-check"))
            .body("extensions.spi", hasItem("authorization-engine"));
    }

    @Test
    void anExtensionsSettingsComeWithTextsAndMaskedSecrets() {
        String body = admin().get("/admin/extensions/audit-scrubber/pii")
            .then()
            .statusCode(200)
            .body("keyPrefix", equalTo("kc-mcp.spi.audit-scrubber.pii."))
            .body("helpText",
                    org.hamcrest.Matchers.startsWith("Use it when stored audit records must not hold personal data"))
            .body("helpTextKey", equalTo("audit-scrubber.pii.help-text"))
            .body("properties.find { it.name == 'mode' }.label", equalTo("Mode"))
            .body("properties.find { it.name == 'mode' }.labelKey", equalTo("audit-scrubber.pii.mode.label"))
            .body("properties.find { it.name == 'mode' }.value", equalTo("pseudonymize"))
            .body("properties.find { it.name == 'mode' }.options.value", hasItem("drop"))
            .body("properties.find { it.name == 'pseudonym-key' }.value", equalTo("******"))
            .body("properties.find { it.name == 'pseudonym-key' }.confidential", equalTo(true))
            .body("properties.find { it.name == 'pseudonym-key' }.appliesWhen[0].on", equalTo("mode"))
            .body("properties.find { it.name == 'pseudonym-key' }.env",
                    equalTo("KC_MCP_SPI_AUDIT_SCRUBBER_PII_PSEUDONYM_KEY"))
            .body("properties.find { it.name == 'args' }.set", equalTo(false))
            .body("properties.find { it.name == 'args' }.value", nullValue())
            .body("undeclared.mdoe", equalTo("******"))
            .body("problems[0].code", equalTo("config.unknown-key"))
            .body("problems[0].severity", equalTo("WARNING"))
            .body("problems[0].message", equalTo(
                    "kc-mcp.spi.audit-scrubber.pii.mdoe is not a setting of this extension and is ignored; it reads"
                            + " mode,args,targets,pseudonym-key"))
            .extract()
            .asString();
        assertFalse(body.contains(SECRET), "the secret never leaves the server");
    }

    @Test
    void nameAndDescriptionOfAnExtensionAreTranslatedWhereABundleHasThem() {
        String english = admin().get("/admin/extensions/audit-scrubber/pii").then().extract().path("displayName");
        String description = admin().get("/admin/extensions/audit-scrubber/pii").then().extract().path("description");
        assertFalse(english.isBlank());
        admin().header("Accept-Language", "de-CH, de;q=0.8")
            .get("/admin/extensions/audit-scrubber/pii")
            .then()
            .statusCode(200)
            .body("displayName", equalTo("Bereinigung personenbezogener Daten"))
            .body("displayNameKey", equalTo("audit-scrubber.pii.display-name"))
            // no German description in any bundle: the extension's own text
            .body("description", equalTo(description))
            .body("descriptionKey", equalTo("audit-scrubber.pii.description"));
        admin().header("Accept-Language", "de")
            .get("/admin/extensions")
            .then()
            .statusCode(200)
            .body("extensions.find { it.spi == 'audit-scrubber' && it.id == 'pii' }.displayName",
                    equalTo("Bereinigung personenbezogener Daten"));
        assertFalse(english.startsWith("Bereinigung"), "English without the header");
    }

    @Test
    void groupsAndSharedTextsOfAnExtensionThatCombinesSpecs() {
        admin().header("Accept-Language", "de-CH, de;q=0.8")
            .get("/admin/extensions/authorization-engine/authzen")
            .then()
            .statusCode(200)
            .body("groups.id", hasItem("authentication"))
            .body("groups.find { it.id == 'authentication' }.label", equalTo("Authentication at the PDP"))
            .body("groups.find { it.id == 'assertion-key' }.label", equalTo("Client assertion key"))
            .body("properties.find { it.name == 'client-secret' }.label", equalTo("Client secret"))
            .body("properties.find { it.name == 'header-value' }.appliesWhen[0].values", hasItem("header"))
            .body("server.enabled", equalTo("true"));
    }

    @Test
    void anUnknownExtensionIsNotFound() {
        admin().get("/admin/extensions/confirmer/nope")
            .then()
            .statusCode(404)
            .body("error", equalTo("unknown_extension"))
            .body("message", not(nullValue()));
    }
}
