package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfigBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RemovedSettingsTest {

    static List<String> problems(Map<String, String> properties) {
        return RemovedSettings.problems(
                new SmallRyeConfigBuilder().withSources(new PropertiesConfigSource(properties, "test", 300)).build());
    }

    @Test
    void theNewNamesAreNoProblem() {
        assertTrue(problems(Map.of("kc-mcp.ui.oidc.issuer", "https://sso/realms/a", "kc-mcp.admin.oauth.role",
                "realm:admin", "kc-mcp.ui.oidc.idps.corp.issuer", "https://corp", "kc-mcp.ui.viewer-role", "realm:v",
                "kc-mcp.admin.token", "t"))
            .isEmpty());
    }

    @Test
    void anOldNameIsToldItsNewOne() {
        assertEquals(List.of("kc-mcp.admin.audience (env KC_MCP_ADMIN_AUDIENCE) is now kc-mcp.admin.oauth.audience (env"
                + " KC_MCP_ADMIN_OAUTH_AUDIENCE)"), problems(Map.of("kc-mcp.admin.audience", "mcp-admin")));
        assertEquals(1, problems(Map.of("kc-mcp.ui.issuer", "https://sso/realms/a")).size());
    }

    @Test
    void namedProvidersCountByTheirPrefixAlsoFromTheEnvironment() {
        assertEquals(List.of("kc-mcp.ui.idps.* (env KC_MCP_UI_IDPS_*) is now kc-mcp.ui.oidc.idps.* (env"
                + " KC_MCP_UI_OIDC_IDPS_*)"), problems(Map.of("kc-mcp.ui.idps.corp.issuer", "https://corp")));
        assertEquals(1, problems(Map.of("KC_MCP_UI_IDPS_CORP_ISSUER", "https://corp")).size());
    }
}
