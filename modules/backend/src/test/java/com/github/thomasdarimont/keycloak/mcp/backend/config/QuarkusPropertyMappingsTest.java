package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The server's names for the settings of the MCP endpoint's authorization server. */
class QuarkusPropertyMappingsTest {

    static SmallRyeConfig config(Map<String, String> properties) {
        return new SmallRyeConfigBuilder().addDefaultInterceptors()
            .withInterceptorFactories(new QuarkusPropertyMappings(), new DefaultTenantInterceptorFactory())
            .withSources(new PropertiesConfigSource(properties, "test", 300))
            .build();
    }

    @Test
    void theQuarkusPropertyAnswersWithTheServersSetting() {
        SmallRyeConfig c = config(Map.of("kc-mcp.mcp.oauth.enabled", "true", "kc-mcp.mcp.oauth.issuer",
                "http://kc/realms/a", "kc-mcp.mcp.oauth.token-issuer", "https://sso/realms/a",
                "kc-mcp.mcp.oauth.audience", "mcp", "kc-mcp.mcp.oauth.resource-metadata.scopes", "openid,x"));
        assertEquals("true", c.getRawValue("quarkus.oidc.tenant-enabled"));
        assertEquals("http://kc/realms/a", c.getRawValue("quarkus.oidc.auth-server-url"));
        assertEquals("https://sso/realms/a", c.getRawValue("quarkus.oidc.token.issuer"));
        assertEquals("mcp", c.getRawValue("quarkus.oidc.token.audience"));
        assertEquals("openid,x", c.getRawValue("quarkus.oidc.resource-metadata.scopes"));
    }

    @Test
    void theServersSettingWinsOverTheQuarkusProperty() {
        SmallRyeConfig c = config(Map.of("kc-mcp.mcp.oauth.audience", "mcp", "quarkus.oidc.token.audience", "other"));
        assertEquals("mcp", c.getRawValue("quarkus.oidc.token.audience"));
    }

    @Test
    void theQuarkusPropertyAloneKeepsWorking() {
        SmallRyeConfig c = config(Map.of("quarkus.oidc.token.audience", "other", "kc-mcp.mcp.oauth.enabled", " "));
        assertEquals("other", c.getRawValue("quarkus.oidc.token.audience"));
        assertNull(c.getRawValue("quarkus.oidc.tenant-enabled"));
    }

    @Test
    void anExpressionSeesTheMappedValue() {
        SmallRyeConfig c = config(Map.of("kc-mcp.mcp.oauth.enabled", "true", "quarkus.oidc.tenant-enabled", "false",
                "quarkus.oidc.resource-metadata.enabled", "${quarkus.oidc.tenant-enabled}"));
        assertEquals("true", c.getRawValue("quarkus.oidc.resource-metadata.enabled"));
    }

    @Test
    void theIssuerIsStillDerivedFromTheDefaultSystemWhenNeitherIsSet() {
        assertEquals("http://a/realms/master",
                config(Map.of("kc-mcp.systems.acme.url", "http://a")).getRawValue("quarkus.oidc.auth-server-url"));
        assertEquals("http://b/realms/x",
                config(Map.of("kc-mcp.systems.acme.url", "http://a", "kc-mcp.mcp.oauth.issuer", "http://b/realms/x"))
                    .getRawValue("quarkus.oidc.auth-server-url"));
    }

    @Test
    void aMappedQuarkusPropertyIsAmongTheNamesOnlyWhenTheSettingIsThere() {
        List<String> names = new ArrayList<>();
        config(Map.of("kc-mcp.mcp.oauth.audience", "mcp")).getPropertyNames().forEach(names::add);
        assertTrue(names.contains("quarkus.oidc.token.audience"));
        assertFalse(names.contains("quarkus.oidc.token.issuer"));
    }
}
