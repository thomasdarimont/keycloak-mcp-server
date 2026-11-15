package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultTenantInterceptorFactoryTest {

    static String authServerUrl(Map<String, String> properties) {
        SmallRyeConfig c = new SmallRyeConfigBuilder().withInterceptorFactories(new DefaultTenantInterceptorFactory())
            .withSources(new PropertiesConfigSource(properties, "test", 300))
            .build();
        return c.getRawValue(DefaultTenantInterceptorFactory.AUTH_SERVER_URL);
    }

    @Test
    void theOnlySystemIsTheDefaultTenant() {
        assertEquals("http://a/realms/master", authServerUrl(Map.of("kc-mcp.systems.acme.url", "http://a/")));
        assertEquals("http://a/realms/corp", authServerUrl(
                Map.of("kc-mcp.systems.acme.url", "http://a", "kc-mcp.system-defaults.auth-realm", "corp")));
    }

    @Test
    void onlyTheSettingPicksTheDefaultAmongSeveral() {
        Map<String, String> two = Map.of("kc-mcp.systems.default.url", "http://d", "kc-mcp.systems.prod.url",
                "http://p", "kc-mcp.systems.prod.auth-realm", "ops");
        // a system called "default" is a name like any other
        assertNull(authServerUrl(two));
        Map<String, String> named = new java.util.HashMap<>(two);
        named.put("kc-mcp.default-system", "prod");
        assertEquals("http://p/realms/ops", authServerUrl(named));
        named.put("kc-mcp.default-system", "default");
        assertEquals("http://d/realms/master", authServerUrl(named));
    }

    @Test
    void severalStaticSystemsWithoutADefaultAreAStartupProblemWithCallerLogin() {
        List<String> two = List.of("default", "prod");
        assertTrue(DefaultTenant.problem(true, false, two).orElseThrow().contains("kc-mcp.default-system"));
        assertTrue(DefaultTenant.problem(false, false, two).isEmpty());
        assertTrue(DefaultTenant.problem(true, true, two).isEmpty());
        assertTrue(DefaultTenant.problem(true, false, List.of("a")).isEmpty());
        // repositories only: entries carry the tenants
        assertTrue(DefaultTenant.problem(true, false, List.of()).isEmpty());
    }

    @Test
    void severalSystemsWithoutADefaultDeriveNothing() {
        assertNull(authServerUrl(Map.of("kc-mcp.systems.a.url", "http://a", "kc-mcp.systems.b.url", "http://b")));
    }

    @Test
    void repositoryOnlyDeploymentsDeriveNothingFromIgnoredBlocks() {
        assertNull(authServerUrl(Map.of("kc-mcp.systems.default.url", "http://d", "kc-mcp.static-systems", "false")));
    }

    @Test
    void aConfiguredValueIsLeftAlone() {
        assertEquals("http://explicit/realms/x", authServerUrl(Map.of("kc-mcp.systems.default.url", "http://d",
                "quarkus.oidc.auth-server-url", "http://explicit/realms/x")));
    }

    /**
     * Dev mode with an example's env file: application.properties names the default
     * system for the dev profile, the environment names it again with the example's
     * address. One system named twice is still one system.
     */
    @Test
    void aSystemNamedByTwoSourcesIsStillTheOnlyOne() {
        String derived = new SmallRyeConfigBuilder().withInterceptorFactories(new DefaultTenantInterceptorFactory())
            .withSources(
                    new PropertiesConfigSource(Map.of("kc-mcp.systems.default.url", "http://localhost:8108",
                            "kc-mcp.systems.default.auth-realm", "demo"), "environment", 300),
                    new PropertiesConfigSource(Map.of("kc-mcp.systems.default.url", "http://localhost:8080"),
                            "application.properties", 250))
            .build()
            .getRawValue(DefaultTenantInterceptorFactory.AUTH_SERVER_URL);
        assertEquals("http://localhost:8108/realms/demo", derived);
    }
}
