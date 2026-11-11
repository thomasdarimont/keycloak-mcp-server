package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.StreamSupport;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DevModeInterceptorFactoryTest {

    static SmallRyeConfig config(Map<String, String> properties) {
        return new SmallRyeConfigBuilder()
            .withInterceptorFactories(new DevModeInterceptorFactory(), new DefaultTenantInterceptorFactory())
            .withSources(new PropertiesConfigSource(properties, "test", 300))
            .build();
    }

    static Set<String> names(SmallRyeConfig c) {
        return StreamSupport.stream(c.getPropertyNames().spliterator(), false)
            .collect(java.util.stream.Collectors.toSet());
    }

    @Test
    void devModeWithoutASystemAssumesTheLocalKeycloak() {
        SmallRyeConfig c = config(Map.of("kc-mcp.dev-mode", "true"));
        assertEquals("http://localhost:8080", c.getRawValue("kc-mcp.systems.default.url"));
        assertTrue(names(c).contains("kc-mcp.systems.default.url"), "the systems mapping finds it by name");
        assertEquals("http://localhost:8080/realms/master",
                c.getRawValue(DefaultTenantInterceptorFactory.AUTH_SERVER_URL),
                "the default tenant follows the assumed system");
    }

    @Test
    void aDistributionGetsAnH2DatabaseAndTheUi(@TempDir Path home) {
        Map<String, String> dev = Map.of("kc-mcp.dev-mode", "true", "kcmcp.home.dir", home.toString(),
                "quarkus.datasource.db-kind", "h2");
        SmallRyeConfig c = config(dev);
        assertEquals("jdbc:h2:file:" + home.resolve("data").resolve("kc-mcp"),
                c.getRawValue("quarkus.datasource.jdbc.url"));
        assertEquals("true", c.getRawValue("kc-mcp.ui.enabled"));
        assertEquals("true", c.getRawValue("kc-mcp.dynamic-systems"), "the UI can register systems");
        assertTrue(names(c).contains("quarkus.datasource.jdbc.url"));
        assertTrue(names(c).contains("kc-mcp.dynamic-systems"));
    }

    @Test
    void whatIsConfiguredWinsOverTheDevelopmentDatabaseAndUi(@TempDir Path home) {
        Map<String, String> dev = new HashMap<>(Map.of("kc-mcp.dev-mode", "true", "kcmcp.home.dir", home.toString(),
                "quarkus.datasource.db-kind", "h2"));
        Map<String, String> ownDatabase = new HashMap<>(dev);
        ownDatabase.put("quarkus.datasource.jdbc.url", "jdbc:h2:mem:mine");
        assertEquals("jdbc:h2:mem:mine", config(ownDatabase).getRawValue("quarkus.datasource.jdbc.url"));
        assertEquals("true", config(ownDatabase).getRawValue("kc-mcp.ui.enabled"), "the UI uses that database");
        Map<String, String> uiOff = new HashMap<>(dev);
        uiOff.put("kc-mcp.ui.enabled", "false");
        assertEquals("false", config(uiOff).getRawValue("kc-mcp.ui.enabled"));
        Map<String, String> staticOnly = new HashMap<>(dev);
        staticOnly.put("kc-mcp.dynamic-systems", "false");
        assertEquals("false", config(staticOnly).getRawValue("kc-mcp.dynamic-systems"));
        Map<String, String> noStorage = new HashMap<>(dev);
        noStorage.put("kc-mcp.storage.enabled", "false");
        assertNull(config(noStorage).getRawValue("quarkus.datasource.jdbc.url"));
        assertNull(config(noStorage).getRawValue("kc-mcp.ui.enabled"));
        assertNull(config(noStorage).getRawValue("kc-mcp.dynamic-systems"));
        ownDatabase.put("kc-mcp.storage.enabled", "false");
        assertNull(config(ownDatabase).getRawValue("kc-mcp.ui.enabled"), "a url alone gives no session store");
    }

    @Test
    void noDevelopmentDatabaseOutsideDevModeOrOnAnotherDatabase(@TempDir Path home) throws Exception {
        SmallRyeConfig notDev = config(Map.of("kcmcp.home.dir", home.toString(), "quarkus.datasource.db-kind", "h2"));
        assertNull(notDev.getRawValue("quarkus.datasource.jdbc.url"));
        assertNull(notDev.getRawValue("kc-mcp.ui.enabled"));
        assertNull(notDev.getRawValue("kc-mcp.dynamic-systems"));
        assertNull(config(Map.of("kc-mcp.dev-mode", "true", "quarkus.datasource.db-kind", "h2"))
            .getRawValue("quarkus.datasource.jdbc.url"), "from source there is no distribution directory");
        Files.createDirectories(home.resolve("lib/quarkus"));
        Files.writeString(home.resolve("lib/quarkus/db-kind"), "postgresql\n");
        SmallRyeConfig rebuilt = config(Map.of("kc-mcp.dev-mode", "true", "kcmcp.home.dir", home.toString(),
                "quarkus.datasource.db-kind", "h2"));
        assertNull(rebuilt.getRawValue("quarkus.datasource.jdbc.url"), "build --db=postgresql has replaced h2");
        assertNull(rebuilt.getRawValue("kc-mcp.ui.enabled"), "no store for the sessions");
    }

    @Test
    void aConfiguredSystemOfAnyNameSwitchesTheAssumptionOff() {
        SmallRyeConfig c = config(Map.of("kc-mcp.dev-mode", "true", "kc-mcp.systems.acme.url", "http://a"));
        assertNull(c.getRawValue("kc-mcp.systems.default.url"));
        assertFalse(names(c).contains("kc-mcp.systems.default.url"));
        assertEquals("http://a/realms/master", c.getRawValue(DefaultTenantInterceptorFactory.AUTH_SERVER_URL));
        assertEquals("http://d", config(Map.of("kc-mcp.dev-mode", "true", "kc-mcp.systems.default.url", "http://d"))
            .getRawValue("kc-mcp.systems.default.url"), "a configured default stays");
    }

    @Test
    void outsideDevModeOrWithRepositoriesOnlyNothingIsAssumed() {
        assertNull(config(Map.of()).getRawValue("kc-mcp.systems.default.url"));
        assertNull(config(Map.of("kc-mcp.dev-mode", "false")).getRawValue("kc-mcp.systems.default.url"));
        assertNull(config(Map.of("kc-mcp.dev-mode", "true", "kc-mcp.static-systems", "false"))
            .getRawValue("kc-mcp.systems.default.url"));
    }
}
