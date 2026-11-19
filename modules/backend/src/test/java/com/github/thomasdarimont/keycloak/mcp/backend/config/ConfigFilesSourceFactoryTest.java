package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfigFilesSourceFactoryTest {

    @TempDir
    Path dir;

    SmallRyeConfig config(String files, Map<String, String> system, Map<String, String> defaults) {
        return new SmallRyeConfigBuilder().withSources(new ConfigFilesSourceFactory())
            .withSources(new PropertiesConfigSource(Map.of(ConfigFilesSourceFactory.PROPERTY, files), "sys", 400))
            .withSources(new PropertiesConfigSource(system, "system properties", 400))
            .withSources(new PropertiesConfigSource(defaults, "application.properties", 250))
            .build();
    }

    @Test
    void filesSitBetweenTheJarDefaultsAndTheCommandLine() throws IOException {
        // a directory with a space, as C:\Program Files or a user's folder
        Path conf = Files.createDirectories(dir.resolve("dist dir").resolve("conf"));
        Path main = Files.writeString(conf.resolve("kcmcp.conf"),
                "kc-mcp.systems.default.url=http://from-file\nkc-mcp.system-defaults.default-realm=file\nkc-mcp.only-in-first=file\n");
        Path extra = Files.writeString(conf.resolve("extra.properties"),
                "kc-mcp.system-defaults.default-realm=extra\nkc-mcp.tools.read-only=true\n");

        SmallRyeConfig c = config(main + ", " + extra, Map.of("kc-mcp.systems.default.url", "http://from-command-line"),
                Map.of("kc-mcp.systems.default.url", "http://default", "kc-mcp.tools.exposure", "hybrid"));

        assertEquals("http://from-command-line", c.getRawValue("kc-mcp.systems.default.url"),
                "a system property beats the file");
        assertEquals("hybrid", c.getRawValue("kc-mcp.tools.exposure"), "defaults stay where no file speaks");
        assertEquals("true", c.getRawValue("kc-mcp.tools.read-only"), "the file beats the defaults");
        assertEquals("extra", c.getRawValue("kc-mcp.system-defaults.default-realm"),
                "a later file overrides an earlier one");
        assertEquals("file", c.getRawValue("kc-mcp.only-in-first"), "the first file is read too");
    }

    @Test
    void theOrderOfTheListDecidesWhateverTheNamesAre() throws IOException {
        Path a = Files.writeString(dir.resolve("a.properties"), "kc-mcp.tools.read-only=true\n");
        Path z = Files.writeString(dir.resolve("z.properties"), "kc-mcp.tools.read-only=false\n");
        assertEquals("false", config(a + "," + z, Map.of(), Map.of()).getRawValue("kc-mcp.tools.read-only"));
        assertEquals("true", config(z + "," + a, Map.of(), Map.of()).getRawValue("kc-mcp.tools.read-only"));
    }

    @Test
    void aDirectoryStandsForItsPropertiesFilesInNameOrder() throws IOException {
        Path systems = Files.createDirectories(dir.resolve("conf").resolve("systems"));
        // .conf as Keycloak names them, .properties as well; anything else is not
        // configuration
        Files.writeString(systems.resolve("staging.conf"),
                "kc-mcp.systems.staging.url=https://sso-staging\nkc-mcp.default-system=staging\n");
        Files.writeString(systems.resolve("prod.properties"),
                "kc-mcp.systems.prod.url=https://sso\nkc-mcp.default-system=prod\n");
        Files.writeString(systems.resolve("README.md"), "not a configuration file\n");
        SmallRyeConfig c = config(systems.toString(), Map.of(), Map.of());
        assertEquals("https://sso", c.getRawValue("kc-mcp.systems.prod.url"));
        assertEquals("https://sso-staging", c.getRawValue("kc-mcp.systems.staging.url"));
        assertEquals("staging", c.getRawValue("kc-mcp.default-system"), "staging.conf comes after prod.properties");
        String source = c.getConfigValue("kc-mcp.systems.prod.url").getConfigSourceName();
        assertTrue(source.contains("prod.properties") && source.contains("staging.conf"),
                "the source names its files: " + source);
    }

    @Test
    void theOrderHoldsForManyFiles() throws IOException {
        // more files than there are ordinals between the jar's defaults (250) and .env
        // (295)
        Path systems = Files.createDirectories(dir.resolve("many"));
        for (int i = 0; i < 25; i++) {
            Files.writeString(systems.resolve(String.format("%02d.conf", i)), "kc-mcp.tools.read-only=" + (i % 2 == 0)
                    + "\nkc-mcp.systems.s" + i + ".url=https://sso-" + i + "\n");
        }
        SmallRyeConfig c = config(systems.toString(), Map.of(), Map.of());
        assertEquals("true", c.getRawValue("kc-mcp.tools.read-only"),
                "the 25th file (24.conf, even) has the last word");
        assertEquals("https://sso-0", c.getRawValue("kc-mcp.systems.s0.url"));
        assertEquals("https://sso-24", c.getRawValue("kc-mcp.systems.s24.url"));
        assertEquals(ConfigFilesSourceFactory.ORDINAL,
                c.getConfigValue("kc-mcp.tools.read-only").getConfigSourceOrdinal());
    }

    @Test
    void anEmptyDirectoryLoadsNothing() throws IOException {
        Path empty = Files.createDirectories(dir.resolve("empty"));
        assertEquals("http://default",
                config(empty.toString(), Map.of(), Map.of("kc-mcp.systems.default.url", "http://default"))
                    .getRawValue("kc-mcp.systems.default.url"));
    }

    @Test
    void aMissingFileStopsTheStart() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> config(dir.resolve("missing.properties").toString(), Map.of(), Map.of()));
        assertTrue(e.getMessage().contains("missing.properties"), e.getMessage());
    }

    @Test
    void noFilesNoSources() {
        assertEquals("http://default", config("", Map.of(), Map.of("kc-mcp.systems.default.url", "http://default"))
            .getRawValue("kc-mcp.systems.default.url"));
    }
}
