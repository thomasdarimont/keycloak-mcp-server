package com.github.thomasdarimont.keycloak.mcp.backend.spi;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfigBuilder;

import static org.junit.jupiter.api.Assertions.*;

/** Extensions that cannot work with the current configuration are left out. */
class IsSupportedTest {

    private static McpServerConfig config(Map<String, String> values) {
        return new SmallRyeConfigBuilder().withMapping(McpServerConfig.class)
            .withSources(new PropertiesConfigSource(values, "test", 500))
            .build()
            .getConfigMapping(McpServerConfig.class);
    }

    /**
     * Supported only when its own setting {@code needs} is set; {@code boom} makes the
     * check throw.
     */
    static final class Picky implements AuditListener {
        private final String id;

        Picky(String id) {
            this.id = id;
        }

        @Override
        public String id() {
            return id;
        }

        @Override
        public boolean isSupported(McpServerConfig serverConfig, ProviderConfig config) {
            if (config.getBoolean("boom", false)) {
                throw new IllegalStateException("cannot tell");
            }
            return config.get("needs").isPresent();
        }

        @Override
        public void onToolCall(AuditEvent event) {
        }
    }

    @Test
    void enabledSwitchFirstThenIsSupported() {
        Picky p = new Picky("picky");
        assertFalse(Extensions.usable(p, "AuditListener", config(Map.of())), "the setting is missing");
        assertTrue(Extensions.usable(p, "AuditListener", config(Map.of("kc-mcp.spi.audit-listener.picky.needs", "x"))));
        assertFalse(Extensions.usable(p, "AuditListener", config(Map.of("kc-mcp.spi.audit-listener.picky.needs", "x",
                "kc-mcp.spi.audit-listener.picky.enabled", "false"))), "switched off wins");
        assertFalse(
                Extensions.usable(p, "AuditListener", config(Map.of("kc-mcp.spi.audit-listener.picky.boom", "true"))),
                "a failing check leaves it out");
    }

    @Test
    void theDefaultSupportsEverything() {
        AuditListener plain = event -> {
        };
        assertTrue(Extensions.usable(plain, "AuditListener", config(Map.of())));
    }

    @Test
    void theRegistryLeavesUnsupportedExtensionsOut() {
        Extensions discovery = new Extensions(null, getClass().getClassLoader(), null) {
            @Override
            @SuppressWarnings("unchecked")
            public <T> List<T> discover(Class<T> spi) {
                return spi == AuditListener.class ? (List<T>) List.of(new Picky("with"), new Picky("without"))
                        : List.of();
            }
        };
        DefaultExtensionRegistry registry = new DefaultExtensionRegistry(discovery, null,
                config(Map.of("kc-mcp.spi.audit-listener.with.needs", "yes")));
        assertEquals(List.of("with"), registry.extensions(AuditListener.class).stream().map(Extension::id).toList());
    }

    @Test
    void requiredExtensionsFailClosed() {
        Picky p = new Picky("picky");
        IllegalStateException off = Assertions.assertThrows(IllegalStateException.class,
                () -> Extensions.usable(p, "AccessCheck",
                        config(Map.of("kc-mcp.spi.audit-listener.picky.required", "true",
                                "kc-mcp.spi.audit-listener.picky.enabled", "false",
                                "kc-mcp.spi.audit-listener.picky.needs", "x"))));
        assertTrue(off.getMessage().contains("switched off"), off.getMessage());
        IllegalStateException unsupported = Assertions.assertThrows(IllegalStateException.class, () -> Extensions
            .usable(p, "AccessCheck", config(Map.of("kc-mcp.spi.audit-listener.picky.required", "true"))));
        assertTrue(unsupported.getMessage().contains("not supported"), unsupported.getMessage());
        assertTrue(Extensions.usable(p, "AccessCheck", config(Map.of("kc-mcp.spi.audit-listener.picky.required", "true",
                "kc-mcp.spi.audit-listener.picky.needs", "x"))));
    }

    @Test
    void aFailingIsSupportedStopsASharedServer() {
        Picky p = new Picky("picky");
        IllegalStateException e = Assertions.assertThrows(IllegalStateException.class,
                () -> Extensions.usable(p, "Confirmer",
                        config(Map.of("kc-mcp.spi.audit-listener.picky.boom", "true", "kc-mcp.profile", "shared"))));
        assertTrue(e.getMessage().contains("profile shared"), e.getMessage());
        assertFalse(Extensions.usable(p, "Confirmer", config(Map.of("kc-mcp.spi.audit-listener.picky.boom", "true"))),
                "local: logged and left out");
    }

    @Test
    void aRequiredExtensionThatIsNotInstalledStopsTheStart() {
        assertEquals(List.of("issuer-policy.acme-policy"),
                Extensions.missingRequired(config(Map.of("kc-mcp.spi.issuer-policy.acme-policy.required", "true",
                        "kc-mcp.spi.audit-listener.other.required", "false")), Set.of()));
        assertTrue(Extensions
            .missingRequired(config(Map.of("kc-mcp.spi.issuer-policy.acme-policy.required", "true")),
                    Set.of("issuer-policy.acme-policy"))
            .isEmpty(), "installed");

        Extensions empty = new Extensions(null, getClass().getClassLoader(), null) {
            @Override
            public <T> List<T> discover(Class<T> spi) {
                return List.of();
            }
        };
        DefaultExtensionRegistry registry = new DefaultExtensionRegistry(empty, null,
                config(Map.of("kc-mcp.spi.issuer-policy.acme-policy.required", "true")));
        IllegalStateException e = Assertions.assertThrows(IllegalStateException.class, () -> registry.onStart(null));
        assertTrue(e.getMessage().contains("acme-policy"), e.getMessage());
    }

    /** Keeps what {@code configure} is given; {@code isSupported} depends on it. */
    static final class Configured implements AuditListener {
        String company;

        @Override
        public String id() {
            return "acme-configured";
        }

        @Override
        public void configure(ProviderConfig config) {
            if (config.getBoolean("boom", false)) {
                throw new IllegalArgumentException("bad setting");
            }
            company = config.get("company", null);
        }

        @Override
        public boolean isSupported(McpServerConfig serverConfig, ProviderConfig config) {
            return company != null;
        }

        @Override
        public void onToolCall(AuditEvent event) {
        }
    }

    @Test
    void configureGetsTheExtensionsSettingsBeforeIsSupported() {
        Configured e = new Configured();
        assertTrue(Extensions.usable(e, "AuditListener",
                config(Map.of("kc-mcp.spi.audit-listener.acme-configured.company", "ACME"))));
        assertEquals("ACME", e.company);
    }

    @Test
    void aSwitchedOffExtensionIsNotConfigured() {
        Configured e = new Configured();
        assertFalse(
                Extensions.usable(e, "AuditListener", config(Map.of("kc-mcp.spi.audit-listener.acme-configured.enabled",
                        "false", "kc-mcp.spi.audit-listener.acme-configured.company", "ACME"))));
        assertNull(e.company);
    }

    @Test
    void aFailingConfigureLeavesTheExtensionOutUnlessItIsRequired() {
        assertFalse(Extensions.usable(new Configured(), "AuditListener",
                config(Map.of("kc-mcp.spi.audit-listener.acme-configured.boom", "true"))));
        Assertions.assertThrows(IllegalStateException.class,
                () -> Extensions.usable(new Configured(), "AuditListener",
                        config(Map.of("kc-mcp.spi.audit-listener.acme-configured.boom", "true",
                                "kc-mcp.spi.audit-listener.acme-configured.required", "true"))));
    }

    /** The variables as the server sees them: an environment source and the map. */
    private static McpServerConfig envConfig(Map<String, String> env) {
        return new SmallRyeConfigBuilder().withMapping(McpServerConfig.class)
            .withSources(new io.smallrye.config.EnvConfigSource(env, 300))
            .build()
            .getConfigMapping(McpServerConfig.class);
    }

    @Test
    void aRequiredFlagFromTheEnvironmentAloneCounts() {
        Map<String, String> env = Map.of("KC_MCP_SPI_ACCESS_CHECK_MISSING_ONE_REQUIRED", "true",
                "KC_MCP_SPI_AUDIT_LISTENER_OPTIONAL_REQUIRED", "false");
        assertEquals(List.of("access-check.missing-one"), Extensions.missingRequired(envConfig(env), Set.of(), env));
        assertEquals(List.of(), Extensions.missingRequired(envConfig(env), Set.of("access-check.missing-one"), env),
                "installed");
    }

    @Test
    void theEnvironmentOverridesAFilesRequiredFlag() {
        McpServerConfig file = config(Map.of("kc-mcp.spi.access-check.other.required", "true"));
        assertEquals(List.of(),
                Extensions.missingRequired(file, Set.of(), Map.of("KC_MCP_SPI_ACCESS_CHECK_OTHER_REQUIRED", "false")));
    }

    @Test
    void aRequiredFlagOfAnUnknownExtensionPointIsNotSkipped() {
        assertEquals(List.of("typo-thing"), Extensions.missingRequired(config(Map.of()), Set.of(),
                Map.of("KC_MCP_SPI_TYPO_THING_REQUIRED", "true")));
    }

    @Test
    void theCommandLineDecidesWhatIsRequired() {
        String property = "kc-mcp.spi.access-check.cli-required.required";
        Map<String, String> envSaysNo = Map.of("KC_MCP_SPI_ACCESS_CHECK_CLI_REQUIRED_REQUIRED", "false");
        Map<String, String> envSaysYes = Map.of("KC_MCP_SPI_ACCESS_CHECK_CLI_REQUIRED_REQUIRED", "true");
        try {
            System.setProperty(property, "true");
            assertEquals(List.of("access-check.cli-required"),
                    Extensions.missingRequired(config(Map.of()), Set.of(), envSaysNo));
            System.setProperty(property, "false");
            assertEquals(List.of(), Extensions.missingRequired(config(Map.of()), Set.of(), envSaysYes));
        }
        finally {
            System.clearProperty(property);
        }
        assertEquals(List.of(), Extensions.missingRequired(config(Map.of()), Set.of(), envSaysNo));
    }
}
