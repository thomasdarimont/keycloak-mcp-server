package com.github.thomasdarimont.keycloak.mcp.backend.spi;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfigBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProviderSelectionTest {

    private static final String SPI = TestPointSpi.NAME;

    private final List<String> configured = new ArrayList<>();

    private final Extensions extensions = new Extensions(null, getClass().getClassLoader(), null);

    private static McpServerConfig config(Map<String, String> values) {
        return new SmallRyeConfigBuilder().withMapping(McpServerConfig.class)
            .withSources(new PropertiesConfigSource(values, "test", 500))
            .build()
            .getConfigMapping(McpServerConfig.class);
    }

    private final class Candidate implements TestPoint {
        private final String id;

        private final int order;

        private final boolean supported;

        Candidate(String id, int order, boolean supported) {
            this.id = id;
            this.order = order;
            this.supported = supported;
        }

        @Override
        public String id() {
            return id;
        }

        @Override
        public int order() {
            return order;
        }

        @Override
        public void configure(ProviderConfig config) {
            configured.add(id);
        }

        @Override
        public boolean isSupported(McpServerConfig serverConfig, ProviderConfig config) {
            return supported;
        }
    }

    private Optional<Candidate> select(List<Candidate> found, Candidate builtIn, Map<String, String> values) {
        return extensions.select(found, List.of(builtIn), SPI, "TestPoint", config(values));
    }

    @Test
    void withoutASelectionTheLowestOrderServesAndTheOthersAreLeftAlone() {
        Candidate low = new Candidate("low", 1, true);
        assertSame(low,
                select(List.of(new Candidate("high", 5, true), low), new Candidate("built-in", 0, true), Map.of())
                    .orElseThrow());
        assertEquals(List.of("low"), configured);
    }

    @Test
    void anUnsupportedCandidateIsSkippedAndTheBuiltInComesLast() {
        Candidate builtIn = new Candidate("built-in", -100, true);
        assertSame(builtIn, select(List.of(new Candidate("low", 1, false)), builtIn, Map.of()).orElseThrow());
    }

    @Test
    void theSelectionBeatsTheOrderAndReachesBuiltIns() {
        Candidate builtIn = new Candidate("file", 0, true);
        Candidate low = new Candidate("low", 1, true);
        assertSame(builtIn,
                select(List.of(low), builtIn, Map.of("kc-mcp.spi.test-point.provider", "file")).orElseThrow());
        assertEquals(List.of("file"), configured, "the one that would have won by order stays untouched");
    }

    @Test
    void aSelectionThatCannotServeStopsTheStartInsteadOfFallingBack() {
        Candidate builtIn = new Candidate("built-in", 0, true);
        IllegalStateException missing = assertThrows(IllegalStateException.class,
                () -> select(List.of(), builtIn, Map.of("kc-mcp.spi.test-point.provider", "nope")));
        assertTrue(missing.getMessage().contains("'nope'"), missing.getMessage());
        assertThrows(IllegalStateException.class, () -> select(List.of(new Candidate("off", 1, false)), builtIn,
                Map.of("kc-mcp.spi.test-point.provider", "off")));
    }

    @Test
    void providerAndExtensionSettingsLiveSideBySide() {
        McpServerConfig c = config(
                Map.of("kc-mcp.spi.test-point.provider", "db", "kc-mcp.spi.test-point.db.grace", "5"));
        assertEquals(Optional.of("db"), ProviderConfig.selectedProvider(SPI, c, Map.of()));
        assertEquals("5", ProviderConfig.forExtension(SPI, "db", c).get("grace", "none"));
        assertEquals(Optional.of("env"),
                ProviderConfig.selectedProvider(SPI, c, Map.of("KC_MCP_SPI_TEST_POINT_PROVIDER", "env")));
    }

    @Test
    void aSelectionWhereEveryExtensionRunsIsRefused() {
        assertEquals(List.of("kc-mcp.spi.tools.provider"),
                Extensions.misplacedProviders(config(Map.of("kc-mcp.spi.tools.provider", "users")), Map.of()));
        assertEquals(List.of("kc-mcp.spi.confirmer.provider"),
                Extensions.misplacedProviders(config(Map.of()), Map.of("KC_MCP_SPI_CONFIRMER_PROVIDER", "built-in")));
        assertEquals(List.of(),
                Extensions.misplacedProviders(config(Map.of("kc-mcp.spi.test-point.provider", "db")), Map.of()));
    }

    @Test
    void aBuiltInCountsAsInstalledForRequired() {
        Candidate builtIn = new Candidate("file", 0, true);
        select(List.of(), builtIn, Map.of("kc-mcp.spi.test-point.file.required", "true"));
        assertEquals(List.of(), Extensions.missingRequired(
                config(Map.of("kc-mcp.spi.test-point.file.required", "true")), extensions.seen(), Map.of()));
    }

    @Test
    void aSwitchedOffBuiltInLeavesNoProvider() {
        assertTrue(
                select(List.of(), new Candidate("file", 0, true), Map.of("kc-mcp.spi.test-point.file.enabled", "false"))
                    .isEmpty());
    }

    @Test
    void theReportTellsSelectedFromNotSelected() {
        Candidate chosen = new Candidate("first", 1, true);
        Candidate other = new Candidate("second", 2, true);
        Candidate unsupported = new Candidate("zero", 0, false);
        McpServerConfig config = config(Map.of());
        extensions.select(List.of(chosen, other, unsupported), List.of(), SPI, "TestPoint", config);

        Map<String, String> statusById = new java.util.TreeMap<>();
        // only the built-in list and what was discovered are reported
        assertTrue(extensions.report(config).isEmpty());
        extensions.select(List.of(), List.of(chosen, other, unsupported), SPI, "TestPoint", config);
        extensions.report(config).forEach(p -> statusById.put(p.id(), p.status()));
        assertEquals(Map.of("first", "selected", "second", "not selected", "zero", "not supported"), statusById);
    }

    @Test
    void theReportShowsADisabledExtensionAndItsOrigin() {
        Candidate off = new Candidate("off", 1, true);
        McpServerConfig config = config(Map.of("kc-mcp.spi.test-point.off.enabled", "false"));
        extensions.select(List.of(), List.of(off), SPI, "TestPoint", config);

        Extensions.ProviderStatus status = extensions.report(config).getFirst();
        assertEquals("disabled", status.status());
        assertEquals("built-in", status.origin());
    }
}
