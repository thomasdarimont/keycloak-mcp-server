package com.github.thomasdarimont.keycloak.mcp.backend.spi;

import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.AccessCheckSpi;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListenerSpi;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeyVaultSpi;
import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.Spi;
import com.github.thomasdarimont.keycloak.mcp.spi.Spis;
import com.github.thomasdarimont.keycloak.mcp.state.StateStore;
import com.github.thomasdarimont.keycloak.mcp.state.StateStoreSpi;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderSpi;

import io.smallrye.config.SmallRyeConfigBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The extension points as descriptors, and which one an extension belongs to. */
class SpisTest {

    private final List<Spi> spis = Spis.onClassPath();

    @Test
    void theServersExtensionPointsAndThoseOfOtherJarsAreFoundByName() {
        List<String> names = spis.stream().map(Spi::name).toList();
        assertEquals(names.stream().sorted().toList(), names, "by name");
        assertEquals(18, names.size(), "the server's 17 and the tests' own: " + names);
        assertTrue(
                names.containsAll(
                        List.of(ToolProviderSpi.NAME, AccessCheckSpi.NAME, StateStoreSpi.NAME, TestPointSpi.NAME)),
                names.toString());
        // the interfaces are distinct and none extends another: an extension has one
        // answer
        for (Spi a : spis) {
            for (Spi b : spis) {
                assertTrue(a == b || !a.extensionType().isAssignableFrom(b.extensionType()),
                        a.name() + " and " + b.name());
            }
        }
    }

    @Test
    void whichExtensionPointsOneExtensionServesAndWhichTheRegistryResolves() {
        Set<String> single = spis.stream().filter(Spi::singleProvider).map(Spi::name).collect(Collectors.toSet());
        assertEquals(Set.of("key-vault", "key-generator", "session-store", "approval-store", "rate-limit-store",
                "state-store", "test-point"), single);
        Set<String> elsewhere = spis.stream()
            .filter(s -> !s.resolvedByRegistry())
            .map(Spi::name)
            .collect(Collectors.toSet());
        assertEquals(
                Set.of("tools", "system-repository", "key-vault", "issuer-policy", "key-generator", "session-store"),
                elsewhere);
    }

    @Test
    void anExtensionBelongsToTheExtensionPointWhoseInterfaceItImplements() {
        AccessCheck check = ctx -> null;
        assertEquals(AccessCheckSpi.NAME, Spis.of(check).name());
        assertSame(Spis.of(check), Spis.of(check.getClass()), "found once per class");
        assertEquals(TestPointSpi.NAME, Spis.of(new TestPoint() {
        }).name());
        assertEquals(KeyVaultSpi.NAME,
                Spis.of(com.github.thomasdarimont.keycloak.mcp.backend.keycloak.FileKeyVault.class, spis).name());
    }

    @Test
    void aClassOfNoExtensionPointOrOfTwoIsRefusedWithAMessageThatSaysWhy() {
        IllegalStateException none = assertThrows(IllegalStateException.class, () -> Spis.of(new Extension() {
        }));
        assertTrue(none.getMessage().contains("implements the interface of no extension point"), none.getMessage());

        IllegalStateException two = assertThrows(IllegalStateException.class, () -> Spis.of(TwoPoints.class, spis));
        assertTrue(two.getMessage().contains(AuditListenerSpi.NAME) && two.getMessage().contains(TestPointSpi.NAME),
                two.getMessage());
        assertTrue(two.getMessage().contains("a class serves one extension point"), two.getMessage());
        assertFalse(two.getMessage().contains(StateStore.class.getSimpleName()));
    }

    @Test
    void anExtensionPointWhoseNameContinuesAnothersIsRefused(@TempDir Path dir) throws Exception {
        Path services = Files.createDirectories(dir.resolve("META-INF/services"));
        Files.writeString(services.resolve(Spi.class.getName()), TestPointExtraSpi.class.getName());
        try (URLClassLoader loader = new URLClassLoader(new URL[] { dir.toUri().toURL() },
                getClass().getClassLoader())) {
            IllegalStateException e = assertThrows(IllegalStateException.class, () -> Spis.load(loader));
            assertTrue(e.getMessage().contains("'test-point-extra'") && e.getMessage().contains("'test-point'"),
                    e.getMessage());
            assertTrue(e.getMessage().contains("rename one"), e.getMessage());
        }
    }

    @Test
    void aRequiredVariableNamesTheMostSpecificExtensionPoint() {
        // KC_MCP_SPI_AUDIT_LISTENER_DB_REQUIRED: 'audit-listener.db', not
        // 'audit.listener-db'
        List<Spi> withAudit = new ArrayList<>(spis);
        withAudit.addFirst(new Spi() {
            @Override
            public String name() {
                return "audit";
            }

            @Override
            public Class<? extends Extension> extensionType() {
                return TestPointExtra.class;
            }
        });
        McpServerConfig config = new SmallRyeConfigBuilder().withMapping(McpServerConfig.class)
            .build()
            .getConfigMapping(McpServerConfig.class);
        Map<String, String> env = Map.of("KC_MCP_SPI_AUDIT_LISTENER_DB_REQUIRED", "true");
        assertEquals(List.of("audit-listener.db"), Extensions.missingRequired(config, Set.of(), env, withAudit));
        assertEquals(List.of(), Extensions.missingRequired(config, Set.of("audit-listener.db"), env, withAudit),
                "installed");
        assertEquals(List.of("audit-listener.db"),
                Extensions.missingRequired(config, Set.of("audit.listener-db"), env, withAudit),
                "an extension of the other extension point does not satisfy it");
    }

    /** An extension point of its own, for a name that continues {@code test-point}. */
    public interface TestPointExtra extends Extension {
    }

    public static class TestPointExtraSpi implements Spi {
        @Override
        public String name() {
            return TestPointSpi.NAME + "-extra";
        }

        @Override
        public Class<? extends Extension> extensionType() {
            return TestPointExtra.class;
        }
    }

    /** What is not allowed: one class for two extension points. */
    abstract static class TwoPoints implements AuditListener, TestPoint {
    }
}
