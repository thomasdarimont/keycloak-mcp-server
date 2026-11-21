package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.Map;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.backend.spi.Extensions;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeyVault;
import com.github.thomasdarimont.keycloak.mcp.keycloak.SigningKey;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfigBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SigningKeysProvidersTest {

    private static McpServerConfig config(Map<String, String> values) {
        return new SmallRyeConfigBuilder().withMapping(McpServerConfig.class)
            .withSources(new PropertiesConfigSource(values, "test", 500))
            .build()
            .getConfigMapping(McpServerConfig.class);
    }

    private final Extensions extensions = new Extensions(null, getClass().getClassLoader(), null);

    @Test
    void theBuiltInsServeByDefault() {
        assertEquals("file", SigningKeys.vault(config(Map.of()), extensions).id());
        assertEquals("default", SigningKeys.generator(config(Map.of()), extensions).id());
    }

    @Test
    void aSwitchedOffBuiltInIsNotUsedAnyway() {
        assertThrows(IllegalStateException.class,
                () -> SigningKeys.vault(config(Map.of("kc-mcp.spi.key-vault.file.enabled", "false")), extensions));
        assertThrows(IllegalStateException.class, () -> SigningKeys
            .generator(config(Map.of("kc-mcp.spi.key-generator.default.enabled", "false")), extensions));
    }

    /**
     * The keys of a key set straight from the vault, for an instance that does not know
     * the system yet: what is stored is published, nothing is created.
     */
    @Test
    void publishesTheKeysOfAKeySetWithoutItsSystem() {
        java.security.KeyPair pair = TestKeys.rsa();
        boolean[] created = { false };
        KeyVault vault = new KeyVault() {
            @Override
            public String id() {
                return "test";
            }

            @Override
            public java.util.Optional<SigningKey> findSigningKey(String system) {
                return "known".equals(system)
                        ? java.util.Optional.of(new SigningKey(pair.getPrivate(), pair.getPublic(), "RS256", "kid-1"))
                        : java.util.Optional.empty();
            }

            @Override
            public boolean supportsKeyCreation() {
                return true;
            }

            @Override
            public SigningKey createSigningKey(String system) {
                created[0] = true;
                return new SigningKey(pair.getPrivate(), pair.getPublic(), "RS256", "created");
            }
        };
        SigningKeys keys = new SigningKeys(config(Map.of()), vault);
        assertEquals(1, keys.publishedJwks("known").orElseThrow().getJsonArray("keys").size());
        assertEquals(java.util.Optional.empty(), keys.publishedJwks("unknown"));
        assertEquals(false, created[0], "asking for a key set creates no key");
    }
}
