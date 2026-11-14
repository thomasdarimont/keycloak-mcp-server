package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;

import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Quarkus test only because the admin client needs the REST client provider the extension
 * registers.
 */
@QuarkusTest
class KeycloakAdminDelegateTest {

    private static String jwt(long exp) {
        String payload = Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(new JsonObject().put("exp", exp).put("sub", "u").encode().getBytes(StandardCharsets.UTF_8));
        return "eyJhbGciOiJub25lIn0." + payload + ".sig";
    }

    private static KeycloakAdmin admin() {
        return new DefaultKeycloakAdmin(KeycloakSystem.builder("default", "http://127.0.0.1:1")
            .clientAuth(ClientAuth.NONE)
            .authRealm("demo")
            .defaultRealm("demo")
            .build(), null);
    }

    @Test
    void expiryComesFromTheToken() {
        long now = 1_000_000L;
        assertEquals(42_000L, DefaultKeycloakAdmin.expiryOf(jwt(42), now));
        assertEquals(now + 300_000L, DefaultKeycloakAdmin.expiryOf("not-a-jwt", now));
    }

    @Test
    void delegateIsCachedPerTokenUntilExpiry() {
        KeycloakAdmin base = admin();
        String fresh = jwt(System.currentTimeMillis() / 1000 + 600);
        KeycloakAdmin a = base.forToken(fresh);
        assertTrue(a.isDelegated());
        assertEquals(fresh, a.accessToken());
        assertSame(a, base.forToken(fresh));
        assertNotSame(a, base.forToken(jwt(System.currentTimeMillis() / 1000 + 601)));

        String expired = jwt(System.currentTimeMillis() / 1000 - 10);
        KeycloakAdmin e1 = base.forToken(expired);
        assertNotSame(e1, base.forToken(expired), "expired entries are rebuilt");
        base.close();
    }
}
