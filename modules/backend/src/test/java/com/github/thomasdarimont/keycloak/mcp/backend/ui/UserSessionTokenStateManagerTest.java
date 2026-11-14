package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.web.UserSession;
import com.github.thomasdarimont.keycloak.mcp.web.UserSessionStore;

import io.quarkus.oidc.AuthorizationCodeTokens;
import io.quarkus.security.AuthenticationFailedException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UserSessionTokenStateManagerTest {

    private final UserSessionTokenStateManager manager = new UserSessionTokenStateManager();

    private static String jwt(String payload) {
        String b64 = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        return "eyJhbGciOiJub25lIn0." + b64 + ".sig";
    }

    @Test
    void readsClaimsWithoutVerifying() {
        String token = jwt("{\"sub\":\"u-1\",\"exp\":1700000000}");
        assertEquals("u-1", manager.claimOf(token, "sub"));
        assertEquals(1700000000L, manager.expOf(token));
        assertNull(manager.claimOf(token, "email"));
        assertNull(manager.claimOf("not a jwt", "sub"));
        assertEquals(0, manager.expOf(null));
        assertEquals(0, manager.expOf("a.b.c"));
    }

    @Test
    void rowLifetimeFollowsTheLatestTokenExpiry() {
        long now = 1_700_000_000_000L;
        AuthorizationCodeTokens tokens = new AuthorizationCodeTokens(jwt("{\"exp\":1700000300}"), "access",
                jwt("{\"exp\":1700001800}"));
        assertEquals(1700001800_000L + UserSessionTokenStateManager.SLACK.toMillis(), manager.expiresAt(tokens, now));
        // no readable expiry: the default lifetime
        assertEquals(now + UserSessionTokenStateManager.DEFAULT_LIFETIME.toMillis(),
                manager.expiresAt(new AuthorizationCodeTokens("opaque", "access", null), now));
        // a token that already expired still gets the slack, so a refresh in flight finds
        // the row
        assertEquals(now + UserSessionTokenStateManager.SLACK.toMillis(),
                manager.expiresAt(new AuthorizationCodeTokens(jwt("{\"exp\":1600000000}"), null, null), now));
    }

    /**
     * Quarkus refreshed the tokens of a session that a logout removed meanwhile: the
     * session is not stored again under the new id, the refresh fails.
     */
    @Test
    void aRefreshDoesNotBringBackARemovedSession() {
        UserSessionCheckTest.MemoryStore store = new UserSessionCheckTest.MemoryStore();
        UserSessionTokenStateManager manager = new UserSessionTokenStateManager() {
            @Override
            public UserSessionStore store() {
                return store;
            }
        };
        UserSession old = UserSessionCheckTest.session("rt-1");
        manager.persist(null, old);
        UserSession refreshed = new UserSession("s-2", old.idp(), old.issuer(), old.subject(), old.sid(), "id-2",
                "access-2", "rt-2", 300L, "openid", old.createdAt(), Long.MAX_VALUE);
        manager.persist("s-1", refreshed);
        assertEquals(Set.of("s-2"), store.rows.keySet(), "moved to the new id");

        store.delete("s-2");
        UserSession again = new UserSession("s-3", old.idp(), old.issuer(), old.subject(), old.sid(), "id-3",
                "access-3", "rt-3", 300L, "openid", old.createdAt(), Long.MAX_VALUE);
        assertThrows(AuthenticationFailedException.class, () -> manager.persist("s-2", again));
        assertTrue(store.rows.isEmpty(), "not stored again: " + store.rows);
    }
}
