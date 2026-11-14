package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.web.UserSession;
import com.github.thomasdarimont.keycloak.mcp.web.UserSessionStore;

import io.quarkus.oidc.AuthorizationCodeTokens;
import io.quarkus.security.AuthenticationFailedException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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

    // ---- the calls of a refresh, in the order Quarkus OIDC makes them
    // -------------------

    private final UserSessionCheckTest.MemoryStore store = new UserSessionCheckTest.MemoryStore();
    private final UserSessionTokenStateManager stored = new UserSessionTokenStateManager() {
        @Override
        public UserSessionStore store() {
            return store;
        }
    };

    /** The routing context data after {@code getTokens} found the session "s-1". */
    private Map<String, Object> requestWithSession() {
        stored.persist(null, UserSessionCheckTest.session("rt-1"));
        Map<String, Object> data = new HashMap<>();
        data.put(UserSessionTokenStateManager.CURRENT_SESSION, "s-1");
        data.put(UserSessionTokenStateManager.LOADED_SESSION, "s-1");
        return data;
    }

    private static UserSession refreshed(String id) {
        UserSession old = UserSessionCheckTest.session("rt-1");
        return new UserSession(id, old.idp(), old.issuer(), old.subject(), old.sid(), "id-2", "access-2", "rt-2", 300L,
                "openid", old.createdAt(), Long.MAX_VALUE);
    }

    @Test
    void theDeleteBeforeARefreshKeepsTheRowForTheGuardedMove() {
        Map<String, Object> data = requestWithSession();
        data.put(UserSessionTokenStateManager.REFRESHED, Boolean.TRUE);

        assertTrue(stored.keptForRefresh(data, "s-1"), "Quarkus removes the old cookie first");
        assertEquals(Set.of("s-1"), store.rows.keySet(), "the row stays: a logout can still find and remove it");

        String id = stored.idFor(stored.previousOf(data));
        assertEquals("s-1", id, "the id, and the cookie, stay: a logout with it still reaches the session");
        stored.persist("s-1", refreshed(id));
        assertEquals(Set.of("s-1"), store.rows.keySet());
        assertEquals("rt-2", store.rows.get("s-1").refreshToken());

        store.delete("s-1"); // a logout that still carries the id from before the refresh
        assertTrue(store.rows.isEmpty());
        assertFalse(stored.idFor(null).isBlank(), "a login gets a new id");
    }

    /**
     * What the review reproduced: revoked between the refresh and the new token state.
     */
    @Test
    void aSessionRevokedDuringTheRefreshIsNotStoredAgain() {
        Map<String, Object> data = requestWithSession();
        data.put(UserSessionTokenStateManager.REFRESHED, Boolean.TRUE);
        assertTrue(stored.keptForRefresh(data, "s-1"));

        store.delete("s-1"); // a back-channel logout, another tab's logout

        String previous = stored.previousOf(data);
        assertEquals("s-1", previous);
        assertThrows(AuthenticationFailedException.class, () -> stored.persist(previous, refreshed("s-2")));
        assertTrue(store.rows.isEmpty(), "not stored again: " + store.rows);
    }

    @Test
    void aSessionRevokedBeforeTheDeleteIsNotStoredAgain() {
        Map<String, Object> data = requestWithSession();
        data.put(UserSessionTokenStateManager.REFRESHED, Boolean.TRUE);
        store.delete("s-1");
        assertTrue(stored.keptForRefresh(data, "s-1"));
        assertThrows(AuthenticationFailedException.class,
                () -> stored.persist(stored.previousOf(data), refreshed("s-2")));
        assertTrue(store.rows.isEmpty());
    }

    /**
     * Should Quarkus stop marking the refresh, the delete removes the row as for a
     * logout; the token state that follows is then refused instead of stored unguarded.
     */
    @Test
    void aRefreshThatWasNotRecognisedIsRefused() {
        Map<String, Object> data = requestWithSession();
        assertFalse(stored.keptForRefresh(data, "s-1"), "no marker: an ordinary removal");
        store.delete("s-1");
        data.remove(UserSessionTokenStateManager.CURRENT_SESSION);

        assertThrows(AuthenticationFailedException.class, () -> stored.previousOf(data));
    }

    @Test
    void aLoginHasNoPreviousSessionAndALogoutIsNotKept() {
        assertNull(stored.previousOf(new HashMap<>()), "a code flow: nothing to move");

        Map<String, Object> data = requestWithSession();
        assertFalse(stored.keptForRefresh(data, "s-1"), "a logout removes the row");
        data.put(UserSessionTokenStateManager.REFRESHED, Boolean.TRUE);
        assertFalse(stored.keptForRefresh(data, "another-cookie"), "only the request's own session is kept");
    }

    @Test
    void aRefreshThatNeverFinishesLeavesNoRow() {
        Map<String, Object> data = requestWithSession();
        data.put(UserSessionTokenStateManager.REFRESHED, Boolean.TRUE);
        assertTrue(stored.keptForRefresh(data, "s-1"));

        stored.removePending(data); // the end of the request, no createTokenState came
        assertTrue(store.rows.isEmpty());
        stored.removePending(data);
    }

    /**
     * The key is not public API of Quarkus OIDC: an upgrade that renames it fails here.
     */
    @Test
    void theRefreshMarkerIsTheOneQuarkusSets() throws Exception {
        var field = Class.forName("io.quarkus.oidc.runtime.OidcIdentityProvider")
            .getDeclaredField("REFRESH_TOKEN_GRANT_RESPONSE");
        field.setAccessible(true);
        assertEquals(field.get(null), UserSessionTokenStateManager.REFRESHED);
    }
}
