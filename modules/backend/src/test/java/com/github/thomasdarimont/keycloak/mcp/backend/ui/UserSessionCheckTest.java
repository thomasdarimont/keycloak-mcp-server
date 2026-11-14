package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.web.UserSession;
import com.github.thomasdarimont.keycloak.mcp.web.UserSessionStore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * When a session check ends a session: only on {@code invalid_grant}, and not when the
 * session was renewed meanwhile.
 */
class UserSessionCheckTest {

    /** Sessions in a map. */
    static final class MemoryStore implements UserSessionStore {
        final Map<String, UserSession> rows = new ConcurrentHashMap<>();

        @Override
        public void save(UserSession session) {
            rows.put(session.id(), session);
        }

        @Override
        public Optional<UserSession> find(String id) {
            return Optional.ofNullable(rows.get(id));
        }

        @Override
        public void delete(String id) {
            rows.remove(id);
        }

        @Override
        public long deleteExpired(long now) {
            return 0;
        }

        @Override
        public long deleteBySession(String issuer, String sid) {
            return 0;
        }

        @Override
        public long deleteBySubject(String issuer, String subject) {
            return 0;
        }
    }

    final MemoryStore store = new MemoryStore();
    final AtomicInteger redeemed = new AtomicInteger();

    UserSessionCheck check(Function<UserSession, UserSessionCheck.TokenAnswer> provider) {
        UserSessionCheck check = new UserSessionCheck() {
            @Override
            TokenAnswer redeem(UserSession session) {
                redeemed.incrementAndGet();
                return provider.apply(session);
            }
        };
        check.sessions = new UserSessionTokenStateManager() {
            @Override
            public UserSessionStore store() {
                return store;
            }
        };
        return check;
    }

    static UserSession session(String refreshToken) {
        return new UserSession("s-1", "default", "https://sso.example.com/realms/demo", "u-1", "sid-1", "id-token",
                "access", refreshToken, 300L, "openid", 1L, Long.MAX_VALUE);
    }

    static UserSessionCheck.TokenAnswer error(int status, String code) {
        return new UserSessionCheck.TokenAnswer(status, "{\"error\":\"" + code + "\",\"error_description\":\"x\"}");
    }

    @Test
    void anEndedSessionLosesItsRow() {
        store.save(session("rt-1"));
        assertFalse(check(s -> error(400, "invalid_grant")).check("s-1").active());
        assertTrue(store.rows.isEmpty());
    }

    @Test
    void aRefusedClientIsNoEndedSession() {
        store.save(session("rt-1"));
        for (var answer : new UserSessionCheck.TokenAnswer[] { error(401, "invalid_client"),
                error(400, "unauthorized_client"),
                new UserSessionCheck.TokenAnswer(400, "<html>bad request</html>") }) {
            assertThrows(IdpDiscovery.Unavailable.class, () -> check(s -> answer).check("s-1"));
            assertTrue(store.rows.containsKey("s-1"), answer.body());
        }
    }

    /**
     * A logout or back-channel logout that removes the session while its refresh token is
     * being redeemed wins: the successful renewal does not bring the session back.
     */
    @Test
    void aSessionRemovedDuringItsRenewalStaysRemoved() {
        store.save(session("rt-1"));
        UserSessionCheck.Result r = check(s -> {
            store.delete("s-1");
            return new UserSessionCheck.TokenAnswer(200, "{\"refresh_token\":\"rt-2\",\"expires_in\":300}");
        }).check("s-1");
        assertFalse(r.active());
        assertTrue(store.rows.isEmpty(), "not stored again: " + store.rows);
    }

    /**
     * Another request renewed the session first: its renewal is kept, not overwritten.
     */
    @Test
    void aRenewalDoesNotOverwriteAnotherOne() {
        store.save(session("rt-1"));
        UserSessionCheck.Result r = check(s -> {
            store.save(session("rt-other"));
            return new UserSessionCheck.TokenAnswer(200, "{\"refresh_token\":\"rt-2\",\"expires_in\":300}");
        }).check("s-1");
        assertTrue(r.active());
        assertEquals("rt-other", store.rows.get("s-1").refreshToken());
    }

    @Test
    void aSessionRenewedMeanwhileIsKept() {
        store.save(session("rt-1"));
        // another request (or instance) rotated the token between our read and our
        // redeem: the old one is refused
        UserSessionCheck.Result r = check(s -> {
            store.save(session("rt-2"));
            return error(400, "invalid_grant");
        }).check("s-1");
        assertTrue(r.active());
        assertEquals("rt-2", r.session().refreshToken());
        assertEquals("rt-2", store.rows.get("s-1").refreshToken());
    }

    @Test
    void concurrentChecksOfOneSessionShareOneRefresh() throws Exception {
        store.save(session("rt-1"));
        CountDownLatch inside = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        // a provider that rotates: the first redeem of rt-1 wins, any later one is
        // invalid_grant
        UserSessionCheck check = check(s -> {
            inside.countDown();
            try {
                release.await(5, TimeUnit.SECONDS);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return "rt-1".equals(s.refreshToken())
                    ? new UserSessionCheck.TokenAnswer(200, "{\"refresh_token\":\"rt-2\",\"expires_in\":300}")
                    : error(400, "invalid_grant");
        });
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<UserSessionCheck.Result> first = pool.submit(() -> check.check("s-1"));
            assertTrue(inside.await(5, TimeUnit.SECONDS));
            Future<UserSessionCheck.Result> second = pool.submit(() -> check.check("s-1"));
            Thread.sleep(100);
            release.countDown();
            assertTrue(first.get(5, TimeUnit.SECONDS).active());
            assertTrue(second.get(5, TimeUnit.SECONDS).active());
        }
        finally {
            pool.shutdownNow();
        }
        assertEquals(1, redeemed.get());
        assertEquals("rt-2", store.rows.get("s-1").refreshToken());
    }

    static String jwt(long exp) {
        return "eyJhbGciOiJub25lIn0."
                + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(("{\"exp\":" + exp + "}").getBytes())
                + ".sig";
    }

    static UserSession withoutRefreshToken(long idTokenExp) {
        return new UserSession("s-1", "default", "https://login.example.com", "u-1", "sid-1", jwt(idTokenExp), "access",
                null, 300L, "openid", 1L, Long.MAX_VALUE);
    }

    @Test
    void withoutARefreshTokenTheSessionLastsAsLongAsItsIdToken() {
        long now = System.currentTimeMillis() / 1000;
        store.save(withoutRefreshToken(now + 600));
        UserSessionCheck check = check(s -> {
            throw new AssertionError("nothing to redeem");
        });
        UserSessionCheck.Result live = check.check("s-1");
        assertTrue(live.active());
        assertFalse(live.renewable(), "no refresh token, no renewal");
        assertEquals(now + 600, live.idTokenExpiresAt().getEpochSecond());

        store.save(withoutRefreshToken(now - 1));
        assertFalse(check.check("s-1").active(), "expired ID token, nothing renews it");
        assertTrue(store.rows.isEmpty());
        assertEquals(0, redeemed.get());
    }
}
