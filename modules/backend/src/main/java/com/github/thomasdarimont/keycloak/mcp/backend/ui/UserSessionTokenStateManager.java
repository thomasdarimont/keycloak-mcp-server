package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Alternative;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.thomasdarimont.keycloak.mcp.backend.spi.Extensions;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.web.UserSession;
import com.github.thomasdarimont.keycloak.mcp.web.UserSessionStore;

import io.quarkus.oidc.AuthorizationCodeTokens;
import io.quarkus.oidc.OidcRequestContext;
import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.TokenStateManager;
import io.quarkus.security.AuthenticationCompletionException;
import io.quarkus.security.AuthenticationFailedException;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

/**
 * Keeps the tokens of a browser session on the server instead of in the cookie: Quarkus
 * OIDC hands the tokens of a finished code flow (or a refresh) to
 * {@link #createTokenState}, which stores them as a {@link UserSession} under a random
 * id, and that id is what the session cookie carries; {@link #getTokens} loads them
 * again, {@link #deleteTokens} ends the session (logout, invalid session). A refresh
 * replaces the tokens of the row, only while it still exists: a session removed while its
 * tokens were refreshed stays removed ({@link UserSessionStore#replace}). The id, and
 * with it the cookie's value, stays the same across refreshes: a logout that still
 * carries it, from another tab or sent just before the refresh finished, removes the
 * refreshed session too, which it would miss under a new id.
 * <p>
 * Quarkus calls {@link #deleteTokens} for the old cookie before {@link #createTokenState}
 * on a refresh as well. Removing the row there would leave nothing a concurrent logout or
 * back-channel logout could remove, and the refreshed session would be stored unguarded.
 * So a {@code deleteTokens} that belongs to a refresh ({@link #REFRESHED}) keeps the row
 * for {@code createTokenState} to move, and a {@code createTokenState} for a request that
 * came with a session but has none to move is refused. The store is the registered
 * {@link UserSessionStore} with the lowest order, the database storage's by default,
 * which encrypts the tokens at rest (the tenant switches Quarkus's own token encryption
 * off, see {@link UiTenant#config}); with the UI on and no store the first login fails,
 * which {@link UiRoutes} already reports at startup. Database calls run on a worker
 * thread.
 */
@ApplicationScoped
@Alternative
@Priority(1)
public class UserSessionTokenStateManager implements TokenStateManager {

    private static final Logger LOG = Logger.getLogger(UserSessionTokenStateManager.class);

    /** Routing context key of the id of the session the current request came with. */
    static final String CURRENT_SESSION = "kc-mcp.user-session";
    /**
     * Routing context key: this request came with a stored session ({@link #getTokens}
     * found it). Stays set whatever happens to the session afterwards.
     */
    static final String LOADED_SESSION = "kc-mcp.user-session.loaded";
    /**
     * Routing context key of a session whose removal waits for {@link #createTokenState}
     * to move it; removed at the end of the request when that never came.
     */
    static final String PENDING_REPLACE = "kc-mcp.user-session.pending-replace";
    /**
     * Routing context key Quarkus OIDC sets to {@code TRUE} once it redeemed the refresh
     * token of the request's session ({@code OidcIdentityProvider}, not public API: the
     * test pins the value). Without it a refresh is refused, never stored unguarded.
     */
    static final String REFRESHED = "refresh_token_grant_response";
    /**
     * Rows live this long past the last token expiry, so a refresh in flight still finds
     * them.
     */
    static final Duration SLACK = Duration.ofMinutes(5);
    /** When no token states an expiry. */
    static final Duration DEFAULT_LIFETIME = Duration.ofHours(12);
    private static final int ID_BYTES = 32;

    private final SecureRandom random = new SecureRandom();
    private final ObjectMapper json = new ObjectMapper();

    @Inject
    McpServerConfig config;
    @Inject
    Extensions extensions;

    private volatile UserSessionStore store;

    @Override
    public Uni<String> createTokenState(RoutingContext routingContext, OidcTenantConfig oidcConfig,
            AuthorizationCodeTokens tokens, OidcRequestContext<String> requestContext) {
        String previous;
        try {
            previous = previousOf(routingContext.data());
        }
        catch (AuthenticationFailedException e) {
            return Uni.createFrom().failure(e);
        }
        String id = idFor(previous);
        long now = System.currentTimeMillis();
        String issuer = claimOf(tokens.getIdToken(), "iss");
        if (issuer == null) {
            issuer = oidcConfig.authServerUrl().orElse("");
        }
        UserSession session = new UserSession(id, UiTenant.aliasOf(oidcConfig.tenantId().orElse(null)), issuer,
                claimOf(tokens.getIdToken(), "sub"), claimOf(tokens.getIdToken(), "sid"), tokens.getIdToken(),
                tokens.getAccessToken(), tokens.getRefreshToken(), tokens.getAccessTokenExpiresIn(),
                tokens.getAccessTokenScope(), now, expiresAt(tokens, now));
        return requestContext.runBlocking(() -> {
            persist(previous, session);
            routingContext.data().remove(PENDING_REPLACE);
            routingContext.put(CURRENT_SESSION, id);
            return id;
        });
    }

    /** A login gets a new random id, a refresh keeps the id of its session. */
    String idFor(String previous) {
        return previous == null ? newId() : previous;
    }

    /**
     * The session the new one replaces: {@code null} for a login, the request's session
     * for a refresh.
     *
     * @throws AuthenticationFailedException when the request came with a session that is
     * no longer there to move: {@link #deleteTokens} removed it without recognising the
     * refresh, so storing the new session could bring back one that was ended meanwhile
     */
    String previousOf(Map<String, Object> data) {
        String previous = (String) data.get(CURRENT_SESSION);
        if (previous == null && data.get(LOADED_SESSION) != null) {
            LOG.errorf("Tokens were refreshed for a session that was removed in the same request without the '%s'"
                    + " marker of Quarkus OIDC; the refreshed session is not stored. If this happens on every refresh,"
                    + " the marker changed with a Quarkus upgrade", REFRESHED);
            throw new AuthenticationFailedException("The session cannot be refreshed");
        }
        return previous;
    }

    /**
     * Whether a {@link #deleteTokens} for {@code tokenState} belongs to a refresh of the
     * request's own session, whose row {@link #createTokenState} moves; it is then
     * recorded as {@link #PENDING_REPLACE} and kept.
     */
    boolean keptForRefresh(Map<String, Object> data, String tokenState) {
        if (Boolean.TRUE.equals(data.get(REFRESHED)) && tokenState != null
                && tokenState.equals(data.get(CURRENT_SESSION))) {
            data.put(PENDING_REPLACE, tokenState);
            return true;
        }
        return false;
    }

    /**
     * Removes the session a refresh kept for {@link #createTokenState} when that never
     * came (the refreshed ID token was refused, say): the browser's cookie is gone by
     * then, so the row would only linger.
     */
    void removePending(Map<String, Object> data) {
        Object pending = data.remove(PENDING_REPLACE);
        if (pending != null) {
            store().delete((String) pending);
            data.remove(CURRENT_SESSION);
            LOG.debugf("User session of an unfinished refresh removed");
        }
    }

    /**
     * Stores a new session, or replaces the session {@code previous} with the refreshed
     * one, only while it still exists: a logout or back-channel logout that came while
     * Quarkus refreshed the tokens wins.
     *
     * @throws AuthenticationFailedException when {@code previous} was removed meanwhile
     */
    void persist(String previous, UserSession session) {
        UserSessionStore s = store();
        if (previous == null) {
            s.save(session);
            LOG.debugf("User session %s created", session);
            return;
        }
        if (!s.replace(previous, session)) {
            LOG.infof("User session %s was removed while its tokens were refreshed, not stored again", session);
            throw new AuthenticationFailedException("The session ended while its tokens were refreshed");
        }
        LOG.debugf("User session %s refreshed", session);
    }

    @Override
    public Uni<AuthorizationCodeTokens> getTokens(RoutingContext routingContext, OidcTenantConfig oidcConfig,
            String tokenState, OidcRequestContext<AuthorizationCodeTokens> requestContext) {
        return requestContext.runBlocking(() -> {
            Optional<UserSession> found = store().find(tokenState);
            if (found.isEmpty()) {
                LOG.debug("Session cookie names no stored user session (expired, logged out or unknown)");
                throw new AuthenticationCompletionException("Unknown or expired user session");
            }
            routingContext.put(CURRENT_SESSION, tokenState);
            routingContext.put(LOADED_SESSION, tokenState);
            UserSession s = found.get();
            return new AuthorizationCodeTokens(s.idToken(), s.accessToken(), s.refreshToken(), s.accessTokenExpiresIn(),
                    s.scope());
        });
    }

    @Override
    public Uni<Void> deleteTokens(RoutingContext routingContext, OidcTenantConfig oidcConfig, String tokenState,
            OidcRequestContext<Void> requestContext) {
        if (keptForRefresh(routingContext.data(), tokenState)) {
            routingContext.addEndHandler(done -> {
                if (routingContext.data().containsKey(PENDING_REPLACE)) {
                    Thread.ofVirtual()
                        .name("kc-mcp-user-session-cleanup")
                        .start(() -> removePending(routingContext.data()));
                }
            });
            return Uni.createFrom().voidItem();
        }
        return requestContext.runBlocking(() -> {
            store().delete(tokenState);
            routingContext.remove(CURRENT_SESSION);
            return null;
        });
    }

    /**
     * The registered store with the lowest order; fails when there is none.
     */
    public UserSessionStore store() {
        UserSessionStore s = store;
        if (s == null) {
            s = resolve().orElseThrow(() -> new IllegalStateException(
                    "The management UI needs a UserSessionStore: configure the database storage"
                            + " (quarkus.datasource.jdbc.url) or register one (kc-mcp.spi.session-store.db)"));
            store = s;
        }
        return s;
    }

    /** The store the server would use, empty when none is registered and enabled. */
    public Optional<UserSessionStore> resolve() {
        return extensions.select(UserSessionStore.class, UserSessionStore.SPI, "UserSessionStore", config, List.of());
    }

    private String newId() {
        byte[] bytes = new byte[ID_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * The latest {@code exp} of the refresh and ID token plus {@link #SLACK}; without a
     * readable expiry {@link #DEFAULT_LIFETIME}.
     */
    long expiresAt(AuthorizationCodeTokens tokens, long now) {
        return expiresAt(tokens.getIdToken(), tokens.getRefreshToken(), now);
    }

    long expiresAt(String idToken, String refreshToken, long now) {
        long latest = Math.max(expOf(refreshToken), expOf(idToken));
        if (latest <= 0) {
            return now + DEFAULT_LIFETIME.toMillis();
        }
        return Math.max(latest * 1000 + SLACK.toMillis(), now + SLACK.toMillis());
    }

    /**
     * The {@code exp} claim of a JWT without verifying it (seconds), {@code 0} when
     * absent.
     */
    long expOf(String jwt) {
        JsonNode payload = payloadOf(jwt);
        return payload == null ? 0 : payload.path("exp").asLong(0);
    }

    /** A string claim of a JWT without verifying it, {@code null} when absent. */
    String claimOf(String jwt, String claim) {
        JsonNode payload = payloadOf(jwt);
        return payload == null || !payload.hasNonNull(claim) ? null : payload.get(claim).asText();
    }

    private JsonNode payloadOf(String jwt) {
        if (jwt == null) {
            return null;
        }
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) {
            return null;
        }
        try {
            return json.readTree(new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
        }
        catch (RuntimeException | IOException e) {
            LOG.debugf("Cannot read the payload of a token (%d parts, head %s, part1 head %s): %s", parts.length,
                    jwt.substring(0, Math.min(16, jwt.length())),
                    parts[1].substring(0, Math.min(16, parts[1].length())), e.toString());
            return null;
        }
    }
}
