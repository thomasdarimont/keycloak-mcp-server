package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.thomasdarimont.keycloak.mcp.web.UserSession;
import com.github.thomasdarimont.keycloak.mcp.web.UserSessionStore;

/**
 * Asks the identity provider whether a browser session is still alive, by redeeming its
 * refresh token: Keycloak refuses ({@code invalid_grant}) once the SSO session ended
 * (logout in another application or the account console, an administrator, the idle
 * timeout), and a success both proves the session and counts as activity there, so the
 * idle timeout moves. The new tokens replace the stored ones under the same session id,
 * and the caller re-sends the cookie with a lifetime that fits the new ID token; an ended
 * session loses its row. This is activity tracking driven by the browser (the UI calls
 * {@code POST /bff/check-session} when its tab becomes visible) rather than a rolling
 * cookie, and the complement of the back-channel logout, which needs the provider to
 * reach this server.
 * <p>
 * Only {@code invalid_grant} ends a session. Any other refusal ({@code invalid_client},
 * {@code unauthorized_client}, ...) is about this server's client, not the user, and
 * answers as an unavailable provider. With rotating refresh tokens two checks of one
 * session would race: the second redeems a token the first already replaced and gets
 * {@code invalid_grant}. Checks of one session on this instance therefore share one
 * refresh, and before deleting, a check reads the row again: when its refresh token is no
 * longer the one redeemed, another request (here, on another instance, or Quarkus's own
 * token refresh) renewed the session, which stays. Comparing and deleting are one step of
 * the store ({@link UserSessionStore#deleteUnlessRenewed}), atomic in the database store.
 */
@ApplicationScoped
public class UserSessionCheck {

    /** What a check found. */
    /**
     * What a check found; {@code renewable} false for a session without a refresh token,
     * which ends with its ID token.
     */
    public record Result(boolean active, UserSession session, Instant idTokenExpiresAt, Instant accessTokenExpiresAt,
            boolean renewable) {
        static Result ended() {
            return new Result(false, null, null, null, false);
        }
    }

    private static final Logger LOG = Logger.getLogger(UserSessionCheck.class);

    private final ObjectMapper json = new ObjectMapper();

    @Inject
    IdpDiscovery discovery;
    @Inject
    UserSessionTokenStateManager sessions;
    @Inject
    UiTenant tenant;

    /** The refresh running per session id; a concurrent check of the session joins it. */
    private final ConcurrentHashMap<String, CompletableFuture<Result>> inFlight = new ConcurrentHashMap<>();

    /** What the token endpoint answered. */
    record TokenAnswer(int status, String body) {
    }

    /**
     * Refreshes the session's tokens at its provider; {@link Result#active()} false when
     * the provider's session is gone (the row is deleted then).
     *
     * @throws IdpDiscovery.Unavailable when the provider cannot be asked
     */
    public Result check(String sessionId) {
        CompletableFuture<Result> mine = new CompletableFuture<>();
        CompletableFuture<Result> running = inFlight.putIfAbsent(sessionId, mine);
        if (running != null) {
            try {
                return running.join();
            }
            catch (CompletionException e) {
                throw e.getCause() instanceof RuntimeException r ? r : e;
            }
        }
        try {
            Result result = refresh(sessionId);
            mine.complete(result);
            return result;
        }
        catch (RuntimeException e) {
            mine.completeExceptionally(e);
            throw e;
        }
        finally {
            inFlight.remove(sessionId, mine);
        }
    }

    private Result refresh(String sessionId) {
        UserSessionStore store = sessions.store();
        Optional<UserSession> found = store.find(sessionId);
        if (found.isEmpty()) {
            return Result.ended();
        }
        UserSession session = found.get();
        if (session.refreshToken() == null) {
            // nothing to ask the provider with: the session lasts as long as its ID
            // token,
            // which Quarkus cannot renew either (a logout elsewhere reaches it only
            // through the back-channel logout)
            Instant idExpiry = expiryOf(session.idToken());
            if (idExpiry != null && !idExpiry.isAfter(Instant.now())) {
                LOG.infof("Session check: %s has no refresh token and its ID token expired, row deleted", session);
                store.delete(sessionId);
                return Result.ended();
            }
            LOG.debugf("Session %s has no refresh token to check with", session);
            return new Result(true, session, idExpiry, null, false);
        }
        TokenAnswer answer = redeem(session);
        int status = answer.status();
        String body = answer.body();
        if (status == 400 || status == 401) {
            String error = errorOf(body);
            if (!"invalid_grant".equals(errorCodeOf(body))) {
                // the client's credentials or configuration, not the user's session
                LOG.warnf("Session check: %s refused by %s (%s), session kept", session, session.issuer(), error);
                throw new IdpDiscovery.Unavailable(
                        "token endpoint of " + session.issuer() + " refused this server's client (" + error + ")");
            }
            Optional<UserSession> kept = store.deleteUnlessRenewed(sessionId, session.refreshToken());
            if (kept.isPresent()) {
                UserSession renewed = kept.get();
                LOG.debugf("Session check: %s was renewed meanwhile, kept", renewed);
                return new Result(true, renewed, expiryOf(renewed.idToken()), null, renewed.refreshToken() != null);
            }
            LOG.infof("Session check: %s ended at %s (%s), row deleted", session, session.issuer(), error);
            return Result.ended();
        }
        if (status != 200) {
            throw new IdpDiscovery.Unavailable("token endpoint of " + session.issuer() + " answered HTTP " + status);
        }
        JsonNode tokens;
        try {
            tokens = json.readTree(body);
        }
        catch (IOException e) {
            throw new IdpDiscovery.Unavailable("token endpoint of " + session.issuer() + " answered no JSON");
        }
        String idToken = tokens.path("id_token").asText(session.idToken());
        String accessToken = tokens.path("access_token").asText(session.accessToken());
        String refreshToken = tokens.path("refresh_token").asText(session.refreshToken());
        Long expiresIn = tokens.hasNonNull("expires_in") ? tokens.get("expires_in").asLong()
                : session.accessTokenExpiresIn();
        long now = System.currentTimeMillis();
        UserSession renewed = new UserSession(session.id(), session.idp(), session.issuer(), session.subject(),
                session.sid(), idToken, accessToken, refreshToken, expiresIn,
                tokens.path("scope").asText(session.scope()), session.createdAt(),
                sessions.expiresAt(idToken, refreshToken, now));
        // only while the session still exists: a logout or back-channel logout that came
        // while the tokens were renewed wins, the session is not written again
        Optional<UserSession> stored = store.renew(renewed, session.refreshToken());
        if (stored.isEmpty()) {
            LOG.infof("Session check: %s was removed while its tokens were renewed, not stored again", session);
            return Result.ended();
        }
        if (stored.get() != renewed) {
            UserSession other = stored.get();
            LOG.debugf("Session check: %s was renewed meanwhile, that renewal kept", other);
            return new Result(true, other, expiryOf(other.idToken()), null, other.refreshToken() != null);
        }
        LOG.debugf("Session check: %s renewed", renewed);
        return new Result(true, renewed, expiryOf(idToken),
                expiresIn == null ? null : Instant.ofEpochMilli(now + expiresIn * 1000), refreshToken != null);
    }

    /** Redeems the session's refresh token at its provider's token endpoint. */
    TokenAnswer redeem(UserSession session) {
        UiTenant.Idp idp = tenant.idp(session.idp())
            .orElseThrow(
                    () -> new IdpDiscovery.Unavailable("identity provider " + session.idp() + " is not configured"));
        IdpDiscovery.Metadata metadata = discovery.of(session.issuer());
        String form = "grant_type=refresh_token&client_id=" + encode(idp.clientId()) + "&refresh_token="
                + encode(session.refreshToken())
                + idp.clientSecret().filter(v -> !v.isBlank()).map(s -> "&client_secret=" + encode(s)).orElse("");
        try (Response r = discovery.client()
            .target(metadata.tokenEndpoint())
            .request(MediaType.APPLICATION_JSON_TYPE)
            .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE))) {
            return new TokenAnswer(r.getStatus(), r.hasEntity() ? r.readEntity(String.class) : "");
        }
        catch (ProcessingException e) {
            throw new IdpDiscovery.Unavailable(
                    "token endpoint of " + session.issuer() + " failed: " + IdpDiscovery.rootMessage(e));
        }
    }

    private Instant expiryOf(String jwt) {
        long exp = sessions.expOf(jwt);
        return exp > 0 ? Instant.ofEpochSecond(exp) : null;
    }

    /**
     * The OAuth {@code error} code of a token endpoint answer, empty when there is none.
     */
    private String errorCodeOf(String body) {
        try {
            return json.readTree(body).path("error").asText("");
        }
        catch (IOException | RuntimeException e) {
            return "";
        }
    }

    private String errorOf(String body) {
        try {
            JsonNode node = json.readTree(body);
            return node.path("error").asText("?") + ": " + node.path("error_description").asText("");
        }
        catch (IOException | RuntimeException e) {
            return body == null ? "?" : body.substring(0, Math.min(120, body.length()));
        }
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
